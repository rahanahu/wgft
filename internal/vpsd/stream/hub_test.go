package stream

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/proto"
)

type fakeBackend struct {
	mu     sync.Mutex
	server wgtypes.Key
	keys   map[string]wgtypes.Key
	gen    uint64
}

func (b *fakeBackend) Authenticate(tok string) (string, error) {
	if strings.HasPrefix(tok, "tok-") {
		return strings.TrimPrefix(tok, "tok-"), nil
	}
	return "", ErrUnauthorized
}
func (b *fakeBackend) ServerPublicKey() wgtypes.Key { return b.server.PublicKey() }
func (b *fakeBackend) OtherAgentHasKey(agent string, key wgtypes.Key) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for n, k := range b.keys {
		if n != agent && k == key {
			return true, nil
		}
	}
	return false, nil
}
func (b *fakeBackend) SetPublicKey(agent string, key wgtypes.Key) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.keys[agent] = key
	return nil
}
func (b *fakeBackend) StateFor(agent string, sel proto.Negotiated) (*proto.State, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := &proto.State{Generation: b.gen, WG: proto.WGConfig{Address: "10.200.0.2/24"}}
	if !sel.Legacy {
		version := sel.Version
		caps := proto.SupportedCapabilities
		st.ServerProtocolVersion = &version
		st.ServerCapabilities = &caps
	}
	return st, nil
}
func dial(t *testing.T, url, token string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + token}}})
}

func sendJSON(t *testing.T, c *websocket.Conn, m proto.Message) {
	t.Helper()
	b, _ := json.Marshal(m)
	if err := c.Write(context.Background(), websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}

func readMsg(t *testing.T, c *websocket.Conn) (proto.Message, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, b, err := c.Read(ctx)
	if err != nil {
		return proto.Message{}, err
	}
	var m proto.Message
	return m, json.Unmarshal(b, &m)
}

func TestStream(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 5}
	h := New(b)
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	// 認証なし・無効
	if _, resp, err := dial(t, url, "bad"); err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token: err=%v resp=%v", err, resp)
	}

	// 鍵の検証:サーバ鍵と同じ → 拒否。他エージェントの鍵 → 拒否。不正な形式 → 拒否
	otherKey, _ := wgtypes.GeneratePrivateKey()
	b.keys["office"] = otherKey.PublicKey()
	for name, key := range map[string]string{"server key": server.PublicKey().String(), "other agent": otherKey.PublicKey().String(), "garbage": "not-a-key"} {
		c, _, err := dial(t, url, "tok-home")
		if err != nil {
			t.Fatal(err)
		}
		sendJSON(t, c, proto.Message{Type: proto.MsgPublicKey, PublicKey: key})
		if _, err := readMsg(t, c); err == nil || websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
			t.Errorf("%s: want policy violation close, got %v", name, err)
		}
		c.CloseNow()
	}
	if h.Status("home").Connected {
		t.Error("rejected connections must not register")
	}

	// 正しい鍵:ピアが設定され、全体状態が届く
	homeKey, _ := wgtypes.GeneratePrivateKey()
	c1, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	sendJSON(t, c1, proto.Message{Type: proto.MsgPublicKey, PublicKey: homeKey.PublicKey().String()})
	m, err := readMsg(t, c1)
	if err != nil || m.Type != proto.MsgState || m.State.Generation != 5 {
		t.Fatalf("first state: %+v %v", m, err)
	}
	if b.keys["home"] != homeKey.PublicKey() {
		t.Error("SetPublicKey not called")
	}
	if st := h.Status("home"); !st.Connected || st.StreamFrom != "127.0.0.1" {
		t.Errorf("status = %+v", st)
	}

	// ハートビートが記録される
	sendJSON(t, c1, proto.Message{Type: proto.MsgHeartbeat, Heartbeat: &proto.Heartbeat{Generation: 5, Tunnel: proto.TunnelStatus{State: proto.StatusOK}}})
	deadline := time.Now().Add(2 * time.Second)
	for h.Status("home").Heartbeat == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hb := h.Status("home").Heartbeat; hb == nil || hb.Generation != 5 {
		t.Errorf("heartbeat not recorded: %+v", hb)
	}

	// Push:配る内容が変わったら送り直す
	b.mu.Lock()
	b.gen = 6
	b.mu.Unlock()
	h.Push("home")
	if m, err := readMsg(t, c1); err != nil || m.State == nil || m.State.Generation != 6 {
		t.Errorf("push: %+v %v", m, err)
	}

	// 2 本目の接続:新しい方が優先され、旧接続は superseded で閉じる
	c2, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	sendJSON(t, c2, proto.Message{Type: proto.MsgPublicKey, PublicKey: homeKey.PublicKey().String()})
	if m, err := readMsg(t, c2); err != nil || m.Type != proto.MsgState {
		t.Fatalf("second conn state: %+v %v", m, err)
	}
	if _, err := readMsg(t, c1); websocket.CloseStatus(err) != websocket.StatusCode(proto.CloseSuperseded) {
		t.Errorf("old conn: want superseded close, got %v", err)
	}
	if !h.Status("home").Connected {
		t.Error("new connection should be connected")
	}

	// 無効化:理由付きで閉じ、状態も消える
	h.Disconnect("home", proto.CloseRevoked, "revoked")
	if _, err := readMsg(t, c2); websocket.CloseStatus(err) != websocket.StatusCode(proto.CloseRevoked) {
		t.Errorf("revoke close: %v", err)
	}
	if h.Status("home").Connected {
		t.Error("revoked agent must be disconnected")
	}
	_ = errors.New
}

// TestHeartbeatTimeout は、ハートビートが期限内に来ない接続を、理由コード付きで
// vpsd 側から閉じることを確かめる。
func TestHeartbeatTimeout(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 1}
	h := New(b)
	h.HeartbeatTimeout = 150 * time.Millisecond // テストなので短くする
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	key, _ := wgtypes.GeneratePrivateKey()
	c, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	sendJSON(t, c, proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String()})
	if m, err := readMsg(t, c); err != nil || m.Type != proto.MsgState {
		t.Fatalf("first state: %+v %v", m, err)
	}

	// ハートビートを送らずに待つ
	if _, err := readMsg(t, c); websocket.CloseStatus(err) != websocket.StatusCode(proto.CloseHeartbeatTimeout) {
		t.Errorf("want heartbeat-timeout close, got %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for h.Status("home").Connected && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.Status("home").Connected {
		t.Error("timed-out connection must be dropped")
	}
}

// TestHeartbeatResetsTimeout は、ハートビートが届き続ける限り期限で切られないことを確かめる。
func TestHeartbeatResetsTimeout(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 1}
	h := New(b)
	h.HeartbeatTimeout = 150 * time.Millisecond
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	key, _ := wgtypes.GeneratePrivateKey()
	c, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	sendJSON(t, c, proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String()})
	if _, err := readMsg(t, c); err != nil {
		t.Fatalf("first state: %v", err)
	}

	// 期限より短い間隔でハートビートを送り続ける限り、接続は保たれる
	for i := 0; i < 4; i++ {
		time.Sleep(80 * time.Millisecond)
		sendJSON(t, c, proto.Message{Type: proto.MsgHeartbeat, Heartbeat: &proto.Heartbeat{Generation: 1, Tunnel: proto.TunnelStatus{State: proto.StatusOK}}})
	}
	if !h.Status("home").Connected {
		t.Error("connection kept alive by heartbeats must stay connected")
	}
}

// intPtr/strSlicePtr build the pointer types Message uses to distinguish "absent" from
// "present but empty" (proto/stream.go).
func intPtr(i int) *int                { return &i }
func strSlicePtr(s []string) *[]string { return &s }

// TestStreamProtocolNegotiationV1 confirms a v1 agent (protocol_min/max=1) gets the version
// it asked for back on the state message, and that the hub records it (spec 7a.6 section).
func TestStreamProtocolNegotiationV1(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 1}
	h := New(b)
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	key, _ := wgtypes.GeneratePrivateKey()
	c, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	sendJSON(t, c, proto.Message{
		Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String(),
		ProtocolMin: intPtr(1), ProtocolMax: intPtr(1), Capabilities: strSlicePtr(nil),
	})
	m, err := readMsg(t, c)
	if err != nil || m.Type != proto.MsgState {
		t.Fatalf("first state: %+v %v", m, err)
	}
	if m.State.ServerProtocolVersion == nil || *m.State.ServerProtocolVersion != 1 {
		t.Errorf("want server_protocol_version=1, got %v", m.State.ServerProtocolVersion)
	}
	if m.State.ServerCapabilities == nil {
		t.Errorf("want a non-nil (possibly empty) server_capabilities, got nil")
	}
	st := h.Status("home")
	if st.Protocol.Legacy || st.Protocol.Version != 1 || st.Protocol.AgentMin != 1 || st.Protocol.AgentMax != 1 {
		t.Errorf("hub did not record the negotiated protocol: %+v", st.Protocol)
	}
}

// TestStreamProtocolNegotiationLegacy confirms a pubkey message without protocol_min/max (an
// old agent) is treated as legacy v0: the state it receives carries no version fields, and the
// hub records it as legacy (spec 7a.6 section).
func TestStreamProtocolNegotiationLegacy(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 1}
	h := New(b)
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	key, _ := wgtypes.GeneratePrivateKey()
	c, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	sendJSON(t, c, proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String()})
	m, err := readMsg(t, c)
	if err != nil || m.Type != proto.MsgState {
		t.Fatalf("first state: %+v %v", m, err)
	}
	if m.State.ServerProtocolVersion != nil {
		t.Errorf("legacy agent: want no server_protocol_version, got %v", *m.State.ServerProtocolVersion)
	}
	if m.State.ServerCapabilities != nil {
		t.Errorf("legacy agent: want no server_capabilities, got %v", *m.State.ServerCapabilities)
	}
	if st := h.Status("home"); !st.Protocol.Legacy {
		t.Errorf("hub did not record the agent as legacy: %+v", st.Protocol)
	}
}

// TestStreamProtocolMismatch confirms that an agent whose declared range does not overlap the
// server's is refused with CloseProtocolMismatch naming both ranges, and is never registered as
// connected (spec 7a.6 section: "共通部分が無ければ、server は双方の範囲を示すエラーで stream を断る").
func TestStreamProtocolMismatch(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 1}
	h := New(b)
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	key, _ := wgtypes.GeneratePrivateKey()
	c, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	sendJSON(t, c, proto.Message{
		Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String(),
		ProtocolMin: intPtr(2), ProtocolMax: intPtr(2),
	})
	_, err = readMsg(t, c)
	if websocket.CloseStatus(err) != websocket.StatusCode(proto.CloseProtocolMismatch) {
		t.Fatalf("want CloseProtocolMismatch, got %v", err)
	}
	var ce websocket.CloseError
	if errors.As(err, &ce) {
		if !strings.Contains(ce.Reason, "[1,1]") || !strings.Contains(ce.Reason, "[2,2]") {
			t.Errorf("close reason should name both ranges: %q", ce.Reason)
		}
	}
	if h.Status("home").Connected {
		t.Error("a version-mismatched agent must not be registered as connected")
	}
}
