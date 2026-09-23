package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
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

// errBackendFailure simulates a genuine backend failure (e.g. a SQLite error), as opposed to a
// routine authentication rejection or a real duplicate public key.
var errBackendFailure = errors.New("simulated backend failure")

type fakeBackend struct {
	mu     sync.Mutex
	server wgtypes.Key
	keys   map[string]wgtypes.Key
	gen    uint64
	// authErr / keyCheckErr, when set, make Authenticate / OtherAgentHasKey fail with this error
	// regardless of the token or key, for the backend-failure tests below.
	authErr     error
	keyCheckErr error
}

func (b *fakeBackend) Authenticate(tok string) (string, error) {
	if b.authErr != nil {
		return "", b.authErr
	}
	if strings.HasPrefix(tok, "tok-") {
		return strings.TrimPrefix(tok, "tok-"), nil
	}
	return "", ErrUnauthorized
}
func (b *fakeBackend) ServerPublicKey() wgtypes.Key { return b.server.PublicKey() }
func (b *fakeBackend) OtherAgentHasKey(agent string, key wgtypes.Key) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.keyCheckErr != nil {
		return false, b.keyCheckErr
	}
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

// TestAuthenticateBackendErrorIsNotUnauthorized は、Authenticate が(無効なトークンではなく)
// backend 自身の失敗で誤りを返したとき、日常的な認証拒否と同じ無言の 401 にしないことを確かめる。
// 直す前は両方が同じ 401 で、原因はログに残らなかった。
func TestAuthenticateBackendErrorIsNotUnauthorized(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, authErr: errBackendFailure}
	h := New(b)
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	_, resp, err := dial(t, url, "tok-home")
	if err == nil || resp == nil || resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("backend failure during authenticate: want 500, got resp=%v err=%v", resp, err)
	}
	if !strings.Contains(buf.String(), "authenticate") || !strings.Contains(buf.String(), errBackendFailure.Error()) {
		t.Errorf("expected the backend failure to be logged with its cause, got %q", buf.String())
	}
}

// TestOtherAgentHasKeyBackendErrorIsNotDuplicateKey は、OtherAgentHasKey が backend 自身の失敗
// (SQLite のエラーなど)で誤りを返したとき、「公開鍵が別のエージェントのものである」という
// 窃取を示す文言で閉じないことを確かめる。直す前は err != nil || dup が 1 つに畳まれ、
// backend の失敗が窃取の文言になり、ログにも残らなかった。
func TestOtherAgentHasKeyBackendErrorIsNotDuplicateKey(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, keyCheckErr: errBackendFailure}
	h := New(b)
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	key, _ := wgtypes.GeneratePrivateKey()
	c, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	sendJSON(t, c, proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String()})
	_, err = readMsg(t, c)
	if websocket.CloseStatus(err) != websocket.StatusInternalError {
		t.Errorf("backend failure during the duplicate-key check: want an internal-error close (so the agent retries with backoff instead of re-enrolling), got %v", err)
	}
	if !strings.Contains(buf.String(), "checking public key") || !strings.Contains(buf.String(), errBackendFailure.Error()) {
		t.Errorf("expected the backend failure to be logged with its cause, got %q", buf.String())
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

// TestPingDoesNotResetHeartbeatTimeout は、agent が送る WebSocket の ping が vpsd 側の
// 90 秒の期限を延ばさないことを確かめる(仕様 5.2 節)。agent は半開きの TCP を測るために
// 30 秒ごとに ping を送る(internal/agent の pingLoop)。制御フレームで期限が戻ると、
// ハートビートが止まったまま ping だけを送り続ける agent が接続中として残ってしまう。
// Conn.Read はデータのメッセージでしか戻らないので、期限を戻す readJSON にも届かない。
func TestPingDoesNotResetHeartbeatTimeout(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 1}
	h := New(b)
	h.HeartbeatTimeout = 300 * time.Millisecond
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

	// 期限より短い間隔で ping を送り続けても、ハートビートを送らない限り閉じられる。
	// ping には vpsd 側が自動で pong を返すので、経路そのものは生きている
	go func() {
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for range tick.C {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			err := c.Ping(ctx)
			cancel()
			if err != nil {
				return
			}
		}
	}()
	if _, err := readMsg(t, c); websocket.CloseStatus(err) != websocket.StatusCode(proto.CloseHeartbeatTimeout) {
		t.Errorf("want heartbeat-timeout close although pings kept arriving, got %v", err)
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

// TestNegotiateVersion is a table test for the pure decision function behind the stream's
// version negotiation (spec 7a.6 section). It exercises every outcome directly, without a
// WebSocket round trip: legacy v0 (both fields absent), a malformed advertisement (exactly one
// field absent, or a well-formed-looking but invalid range), a well-formed range with no
// overlap, and a well-formed overlapping range.
func TestNegotiateVersion(t *testing.T) {
	one, two := 1, 2
	zero := 0
	negative := -1
	caps := []string{"x"}

	tests := []struct {
		name          string
		msg           proto.Message
		wantOK        bool
		wantMalformed bool
		wantLegacy    bool
		wantVersion   int
	}{
		{
			name:       "both protocol fields absent: legacy v0",
			msg:        proto.Message{Type: proto.MsgPublicKey},
			wantOK:     true,
			wantLegacy: true,
		},
		{
			name:          "protocol_min present, protocol_max absent: malformed",
			msg:           proto.Message{Type: proto.MsgPublicKey, ProtocolMin: &one},
			wantOK:        false,
			wantMalformed: true,
		},
		{
			name:          "protocol_max present, protocol_min absent: malformed",
			msg:           proto.Message{Type: proto.MsgPublicKey, ProtocolMax: &one},
			wantOK:        false,
			wantMalformed: true,
		},
		{
			name:          "both present but min is 0 (versions start at 1): malformed",
			msg:           proto.Message{Type: proto.MsgPublicKey, ProtocolMin: &zero, ProtocolMax: &one},
			wantOK:        false,
			wantMalformed: true,
		},
		{
			name:          "both present but min is negative: malformed",
			msg:           proto.Message{Type: proto.MsgPublicKey, ProtocolMin: &negative, ProtocolMax: &one},
			wantOK:        false,
			wantMalformed: true,
		},
		{
			name:          "both present but min > max: malformed",
			msg:           proto.Message{Type: proto.MsgPublicKey, ProtocolMin: &two, ProtocolMax: &one},
			wantOK:        false,
			wantMalformed: true,
		},
		{
			name:          "valid range, no overlap with the server's [1,1]: mismatch, not malformed",
			msg:           proto.Message{Type: proto.MsgPublicKey, ProtocolMin: &two, ProtocolMax: &two},
			wantOK:        false,
			wantMalformed: false,
		},
		{
			name:        "valid overlapping range: selects the highest common version",
			msg:         proto.Message{Type: proto.MsgPublicKey, ProtocolMin: &one, ProtocolMax: &one, Capabilities: &caps},
			wantOK:      true,
			wantVersion: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sel, ok, malformed, reason := negotiateVersion(tt.msg)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (reason=%q)", ok, tt.wantOK, reason)
			}
			if !ok {
				if malformed != tt.wantMalformed {
					t.Errorf("malformed = %v, want %v", malformed, tt.wantMalformed)
				}
				if reason == "" {
					t.Error("reason must be non-empty when ok is false")
				}
				return
			}
			if reason != "" {
				t.Errorf("reason must be empty when ok is true, got %q", reason)
			}
			if sel.Legacy != tt.wantLegacy {
				t.Errorf("Legacy = %v, want %v", sel.Legacy, tt.wantLegacy)
			}
			if !tt.wantLegacy && sel.Version != tt.wantVersion {
				t.Errorf("Version = %d, want %d", sel.Version, tt.wantVersion)
			}
		})
	}
}

// TestStreamProtocolMalformed confirms that a pubkey with exactly one of
// protocol_min/protocol_max is refused with CloseProtocolMalformed (a distinct code from
// CloseProtocolMismatch, since this is a broken advertisement rather than a well-formed range
// with no overlap), and that the reason says what was wrong.
func TestStreamProtocolMalformed(t *testing.T) {
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
		ProtocolMin: intPtr(1), // protocol_max deliberately left nil
	})
	_, err = readMsg(t, c)
	if websocket.CloseStatus(err) != websocket.StatusCode(proto.CloseProtocolMalformed) {
		t.Fatalf("want CloseProtocolMalformed, got %v", err)
	}
	var ce websocket.CloseError
	if errors.As(err, &ce) {
		if !strings.Contains(ce.Reason, "protocol_min") || !strings.Contains(ce.Reason, "protocol_max") {
			t.Errorf("close reason should name the missing/present fields: %q", ce.Reason)
		}
	}
	if h.Status("home").Connected {
		t.Error("a malformed advertisement must not be registered as connected")
	}
}

// TestOnHeartbeatReportsGeneration は、今の接続から届いたハートビートの世代が OnHeartbeat に
// 渡ることを確かめる。vpsd はこれでルール集合の世代の遅れの始まりを記録する(設計文書 10.2a 節)。
func TestOnHeartbeatReportsGeneration(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 7}
	h := New(b)
	got := make(chan uint64, 4)
	h.OnHeartbeat = func(agent string, generation uint64) {
		if agent == "home" {
			got <- generation
		}
	}
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
	sendJSON(t, c, proto.Message{Type: proto.MsgHeartbeat, Heartbeat: &proto.Heartbeat{Generation: 6, Tunnel: proto.TunnelStatus{State: proto.StatusOK}}})
	select {
	case g := <-got:
		if g != 6 {
			t.Errorf("OnHeartbeat generation = %d, want 6", g)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnHeartbeat was not called for a heartbeat on the current connection")
	}
}

// TestDisconnectWaitsForTheHeartbeatHook は、実行中の OnHeartbeat が終わるまで Disconnect が
// 接続を外さないことを確かめる。vpsd の Revoke は Disconnect の後に遅れの記録を消すので、先に
// 外すと、実行中だったハートビートが消した後の記録を作り直してしまう(設計文書 10.2a 節)。
func TestDisconnectWaitsForTheHeartbeatHook(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 7}
	h := New(b)
	entered := make(chan struct{})
	release := make(chan struct{})
	h.OnHeartbeat = func(string, uint64) {
		close(entered)
		<-release
	}
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
	sendJSON(t, c, proto.Message{Type: proto.MsgHeartbeat, Heartbeat: &proto.Heartbeat{Generation: 6, Tunnel: proto.TunnelStatus{State: proto.StatusOK}}})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("OnHeartbeat was not called")
	}
	done := make(chan struct{})
	go func() {
		h.Disconnect("home", proto.CloseRevoked, "revoked")
		close(done)
	}()
	select {
	case <-done:
		close(release)
		t.Fatal("Disconnect returned while OnHeartbeat for that agent was still running")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect did not return after OnHeartbeat finished")
	}
}

// TestSupersedeWaitsForTheHeartbeatHook は、実行中の OnHeartbeat が終わるまで新しい接続が旧い接続を
// 置き換えないことを確かめる。先に置き換えると、旧い接続の古い世代の報告が新しい接続の報告の後に
// 記録され、vpsd が止まっていない遅れを記録してしまう(設計文書 10.2a 節)。
func TestSupersedeWaitsForTheHeartbeatHook(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 7}
	h := New(b)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h.OnHeartbeat = func(string, uint64) {
		entered <- struct{}{}
		<-release
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	key, _ := wgtypes.GeneratePrivateKey()
	dialHome := func() *websocket.Conn {
		c, _, err := dial(t, url, "tok-home")
		if err != nil {
			t.Fatal(err)
		}
		sendJSON(t, c, proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String()})
		return c
	}

	old := dialHome()
	defer old.CloseNow()
	if _, err := readMsg(t, old); err != nil {
		t.Fatalf("first state: %v", err)
	}
	sendJSON(t, old, proto.Message{Type: proto.MsgHeartbeat, Heartbeat: &proto.Heartbeat{Generation: 6, Tunnel: proto.TunnelStatus{State: proto.StatusOK}}})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("OnHeartbeat was not called")
	}

	cur := dialHome()
	defer cur.CloseNow()
	stateSent := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, err := cur.Read(ctx)
		stateSent <- err
	}()
	select {
	case <-stateSent:
		close(release)
		t.Fatal("the new connection replaced the old one while OnHeartbeat for the old one was still running")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-stateSent:
		if err != nil {
			t.Fatalf("first state on the new connection: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the new connection did not get its state after OnHeartbeat finished")
	}
}
