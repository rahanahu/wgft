package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、言語に依らない仕様(docs/design/spec の stream.md と messages.md)の fixture と、
// agent が実際に stream に書く byte 列を照らす。fixture はリポジトリの直下の testdata/spec にあり、
// Rust の実装も読む。

// specDir は fixture の置き場所である。
var specDir = filepath.Join("..", "..", "testdata", "spec")

// specFixture は fixture を読み、末尾の改行を 1 つだけ除く。メッセージの fixture は、送る byte 列の
// 後に改行を 1 つ付けて保存する。
func specFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(specDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(b, []byte("\n"))
}

// specAgentKey は fixture の agent の秘密鍵である。credentials/agent-userspace.json と同じ値で、
// 本物の鍵ではない。
const specAgentKey = "8Inc6Pvc3TkpuTejNwodOzlo4qtm41jqQlu+4IkXNlc="

// TestSpecWireAgentStream は、agent の streamOnce が送る pubkey とハートビートの byte 列が fixture と
// 一致し、fixture の全体状態をそのまま受けて適用することを確かめる。server の側は fixture の
// byte 列をそのまま送る。
func TestSpecWireAgentStream(t *testing.T) {
	stateRaw := specFixture(t, "wire/state.json")
	raws := make(chan []byte, 8)
	auth := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/stream", func(w http.ResponseWriter, r *http.Request) {
		auth <- r.Header.Get("Authorization")
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		ws.SetReadLimit(1 << 20)
		ctx := r.Context()
		_, first, err := ws.Read(ctx)
		if err != nil {
			return
		}
		raws <- first
		if err := ws.Write(ctx, websocket.MessageText, stateRaw); err != nil {
			return
		}
		for {
			typ, b, err := ws.Read(ctx)
			if err != nil {
				return
			}
			if typ != websocket.MessageText {
				t.Errorf("message type = %v, want text", typ)
			}
			select {
			case raws <- b:
			default:
			}
		}
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	pin := sha256.Sum256(srv.Certificate().Raw)

	dp := &fakeDataplane{reading: agentdp.Reading{
		Tunnel: agentdp.TunnelReading{Present: true,
			Endpoint:      netip.MustParseAddrPort("203.0.113.10:51820"),
			LastHandshake: time.Date(2026, 11, 1, 12, 0, 0, 123456789, time.UTC)},
		Rules: []proto.RuleStatus{
			{ID: "01JBX80A1B2C3D4E5F6G7H8J9K", State: proto.StatusError, Reason: "udp/9000: dial udp: lookup nas.lan on 192.168.1.1:53: no such host"},
			{ID: "r_01JBX7Z8Q4N6M2K5T9V3W1Y0AB", State: proto.StatusOK},
		},
	}}
	priv, err := wgtypes.ParseKey(specAgentKey)
	if err != nil {
		t.Fatal(err)
	}
	rt := &runtime{
		opts: Options{CredentialsPath: filepath.Join(t.TempDir(), "agent.json")},
		dp:   dp,
		f: &credentials.Credentials{
			Endpoint:       strings.TrimPrefix(srv.URL, "https://"),
			CertSHA256:     hex.EncodeToString(pin[:]),
			PermanentToken: "permanent-token",
		},
		heartbeatInterval: time.Hour,
	}
	rt.setPrivKey(priv)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.streamOnce(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	next := func(what string) []byte {
		t.Helper()
		select {
		case b := <-raws:
			return b
		case err := <-done:
			t.Fatalf("streamOnce ended before the %s: %v", what, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("no %s within 5 s", what)
		}
		return nil
	}
	if got := <-auth; got != "Bearer permanent-token" {
		t.Errorf("Authorization = %q", got)
	}
	if got, want := next("pubkey"), specFixture(t, "wire/pubkey.json"); !bytes.Equal(got, want) {
		t.Errorf("pubkey:\n got %s\nwant %s", got, want)
	}
	if got, want := next("heartbeat"), specFixture(t, "wire/heartbeat.json"); !bytes.Equal(got, want) {
		t.Errorf("heartbeat:\n got %s\nwant %s", got, want)
	}

	var sent proto.Message
	if err := json.Unmarshal(stateRaw, &sent); err != nil {
		t.Fatal(err)
	}
	rt.mu.Lock()
	gen, last := rt.gen, rt.f.LastState
	rt.mu.Unlock()
	if gen != sent.State.Generation || !reflect.DeepEqual(last, sent.State) {
		t.Errorf("applied generation %d, last_state %+v; want the fixture's state", gen, last)
	}
	if len(dp.applied) != 1 || !reflect.DeepEqual(dp.applied[0], sent.State.Rules) {
		t.Errorf("rules applied = %+v, want %+v", dp.applied, sent.State.Rules)
	}
}

// TestSpecWireHeartbeatNoTunnel は、全体状態をまだ受け取っていない agent のハートビートが fixture と
// 一致することを確かめる。
func TestSpecWireHeartbeatNoTunnel(t *testing.T) {
	rt := &runtime{dp: &fakeDataplane{}, f: &credentials.Credentials{}}
	hb := wireHeartbeat(rt.heartbeat())
	got, err := encodeMessage(proto.Message{Type: proto.MsgHeartbeat, Heartbeat: &hb})
	if err != nil {
		t.Fatal(err)
	}
	if want := specFixture(t, "wire/heartbeat-no-tunnel.json"); !bytes.Equal(got, want) {
		t.Errorf("heartbeat:\n got %s\nwant %s", got, want)
	}
}

// TestSpecWireReasons は、messages.md の「理由の切り詰め」の例を、agent がハートビートに載せる前の
// 変換(wireReason)と照らす。
func TestSpecWireReasons(t *testing.T) {
	var cases []struct {
		Name     string `json:"name"`
		In       string `json:"in"`
		InBase64 string `json:"in_base64"`
		Out      string `json:"out"`
	}
	if err := json.Unmarshal(specFixture(t, "wire/reasons.json"), &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range cases {
		in := c.In
		if c.InBase64 != "" {
			b, err := base64.StdEncoding.DecodeString(c.InBase64)
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			in = string(b)
		}
		if got := wireReason(in); got != c.Out {
			t.Errorf("%s:\n got %q\nwant %q", c.Name, got, c.Out)
		}
	}
}

// TestSpecWireAgentConstants は、stream.md の agent の側の時間と上限を固定する。
func TestSpecWireAgentConstants(t *testing.T) {
	rt := newRuntime(Options{}, &credentials.Credentials{}, wgtypes.Key{})
	got := map[string]time.Duration{
		"heartbeat":           rt.heartbeatInterval,
		"handshake retry":     rt.handshakeRetryInterval,
		"handshake retry max": rt.handshakeRetryTimeout,
		"ping":                rt.pingInterval,
		"pong timeout":        rt.pongTimeout,
		"backoff min":         rt.reconnectBackoffMin,
		"backoff max":         rt.reconnectBackoffMax,
		"backoff fresh max":   rt.reconnectBackoffFreshMax,
		"fresh for":           tunnelFreshFor,
	}
	want := map[string]time.Duration{
		"heartbeat": 30 * time.Second, "handshake retry": time.Second, "handshake retry max": 10 * time.Second,
		"ping": 30 * time.Second, "pong timeout": 20 * time.Second,
		"backoff min": time.Second, "backoff max": 5 * time.Minute, "backoff fresh max": 10 * time.Second,
		"fresh for": 180 * time.Second,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("durations = %v, want %v", got, want)
	}
	if streamReadLimit != 4<<20 {
		t.Errorf("streamReadLimit = %d", streamReadLimit)
	}
}
