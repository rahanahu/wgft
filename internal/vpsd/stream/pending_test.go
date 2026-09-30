package stream

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/proto"
)

func newPendingTestHub(t *testing.T) (*Hub, string) {
	t.Helper()
	server, _ := wgtypes.GeneratePrivateKey()
	h := New(&fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 1})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return h, "ws" + strings.TrimPrefix(srv.URL, "http")
}

// pubkeyWithCaps は、capabilities を n 個持つ pubkey のメッセージである。大きさを変えるのに使う。
func pubkeyWithCaps(key wgtypes.Key, n int) proto.Message {
	caps := make([]string, n)
	for i := range caps {
		caps[i] = fmt.Sprintf("capability-%020d", i)
	}
	lo, hi := proto.SupportedProtocol.Min, proto.SupportedProtocol.Max
	return proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String(), ProtocolMin: &lo, ProtocolMax: &hi, Capabilities: &caps}
}

// TestFirstMessageReadLimit は、最初のメッセージを 4 KiB までで読み、確立の後はハートビートを
// 1 MiB まで読むことを確かめる(設計文書 5.2 節、11 節)。4 KiB を超える最初のメッセージの接続は
// 確立しない。
// 変異の確認:ServeHTTP の SetReadLimit(firstMessageReadLimit) を 1 MiB のままにすると大きい pubkey の
// 接続が確立して落ちる。serve の SetReadLimit(streamReadLimit) を外すと大きいハートビートで接続が
// 切れて落ちる。
func TestFirstMessageReadLimit(t *testing.T) {
	h, url := newPendingTestHub(t)
	var beats atomic.Int32
	h.OnHeartbeat = func(string, uint64) { beats.Add(1) }
	key, _ := wgtypes.GeneratePrivateKey()

	big := pubkeyWithCaps(key, 200) // 約 7 KiB
	c, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	sendJSON(t, c, big)
	if m, err := readMsg(t, c); err == nil {
		t.Fatalf("a first message over 4 KiB established the stream: got %+v", m)
	}
	c.CloseNow()
	if h.Status("home").Connected {
		t.Fatal("a stream whose first message is over 4 KiB was registered")
	}

	// 4 KiB に収まる最初のメッセージは通り、確立の後は 4 KiB を超えるハートビートも読む
	small := pubkeyWithCaps(key, 100) // 約 3.5 KiB
	c, _, err = dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	sendJSON(t, c, small)
	if m, err := readMsg(t, c); err != nil || m.Type != proto.MsgState {
		t.Fatalf("a first message within 4 KiB: %+v %v", m, err)
	}
	rules := make([]proto.RuleStatus, 2000) // 約 64 KiB
	for i := range rules {
		rules[i] = proto.RuleStatus{ID: fmt.Sprintf("rule-%d", i), State: proto.StatusOK}
	}
	sendJSON(t, c, proto.Message{Type: proto.MsgHeartbeat, Heartbeat: &proto.Heartbeat{Generation: 1, Rules: rules}})
	deadline := time.Now().Add(2 * time.Second)
	for beats.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if beats.Load() != 1 || !h.Status("home").Connected {
		t.Fatalf("a 64 KiB heartbeat on an established stream: heartbeats = %d, connected = %v", beats.Load(), h.Status("home").Connected)
	}
}

// TestFirstMessageTimeout は、最初のメッセージを送らない stream を期限で閉じることを確かめる
// (設計文書 5.2 節)。
// 変異の確認:serve の最初の読みの期限を firstMessageTimeout でなく 30 秒に戻すと、2 秒の予算で
// 閉じられずに落ちる。
func TestFirstMessageTimeout(t *testing.T) {
	h, url := newPendingTestHub(t)
	h.firstMessageTimeout = 200 * time.Millisecond
	c, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	start := time.Now()
	if _, err := readMsg(t, c); err == nil {
		t.Fatal("a stream without a first message got a message")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("closed after %s, want about the 200 ms deadline", took)
	}
}

// TestPendingStreamsPerAgent は、1 つのエージェントが同時に持てる確立前の stream を 2 本に抑え、
// 3 本目を 429 で断り、断った接続では Authenticated を呼ばないことを確かめる。確立した stream と
// 閉じた stream は数から外れ、他のエージェントは影響を受けない(設計文書 11 節)。
// 変異の確認:ServeHTTP の reservePending の判定を外すと 3 本目が通って落ちる。serve の established を
// 呼ばないと、確立の後の接続が断られて落ちる。reservePending の release で数を戻さないと、閉じた
// 後の接続が断られて落ちる。
func TestPendingStreamsPerAgent(t *testing.T) {
	h, url := newPendingTestHub(t)
	var authenticated atomic.Int32
	h.Authenticated = func(*http.Request) { authenticated.Add(1) }

	var pending []*websocket.Conn
	t.Cleanup(func() {
		for _, c := range pending {
			c.CloseNow()
		}
	})
	for i := 0; i < maxPendingPerAgent; i++ {
		c, _, err := dial(t, url, "tok-home")
		if err != nil {
			t.Fatalf("pending stream %d: %v", i, err)
		}
		pending = append(pending, c)
	}
	if _, resp, err := dial(t, url, "tok-home"); err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a stream over the agent's pending cap: err=%v resp=%v", err, resp)
	}
	if n := authenticated.Load(); n != maxPendingPerAgent {
		t.Errorf("Authenticated ran %d times, want %d: a refused stream must stay counted as unauthenticated", n, maxPendingPerAgent)
	}
	// 他のエージェントは数えられない
	other, _, err := dial(t, url, "tok-office")
	if err != nil {
		t.Fatalf("another agent's stream was refused: %v", err)
	}
	other.CloseNow()

	// 1 本を確立すると、その枠が空く
	key, _ := wgtypes.GeneratePrivateKey()
	sendJSON(t, pending[0], proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String()})
	if m, err := readMsg(t, pending[0]); err != nil || m.Type != proto.MsgState {
		t.Fatalf("establishing a pending stream: %+v %v", m, err)
	}
	c, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatalf("after one stream was established, a new stream was refused: %v", err)
	}
	pending = append(pending, c)

	// 確立前の 1 本を閉じると、その枠が空く
	pending[1].CloseNow()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, resp, err := dial(t, url, "tok-home")
		if err == nil {
			pending = append(pending, c)
			break
		}
		if resp == nil || resp.StatusCode != http.StatusTooManyRequests || time.Now().After(deadline) {
			t.Fatalf("after a pending stream closed, a new stream: err=%v resp=%v", err, resp)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
