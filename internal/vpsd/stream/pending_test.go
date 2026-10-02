package stream

import (
	"context"
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

// establishStream は stream を張って pubkey を送り、最初の全体状態を受け取るまで待つ。
func establishStream(t *testing.T, url, token string, key wgtypes.Key) *websocket.Conn {
	t.Helper()
	c, _, err := dial(t, url, token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.CloseNow() })
	sendJSON(t, c, proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String()})
	if m, err := readMsg(t, c); err != nil || m.Type != proto.MsgState {
		t.Fatalf("establishing a stream: %+v %v", m, err)
	}
	return c
}

// requireRefused は、そのエージェントの次の stream が 429 で断られることを確かめる。
func requireRefused(t *testing.T, url, token, label string) {
	t.Helper()
	if c, resp, err := dial(t, url, token); err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		if c != nil {
			c.CloseNow()
		}
		t.Fatalf("%s: a stream over the agent's cap: err=%v resp=%v", label, err, resp)
	}
}

// waitAccepted は、そのエージェントの stream が 2 秒以内に受け付けられることを確かめる。
func waitAccepted(t *testing.T, url, token, label string) *websocket.Conn {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, resp, err := dial(t, url, token)
		if err == nil {
			t.Cleanup(func() { c.CloseNow() })
			return c
		}
		if resp == nil || resp.StatusCode != http.StatusTooManyRequests || time.Now().After(deadline) {
			t.Fatalf("%s: err=%v resp=%v", label, err, resp)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// requireSuperseded は、置き換えられた旧接続のクライアントが superseded の理由コードで閉じられる
// ことを確かめる。旧接続のクライアントが読むと close の応答が返り、サーバの側の close の手順が終わる。
func requireSuperseded(t *testing.T, c *websocket.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		if _, _, err := c.Read(ctx); err != nil {
			if got := websocket.CloseStatus(err); got != websocket.StatusCode(proto.CloseSuperseded) {
				t.Fatalf("old stream closed with %v (%v), want superseded", got, err)
			}
			return
		}
	}
}

// TestReplacedStreamHoldsPendingSlot は、旧接続を置き換えた stream が、旧接続の serve が戻るまで
// 確立前の枠を返さないことを確かめる(設計文書 7 節、11 節)。旧接続のクライアントが close の
// フレームに応えない間、サーバの側の旧接続は close の手順で待つ。その間は、置き換えた stream の枠と
// 確立前の 1 本で上限に達し、3 本目は 429 で断られる。置き換えた stream はすぐに確立して全体状態を
// 受け取る。旧接続のクライアントが close に応えると、旧接続は superseded で閉じ、枠が戻る。
// 変異の確認:serve の returnSlot が旧接続の done を待たずに release を呼ぶと、3 本目が通って落ちる。
// 旧接続の done を閉じないと、旧接続が閉じた後も枠が戻らずに落ちる。
func TestReplacedStreamHoldsPendingSlot(t *testing.T) {
	h, url := newPendingTestHub(t)
	key, _ := wgtypes.GeneratePrivateKey()
	old := establishStream(t, url, "tok-home", key)

	// 置き換える stream は旧接続の close を待たずに確立する(establishStream が全体状態を待つ)
	start := time.Now()
	replacement := establishStream(t, url, "tok-home", key)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the replacing stream took %s to establish, want no wait for the old stream's close", took)
	}
	if !h.Status("home").Connected {
		t.Fatal("the replacing stream is not registered")
	}
	// 置き換えた stream の枠は旧接続が閉じるまで残るので、確立前の 1 本で上限に達する
	waitAccepted(t, url, "tok-home", "one pending stream next to the held slot")
	requireRefused(t, url, "tok-home", "while the old stream is closing")
	// 他のエージェントは影響を受けない
	other, _, err := dial(t, url, "tok-office")
	if err != nil {
		t.Fatalf("another agent's stream was refused: %v", err)
	}
	other.CloseNow()

	// 旧接続のクライアントが close に応えると、旧接続の serve が戻り、枠が戻る
	requireSuperseded(t, old)
	waitAccepted(t, url, "tok-home", "after the old stream closed")
	// 置き換えた stream は使えるまま
	h.Push("home")
	if m, err := readMsg(t, replacement); err != nil || m.Type != proto.MsgState {
		t.Fatalf("the replacing stream after the old one closed: %+v %v", m, err)
	}
}

// TestReplacedStreamHoldsSlotAfterItsOwnExit は、旧接続を置き換えた stream が旧接続より先に
// 終わっても、旧接続の serve が戻るまで枠を返さないことを確かめる。先に返すと、閉じる途中の旧接続が
// どの枠にも数えられないまま残り、置き換えと切断を繰り返すと閉じる途中の stream を数の上限なく
// 積める(設計文書 7 節)。
// 変異の確認:serve を抜けるときの returnSlot が旧接続の done を待たずに release を呼ぶと、
// 3 本目が通って落ちる。
func TestReplacedStreamHoldsSlotAfterItsOwnExit(t *testing.T) {
	h, url := newPendingTestHub(t)
	key, _ := wgtypes.GeneratePrivateKey()
	old := establishStream(t, url, "tok-home", key)
	replacement := establishStream(t, url, "tok-home", key)

	// 置き換えた stream を閉じ、サーバの側でも外れるまで待つ
	replacement.CloseNow()
	deadline := time.Now().Add(2 * time.Second)
	for h.Status("home").Connected {
		if time.Now().After(deadline) {
			t.Fatal("the closed replacing stream is still registered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// 旧接続はまだ close の手順の途中なので、枠は 1 つしか空いていない
	waitAccepted(t, url, "tok-home", "one pending stream next to the held slot")
	requireRefused(t, url, "tok-home", "after the replacing stream exited while the old stream is closing")

	requireSuperseded(t, old)
	waitAccepted(t, url, "tok-home", "after the old stream closed")
}

// TestFailedUpgradeReturnsPendingSlot は、恒久トークンの確認を通ったが WebSocket への切り替えに
// 失敗した要求が、確立前の枠を返すことを確かめる。
// 変異の確認:ServeHTTP の websocket.Accept の失敗の分岐で release を呼ばないと、枠が戻らずに落ちる。
func TestFailedUpgradeReturnsPendingSlot(t *testing.T) {
	_, url := newPendingTestHub(t)
	httpURL := "http" + strings.TrimPrefix(url, "ws")
	for i := 0; i < maxPendingPerAgent+1; i++ {
		req, _ := http.NewRequest(http.MethodGet, httpURL, nil)
		req.Header.Set("Authorization", "Bearer tok-home")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusSwitchingProtocols {
			t.Fatalf("plain request %d without an upgrade: status %d", i, resp.StatusCode)
		}
	}
	waitAccepted(t, url, "tok-home", "after failed upgrades")
	waitAccepted(t, url, "tok-home", "a second stream after failed upgrades")
}
