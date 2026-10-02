package agent

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/rahanahu/wgft/internal/agent/usermode"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/tunnel"
	"github.com/rahanahu/wgft/proto"
)

// newKeyRecordingStreamServer は、接続のたびに最初のメッセージの公開鍵を記録し、すぐに接続を閉じる
// server を立てる。agent は閉じられるたびに繋ぎ直すので、stream の接続が途切れずに続く。
// 返す関数は、それまでに記録した公開鍵の一覧を返す。
func newKeyRecordingStreamServer(t *testing.T) (endpoint string, pin [32]byte, seen func() []string) {
	t.Helper()
	var mu sync.Mutex
	var keys []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/stream", func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		var first proto.Message
		if _, b, err := ws.Read(r.Context()); err != nil || json.Unmarshal(b, &first) != nil {
			return
		}
		mu.Lock()
		keys = append(keys, first.PublicKey)
		mu.Unlock()
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://"), sha256.Sum256(srv.Certificate().Raw), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), keys...)
	}
}

// 稼働中の rotate-key は、stream が接続のたびに読む鍵と競合しない。rotate-key は制御ソケットの
// goroutine で鍵を書き換え、stream は rt.mu を持たずに鍵を読んで宣言する(stream.go の streamOnce)。
// rotate-key は鍵を書き換えた後、stream を張り直す前に最後の全体状態でトンネルを立て直す。この試験は
// その立て直しの中で、stream の接続が 2 回新しく鍵を宣言するまで待つ。2 回目の接続は鍵の書き換えより
// 後に始まり、rotate-key の側は rt.mu を持ったまま待っているので、書き換えと stream の読みの間に
// 同期は無い。鍵の読み書きが atomic でなければ、-race はこの組を競合として報告する。
// -race が無くても、server が受け取った公開鍵がどれも agent が持ったことのある鍵の公開鍵であることと、
// 張り直しの後の接続が新しい鍵を宣言することは確かめる。
func TestRotateKeyDoesNotRaceTheStreamKeyRead(t *testing.T) {
	const rotations = 3
	endpoint, pin, seen := newKeyRecordingStreamServer(t)
	// 稼働中のエージェントと同じく最後の全体状態を持たせる
	initial := newKey(t)
	rt := newRebuildTestRuntime(t, closedUDPPort(t), newKey(t).PublicKey(), initial, nil)
	alive := newAliveTestRuntime(t, endpoint, pin)
	// runStreamLoop より前の書き込みと読みは、goroutine の起動で順序が付くので競合しない
	rt.f.Endpoint, rt.f.CertSHA256, rt.f.PermanentToken = alive.f.Endpoint, alive.f.CertSHA256, alive.f.PermanentToken
	rt.f.WGPrivateKey = initial.String()
	rt.heartbeatInterval, rt.pingInterval, rt.pongTimeout = alive.heartbeatInterval, alive.pingInterval, alive.pongTimeout
	rt.reconnectBackoffMin, rt.reconnectBackoffMax = alive.reconnectBackoffMin, alive.reconnectBackoffMax
	rt.handshakeWake = make(chan struct{}, 1)
	if rt.f.LastState == nil {
		t.Fatal("the runtime has no last state to rebuild the tunnel from")
	}
	known := map[string]bool{initial.PublicKey().String(): true}

	waitKeys := func(n int) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for len(seen()) < n {
			if time.Now().After(deadline) {
				t.Errorf("the server saw %d stream connections within 10s, want at least %d", len(seen()), n)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}
	// rotate-key の立て直しのトンネルの作成で、stream の接続が 2 回新しく鍵を宣言するまで待つ
	real := usermode.NewTunnel
	usermode.NewTunnel = func(cfg tunnel.Config) (*tunnel.Tunnel, error) {
		waitKeys(len(seen()) + 2)
		return real(cfg)
	}
	t.Cleanup(func() { usermode.NewTunnel = real })

	// ログの出力は排他を取るので、rotate-key のログの後に stream がログを出すと、その排他が鍵の
	// 書き換えと読みの間に偶然の順序を付け、-race から競合を隠す。捨て先の Logger は排他を取らない
	prevOut := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prevOut) })

	runStreamLoop(t, rt)
	waitKeys(1)

	var last string
	for i := 0; i < rotations; i++ {
		pub, err := rt.rotateKey()
		if err != nil {
			t.Fatalf("rotate-key %d: %v", i, err)
		}
		last = pub.String()
		known[last] = true
	}
	// 最後の rotate-key の張り直しの後の接続は、最後の鍵を宣言する
	deadline := time.Now().Add(10 * time.Second)
	for {
		keys := seen()
		if keys[len(keys)-1] == last {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the stream did not declare the last rotated key within 10s; last declared %s, want %s", keys[len(keys)-1], last)
		}
		time.Sleep(time.Millisecond)
	}
	for _, k := range seen() {
		if !known[k] {
			t.Errorf("the stream declared %s, which is none of the keys the agent held", k)
		}
	}
	if pub := rt.privKey().PublicKey().String(); pub != last {
		t.Errorf("the runtime holds the key for %s after the rotations, want %s", pub, last)
	}
}
