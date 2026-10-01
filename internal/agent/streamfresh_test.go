package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/rahanahu/wgft/internal/agent/enroll"
	"github.com/rahanahu/wgft/proto"
)

// 仕様 5.2 節の「トンネルが新しい間の待ちの上限」の試験。判定は時刻を引数に取るので、境目は
// 固定の時刻で確かめる。streamLoop の間隔は、既存の再接続の試験と同じく runtime のフィールドで
// 短くし、実時間で測る。

// 最終ハンドシェイクは、観測した時刻からも値そのものからも 180 秒未満のときだけ新しい。
func TestHandshakeObservationFreshness(t *testing.T) {
	base := time.Date(2026, 9, 25, 9, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		obs  *handshakeObservation
		now  time.Time
		want bool
	}{
		{"never observed", nil, base, false},
		{"no handshake yet", &handshakeObservation{observedAt: base}, base, false},
		{"just observed", &handshakeObservation{handshake: base, observedAt: base.Add(20 * time.Second)}, base.Add(20 * time.Second), true},
		{"179 s after the handshake", &handshakeObservation{handshake: base, observedAt: base.Add(20 * time.Second)}, base.Add(179 * time.Second), true},
		// 観測からは 160 秒だが、値そのものからは 180 秒である
		{"180 s after the handshake", &handshakeObservation{handshake: base, observedAt: base.Add(20 * time.Second)}, base.Add(180 * time.Second), false},
		// 起動の直後に初めて読んだ古い値。観測したばかりでも新しくない
		{"an old value seen for the first time", &handshakeObservation{handshake: base.Add(-time.Hour), observedAt: base}, base, false},
		// 壁時計が戻り、値が未来に見える。観測から 180 秒で古くなる
		{"a value from the future, 179 s after it was observed", &handshakeObservation{handshake: base.Add(time.Hour), observedAt: base}, base.Add(179 * time.Second), true},
		{"a value from the future, 180 s after it was observed", &handshakeObservation{handshake: base.Add(time.Hour), observedAt: base}, base.Add(180 * time.Second), false},
	}
	for _, c := range cases {
		if got := c.obs.fresh(c.now); got != c.want {
			t.Errorf("%s: fresh = %v, want %v", c.name, got, c.want)
		}
	}
}

// checkTunnel は読んだ最終ハンドシェイクを証拠として残す。閾値を持たない runtime(カーネルモード)と
// 作り直しの閾値を持つ runtime(ユーザー空間モード)の両方で、同じ値が同じ判定になる。証拠は
// 180 秒で古くなり、新しいハンドシェイクで再び新しくなる。
func TestCheckTunnelRecordsTheHandshakeEvidence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rebuild rebuildState
	}{
		{"without a rebuild threshold, as in kernel mode", rebuildState{}},
		{"with a rebuild threshold, as in userspace mode", rebuildState{after: defaultRebuildAfter, backoffMax: defaultRebuildBackoffMax}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hs := time.Date(2026, 9, 25, 9, 0, 0, 0, time.UTC)
			dp := &fakeDataplane{up: true, reading: dataplaneReading{tunnel: tunnelReading{present: true}}}
			rt := newFakeDataplaneRuntime(t, dp)
			rt.f.LastState = &proto.State{Generation: 1}
			rt.rebuild = tc.rebuild
			now := hs.Add(5 * time.Second)

			rt.checkTunnel(now)
			if rt.handshakeSeen.Load().fresh(now) {
				t.Fatal("a tunnel without a handshake counts as fresh")
			}
			dp.reading.tunnel.lastHandshake = hs
			rt.checkTunnel(now)
			if !rt.handshakeSeen.Load().fresh(now) {
				t.Fatal("a handshake 5 s old does not count as fresh")
			}
			// 同じ値を読み続けても、観測した時刻は進まない
			for i := 1; i <= 5; i++ {
				rt.checkTunnel(now.Add(time.Duration(i) * 30 * time.Second))
			}
			if !rt.handshakeSeen.Load().fresh(hs.Add(179 * time.Second)) {
				t.Error("the handshake is not fresh 179 s after it")
			}
			if rt.handshakeSeen.Load().fresh(hs.Add(180 * time.Second)) {
				t.Error("the handshake is still fresh 180 s after it; one fresh handshake must not keep the cap forever")
			}
			// 新しいハンドシェイクで再び新しくなる
			dp.reading.tunnel.lastHandshake = hs.Add(200 * time.Second)
			rt.checkTunnel(hs.Add(205 * time.Second))
			if !rt.handshakeSeen.Load().fresh(hs.Add(205 * time.Second)) {
				t.Error("a new handshake did not make the tunnel fresh again")
			}
			// 壁時計が戻ると、値は未来に見え続ける。同じ値を読み続けても、最初に観測してから 180 秒で古くなる
			back := hs.Add(300 * time.Second)
			dp.reading.tunnel.lastHandshake = back.Add(time.Hour)
			for i := 0; i <= 6; i++ {
				rt.checkTunnel(back.Add(time.Duration(i) * 30 * time.Second))
			}
			if rt.handshakeSeen.Load().fresh(back.Add(180 * time.Second)) {
				t.Error("a handshake from the future is still fresh 180 s after it was first observed")
			}
		})
	}
}

// attemptIntervals は attempts から n 回分の試みを受け取り、隣り合う試みの間隔を返す。
func attemptIntervals(t *testing.T, attempts <-chan time.Time, prev time.Time, n int) ([]time.Duration, time.Time) {
	t.Helper()
	var out []time.Duration
	for i := 0; i < n; i++ {
		select {
		case at := <-attempts:
			if !prev.IsZero() {
				out = append(out, at.Sub(prev))
			}
			prev = at
		case <-time.After(15 * time.Second):
			t.Fatalf("only %d of %d attempts within 15s; intervals so far %v", i, n, out)
		}
	}
	return out, prev
}

// streamAttempt は、refusing server が受けた 1 回の試みの時刻と、その試みの直前に streamLoop が
// 待った間隔(観測の Backoff)。
type streamAttempt struct {
	at   time.Time
	wait time.Duration
}

// newWaitRecordingStreamServer は stream の要求をいつも 503 で断る server を立て、試みごとに、
// 応答する前に rt の観測から直前の待ちを読む。streamLoop は応答を受けるまで次の待ちを記録しない
// ので、読んだ値はこの試みの直前の待ちである。rt は最初の試みの前に Store する。
func newWaitRecordingStreamServer(t *testing.T) (endpoint string, pin [32]byte, rt *atomic.Pointer[runtime], attempts chan streamAttempt) {
	t.Helper()
	rt = new(atomic.Pointer[runtime])
	attempts = make(chan streamAttempt, 256)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/stream", func(w http.ResponseWriter, r *http.Request) {
		a := streamAttempt{at: time.Now(), wait: rt.Load().streamStatus().Backoff}
		select {
		case attempts <- a:
		default:
		}
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://"), sha256.Sum256(srv.Certificate().Raw), rt, attempts
}

// recordedWaits は attempts から n 回分の試みを受け取り、各試みの直前の待ちを返す。前の試みからの
// 実時間の間隔は、その待ち以上で、待ちに stall を足した値以下でなければならない。下の限りは、記録した
// 待ちを実際に待ったことを確かめる。上の限りは、記録よりはるかに長く待つ誤りを捉えるためのもので、
// 試みそのものに要する時間と、混んだ機械で timer と goroutine が遅れる分を含めて広く取る。
func recordedWaits(t *testing.T, attempts <-chan streamAttempt, prev time.Time, n int) ([]time.Duration, time.Time) {
	t.Helper()
	const stall = 2 * time.Second
	var out []time.Duration
	for i := 0; i < n; i++ {
		select {
		case a := <-attempts:
			if !prev.IsZero() {
				if d := a.at.Sub(prev); d < a.wait || d > a.wait+stall {
					t.Fatalf("attempt %d came %s after the previous one, but the recorded wait was %s; waits so far %v", i, d, a.wait, out)
				}
			}
			out = append(out, a.wait)
			prev = a.at
		case <-time.After(15 * time.Second):
			t.Fatalf("only %d of %d attempts within 15s; waits so far %v", i, n, out)
		}
	}
	return out, prev
}

// トンネルが新しい間は待ちが上限で止まり、古くなると上限から倍々に伸び、再び新しくなると
// 上限に戻る(仕様 5.2 節)。上限が無ければ、1 つ目の段で待ちは初期値から倍々に伸び続ける。
// 待ちの長さは streamLoop が待ちに入るときに記録する観測(設計文書 10.2c 節)の値で比べる。
// 試みの間隔の実時間には試みそのものの時間と機械の混み具合が乗るので、上限との比較には使わず、
// 記録した待ちを実際に待ったことの確かめにだけ使う(recordedWaits)。
func TestReconnectWaitIsCappedWhileTheTunnelIsFresh(t *testing.T) {
	const (
		backoffMin = 50 * time.Millisecond
		freshMax   = 200 * time.Millisecond
		backoffMax = 5 * time.Second
	)
	endpoint, pin, rtp, attempts := newWaitRecordingStreamServer(t)
	rt := newAliveTestRuntime(t, endpoint, pin)
	rtp.Store(rt)
	rt.reconnectBackoffMin, rt.reconnectBackoffMax, rt.reconnectBackoffFreshMax = backoffMin, backoffMax, freshMax
	setFresh := func() {
		now := time.Now()
		rt.handshakeSeen.Store(&handshakeObservation{handshake: now, observedAt: now})
	}
	setStale := func() {
		now := time.Now()
		rt.handshakeSeen.Store(&handshakeObservation{handshake: now, observedAt: now.Add(-tunnelFreshFor)})
	}
	setFresh()
	runStreamLoop(t, rt)

	// 1 つ目の段: 新しい間。待ちは 50 ms、100 ms、200 ms と伸びて上限で止まる。上限が無ければ
	// 400 ms、800 ms、1.6 s と伸びる。最初の試みの前には待たない
	w, last := recordedWaits(t, attempts, time.Time{}, 8)
	for i, d := range w[1:] {
		if d > freshMax {
			t.Fatalf("while the tunnel is fresh, wait %d was %s, above the %s cap; waits %v", i+1, d, freshMax, w)
		}
	}
	if w[len(w)-1] != freshMax {
		t.Fatalf("while the tunnel is fresh, the wait did not reach the %s cap; waits %v", freshMax, w)
	}

	// 2 つ目の段: 古くなった。切り替えの直前に決まった待ちは上限のままでありうるので、その次から見る
	setStale()
	w, last = recordedWaits(t, attempts, last, 3)
	grew := false
	for _, d := range w {
		if d > freshMax {
			grew = true
		}
	}
	if !grew {
		t.Errorf("after the tunnel went stale the wait did not grow past the %s cap; waits %v", freshMax, w)
	}
	// 伸び始めは上限の 2 倍からであり、上限の下で倍加を続けた値からではない
	if w[1] > 4*freshMax {
		t.Errorf("the first stale wait was %s; it must grow from the %s cap, not jump toward the %s maximum; waits %v",
			w[1], freshMax, backoffMax, w)
	}

	// 3 つ目の段: 再び新しくなった。今の待ちが明けた次から上限に戻る
	setFresh()
	w, _ = recordedWaits(t, attempts, last, 3)
	for i, d := range w[1:] {
		if d > freshMax {
			t.Errorf("after the tunnel was fresh again, wait %d was %s, above the %s cap; waits %v", i+1, d, freshMax, w)
		}
	}
}

// vpsd が応じたうえで閉じた場合(ここでは置き換え)は、トンネルが新しくても上限を下げない
// (仕様 5.2 節)。善意の二重起動どうしの振動を抑えるバックオフの役目を保つためである。
func TestReconnectWaitAfterSupersededIgnoresTheFreshCap(t *testing.T) {
	const (
		backoffMin = 50 * time.Millisecond
		freshMax   = 60 * time.Millisecond
	)
	attempts := make(chan time.Time, 64)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/stream", func(w http.ResponseWriter, r *http.Request) {
		select {
		case attempts <- time.Now():
		default:
		}
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		var first proto.Message
		if _, b, err := ws.Read(r.Context()); err != nil || json.Unmarshal(b, &first) != nil {
			return
		}
		ws.Close(websocket.StatusCode(proto.CloseSuperseded), "superseded")
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	rt := newAliveTestRuntime(t, strings.TrimPrefix(srv.URL, "https://"), sha256.Sum256(srv.Certificate().Raw))
	rt.reconnectBackoffMin, rt.reconnectBackoffMax, rt.reconnectBackoffFreshMax = backoffMin, 5*time.Second, freshMax
	now := time.Now()
	rt.handshakeSeen.Store(&handshakeObservation{handshake: now, observedAt: now})
	runStreamLoop(t, rt)

	// 50、100、200、400 ms と伸びる。上限を下げれば 60 ms で止まる
	iv, _ := attemptIntervals(t, attempts, time.Time{}, 5)
	if last := iv[len(iv)-1]; last < 300*time.Millisecond {
		t.Errorf("after superseded closes the wait stayed at %s; the fresh-tunnel cap must not apply; intervals %v", last, iv)
	}
}

// 上限を当てない切断と当てる切断の一覧(仕様 5.2 節)。当てないのは、server が応答したうえで、再試行では
// 直らない食い違いを示した切断だけである。
func TestCapsWhileFreshClassifiesTheDisconnect(t *testing.T) {
	three := 3
	versionErr := checkServerProtocolVersion(proto.ProtocolRange{Min: 1, Max: 1}, &proto.State{ServerProtocolVersion: &three})
	zeroErr := checkServerProtocolVersion(proto.ProtocolRange{Min: 1, Max: 1}, &proto.State{ServerProtocolVersion: new(int)})
	closeErr := func(code websocket.StatusCode) error {
		return fmt.Errorf("failed to get reader: %w", websocket.CloseError{Code: code, Reason: "x"})
	}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"permanent token rejected", errUnauthorized, false},
		{"superseded", closeErr(websocket.StatusCode(proto.CloseSuperseded)), false},
		{"permanent token revoked", closeErr(websocket.StatusCode(proto.CloseRevoked)), false},
		{"no shared protocol version", closeErr(websocket.StatusCode(proto.CloseProtocolMismatch)), false},
		{"the server selected a version outside the agent's range", versionErr, false},
		{"the server selected version 0", zeroErr, false},
		{"certificate pin mismatch", fmt.Errorf("dial: %w", enroll.ErrPinMismatch), false},
		{"public key belongs to another agent", closeErr(websocket.StatusPolicyViolation), false},

		{"connection refused", errors.New("dial tcp 203.0.113.1:8443: connect: connection refused"), true},
		{"too many attempts", errors.New("failed to WebSocket dial: expected handshake response status code 101 but got 429"), true},
		{"heartbeat timeout", closeErr(websocket.StatusCode(proto.CloseHeartbeatTimeout)), true},
		{"malformed protocol advertisement", closeErr(websocket.StatusCode(proto.CloseProtocolMalformed)), true},
		{"server internal error", closeErr(websocket.StatusInternalError), true},
		{"ping deadline closed the connection", errors.New("failed to get reader: failed to read frame header: use of closed network connection"), true},
		{"connection ended without an error", nil, true},
	}
	for _, c := range cases {
		if got := capsWhileFresh(c.err); got != c.want {
			t.Errorf("%s: capsWhileFresh = %v, want %v", c.name, got, c.want)
		}
	}
	if versionErr == nil || !strings.Contains(versionErr.Error(), "outside the agent's supported range") {
		t.Errorf("version error text changed: %v", versionErr)
	}
}

// 再接続の待ちの行は、前と同じ文面なら 1 分に 1 行までに間引き、文面が変われば出す(仕様 5.2 節)。
// 間引いた数は次に出す行に添える。
func TestReconnectLogThinsIdenticalLines(t *testing.T) {
	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })

	var l reconnectLog
	l.print("reconnecting in 8s")
	for i := 0; i < 5; i++ {
		l.print("reconnecting in 10s")
	}
	l.print("reconnecting in 20s")
	l.reset()
	l.print("reconnecting in 20s")
	got := strings.Split(strings.TrimSpace(buf.String()), "\n")
	want := []string{
		"reconnecting in 8s",
		"reconnecting in 10s",
		"reconnecting in 20s; 4 repeat(s) of the previous line not logged",
		"reconnecting in 20s",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("logged\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// 公開鍵の拒否で閉じる server に対しても、トンネルが新しいことを理由に待ちを縮めない(仕様 5.2 節)。
func TestReconnectWaitAfterAPolicyViolationIgnoresTheFreshCap(t *testing.T) {
	const (
		backoffMin = 50 * time.Millisecond
		freshMax   = 60 * time.Millisecond
	)
	attempts := make(chan time.Time, 64)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/stream", func(w http.ResponseWriter, r *http.Request) {
		select {
		case attempts <- time.Now():
		default:
		}
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		if _, _, err := ws.Read(r.Context()); err != nil {
			return
		}
		ws.Close(websocket.StatusPolicyViolation, "public key belongs to another agent")
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	rt := newAliveTestRuntime(t, strings.TrimPrefix(srv.URL, "https://"), sha256.Sum256(srv.Certificate().Raw))
	rt.reconnectBackoffMin, rt.reconnectBackoffMax, rt.reconnectBackoffFreshMax = backoffMin, 5*time.Second, freshMax
	now := time.Now()
	rt.handshakeSeen.Store(&handshakeObservation{handshake: now, observedAt: now})
	runStreamLoop(t, rt)

	iv, _ := attemptIntervals(t, attempts, time.Time{}, 5)
	if last := iv[len(iv)-1]; last < 300*time.Millisecond {
		t.Errorf("after a policy violation close the wait stayed at %s; the fresh-tunnel cap must not apply; intervals %v", last, iv)
	}
}
