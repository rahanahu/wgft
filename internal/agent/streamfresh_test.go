package agent

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

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

// トンネルが新しい間は待ちが上限で止まり、古くなると上限から倍々に伸び、再び新しくなると
// 上限に戻る(仕様 5.2 節)。上限が無ければ、1 つ目の段で待ちは初期値から倍々に伸び続ける。
func TestReconnectWaitIsCappedWhileTheTunnelIsFresh(t *testing.T) {
	const (
		backoffMin = 50 * time.Millisecond
		freshMax   = 200 * time.Millisecond
		backoffMax = 5 * time.Second
		// slack は、試みそのものに要する時間と、機械の混み具合の余裕である
		slack = 150 * time.Millisecond
	)
	endpoint, pin, attempts := newRefusingStreamServer(t)
	rt := newAliveTestRuntime(t, endpoint, pin)
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

	// 1 つ目の段: 新しい間。上限が無ければ 400 ms、800 ms、1.6 s と伸びる
	iv, last := attemptIntervals(t, attempts, time.Time{}, 8)
	for i, d := range iv {
		if d > freshMax+slack {
			t.Fatalf("while the tunnel is fresh, interval %d was %s, above the %s cap; intervals %v", i, d, freshMax, iv)
		}
	}

	// 2 つ目の段: 古くなった。切り替えの直前に決まった待ちは上限のままでありうるので、その次から見る
	setStale()
	iv, last = attemptIntervals(t, attempts, last, 3)
	grew := false
	for _, d := range iv {
		if d > 2*freshMax+slack/2 {
			grew = true
		}
	}
	if !grew {
		t.Errorf("after the tunnel went stale the wait did not grow past the %s cap; intervals %v", freshMax, iv)
	}
	// 伸び始めは上限の 2 倍からであり、上限の下で倍加を続けた値からではない
	if iv[1] > 4*freshMax+slack {
		t.Errorf("the first stale wait was %s; it must grow from the %s cap, not jump toward the %s maximum; intervals %v",
			iv[1], freshMax, backoffMax, iv)
	}

	// 3 つ目の段: 再び新しくなった。今の待ちが明けた次から上限に戻る
	setFresh()
	iv, _ = attemptIntervals(t, attempts, last, 3)
	for i, d := range iv[1:] {
		if d > freshMax+slack {
			t.Errorf("after the tunnel was fresh again, interval %d was %s, above the %s cap; intervals %v", i+1, d, freshMax, iv)
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
