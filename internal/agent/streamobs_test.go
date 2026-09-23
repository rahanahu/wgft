package agent

import (
	"errors"
	"testing"
	"time"
)

// 制御ストリームの観測の試験(設計文書 10.2c 節)。前半は記録そのものを直接動かし、後半は
// streamLoop と pingLoop が実際に書いた値を、別の goroutine から読んで確かめる。読みは
// streamStatus だけを通すので、-race はこの読みと stream の書きの競合も見る。

// waitStreamObs は、観測が条件を満たすまで読み続ける。実時間の sleep を同期の手段にしないため、
// 短い周期で読み直し、期限に達したら何が満たされなかったかを添えて落とす。
func waitStreamObs(t *testing.T, rt *runtime, within time.Duration, want string, ok func(streamObservation) bool) streamObservation {
	t.Helper()
	deadline := time.After(within)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if obs := rt.streamStatus(); ok(obs) {
			return obs
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatalf("the stream observation did not show %s within %s: %+v", want, within, rt.streamStatus())
			return streamObservation{}
		}
	}
}

// 切断の理由は保持され、次の切断で置き換わる。接続に至らなかった試みの失敗も同じ組に入る。
func TestStreamObservationKeepsTheLastDisconnectReason(t *testing.T) {
	rt := &runtime{}
	if obs := rt.streamStatus(); obs.Connected || obs.DisconnectReason != "" || !obs.DisconnectedAt.IsZero() {
		t.Fatalf("a runtime that never connected must have an empty observation: %+v", obs)
	}

	first := time.Now()
	rt.noteStreamDisconnected(first, errors.New("dial tcp: connection refused"))
	obs := rt.streamStatus()
	if obs.Connected {
		t.Error("the stream must not look connected after a disconnect")
	}
	if obs.DisconnectReason != "dial tcp: connection refused" || !obs.DisconnectedAt.Equal(first) {
		t.Errorf("the first disconnect was not kept: %+v", obs)
	}

	second := first.Add(time.Second)
	rt.noteStreamDisconnected(second, errors.New("received close frame: status = 4001"))
	obs = rt.streamStatus()
	if obs.DisconnectReason != "received close frame: status = 4001" || !obs.DisconnectedAt.Equal(second) {
		t.Errorf("the second disconnect did not replace the first: %+v", obs)
	}

	// 誤りの無い終わり方でも、理由の欄は空にしない
	rt.noteStreamDisconnected(second.Add(time.Second), nil)
	if obs = rt.streamStatus(); obs.DisconnectReason == "" {
		t.Errorf("a disconnect without an error must still carry a reason: %+v", obs)
	}
}

// 接続の成立は、ping と pong の観測と次に試す時刻を消し、接続の通し番号を進める。
func TestStreamObservationConnectClearsTheLivenessAndTheRetry(t *testing.T) {
	rt := &runtime{}
	rt.noteStreamWaiting(time.Now(), time.Second)
	epoch := rt.noteStreamConnected()
	rt.noteStreamPingSent(time.Now(), epoch)
	rt.noteStreamPingAnswered(time.Now(), epoch, true)

	next := rt.noteStreamConnected()
	if next == epoch {
		t.Errorf("the connection number must advance on every connection: %d", next)
	}
	obs := rt.streamStatus()
	if !obs.Connected {
		t.Error("the stream must look connected after the public key is sent")
	}
	if !obs.RetryAt.IsZero() {
		t.Errorf("a connected stream has no pending retry: %+v", obs)
	}
	if !obs.LastPingAt.IsZero() || !obs.LastPongAt.IsZero() || obs.AwaitingPong {
		t.Errorf("the liveness of the previous connection must not survive a new one: %+v", obs)
	}
	if obs.Backoff != time.Second {
		t.Errorf("the current reconnect interval must survive a connection: %+v", obs)
	}

	// 前の接続の pingLoop が遅れて書いても、今の接続の観測は動かさない
	rt.noteStreamPingSent(time.Now(), epoch)
	rt.noteStreamPingAnswered(time.Now(), epoch, true)
	if obs = rt.streamStatus(); !obs.LastPingAt.IsZero() || !obs.LastPongAt.IsZero() || obs.AwaitingPong {
		t.Errorf("a late write from the previous connection was accepted: %+v", obs)
	}
}

// 次に試す時刻は間隔から導ける。待ちに入っていない間はゼロである。
func TestStreamObservationDerivesTheRetryTimeFromTheBackoff(t *testing.T) {
	rt := &runtime{}
	now := time.Now()
	rt.noteStreamWaiting(now, 2*time.Second)
	obs := rt.streamStatus()
	if obs.Backoff != 2*time.Second {
		t.Errorf("the current reconnect interval was not kept: %+v", obs)
	}
	if !obs.RetryAt.Equal(now.Add(2 * time.Second)) {
		t.Errorf("the next attempt must be the wait plus the interval: %+v", obs)
	}

	rt.noteStreamAttempt()
	if obs = rt.streamStatus(); !obs.RetryAt.IsZero() {
		t.Errorf("an attempt in progress has no pending retry: %+v", obs)
	}
	if obs.Backoff != 2*time.Second {
		t.Errorf("the current reconnect interval must survive the attempt: %+v", obs)
	}
}

// ping と pong の時刻は、送るたびと返るたびに進む。期限切れは pong の時刻を進めない。
func TestStreamObservationTracksThePingAndThePong(t *testing.T) {
	rt := &runtime{}
	epoch := rt.noteStreamConnected()

	sent := time.Now()
	rt.noteStreamPingSent(sent, epoch)
	obs := rt.streamStatus()
	if !obs.LastPingAt.Equal(sent) || !obs.AwaitingPong {
		t.Fatalf("a sent ping must show up as an outstanding pong: %+v", obs)
	}

	answered := sent.Add(10 * time.Millisecond)
	rt.noteStreamPingAnswered(answered, epoch, true)
	obs = rt.streamStatus()
	if !obs.LastPongAt.Equal(answered) || obs.AwaitingPong {
		t.Fatalf("an answered ping must end the wait: %+v", obs)
	}

	// 期限切れは、待ちを終わらせるが直近の pong の時刻は動かさない
	rt.noteStreamPingSent(answered.Add(time.Second), epoch)
	rt.noteStreamPingAnswered(answered.Add(2*time.Second), epoch, false)
	obs = rt.streamStatus()
	if !obs.LastPongAt.Equal(answered) {
		t.Errorf("an unanswered ping must not move the last pong: %+v", obs)
	}
	if obs.AwaitingPong {
		t.Errorf("an unanswered ping must end the wait as well: %+v", obs)
	}
	if !obs.LastPingAt.Equal(answered.Add(time.Second)) {
		t.Errorf("the last ping must be the one just sent: %+v", obs)
	}

	// 接続が終われば pong を待っている最中ではない
	rt.noteStreamPingSent(answered.Add(3*time.Second), epoch)
	rt.noteStreamDisconnected(answered.Add(4*time.Second), errors.New("closed"))
	if obs = rt.streamStatus(); obs.AwaitingPong {
		t.Errorf("a closed connection cannot be waiting for a pong: %+v", obs)
	}
}

// streamLoop が書く値を確かめる。間隔は streamLoop が実際に待つ値と一致し、次に試す時刻は
// その間隔から導け、切断の理由は再接続のたびに新しくなる。
func TestStreamLoopRecordsTheBackoffAndTheDisconnect(t *testing.T) {
	const backoff = 300 * time.Millisecond
	endpoint, pin, attempts := newRefusingStreamServer(t)
	rt := newAliveTestRuntime(t, endpoint, pin)
	rt.reconnectBackoffMin, rt.reconnectBackoffMax = backoff, backoff

	runStreamLoop(t, rt)

	var first time.Time
	select {
	case first = <-attempts:
	case <-time.After(5 * time.Second):
		t.Fatal("no first connection attempt within 5s")
	}
	obs := waitStreamObs(t, rt, 5*time.Second, "a pending retry after the first failure", func(o streamObservation) bool {
		return !o.RetryAt.IsZero()
	})
	if obs.Connected {
		t.Error("a refused stream must not look connected")
	}
	if obs.DisconnectReason == "" || obs.DisconnectedAt.IsZero() {
		t.Errorf("the refused attempt must leave a reason: %+v", obs)
	}
	if obs.Backoff != backoff {
		t.Errorf("the recorded interval %s is not the %s that streamLoop waits", obs.Backoff, backoff)
	}
	// 次に試す時刻は、待ちに入った時刻に間隔を足したものである。待ちに入るのは切断の直後なので、
	// 差は間隔以上、間隔にその直後の処理の分を足した範囲に収まる
	if d := obs.RetryAt.Sub(obs.DisconnectedAt); d < backoff || d > backoff+2*time.Second {
		t.Errorf("the next attempt is %s after the disconnect; it must be the %s interval", d, backoff)
	}

	// 記録した間隔が、実際に待った時間とも一致することを、次の試みの時刻で確かめる
	var second time.Time
	select {
	case second = <-attempts:
	case <-time.After(5 * time.Second):
		t.Fatal("no second connection attempt within 5s")
	}
	if d := second.Sub(first); d < backoff*8/10 {
		t.Errorf("the second attempt came %s after the first, below the recorded %s interval", d, backoff)
	}

	// 再接続のたびに切断の記録が新しくなる
	prev := obs.DisconnectedAt
	next := waitStreamObs(t, rt, 5*time.Second, "a newer disconnect", func(o streamObservation) bool {
		return o.DisconnectedAt.After(prev)
	})
	if next.DisconnectReason == "" {
		t.Errorf("the newer disconnect lost its reason: %+v", next)
	}
}

// pingLoop が書く値を確かめる。ping に応じる server につないでいる間、ping と pong の時刻が進む。
func TestStreamLoopRecordsThePingAndThePong(t *testing.T) {
	endpoint, pin, conns := newSilentStreamServer(t, true)
	rt := newAliveTestRuntime(t, endpoint, pin)

	runStreamLoop(t, rt)
	select {
	case <-conns:
	case <-time.After(5 * time.Second):
		t.Fatal("no connection within 5s")
	}

	obs := waitStreamObs(t, rt, 5*time.Second, "an answered ping", func(o streamObservation) bool {
		return !o.LastPongAt.IsZero()
	})
	if !obs.Connected {
		t.Errorf("a live stream must look connected: %+v", obs)
	}
	if obs.LastPingAt.IsZero() {
		t.Errorf("an answered ping must have been sent first: %+v", obs)
	}
	if obs.LastPongAt.Before(obs.LastPingAt) {
		t.Errorf("the pong of the ping it answers cannot precede it: %+v", obs)
	}

	// 時刻は周期ごとに進む
	prev := obs.LastPongAt
	waitStreamObs(t, rt, 5*time.Second, "a later pong", func(o streamObservation) bool {
		return o.LastPongAt.After(prev)
	})
}
