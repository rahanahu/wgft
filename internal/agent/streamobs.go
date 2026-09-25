package agent

import (
	"errors"
	"time"
)

// 制御ストリームの観測(設計文書 10.2c 節)。`wgft agent doctor` の stream.connection・stream.backoff・
// stream.liveness の 3 つの検査が読む値を、稼働中のプロセスの中に保つ。
//
// 書き手は stream の 3 つの経路である。streamLoop が接続の終わりと再接続の待ちを、streamOnce が
// 接続の成立を、pingLoop が ping と pong を書く。読み手は後から制御ソケットの応答を組み立てる
// 別の goroutine なので、値は streamMu で守り、読み出しは streamStatus が写しを返す。
//
// streamMu を使うのは、この観測が stream の状態だからであり、rt.mu と混ぜないためでもある。
// rt.mu は全体状態の適用の間じゅう保たれ、適用は宛先 1 つにつき最長 10 秒の試し接続を含むので、
// 観測をそちらに置くと読み出しが適用の後ろで待つ。streamMu を取る区間はどれも値の代入だけで、
// この mutex を持ったまま他の mutex を取ることも、時間のかかる処理を呼ぶこともしない。
// 逆向きも同じで、rt.mu を持ったまま streamStatus を呼ばない。この向きは runtime の handshakeWake
// が既に守っている規則であり、制御ソケットの応答を組み立てる経路を rt.mu を取る heartbeat の隣に
// 置くときも、観測は rt.mu の外で読む。

// streamObservation は制御ストリームの観測の写し。ポインタも slice も持たないので、値の複製が
// そのまま独立した写しになる。
type streamObservation struct {
	// Connected は制御ストリームが今つながっているかどうか。公開鍵を送り終えた時点から、その接続が
	// 終わるまでが true である
	Connected bool
	// DisconnectedAt と DisconnectReason は、直近の接続が終わった時刻と理由。接続に至らなかった
	// 試みの失敗も同じ組に記録する。どちらも「今つながっていない理由」を答えるためである
	DisconnectedAt   time.Time
	DisconnectReason string
	// PinMismatch は、直近の接続の終わりか試みの失敗が、server の証明書が登録のときに固定したものと
	// 一致しないためだったことである。再試行では直らないので、`agent doctor` が他の切断と分けて示す
	// (設計文書 10.2c 節)。
	PinMismatch bool

	// Backoff は直近に待った再接続の間隔で、RetryAt は次に繋ぎ直す時刻。どちらも streamLoop が待ちに
	// 入るたびに書く。待ちに入っていない間、RetryAt はゼロである。Backoff は streamLoop のローカル
	// 変数の今の値ではない。待ちを抜けた後の倍加も、初期値に戻す 5 か所のうち待ちに入る前に continue
	// する 4 か所も、次に待ちに入るまで記録に現れない。その 4 か所のうち実際に待ちを打ち切るのは
	// 新しいハンドシェイクによる再接続の 1 つだけで、残る 3 つは待ちに入る前に抜ける経路である。
	// 5 か所目、つまり 1 分以上つながっていた後の失敗はそのまま下へ落ちるので、その値は記録に現れる。
	// いずれの場合も、つながっている間の Backoff は最後に待った間隔のままである。トンネルが新しい間に
	// 上限を下げる変更(仕様 5.2 節)は待ちに入る前に行うので、その値は記録に現れる
	Backoff time.Duration
	RetryAt time.Time

	// LastPingAt と LastPongAt は直近に ping を送った時刻と pong が返った時刻、AwaitingPong は
	// pong を待っている最中かどうか。3 つとも接続ごとの値なので、接続が成立した時点で消す
	LastPingAt   time.Time
	LastPongAt   time.Time
	AwaitingPong bool
}

// streamStatus は観測の写しを返す。制御ソケットの応答を組み立てる経路はこの入口から読む。
func (rt *runtime) streamStatus() streamObservation {
	rt.streamMu.Lock()
	defer rt.streamMu.Unlock()
	return rt.streamObs
}

// noteStreamAttempt は、再接続の待ちを抜けて接続を試み始めたことを記録する。待っていない間に
// 過去の予定を残さないよう、次に試す時刻を消す。直近に待った間隔はそのまま残し、次に待ちに
// 入ったときに書き換える。
func (rt *runtime) noteStreamAttempt() {
	rt.streamMu.Lock()
	defer rt.streamMu.Unlock()
	rt.streamObs.RetryAt = time.Time{}
}

// noteStreamConnected は接続の成立を記録し、この接続の通し番号を返す。ping と pong の観測は
// 接続ごとの値なので、ここで消す。通し番号は、前の接続の pingLoop が遅れて書き込むことを
// 防ぐために使う。
func (rt *runtime) noteStreamConnected() uint64 {
	rt.streamMu.Lock()
	defer rt.streamMu.Unlock()
	rt.streamEpoch++
	rt.streamObs.Connected = true
	rt.streamObs.RetryAt = time.Time{}
	rt.streamObs.LastPingAt, rt.streamObs.LastPongAt, rt.streamObs.AwaitingPong = time.Time{}, time.Time{}, false
	return rt.streamEpoch
}

// noteStreamDisconnected は接続が終わったことと、その理由を記録する。接続に至らなかった試みの
// 失敗も同じ組に書く。
func (rt *runtime) noteStreamDisconnected(now time.Time, err error) {
	reason := "connection ended without an error"
	if err != nil {
		reason = err.Error()
	}
	rt.streamMu.Lock()
	defer rt.streamMu.Unlock()
	rt.streamObs.Connected, rt.streamObs.AwaitingPong = false, false
	rt.streamObs.DisconnectedAt, rt.streamObs.DisconnectReason = now, reason
	rt.streamObs.PinMismatch = errors.Is(err, ErrPinMismatch)
}

// noteStreamWaiting は、次の接続までの待ちに入ったことを記録する。backoff は streamLoop が実際に
// 待つ間隔であり、次に試す時刻はその間隔から決まる。
func (rt *runtime) noteStreamWaiting(now time.Time, backoff time.Duration) {
	rt.streamMu.Lock()
	defer rt.streamMu.Unlock()
	rt.streamObs.Backoff, rt.streamObs.RetryAt = backoff, now.Add(backoff)
}

// noteStreamPingSent は ping を送ったことを記録する。epoch が今の接続のものでなければ、前の接続の
// pingLoop からの遅れた書き込みなので捨てる。
func (rt *runtime) noteStreamPingSent(now time.Time, epoch uint64) {
	rt.streamMu.Lock()
	defer rt.streamMu.Unlock()
	if epoch != rt.streamEpoch {
		return
	}
	rt.streamObs.LastPingAt, rt.streamObs.AwaitingPong = now, true
}

// noteStreamPingAnswered は ping の待ちが終わったことを記録する。pong が返った場合だけ時刻を進め、
// 期限切れや接続の終了で終わった場合は直近の pong の時刻をそのまま残す。
func (rt *runtime) noteStreamPingAnswered(now time.Time, epoch uint64, ok bool) {
	rt.streamMu.Lock()
	defer rt.streamMu.Unlock()
	if epoch != rt.streamEpoch {
		return
	}
	rt.streamObs.AwaitingPong = false
	if ok {
		rt.streamObs.LastPongAt = now
	}
}
