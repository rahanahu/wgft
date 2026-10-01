package agent

import (
	"log"
	"time"

	"github.com/rahanahu/wgft/proto"
)

// defaultRebuildAfter と defaultRebuildBackoffMax は、トンネルを作り直す判定の既定の閾値(仕様 7 節)。
// 300 秒は WireGuard の時定数から決めた値で、健全なトンネルでは最終ハンドシェイクが 145 秒
// (RekeyAfterTime 120 秒 + keepalive 25 秒)より古くならず、180 秒(RejectAfterTime)を過ぎた鍵は
// 送信にも使えないため、300 秒の時点のトンネルは既に 120 秒以上まったく通信していない。
// keepalive の倍数にしないのは、WireGuard のこの 3 つの時定数が keepalive の値によらず一定だからである。
const (
	defaultRebuildAfter      = 300 * time.Second
	defaultRebuildBackoffMax = 900 * time.Second
)

// rebuildState はトンネルを作り直す判定の状態。after はハンドシェイクが新しくならないまま最初の
// 作り直しに至るまでの時間、backoffMax は作り直しの間隔の上限、wait は次の作り直しに要する時間である。
// テストで短くできるよう、閾値は定数ではなくこの値で持つ。
//
// lastHandshake と observedAt は、経過時間を壁時計の差ではなく観測からの単調な時間で測るために持つ。
// IpcGet が返す最終ハンドシェイクは壁時計の秒で、NTP の補正や手動の変更で飛ぶ値であり、その値と
// 現在時刻の差で測ると、前方への飛びが健全なトンネルを古く見せてしまう(仕様 7 節)。
type rebuildState struct {
	after      time.Duration
	backoffMax time.Duration
	wait       time.Duration

	lastHandshake time.Time // 直近に観測した最終ハンドシェイクの値
	observedAt    time.Time // その値を最初に観測した時刻

	// retryAt と retryWait は、作り直しがトンネルの作成そのものに失敗したときの再試行の予定。
	// retryAt がゼロなら再試行を待っているトンネルは無い。閉じたトンネルを watchdog が勝手に
	// 立て直さないよう、この印を付けるのは checkTunnel の失敗だけで、closeLocked が必ず消す
	retryAt   time.Time
	retryWait time.Duration
}

// failedBuild は、トンネルの作成に失敗したことを記録し、次に試す時刻を決める(仕様 7 節)。
// トンネルが 1 つも無い状態なので、最初の 1 回は次のティッカーで試し、続けて失敗するほど
// 間隔を after から上限まで広げる。
func (s *rebuildState) failedBuild(now time.Time) {
	if s.retryAt.IsZero() {
		s.retryAt, s.retryWait = now, s.after
		return
	}
	s.retryAt = now.Add(s.retryWait)
	s.retryWait = min(2*s.retryWait, max(s.backoffMax, s.after))
}

// clearRetry は再試行の予定を捨てる。closeLocked から呼ぶので、作成に成功した場合も、
// rotate-key や停止でトンネルを閉じた場合も消える。
func (s *rebuildState) clearRetry() { s.retryAt, s.retryWait = time.Time{}, 0 }

// effectiveWait は step が判定に使う作り直しの間隔である。保持している値と閾値の大きい方で、
// 閾値を下回らない。ゼロでない最終ハンドシェイクを一度も観測しておらず作り直しも一度も起きて
// いないトンネルでは wait が 0 のままだが、その場合も判定は閾値で動く。doctor はこの実効値を
// 示すので(設計文書 10.2c 節)、step と同じ式をここに一本化する。閾値を持たない runtime は
// 作り直さないので 0 を返す。
func (s *rebuildState) effectiveWait() time.Duration {
	if s.after <= 0 {
		return 0
	}
	return max(s.wait, s.after)
}

// step は、今の最終ハンドシェイクの値 handshake を観測し、その値が新しくならないまま経った時間で
// トンネルを作り直すかどうかを決める(仕様 7 節)。作り直すときは次の間隔を倍にし、ゼロでない新しい
// ハンドシェイクを観測したときは間隔を初期値に戻す。
//
// 起点には、値を観測した時刻とトンネルを立てた時刻 start の遅い方を使う。作り直した直後の device は
// ハンドシェイクがゼロで、前の値もゼロだったときは値が変わらず、観測の時刻が更新されないためである。
// now と start は time.Now が返す単調な読みを持つので、両者の差は壁時計の飛びに左右されない。
//
// サーバが停止しているだけの場合と、受信の経路が死んだ場合は、エージェントからは区別できない。
// そこで、作り直しても戻らない間は間隔を広げ、上限で頭打ちにする。
func (s *rebuildState) step(now, start, handshake time.Time) (idle time.Duration, rebuild bool) {
	// 観測は閾値を持たない runtime でも控える。checkTunnel は控えた値と比べて新しいハンドシェイクを
	// 見分け、stream の再接続の待ちを打ち切らせるので、控えなければ同じ値を毎回新しいと数える
	if !handshake.Equal(s.lastHandshake) {
		s.lastHandshake, s.observedAt = handshake, now
		if !handshake.IsZero() {
			s.wait = s.after
		}
	}
	if s.after <= 0 {
		return 0, false // 閾値を持たない runtime では作り直さない
	}
	since := s.observedAt
	if since.IsZero() || start.After(since) {
		since = start
	}
	idle = now.Sub(since)
	wait := s.effectiveWait()
	if idle < wait {
		return idle, false
	}
	s.wait = min(2*wait, max(s.backoffMax, s.after))
	return idle, true
}

// startTunnelLocked は今のトンネルと転送を閉じてから、全体状態の wg 設定で立て直す(仕様 7 節)。
// 呼び出し側は rt.mu を持つ。ルールは適用しないので、呼び出し側が続けて dp.applyRules を呼ぶ。
// 閉じるのが先なので、古い device と netstack、その goroutine は新しいものを作る前に必ず片付く。
//
// retryable は、失敗が試し直す価値のあるものかどうかを表す。誤りが無いときの値に意味は無い。
// wg 設定の誤りは同じ全体状態では何度試しても同じ結果になるので、試し直しの対象にしない。
func (rt *runtime) startTunnelLocked(st *proto.State) (retryable bool, err error) {
	rt.closeLocked()
	rt.tunStart = time.Now()
	retryable, err = rt.dp.build(rt.priv, st.WG)
	if err != nil {
		return retryable, err
	}
	rt.wgCfg = st.WG
	return true, nil
}

// checkTunnel は 30 秒ごとに呼ばれ(Run のティッカー)、ハンドシェイクが新しくならない時間が作り直しの
// 間隔を超えたらトンネルを作り直す(仕様 7 節)。第 1 段の軽い回復(エンドポイントの引き直しと
// トンネル内への ping)は tunnel.Run が keepalive ごとに行うので、checkTunnel は第 2 段だけを担う。
//
// 作り直しが要るのは、wireguard-go の受信ループが回復不能な誤りで終わったまま戻らない状態である。
// そのトンネルは送信を続けるが二度と受信しないので、ハンドシェイクは永久に成立しない。サーバが単に
// 停止している場合もエージェントから見た症状は同じで区別できないため、作り直しの間隔はバックオフで
// 広げ、ハンドシェイクが成立したら初期値に戻す。
//
// トンネルの作成そのものに失敗するとトンネルが 1 つも無い状態になるので、予定の時刻に作成だけを
// 試し直す。対象は、作り直しの作成が失敗した場合と、全体状態の適用の中で作成が失敗した場合である。
// rotate-key・停止・最初の全体状態を受け取る前の「トンネルが無い」状態には手を出さない。
func (rt *runtime) checkTunnel(now time.Time) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if !rt.dp.built() {
		rt.retryBuildLocked(now)
		return
	}
	if rt.f == nil || rt.f.LastState == nil {
		return
	}
	st := rt.f.LastState
	// 読むのは今の device なので、ゼロでない最終ハンドシェイクは必ず今のトンネルのものである
	handshake := rt.dp.lastHandshake()
	// 新しいハンドシェイクは、vpsd までの経路が戻ったことを示す。stream が再接続の待ちに入って
	// いれば、その待ちを打ち切らせる(仕様 5.2 節)。判定は step が値を控え直す前に行う。観測は
	// この 1 回の読みだけで、別の監視は持たない
	if !handshake.IsZero() && !handshake.Equal(rt.rebuild.lastHandshake) {
		notifyNonBlocking(rt.handshakeWake)
	}
	idle, rebuild := rt.rebuild.step(now, rt.tunStart, handshake)
	// 同じ読みを、再接続の待ちの上限を決める証拠として streamLoop に渡す(仕様 5.2 節)。step が
	// 控えた値と、その値を最初に観測した時刻をそのまま写すので、判定はモードによらず同じになる
	rt.handshakeSeen.Store(&handshakeObservation{handshake: rt.rebuild.lastHandshake, observedAt: rt.rebuild.observedAt})
	if !rebuild {
		return
	}
	log.Printf("no new wireguard handshake for %s; rebuilding the tunnel; the next rebuild needs %s without one",
		idle.Round(time.Second), rt.rebuild.wait.Round(time.Second))
	// 既に適用を終えた全体状態なので、世代の記録はやり直さない。誤りは buildLocked が 1 行出す
	rt.buildLocked(now, st, true, nil) //nolint:errcheck // 誤りは buildLocked が出す
}

// retryBuildLocked は、作成に失敗して残ったトンネルの無い状態を、予定の時刻に試し直す(仕様 7 節)。
// 予定が無ければ何もしないので、rotate-key や停止で閉じたトンネルは立て直さない。
//
// 立てるのは、作成に失敗したときの全体状態(retrySt)からである。認証情報ファイルの last_state は
// 適用を終えた全体状態しか指さず、新しい全体状態の適用が失敗した後は 1 つ前の全体状態を指したままな
// ので、そちらから立てるとサーバが想定していないトンネルになる。成功したときは世代の記録まで行う。
// 既に適用を終えた全体状態なら、同じ値を書き直すだけで害は無い。呼び出し側は rt.mu を持つ。
func (rt *runtime) retryBuildLocked(now time.Time) {
	if rt.retrySt == nil || rt.rebuild.retryAt.IsZero() || now.Before(rt.rebuild.retryAt) {
		return
	}
	log.Printf("no tunnel since the last build failed %s ago; building it again", now.Sub(rt.tunStart).Round(time.Second))
	st := rt.retrySt
	// 作成の失敗は buildLocked が 1 行出す。立った後のルールの適用と認証情報ファイルの保存の誤りは
	// buildLocked が出さないので、ここで出す
	if err := rt.buildLocked(now, st, false, nil); err != nil && rt.dp.built() {
		log.Printf("applying generation %d after building the tunnel again: %v", st.Generation, err)
	}
}

// buildLocked はトンネルを立ててリスナーを開き直す。applied は、渡した全体状態の適用が世代の記録まで
// 済んでいるかを表す。済んでいなければ、作成に成功した時点で finishApplyLocked まで行う。
//
// 作成に失敗したときは理由を 1 行出し、作成そのものの失敗なら次に試す時刻と全体状態を控える。
// wg 設定の誤りは控えず、次の全体状態を待つ。呼び出し側は rt.mu を持つ。
func (rt *runtime) buildLocked(now time.Time, st *proto.State, applied bool, prepared any) error {
	// startTunnelLocked は最初に closeLocked を呼び、closeLocked は試し直しの控えを消す。続けて失敗した
	// ときに間隔を広げられるよう、予定は呼ぶ前に控えておき、失敗したら戻してから次を決める
	retryAt, retryWait := rt.rebuild.retryAt, rt.rebuild.retryWait
	retryable, err := rt.startTunnelLocked(st)
	if err != nil {
		rt.retrySt = st // 失敗した全体状態は、試し直さない場合もハートビートの理由のために控える
		if !retryable {
			log.Printf("build tunnel: %v; not retrying until a new full state arrives", err)
			return err
		}
		rt.rebuild.retryAt, rt.rebuild.retryWait = retryAt, retryWait
		rt.rebuild.failedBuild(now)
		if d := rt.rebuild.retryAt.Sub(now); d > 0 {
			log.Printf("build tunnel: %v; trying again in %s", err, d.Round(time.Second))
		} else {
			log.Printf("build tunnel: %v; trying again at the next check", err)
		}
		return err
	}
	if applied {
		if _, err := rt.dp.applyRules(st.Generation, st.Rules, prepared); err != nil {
			log.Printf("apply rules after rebuilding the tunnel: %v", err)
		}
		return nil
	}
	return rt.finishApplyLocked(st, prepared)
}
