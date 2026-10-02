package agent

import (
	"fmt"
	"log"
	"net/netip"
	"reflect"
	"time"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/agent/controlapi"
	"github.com/rahanahu/wgft/proto"
)

// retryPending は、公開できなかった全体状態を試し直す(仕様 7a.3 節、7b.3 節の 3 つ目の種類)。
// 名前の解決などの準備は rt.mu の外で行い、排他を取り直したときに控えが別の全体状態に替わって
// いれば、準備を捨てて次の試し直しを待つ。プロセスを終える誤りだけを返す。
func (rt *runtime) retryPending() error {
	rt.mu.Lock()
	st := rt.pendingSt
	ok := st != nil && rt.dp.Built()
	rt.mu.Unlock()
	if !ok {
		return nil
	}
	prepared := rt.prepare(st)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.pendingSt != st {
		return nil
	}
	return rt.retryPendingLocked(prepared)
}

// retryPendingLocked は retryPending の後半である。試し直しが同じ誤りで失敗する間は何も出さず、
// 誤りが変わったときと成功したときに 1 行出す。成功したら、次の 30 秒を待たずにハートビートを
// 送らせる。呼び出し側は rt.mu を持つ。
func (rt *runtime) retryPendingLocked(prepared any) error {
	st := rt.pendingSt
	if st == nil || !rt.dp.Built() {
		return nil
	}
	before := rt.pendingErr
	err := rt.applyLocked(st, prepared)
	switch {
	case err == nil:
		log.Printf("applied generation %d on retry", st.Generation)
		notifyNonBlocking(rt.stateNotify)
	case agentdp.IsFatal(err):
		return err
	case rt.pendingSt == st && rt.pendingErr != before:
		log.Printf("retrying generation %d: %v; the previous publication stays in place", st.Generation, err)
	}
	return nil
}

func (rt *runtime) generation() uint64 {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.gen
}

// apply は全体状態を適用する。wg 設定が変わればトンネルを張り直し(セッションは切れる)、
// リスナーは変わったものだけを開閉する(仕様 5.2, 7 節)。部分失敗でも世代は進め、認証情報ファイルに保存する。
//
// dataplane が準備を持てば(カーネルモードの名前の解決)、rt.mu を取る前に行う。準備は st だけから
// 決まるので、その間に他の経路が別の全体状態を適用しても、st の適用には使える。
func (rt *runtime) apply(st *proto.State) error {
	prepared := rt.prepare(st)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.applyLocked(st, prepared)
}

// applyLocked は apply の後半である。wg 設定が今のものと違うか、トンネルが無ければ立て直してから
// ルールを合わせ、同じならルールだけを合わせる。公開できなかった全体状態の試し直しもこの経路を通る。
// rotate-key が 1 つ前の全体状態の wg 設定で立て直した後でも、控えた全体状態の wg 設定で適用する
// ためである。呼び出し側は rt.mu を持つ。
func (rt *runtime) applyLocked(st *proto.State, prepared any) error {
	if err := rt.checkWGLocked(st); err != nil {
		return err
	}
	if !rt.dp.Built() || !reflect.DeepEqual(rt.wgCfg, st.WG) {
		if rt.dp.Built() {
			log.Printf("wg config changed; rebuilding tunnel")
		}
		// 作成に失敗したら、世代も認証情報ファイルも進めずに返す。作成そのものの失敗なら
		// buildLocked が試し直しを控えるので、次の全体状態を待たずに watchdog が立て直す(仕様 7 節)。
		// トンネルが立った後の誤り(ルールの適用と認証情報ファイルの保存)には wireguard の接頭辞を付けない
		if err := rt.buildLocked(time.Now(), st, false, prepared); err != nil {
			if rt.dp.Built() {
				return err
			}
			return fmt.Errorf("wireguard: %w", err)
		}
		return nil
	}
	return rt.finishApplyLocked(st, prepared)
}

// refusedState は、dataplane が wg 設定を拒んだ全体状態の世代と理由である。
type refusedState struct {
	gen uint64
	err error
}

// checkWGLocked は、トンネルが立っている間に届いた全体状態の wg 設定を、今のトンネルに手を付ける前に
// dataplane に確かめさせる(agentdp.WGChecker、設計文書 7b.1・11 節)。拒んだら、トンネルもルールも処理済み世代も
// そのままにして誤りを返す。トンネルが無い間は確かめない。Build が同じ検証を通し、他の wg 設定の誤りと
// 同じく作成の失敗になるためである。呼び出し側は rt.mu を持つ。
func (rt *runtime) checkWGLocked(st *proto.State) error {
	c, ok := rt.dp.(agentdp.WGChecker)
	if !ok || !rt.dp.Built() {
		return nil
	}
	if _, err := c.CheckWG(st.WG); err != nil {
		// 古い世代の試し直しが拒まれても、新しい世代の拒否の表示を古い世代で置き換えない
		if rt.refused == nil || st.Generation >= rt.refused.gen {
			rt.refused = &refusedState{gen: st.Generation, err: err}
		}
		return fmt.Errorf("%s; the tunnel and rules stay as generation %d left them: %w", controlapi.ReasonWGRefused, rt.gen, err)
	}
	// 受け入れた wg 設定が拒んだ世代と同じか新しいときだけ、拒否の表示を消す。公開できなかった古い世代の
	// 試し直し(retryPending)が通っても、新しい世代を拒んでいることは変わらない
	if rt.refused != nil && st.Generation >= rt.refused.gen {
		rt.refused = nil
	}
	return nil
}

// prepare は、dataplane が agentdp.Preparer なら st の適用の準備を行う。rt.mu を持たずに呼ぶ。rt.dp は
// 組み立ての後に替わらないので、排他なしで読める。
func (rt *runtime) prepare(st *proto.State) any {
	if p, ok := rt.dp.(agentdp.Preparer); ok {
		return p.PrepareApply(st)
	}
	return nil
}

// alreadyApplied は、st が手元で最後に適用に成功した全体状態と世代も中身も同じかどうかを返す
// (設計文書 5.2 節)。トンネルが立っていて、試し直しを待つ全体状態も、拒んだ wg 設定も無いときだけ
// 真にする。このとき適用し直しても宣言は変わらず、カーネルモードではテーブルの差し替えと宛先への
// 試し接続だけが繰り返される。同じ世代でも中身が違えば偽にする。server は UDP のタイムアウトの値を、
// 世代を上げずに全体状態へ書き込むことがあるためである。
func (rt *runtime) alreadyApplied(st *proto.State) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.dp.Built() && rt.pendingSt == nil && rt.refused == nil && rt.f.LastState != nil &&
		st.Generation == rt.gen && reflect.DeepEqual(rt.f.LastState, st)
}

// applyFromStream は stream が受け取った全体状態を適用する。適用の間は読みが止まるので、pingLoop に
// 判定を見送らせる(仕様 5.2 節)。入るときと出るときに applySeq を 1 つ進めるので、適用の最中は値が
// 奇数になる。プロセスを終える誤りは Run に伝える(11b 節)。
func (rt *runtime) applyFromStream(st *proto.State) {
	rt.applySeq.Add(1)
	err := rt.apply(st)
	rt.applySeq.Add(1)
	if err != nil {
		log.Printf("stream: applying generation %d: %v", st.Generation, err)
		if agentdp.IsFatal(err) {
			rt.reportFatal(err)
		}
	}
}

// finishApplyLocked はトンネルが立った後の共通の後始末である。ルールを宣言に合わせ、処理済み世代を
// 進め、認証情報ファイルに保存する(仕様 5.2 節)。呼び出し側は rt.mu を持つ。
//
// dataplane が宣言をまとめて公開できなかったときは、世代も認証情報ファイルも進めずに返す
// (設計文書 7a.3 節)。ユーザー空間モードの dataplane はこの失敗を持たない。
//
// 控えは、失敗した全体状態が今の控えと同じか新しいときだけ置き換える。rotate-key が last_state を
// 適用し直して失敗した場合に、控えていた新しい世代を古い世代で置き換えないためである。
func (rt *runtime) finishApplyLocked(st *proto.State, prepared any) error {
	var firstErr error
	summary, err := rt.dp.ApplyRules(st.Generation, st.Rules, prepared)
	if err != nil {
		if !agentdp.IsFatal(err) && (rt.pendingSt == nil || st.Generation >= rt.pendingSt.Generation) {
			rt.pendingSt, rt.pendingErr = st, err.Error()
		}
		return fmt.Errorf("dataplane: %w", err)
	}
	if rt.pendingSt != nil && rt.pendingSt.Generation <= st.Generation {
		rt.pendingSt, rt.pendingErr = nil, ""
	}
	rt.gen = st.Generation
	rt.f.LastState = st
	rt.recordTunnelAddressLocked(st.WG)
	if err := rt.f.Save(rt.opts.CredentialsPath); err != nil {
		firstErr = fmt.Errorf("save credentials file: %w", err)
	}
	log.Printf("applied generation %d: %s", st.Generation, summary)
	return firstErr
}

// recordTunnelAddressLocked は、適用が済んだ全体状態のトンネルのアドレスを認証情報ファイルに記録する
// (設計文書 9・11 節)。記録が無いか、登録の応答からアドレスだけを記録していれば、ここで帯の長さまで
// 記録する。保存は呼び出し側が行う。カーネルモードは記録と違うアドレスを適用の前に拒むので、ここで
// 記録と違うのはユーザー空間モードだけである。ユーザー空間モードは記録と違うアドレスも使う。トンネルが
// netstack の中に閉じ、ホストのアドレスと経路に触れないためである。記録は書き換えず、同じ値の間は
// 1 度だけ警告する。呼び出し側は rt.mu を持つ。
func (rt *runtime) recordTunnelAddressLocked(w proto.WGConfig) {
	p, err := netip.ParsePrefix(w.Address)
	if err != nil || !p.Addr().Is4() {
		return
	}
	if err := rt.f.CheckTunnelAddress(p); err != nil {
		if w.Address != rt.tunnelWarned {
			log.Printf("warning: %v; userspace mode uses it, since its tunnel does not touch this host's addresses or routes, but kernel mode would refuse it; "+
				"the server moves an agent to a new address only when the agent registers again", err)
			rt.tunnelWarned = w.Address
		}
		return
	}
	rt.tunnelWarned = ""
	if rt.f.RecordTunnelAddress(p) {
		log.Printf("recorded the tunnel address %s in the credentials file; kernel mode refuses any other address the server sends until this agent registers again", p)
	}
}
