package agent

import (
	"context"
	"log"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/reconcile"
)

// observe は 30 秒ごとの見直しである(仕様 7b.2・7b.4 節)。dataplane が agentdp.Observer でなければ何もしない。
// 名前の解決は rt.mu の外で行い、その間に処理済みの全体状態が変わったか、公開できなかった全体状態の
// 試し直しを待っていれば、解決の結果を捨てる。古い宣言の解決の結果で新しい公開を上書きしないため
// である。試し直しを待つ間の公開は、試し直しが担う。記録が変わったら、認証情報ファイルを保存し、
// 次の 30 秒を待たずにハートビートを送らせる。
func (rt *runtime) observe() {
	ob, ok := rt.dp.(agentdp.Observer)
	if !ok {
		return
	}
	rt.mu.Lock()
	st := rt.f.LastState
	busy := st == nil || rt.pendingSt != nil || !rt.dp.Built()
	rt.mu.Unlock()
	if busy {
		return
	}
	prepared := ob.ObservePrepare(st.Rules)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.f.LastState != st || rt.pendingSt != nil || !rt.dp.Built() {
		return
	}
	// 誤りは ObserveCommit が出す。誤りがあっても記録が変わっていれば保存する。引き直したエンドポイントの
	// 収束に失敗した見直しも、表を公開し直していることがあるためである
	saved, _ := ob.ObserveCommit(st.Generation, st.Rules, prepared)
	if !saved {
		return
	}
	notifyNonBlocking(rt.stateNotify)
	if err := rt.f.Save(rt.opts.CredentialsPath); err != nil {
		log.Printf("save credentials file after the 30-second check: %v", err)
	}
}

// watchKernel は、dataplane がカーネルの変更の通知を購読できれば、ctx が取り消されるまで購読する
// (仕様 7b.4 節の変更の通知)。購読が失敗したら、vpsd と同じく間隔を倍にしながら張り直し
// (reconcile.Watch)、通知を失ったかもしれないので見直しを 1 回起こす。ユーザー空間モードでは何もしない。
func (rt *runtime) watchKernel(ctx context.Context) {
	s, ok := rt.dp.(agentdp.Sensed)
	if !ok {
		return
	}
	logf := func(format string, args ...any) { log.Printf("kernel mode: "+format, args...) }
	go reconcile.Watch(ctx, s.Sensor(), rt.pokeKernel, reconcile.DefaultBackoff, logf)
}

// pokeKernel は、カーネルの変更の通知を serve に伝える。塞がらない。
func (rt *runtime) pokeKernel() { notifyNonBlocking(rt.kernelWake) }

// observeNotified は、変更の通知をまとめた後の見直しである(仕様 7b.4 節の変更の通知)。30 秒ごとの
// 見直し(observe)と違って名前を引かないので、rt.mu を持ったまま 1 回で済む。処理済みの全体状態が
// 無い間と、公開できなかった全体状態の試し直しを待つ間は、observe と同じく何もしない。試し直しが
// 公開を担うためである。記録が変わったら、認証情報ファイルを保存し、次の 30 秒を待たずにハートビートを
// 送らせる。
func (rt *runtime) observeNotified() {
	s, ok := rt.dp.(agentdp.Sensed)
	if !ok {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	st := rt.f.LastState
	if st == nil || rt.pendingSt != nil || !rt.dp.Built() {
		return
	}
	// 誤りは ObserveNotified が出す。誤りがあっても記録が変わっていれば保存する
	saved, _ := s.ObserveNotified(st.Generation, st.Rules)
	if !saved {
		return
	}
	notifyNonBlocking(rt.stateNotify)
	if err := rt.f.Save(rt.opts.CredentialsPath); err != nil {
		log.Printf("save credentials file after a change notification: %v", err)
	}
}
