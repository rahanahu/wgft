package agent

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/user"
	"runtime/debug"
	"sort"
	"strconv"
	"time"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/controlapi"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/agent/kernelmode"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/sockbuf"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/internal/textsafe"
	"github.com/rahanahu/wgft/proto"
)

// 稼働中のエージェントの診断(設計文書 10.2c 節)。制御ソケットの doctor が返す 1 行の JSON は、
// 稼働中のプロセスしか持たない証拠だけを載せる。認証情報ファイル、OS、名前解決のような静的で
// 永続する事実は、エージェントが止まっていても読めるので CLI 自身が読み、この応答には入れない。
//
// 運用者が読む wgft agent doctor --json の出力とこの応答は別の模型であり、この応答はその材料である。
// どの検査にどう畳むか、どの状態の語を当てるか、終了コードをどう決めるかは CLI が決める。
// 応答の型は internal/agent/controlapi にあり、この package はそれを組み立てる。

// doctorSocketBuffers は測った結果を応答の形に写す。
func doctorSocketBuffers(r sockbuf.Reading) *controlapi.DoctorSocketBuffers {
	if !r.Supported {
		return &controlapi.DoctorSocketBuffers{}
	}
	out := &controlapi.DoctorSocketBuffers{Supported: true, Port: r.Port, Required: sockbuf.Required}
	if !r.Measured() {
		err := r.Err
		if err == nil {
			err = fmt.Errorf("no UDP socket bound to port %d was found", r.Port)
		}
		out.Error = clipText(err.Error())
		return out
	}
	out.Sockets, out.Recv, out.Send = r.Sockets, r.Recv, r.Send
	return out
}

// defaultDoctorLockWait は doctor が実行時の状態を守る排他を待つ既定の期限である
// (設計文書 10.2c 節)。
//
// 30 秒ごとの定期処理は、この排他を取ったまま宛先への試し接続を一巡させる。黙って捨てる宛先が
// 多い配置では一巡が数十秒に及ぶので、待ち切る形にすると agent doctor は、繰り返し使いたい
// トラブルの最中にこそ応答しなくなる。2 秒にするのは、ふだんこの排他を取る経路が帳簿の書き換え
// だけで、マイクロ秒の桁しか持たないためである。2 秒待っても取れない実行は定期処理の試し接続の
// 最中であり、その一巡は宛先 1 つの期限と同じ 2 秒の何倍も続くので、待ちを延ばしても取れない。
// 制御ソケットの接続の期限 30 秒に対しても十分に短く、取れなかった事実を返す時間が残る。
const defaultDoctorLockWait = 2 * time.Second

// doctorSnapshot は doctor の応答を組む。値は collectDoctor で、テストだけが panic を模すために
// 差し替える(この package の中だけの口)。
var doctorSnapshot = (*runtime).collectDoctor

// doctorResponseLine は制御ソケットに書く doctor の応答 1 行を組む。JSON は複数行にせず、
// pretty-print もしない(設計文書 10.2c 節)。
//
// 応答を組む処理が panic しても、常駐プロセスごと落とさない。診断のために転送を止めないためで
// ある。受け止めが安全なのは、この経路が取る排他が、collectDoctor の rt.mu も、その下の中継と
// フロー予算の排他も、すべて defer で放されるからである。持ったままになる排他は残らない。
// 応答は 1 行を組み上げてから返し、書くのは呼び出し側なので、受け止めた応答が書きかけの行に
// 足されることもない。rotate-key をこの受け止めに含めない理由は control.ServeConn にある。
func (rt *runtime) doctorResponseLine() (line []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("doctor: recovered from a panic while collecting the agent state: %v\n%s", r, debug.Stack())
			line = doctorErrorLine(fmt.Sprintf("the agent panicked while collecting its state: %v", r))
		}
	}()
	b, err := json.Marshal(doctorSnapshot(rt))
	if err != nil {
		return doctorErrorLine("the agent state could not be encoded as JSON: " + err.Error())
	}
	return append(b, '\n')
}

// doctorErrorLine は理由だけを載せた応答 1 行を組む。
func doctorErrorLine(msg string) []byte {
	b, err := json.Marshal(controlapi.DoctorResponse{Error: clipText(msg)})
	if err != nil {
		// 固定の形なので届かないが、ここでも 1 行の JSON を返す
		return []byte("{\"error\":\"the agent could not describe its own failure\"}\n")
	}
	return append(b, '\n')
}

// maxDoctorText は応答に載せる 1 つの文字列の長さの上限である。単位はバイト。値と理由は
// controlapi.DoctorTextMaxBytes にあり、カーネルモードの読み取りの側(clipKernelText)も同じ値で切る。
const maxDoctorText = controlapi.DoctorTextMaxBytes

// clipText は上限を超える文字列を切り、切ったことを添える。切る位置は rune の境目に合わせるので、
// 結果は正しい UTF-8 のままである。
func clipText(s string) string {
	return textsafe.ClipText(s, maxDoctorText)
}

// collectDoctor は doctor の応答を組む。実行時の状態を守る排他は期限付きで取り、取れなければ
// 実行時の状態を欠いた応答を返す(設計文書 10.2c 節)。黙って待たない。
//
// 制御ストリームの観測は rt.mu の外で読む。rt.mu は全体状態の適用の間じゅう保たれるので、
// この向きは internal/agent/streamobs.go が定めた規則である。
func (rt *runtime) collectDoctor() controlapi.DoctorResponse {
	allow := doctorAllowTargets(rt.opts.AllowTargets)
	stream := controlapi.DoctorStream(rt.streamStatus())
	stream.DisconnectReason = clipText(stream.DisconnectReason)
	proc := doctorProcess()
	res := controlapi.DoctorResponse{AllowTargets: &allow, Stream: &stream, Process: &proc}
	wait := rt.doctorLockWait
	if wait <= 0 {
		wait = defaultDoctorLockWait
	}
	if !rt.lockRuntime(wait) {
		res.RuntimeStateTimeout = wait
		return res
	}
	defer rt.mu.Unlock()
	res.RuntimeState = rt.runtimeStateLocked()
	return res
}

// lockRuntime は実行時の状態を守る排他を期限付きで取る。取れたら真を返し、呼び出し側が放つ。
//
// sync.Mutex は期限付きの取得を持たないので、取れなかった場合は別の goroutine に取らせて
// そのまま放たせる。控えの goroutine が待つ時間は、その時点で排他を持っている処理が終わるまでで
// あり、取ってから放つまではこの関数の中の 1 命令だけなので、他の経路を止めない。
func (rt *runtime) lockRuntime(wait time.Duration) bool {
	if rt.mu.TryLock() {
		return true
	}
	// 緩衝を持つので、諦めた後に取れた場合も送り手は止まらない
	got := make(chan struct{}, 1)
	go func() {
		rt.mu.Lock()
		got <- struct{}{}
	}()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-got:
		return true
	case <-t.C:
		go func() { <-got; rt.mu.Unlock() }()
		return false
	}
}

// runtimeStateLocked は実行時の状態を 1 度に読む。呼び出し側は rt.mu を持つ。
// トンネルの状態も中継の状態も 1 回だけ読むので、1 つの応答に異なる時点の値が混ざらない。
func (rt *runtime) runtimeStateLocked() *controlapi.DoctorRuntimeState {
	st := &controlapi.DoctorRuntimeState{Generation: rt.gen}
	if rt.opts.Mode == credentials.ModeKernel {
		st.Mode = credentials.ModeKernel
	}
	if rt.f != nil && rt.f.LastState != nil {
		st.AgentDisabled = rt.f.LastState.AgentDisabled
	}
	r := rt.dp.Read()
	tun := rt.tunnelSnapshotLocked(r.Tunnel)
	st.Tunnel = controlapi.DoctorTunnel{
		Present:       tun.present,
		State:         tun.hb.State,
		Reason:        clipText(tun.hb.Reason),
		Endpoint:      tun.hb.Endpoint,
		LastHandshake: tun.hb.LastHandshake,
		Watchdog: controlapi.DoctorWatchdog{
			RebuildInterval: rt.rebuild.effectiveWait(),
			RetryAt:         rt.rebuild.retryAt,
		},
	}
	if tun.present {
		st.Tunnel.RxBytes, st.Tunnel.TxBytes = tun.raw.RxBytes, tun.raw.TxBytes
		st.Tunnel.StartedAt = rt.tunStart
		if b := tun.raw.SocketBuffers; b != nil {
			st.Tunnel.SocketBuffers = doctorSocketBuffers(*b)
		}
		if u := tun.raw.UDPAccounting; u != nil {
			st.Tunnel.UDPAccounting = &controlapi.DoctorUDPAccounting{}
			if u.Fault != nil {
				st.Tunnel.UDPAccounting.Stopped = true
				st.Tunnel.UDPAccounting.Error = clipText(u.Fault.Error())
			}
		}
	}
	if r.Relay == nil {
		// カーネルモードのルールごとの状態はハートビートと同じ読みから来る(設計文書 10.2c 節)。
		// リスナーもフロー予算も無い
		if r.Rules != nil {
			st.Rules = doctorRules(r.Rules, nil)
		}
		if kd, ok := rt.dp.(agentdp.KernelDoctor); ok {
			st.Kernel = kd.DoctorKernel()
			st.CheckError = clipText(kd.CheckError())
			st.PublishError = clipText(rt.pendingErr)
			withRulePorts(st.Rules, st.Kernel.Table.Rules)
		}
		return st
	}
	// 中継とトンネルは一緒に作り直されるので、拒否の累計の起点はトンネルを立てた時刻である
	st.RefusalsSince = rt.tunStart
	st.Rules = doctorRules(r.Rules, r.Relay.Listeners)
	st.Budgets = []controlapi.DoctorBudget{
		doctorBudget(proto.TCP, r.Relay.TCP),
		doctorBudget(proto.UDP, r.Relay.UDP),
	}
	return st
}

// withRulePorts は、ハートビートのルールごとの状態に、公開の記録が持つポートの数を写す。
func withRulePorts(rules, record []controlapi.DoctorRule) {
	at := make(map[string]controlapi.DoctorRule, len(record))
	for _, r := range record {
		at[r.ID] = r
	}
	for i := range rules {
		if r, ok := at[rules[i].ID]; ok {
			rules[i].Proto, rules[i].Ports, rules[i].DNATPorts = r.Proto, r.Ports, r.DNATPorts
		}
	}
}

// doctorProcess はこのプロセスの実行主体を読む。
func doctorProcess() controlapi.DoctorProcess {
	p := controlapi.DoctorProcess{UID: os.Getuid(), NetAdmin: kernelmode.ProcessNetAdmin()}
	if p.UID >= 0 {
		if u, err := user.LookupId(strconv.Itoa(p.UID)); err == nil {
			p.User = u.Username
		}
	}
	return p
}

// doctorRules はリスナーの状態をルール単位にまとめる。states はそのリスナーの状態から合成した
// ルールごとの状態で、両方とも Manager.Status の 1 回の読みから来る。
func doctorRules(states []proto.RuleStatus, sts []relay.Status) []controlapi.DoctorRule {
	out := make([]controlapi.DoctorRule, len(states))
	at := make(map[string]int, len(states))
	for i, s := range states {
		out[i] = controlapi.DoctorRule{ID: s.ID, State: s.State, Reason: clipText(s.Reason)}
		at[s.ID] = i
	}
	for _, s := range sts {
		i, ok := at[s.RuleID]
		if !ok {
			continue
		}
		r := &out[i]
		r.Proto = s.Key.Proto
		r.Listeners++
		r.Sessions += s.Sessions
		r.Flows += s.Flows
		switch {
		case !s.Listening:
			r.BindErrors++
			if r.BindError == "" && s.Err != nil {
				r.BindError = clipText(fmt.Sprintf("%s: %v", s.Key, s.Err))
			}
		case s.Err != nil:
			r.Listening++
			r.TargetErrors++
			if r.TargetError == "" {
				r.TargetError = clipText(fmt.Sprintf("%s: %v", s.Key, s.Err))
			}
		default:
			r.Listening++
		}
	}
	return out
}

// doctorBudget は 1 つのプロトコルのフロー予算を読む。拒否の並びは、ルール ID と理由の順に
// 並べ替えて、実行のたびに変わらないようにする。
func doctorBudget(p proto.Proto, pool *resource.Pool) controlapi.DoctorBudget {
	b := controlapi.DoctorBudget{
		Proto:   p,
		Total:   pool.Total(),
		InUse:   pool.InUse(),
		RuleCap: pool.RuleCap(),
		Reserve: pool.Reserve(),
		Rules:   pool.Rules(),
	}
	for rule, byReason := range pool.Refusals() {
		for reason, n := range byReason {
			b.Refusals = append(b.Refusals, controlapi.DoctorRefusal{RuleID: rule, Reason: reason, Count: n})
		}
	}
	sort.Slice(b.Refusals, func(i, j int) bool {
		if b.Refusals[i].RuleID != b.Refusals[j].RuleID {
			return b.Refusals[i].RuleID < b.Refusals[j].RuleID
		}
		return b.Refusals[i].Reason < b.Refusals[j].Reason
	})
	return b
}

// doctorAllowTargets は宛先の許可一覧を読む。一覧が無ければ Set を偽にする。
func doctorAllowTargets(l *allowtargets.List) controlapi.DoctorAllowTargets {
	out := controlapi.DoctorAllowTargets{Env: allowtargets.Env}
	if l != nil {
		out.Set, out.List = true, clipText(l.String())
	}
	return out
}
