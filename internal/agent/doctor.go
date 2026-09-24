package agent

import (
	"encoding/json"
	"fmt"
	"log"
	"runtime/debug"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// 稼働中のエージェントの診断(設計文書 10.2c 節)。制御ソケットの doctor が返す 1 行の JSON は、
// 稼働中のプロセスしか持たない証拠だけを載せる。認証情報ファイル、OS、名前解決のような静的で
// 永続する事実は、エージェントが止まっていても読めるので CLI 自身が読み、この応答には入れない。
//
// 運用者が読む wgft agent doctor --json の出力とこの応答は別の模型であり、この応答はその材料である。
// どの検査にどう畳むか、どの状態の語を当てるか、終了コードをどう決めるかは CLI が決める。

// DoctorCommand は制御ソケットに送る 1 行の要求である。
const DoctorCommand = "doctor"

// DoctorResponse は doctor の応答である。1 行の JSON として送る。
//
// Error があるときは、他の 3 つの項目が無い。応答を組む処理が panic したことを表すためである。
// RuntimeState が無く RuntimeStateTimeout があるときは、実行時の状態を守る排他を期限内に
// 取れなかったことを表す。エージェントは生きているが内部の処理で詰まっている。
type DoctorResponse struct {
	// Error は応答を組む処理が失敗したことと、その理由である。運用者に何が起きたかを伝えるために
	// 載せる。値があるとき、残りの項目は無い
	Error string `json:"error,omitempty"`

	// AllowTargets は宛先の許可一覧である。起動時に決まって以後変わらず、実行時の排他も要らないので、
	// 排他を取れなかった応答にも載る
	AllowTargets *DoctorAllowTargets `json:"allow_targets,omitempty"`

	// Stream は制御ストリームの観測である。streamMu だけで読めるので、実行時の排他を取れなかった
	// 応答にも載る
	Stream *DoctorStream `json:"stream,omitempty"`

	// RuntimeState は実行時の排他の下でしか読めない状態である。排他を期限内に取れなければ無い
	RuntimeState *DoctorRuntimeState `json:"runtime_state,omitempty"`
	// RuntimeStateTimeout は、実行時の排他を取れなかったときに待った期限である。単位はナノ秒。
	// 取れた場合は 0 になる
	RuntimeStateTimeout time.Duration `json:"runtime_state_timeout,omitempty"`
}

// DoctorAllowTargets は宛先の許可一覧である。一覧の中身はエージェントのホストにしか無く、
// server には届かない(設計文書 10.2c 節)。
type DoctorAllowTargets struct {
	// Set は一覧を持っているかどうか。偽なら、server はこのエージェントが届くどの宛先も指せる
	Set bool `json:"set"`
	// List は正規化した一覧。Set が偽なら空
	List string `json:"list,omitempty"`
	// Env は一覧を渡す設定の名前
	Env string `json:"env"`
}

// DoctorStream は制御ストリームの観測の写しである。項目の意味は streamObservation にある。
type DoctorStream struct {
	Connected bool `json:"connected"`
	// DisconnectedAt と RetryAt、LastPingAt、LastPongAt は、値が無ければゼロ値の時刻になる。
	// encoding/json の omitempty は struct に効かないので、項目そのものは必ず出る。読み手は
	// IsZero で判定する
	DisconnectedAt   time.Time `json:"disconnected_at"`
	DisconnectReason string    `json:"disconnect_reason,omitempty"`
	// Backoff は直近に待った再接続の間隔。単位はナノ秒
	Backoff      time.Duration `json:"backoff,omitempty"`
	RetryAt      time.Time     `json:"retry_at"`
	LastPingAt   time.Time     `json:"last_ping_at"`
	LastPongAt   time.Time     `json:"last_pong_at"`
	AwaitingPong bool          `json:"awaiting_pong"`
}

// DoctorRuntimeState は実行時の排他の下で 1 度に読んだ状態である。トンネル、ルール、フロー予算の
// 値はどれも同じ時点のものである。
type DoctorRuntimeState struct {
	// Mode は稼働中のエージェントの転送の方式である(kernel か userspace。仕様 11a 節)。旧い版の
	// エージェントは送らないので、空ならユーザー空間モードである
	Mode string `json:"mode,omitempty"`
	// Generation は最後に受け取って処理した全体状態の世代
	Generation uint64       `json:"generation"`
	Tunnel     DoctorTunnel `json:"tunnel"`
	// Rules はルールごとの状態である。リスナー 1 つずつは並べない。ルールを受け付ける資源が無ければ
	// 項目ごと出ない。カーネルモードでは、リスナーの数と中継の数はどれも 0 で、状態と理由だけが意味を持つ
	Rules []DoctorRule `json:"rules,omitempty"`
	// Budgets はプロトコルごとのフロー予算である。中継が無ければ項目ごと出ない
	Budgets []DoctorBudget `json:"budgets,omitempty"`
	// RefusalsSince は Budgets の拒否の累計の起点、つまり今のトンネルを立てた時刻である。
	// フロー予算はトンネルを立て直すたびに中継ごと作り直され、累計はそのたびに 0 に戻る
	// (設計文書 10.2c 節)。中継が無ければゼロ値の時刻になる。項目そのものは必ず出るので、
	// 読み手は IsZero で判定する
	RefusalsSince time.Time `json:"refusals_since"`
	// AgentDisabled は、最後に適用した全体状態の proto.State.AgentDisabled をそのまま写した
	// ものである(仕様 5.1 節)。server がこのエージェントを無効にしていることをエージェント
	// 自身の診断のために示すだけで、守りには使わない。relay.listeners はこの値から SKIPPED を
	// 判定する(設計文書 10.2c 節)
	AgentDisabled bool `json:"agent_disabled"`
}

// DoctorTunnel はトンネルの状態である。State と Reason はハートビートが組み立てる値そのもので、
// doctor のための 2 つ目の判定は持たない(設計文書 10.2c 節)。
type DoctorTunnel struct {
	// Present はトンネルがあるかどうか。偽なら Reason がその理由を言う
	Present bool `json:"present"`
	// State は ok か error
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// Endpoint は解決済みのエンドポイント。初回の名前解決に失敗したトンネルは持たない
	Endpoint string `json:"endpoint,omitempty"`
	// LastHandshake は今の device から読んだ最終ハンドシェイクである。watchdog が別に持つ値は
	// トンネルを閉じても消えず、立て直した直後は前のトンネルの値が残るので、そちらは載せない。
	// 成立していなければゼロ値の時刻になる。項目そのものは必ず出るので、読み手は IsZero で判定する
	LastHandshake time.Time `json:"last_handshake"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
	// StartedAt は今のトンネルを立てた時刻。トンネルが無ければゼロ値の時刻になる
	StartedAt time.Time      `json:"started_at"`
	Watchdog  DoctorWatchdog `json:"watchdog"`
}

// DoctorWatchdog はトンネルを作り直す判定の状態である。次の作り直しまでの残り時間は載せない。
// 残りは保持されておらず、示すには起点を求める規則を診断の側に写すことになるためである
// (設計文書 10.2c 節)。
type DoctorWatchdog struct {
	// RebuildInterval は判定に使う作り直しの間隔の実効値である。単位はナノ秒
	RebuildInterval time.Duration `json:"rebuild_interval"`
	// RetryAt は、作成に失敗して試し直しを待っている場合の予定の時刻。待っていなければゼロ値の
	// 時刻になる。項目そのものは必ず出るので、読み手は IsZero で判定する
	RetryAt time.Time `json:"retry_at"`
}

// DoctorRule はルール 1 本の状態である。リスナー 1 つずつは並べない。ポート範囲の幅に上限が無く、
// listen_port=1-65535 のルール 1 本で 65535 個のリスナーができるので、そのまま並べると 1 行が
// 数 MB になる(設計文書 10.2c 節)。
type DoctorRule struct {
	ID string `json:"id"`
	// State と Reason はハートビートが組み立てる proto.RuleStatus の値そのものである
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// Proto は tcp か udp
	Proto proto.Proto `json:"proto,omitempty"`
	// Listeners はこのルールに属するリスナーの数、Listening はそのうち待ち受けを開けている数である
	Listeners int `json:"listeners"`
	Listening int `json:"listening"`
	// BindErrors は待ち受けを開けなかったリスナーの数、BindError はその 1 つの理由である。
	// 開けない原因はポートの衝突を指す
	BindErrors int    `json:"bind_errors"`
	BindError  string `json:"bind_error,omitempty"`
	// TargetErrors は待ち受けは開いていて宛先に届かないリスナーの数、TargetError はその 1 つの
	// 理由である。届かない原因は宛先の機器を指すので、運用者の次の行動が bind の失敗とは違う
	TargetErrors int    `json:"target_errors"`
	TargetError  string `json:"target_error,omitempty"`
	// Sessions は中継が持っている接続の数である。TCP は公開側と宛先側の両方を数えるので、
	// フロー予算の上限の対象とは一致しない。上限の対象の数は Flows である
	Sessions int `json:"sessions"`
	Flows    int `json:"flows"`
}

// DoctorBudget は 1 つのプロトコルのフロー予算である。記号は設計文書 7a.10 節に合わせる。
type DoctorBudget struct {
	Proto proto.Proto `json:"proto"`
	// Total は予算 T、InUse は今のフロー数 u である
	Total int `json:"total"`
	InUse int `json:"in_use"`
	// RuleCap はルールが 2 本以上あるときのルール 1 本の上限 C、Reserve はルール 1 本あたりの
	// 隔離予約 q、Rules は今受け付けているルールの数 N である
	RuleCap int `json:"rule_cap"`
	Reserve int `json:"reserve"`
	Rules   int `json:"rules"`
	// Refusals は拒否の累計である。起点は DoctorRuntimeState.RefusalsSince
	Refusals []DoctorRefusal `json:"refusals,omitempty"`
}

// DoctorRefusal はルール 1 本の 1 つの理由の拒否の累計である。
type DoctorRefusal struct {
	RuleID string `json:"rule_id"`
	// Reason は budget、rule_cap、reserve のいずれか(設計文書 7a.10 節)
	Reason resource.Reason `json:"reason"`
	Count  uint64          `json:"count"`
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
// 差し替える(newTunnel と同じ流儀の、この package の中だけの口)。
var doctorSnapshot = (*runtime).collectDoctor

// doctorResponseLine は制御ソケットに書く doctor の応答 1 行を組む。JSON は複数行にせず、
// pretty-print もしない(設計文書 10.2c 節)。
//
// 応答を組む処理が panic しても、常駐プロセスごと落とさない。診断のために転送を止めないためで
// ある。受け止めが安全なのは、この経路が取る排他が、collectDoctor の rt.mu も、その下の中継と
// フロー予算の排他も、すべて defer で放されるからである。持ったままになる排他は残らない。
// 応答は 1 行を組み上げてから返し、書くのは呼び出し側なので、受け止めた応答が書きかけの行に
// 足されることもない。rotate-key をこの受け止めに含めない理由は serveControlConn にある。
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
	b, err := json.Marshal(DoctorResponse{Error: clipText(msg)})
	if err != nil {
		// 固定の形なので届かないが、ここでも 1 行の JSON を返す
		return []byte("{\"error\":\"the agent could not describe its own failure\"}\n")
	}
	return append(b, '\n')
}

// maxDoctorText は応答に載せる 1 つの文字列の長さの上限である。単位はバイト。
//
// 制御ソケットの応答には大きさの上限が無く、リスナーの誤りも panic の値も長さに上限を持たない。
// 節の趣旨は応答が大きくなりすぎないことなので(設計文書 10.2c 節)、リスナーの一覧をルール単位に
// まとめるのと同じ理由でここにも上限を置く。実際の bind の失敗と宛先の到達確認の失敗はどちらも
// 100 バイトに満たないので、512 バイトには 5 倍の余裕がある。
const maxDoctorText = 512

// clipText は上限を超える文字列を切り、切ったことを添える。切る位置は rune の境目に合わせるので、
// 結果は正しい UTF-8 のままである。
func clipText(s string) string {
	if len(s) <= maxDoctorText {
		return s
	}
	n := maxDoctorText
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "... truncated"
}

// collectDoctor は doctor の応答を組む。実行時の状態を守る排他は期限付きで取り、取れなければ
// 実行時の状態を欠いた応答を返す(設計文書 10.2c 節)。黙って待たない。
//
// 制御ストリームの観測は rt.mu の外で読む。rt.mu は全体状態の適用の間じゅう保たれるので、
// この向きは internal/agent/streamobs.go が定めた規則である。
func (rt *runtime) collectDoctor() DoctorResponse {
	allow := doctorAllowTargets(rt.opts.AllowTargets)
	stream := DoctorStream(rt.streamStatus())
	stream.DisconnectReason = clipText(stream.DisconnectReason)
	res := DoctorResponse{AllowTargets: &allow, Stream: &stream}
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
func (rt *runtime) runtimeStateLocked() *DoctorRuntimeState {
	st := &DoctorRuntimeState{Generation: rt.gen}
	if rt.opts.Mode == credentials.ModeKernel {
		st.Mode = credentials.ModeKernel
	}
	if rt.f != nil && rt.f.LastState != nil {
		st.AgentDisabled = rt.f.LastState.AgentDisabled
	}
	r := rt.dp.read()
	tun := rt.tunnelSnapshotLocked(r.tunnel)
	st.Tunnel = DoctorTunnel{
		Present:       tun.present,
		State:         tun.hb.State,
		Reason:        clipText(tun.hb.Reason),
		Endpoint:      tun.hb.Endpoint,
		LastHandshake: tun.hb.LastHandshake,
		Watchdog: DoctorWatchdog{
			RebuildInterval: rt.rebuild.effectiveWait(),
			RetryAt:         rt.rebuild.retryAt,
		},
	}
	if tun.present {
		st.Tunnel.RxBytes, st.Tunnel.TxBytes = tun.raw.rxBytes, tun.raw.txBytes
		st.Tunnel.StartedAt = rt.tunStart
	}
	if r.relay == nil {
		// カーネルモードのルールごとの状態はハートビートと同じ読みから来る(設計文書 10.2c 節)。
		// リスナーもフロー予算も無い
		if r.rules != nil {
			st.Rules = doctorRules(r.rules, nil)
		}
		return st
	}
	// 中継とトンネルは一緒に作り直されるので、拒否の累計の起点はトンネルを立てた時刻である
	st.RefusalsSince = rt.tunStart
	st.Rules = doctorRules(r.rules, r.relay.listeners)
	st.Budgets = []DoctorBudget{
		doctorBudget(proto.TCP, r.relay.tcp),
		doctorBudget(proto.UDP, r.relay.udp),
	}
	return st
}

// doctorRules はリスナーの状態をルール単位にまとめる。states はそのリスナーの状態から合成した
// ルールごとの状態で、両方とも Manager.Status の 1 回の読みから来る。
func doctorRules(states []proto.RuleStatus, sts []relay.Status) []DoctorRule {
	out := make([]DoctorRule, len(states))
	at := make(map[string]int, len(states))
	for i, s := range states {
		out[i] = DoctorRule{ID: s.ID, State: s.State, Reason: clipText(s.Reason)}
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
func doctorBudget(p proto.Proto, pool *resource.Pool) DoctorBudget {
	b := DoctorBudget{
		Proto:   p,
		Total:   pool.Total(),
		InUse:   pool.InUse(),
		RuleCap: pool.RuleCap(),
		Reserve: pool.Reserve(),
		Rules:   pool.Rules(),
	}
	for rule, byReason := range pool.Refusals() {
		for reason, n := range byReason {
			b.Refusals = append(b.Refusals, DoctorRefusal{RuleID: rule, Reason: reason, Count: n})
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
func doctorAllowTargets(l *allowtargets.List) DoctorAllowTargets {
	out := DoctorAllowTargets{Env: allowtargets.Env}
	if l != nil {
		out.Set, out.List = true, clipText(l.String())
	}
	return out
}
