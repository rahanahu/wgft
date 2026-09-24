// Package doctor holds the forwarding diagnosis: it turns the evidence the admin API already
// carries into the checks, per-rule verdicts and next steps that `wgft server doctor` (design.md
// 10.2a 節) and the Web UI's diagnostics page (design.md 10.2d 節) both show.
//
// The package sits beside internal/vpsd/admin rather than inside it (design.md 10.2d 節「診断の
// ロジックの置き場所」): the judgment belongs neither to the admin API nor to the CLI, and both
// import it. Two constraints follow from that and hold for every file here.
//
//   - It must not import internal/vpsd/admin, which imports this package, nor internal/vpsd itself
//     (internal/dataplane/deps_test.go's TestVpsdSubpackagesDoNotImportVpsd). The evidence it reads
//     therefore comes from internal/vpsd/adminapi, which both packages import.
//   - It carries no build tag, so the diagnosis stays available on every OS; only the registration
//     of `server doctor` lives in the Linux-only `server` group (design.md 10.2a 節).
//
// The two callers differ only in how they reach the evidence, which they hand over as an Evidence
// (evidence.go): the CLI reads it over the admin API through *admin.Client, the Web UI reads it in
// the same process through the Backend. The judgment below sees neither.
//
// Nothing here writes: every check reads evidence that was already collected, except the one active
// probe the operator asks for explicitly (Input.AddProbe).
package doctor

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/adminapi"
	"github.com/rahanahu/wgft/proto"
)

// 検査の識別子。JSON の "id" の値であり、機械向けの保証である(設計文書 10.2a 節)。開いた集合
// として扱い、項目を増やすことだけができる。名前の変更も意味の変更も互換ではない。
const (
	CheckDataplane = "server.dataplane"
	CheckEnabled   = "rule.enabled"
	// CheckAgentEnabled は、ルールの持ち主のエージェントに無効の印があるかどうかである(設計文書
	// 5.1、10.2a 節)。server は無効の印の正本である自分のデータベースを読むので、登録の無い
	// エージェントのルールでも OK になる。登録の有無は CheckConnection が判定する。
	CheckAgentEnabled  = "agent.enabled"
	CheckPublicPort    = "rule.public_port"
	CheckSourceFilter  = "rule.source_filter"
	CheckHandshake     = "tunnel.handshake"
	CheckConnection    = "agent.connection"
	CheckRulesReceived = "agent.rules_received"
	CheckCredentials   = "agent.credentials"
	CheckTargetResolve = "rule.target_resolve"
	CheckTarget        = "rule.target"
	CheckFlowBudget    = "rule.flow_budget"
	CheckProbe         = "rule.probe"
)

// checkOrder は検査を、公開側から自宅側への経路の順に並べたものである。最初に failed になった
// 検査が、そのルールの止まった位置になる。CheckOrder が写しを返す。
var checkOrder = []string{
	CheckEnabled, CheckAgentEnabled, CheckPublicPort, CheckSourceFilter, CheckDataplane,
	CheckHandshake,
	CheckConnection, CheckRulesReceived, CheckCredentials, CheckTargetResolve, CheckTarget, CheckFlowBudget, CheckProbe,
}

// CheckOrder は検査の ID を、公開側から自宅側への経路の順に返す。写しを返すので、呼び出し側が
// 並びを変えても判定は変わらない。
func CheckOrder() []string { return append([]string(nil), checkOrder...) }

// 検査の状態。JSON の "status" の値であり、5 つだけである(設計文書 10.2a 節)。
const (
	// StatusOK は、その項目が成功することを実際に観測した状態である。検証していないものに
	// 使ってはならない。
	StatusOK = "ok"
	// StatusFailed は、その項目が失敗することを実際に観測した状態である。
	StatusFailed = "failed"
	// StatusUnknown は、証拠はあるが古い、食い違う、または判定に足りない状態である。
	StatusUnknown = "unknown"
	// StatusNotTested は、その到達性や条件をこのコマンドがそもそも試さない状態である。
	StatusNotTested = "not_tested"
	// StatusSkipped は、試せたはずだが、手前の失敗によって今回は試せなかった状態である。
	StatusSkipped = "skipped"
)

// 理由の符号。JSON の "reason" の値であり、機械向けの保証である。開いた集合として扱い、
// 読み手は知らない値を「不明」として扱う(設計文書 10.2a、7a.11 節)。
const (
	ReasonRuleDisabled = "rule_disabled"
	// ReasonAgentDisabled は、ルールは有効だが持ち主のエージェントが無効なときの skipped の理由
	// である(設計文書 5.1、10.2a 節)。直す操作が rule enable ではなく agent enable なので、
	// rule_disabled を流用しない。
	ReasonAgentDisabled       = "agent_disabled"
	ReasonBindFailed          = "bind_failed"
	ReasonNotPublished        = "not_published"
	ReasonGenerationBehind    = "generation_behind"
	ReasonGenerationPending   = "generation_pending"
	ReasonAgentNotRegistered  = "agent_not_registered"
	ReasonAgentDisconnected   = "agent_disconnected"
	ReasonNoRecentHandshake   = "no_recent_handshake"
	ReasonTunnelError         = "tunnel_error"
	ReasonDeniedByDenyList    = "denied_by_deny_list"
	ReasonNotInAllowList      = "not_in_allow_list"
	ReasonTargetNotAllowed    = "target_not_allowed"
	ReasonListenerBindFailed  = "listener_bind_failed"
	ReasonResolveFailed       = "target_resolve_failed"
	ReasonConnectionRefused   = "connection_refused"
	ReasonTargetTimeout       = "target_timeout"
	ReasonTargetError         = "target_error"
	ReasonTargetUnreachable   = "target_unreachable"
	ReasonAgentUnreachable    = "agent_unreachable"
	ReasonNotReported         = "not_reported"
	ReasonStaleReport         = "stale_report"
	ReasonRepairFailed        = "repair_failed"
	ReasonResourceRefusals    = "resource_refusals"
	ReasonCredentialWarning   = "credential_warning"
	ReasonNotIPv4             = "not_ipv4"
	ReasonNoProbe             = "no_probe"
	ReasonNoFrom              = "no_source_given"
	ReasonNotReportedByServer = "not_reported_by_server"
	ReasonUnknownValue        = "unknown_value"
	ReasonExternalNotTested   = "external_not_tested"
	ReasonResolvedByAgent     = "resolved_by_agent"
	// ReasonUDPListenerOnly は、UDP のルールの rule.target の not_tested の理由である。エージェント
	// の報告が示すのはリスナーを開けたことだけで、宛先が応えたことではない(設計文書 10.2a 節)。
	ReasonUDPListenerOnly = "udp_listener_only"
)

// 検査のまとまり。人向けの出力の見出しになる。保証の対象ではない。
const (
	GroupServer = "Server"
	GroupTunnel = "Tunnel"
	GroupAgent  = "Agent"
)

// 証拠が古くなる閾値。項目ごとに違う値を選んである(設計文書 10.2a 節)。
const (
	// HeartbeatStale は、エージェントの接続の観測が古くなる長さである。エージェントは 30 秒
	// ごとにハートビートを送る(設計文書 5.2 節)ので、3 回分の沈黙を越えたら、接続していると
	// いう表示を今の値として扱わない。
	HeartbeatStale = 90 * time.Second
	// HandshakeStale は、最終ハンドシェイクがトンネルの健全を示さなくなる長さである。健全な
	// トンネルの最終ハンドシェイクは 145 秒以内に必ず新しくなり(設計文書 7 節)、窃取検知も
	// 3 分以内のものだけを生きていると見なす(5.2 節)ので、同じ 3 分を使う。
	//
	// 他の 2 つの閾値と違い、これを越えた値は古い証拠ではなく、今読んだ現在の観測である
	// (10.2a 節)。`tunnel.handshake` は報告ではなく、server が WireGuard から今読む値なので、
	// 越えていれば FAILED になる。受信だけが死んだトンネルを見分けられない期間も同じ長さで
	// あり、別の定数を持たない。エージェントが device と netstack を作り直す 300 秒(7 節)は
	// エージェント側の watchdog の閾値であって、診断が気付けない期間ではない。1 つの数に
	// 2 つの定数を置いたことが、両者の取り違えを生んでいた。
	HandshakeStale = 3 * time.Minute
	// TargetReportStale は、エージェントが報告したルールの状態が古くなる長さである。TCP の
	// target への接続確認は 30 秒ごとに行われる(設計文書 5.2 節)ので、ハートビートと同じ
	// 90 秒を越えた報告は、今の値として扱わない。
	TargetReportStale = 90 * time.Second
	// GenerationBehindLimit は、エージェントがルール集合の世代に追いつかない状態を、届きかけ
	// ではなく止まった遅れとして扱い始める長さである(設計文書 10.2a 節)。ラボではエージェントは
	// 新しい世代を 1 秒未満で取り、取った直後にハートビートを送る(5.2 節)ので、この長さまで
	// 続く遅れは届きかけではない。
	GenerationBehindLimit = 60 * time.Second
)

// Report は 1 回の診断の結果全体である。JSON はこの形で出し、人向けの出力とは別の、
// 診断そのものの模型である(設計文書 10.2a 節)。最上位をオブジェクトにしてあるのは、後から
// 項目を加えても読み手が壊れないようにするためである(7a.11 節の加算の規則)。
type Report struct {
	// Status は全体の判定である。failed の検査が 1 つでもあれば failed、それ以外は ok になる。
	Status    string `json:"status"`
	CheckedAt string `json:"checked_at"` // RFC3339
	// Probed は能動的な疎通確認を行ったかどうかである。
	Probed bool `json:"probed"`
	// Checks はこの実行が行った検査すべてである。ルールに属する検査は RuleID を持つ。
	Checks []Check `json:"checks"`
	// Rules は検査をルールごとにまとめた索引で、Checks の要約である。
	Rules []RuleReport `json:"rules"`
	// History は、この版が履歴を持たないことを明示する(設計文書 10.2a 節)。
	History History `json:"history"`
	// NotTested は、この診断が試していない範囲である。何も壊れていない実行でも必ず載せる。
	NotTested []NotTested `json:"not_tested"`
}

// Check は 1 つの検査である。
type Check struct {
	// ID は機械向けの保証である。増えることはあっても、名前も意味も変わらない。
	ID string `json:"id"`
	// RuleID は、この検査が 1 本のルールに属する場合のそのルールである。
	RuleID string `json:"rule_id,omitempty"`
	// Agent は、この検査がエージェントに属する場合のその名前である。
	Agent  string `json:"agent,omitempty"`
	Status string `json:"status"`
	// Reason は機械向けの理由の符号で、ok の検査では省く。
	Reason string `json:"reason,omitempty"`
	// ObservedAt は、この判定の根拠になった観測の時刻である。観測が無ければ省く。
	ObservedAt string `json:"observed_at,omitempty"`
	// Group と Label は人向けの見出しであり、保証の対象ではない(設計文書 7a.11 節)。
	Group string `json:"group"`
	Label string `json:"label"`
	// Detail は人向けの 1 文である。保証の対象ではない。
	Detail string `json:"detail"`
	// Causes は、この証拠だけでは切り分けられない原因の一覧である。1 つに決めつけないために
	// 持つ(設計文書 10.2a 節)。切り分けられる所見では省く。
	Causes []string `json:"causes,omitempty"`
	// Next は運用者が次に見るものである。ok と not_tested 以外の検査は必ず持つ。
	Next string `json:"next,omitempty"`
	// Internal は wgft 自身を追うときだけ要る値である。人向けの出力では --verbose で出す。
	Internal []string `json:"internal,omitempty"`
	// LastReplyAt、ReplySince、ReplyNotObserved は、UDP のルールの rule.target だけが持つ、server
	// 自身が見た宛先の応答の観測である(設計文書 10.2a 節「UDP の応答の観測」)。管理用 API の
	// udp_replies の写しで、報告の無い server では省く。どれも Status、Reason、ObservedAt を
	// 動かさない。LastReplyAt は ReplySince 以降に見た最後の応答の時刻(RFC3339)で、見ていなければ
	// 省く。ReplySince は途切れずに観測している始まりである。ReplyNotObserved は観測できない理由で、
	// そのときは他の 2 つを省く。
	LastReplyAt      string `json:"last_reply_at,omitempty"`
	ReplySince       string `json:"reply_since,omitempty"`
	ReplyNotObserved string `json:"reply_not_observed,omitempty"`
	// ReplyLine は上の観測を人向けの 1 行にしたもので、人向けの出力が detail の下に出す。
	// 保証の対象ではないので JSON には載せない。
	ReplyLine string `json:"-"`
	// hideWhenOK と hideWhenUntested は、既定の表示から外す条件である。JSON には常に載せる。
	// 経路の要になる検査(公開ポート、トンネル、接続、target)はどちらも立てない。
	hideWhenOK       bool
	hideWhenUntested bool
	// offPath は、転送の経路の上に無い検査である。運用者に見せる事実ではあるが、そのルールが
	// 今転送しているかどうかを述べないので、ルールの総合判定を動かさない(設計文書 10.2a 節)。
	offPath bool
}

// RuleReport は 1 本のルールの要約である。
type RuleReport struct {
	RuleID     string `json:"rule_id"`
	Agent      string `json:"agent"`
	Proto      string `json:"proto"`
	ListenPort string `json:"listen_port"`
	Target     string `json:"target"`
	Group      string `json:"group,omitempty"`
	Enabled    bool   `json:"enabled"`
	Status     string `json:"status"`
	// StoppedAt は最初に failed になった検査の ID で、failed が無ければ省く。
	StoppedAt string `json:"stopped_at,omitempty"`
}

// History は履歴の有無である。この版は現在の状態しか見ない。
type History struct {
	Available bool   `json:"available"`
	Detail    string `json:"detail"`
}

// NotTested は試していない範囲 1 件である。
type NotTested struct {
	ID     string `json:"id"`
	Detail string `json:"detail"`
}

// ProbeResult は 1 本のルールに対する能動的な疎通確認の結果である。Err は管理用 API が確認
// そのものを拒んだ場合(UDP のルール、無効なルール、未登録のエージェント)に入る。
type ProbeResult struct {
	Check *adminapi.ConnCheck
	Err   error
}

// Input は診断が読む証拠をまとめたものである。純粋な関数として試験できるよう、
// 管理用 API の呼び出しと分けてある。
type Input struct {
	Now     time.Time
	Rules   *adminapi.BatchResponse
	Agents  []adminapi.AgentInfo
	From    netip.Addr
	HasFrom bool
	Probed  bool
	Probes  map[string]ProbeResult
}

// BuildReport は検査一式と、ルールごとの要約と、試していない範囲を組み立てる。
func BuildReport(rules []proto.Rule, in Input) Report {
	rep := Report{CheckedAt: in.Now.UTC().Format(time.RFC3339), Probed: in.Probed, Status: StatusOK}
	rep.History = History{Detail: "this command only evaluates the current state. To find when a rule stopped working, read the server log via journalctl -u wgft, and the agent's log."}
	for _, r := range rules {
		checks := Diagnose(r, in)
		rr := RuleReport{
			RuleID: r.ID, Agent: r.Agent, Proto: string(r.Proto), ListenPort: r.ListenPort.String(),
			Target: r.TargetDisplay(), Group: r.Group, Enabled: r.Enabled, Status: StatusOK,
		}
		// ルールの総合判定は、経路の上の検査だけから決める(設計文書 10.2a 節)。経路の外の
		// 検査(累積の拒否、窃取の警告)は起動からの事実を述べるだけで、今転送しているかを
		// 述べないため、要約をいつまでも下げ続けないようにする。
		for _, c := range checks {
			if c.offPath {
				continue
			}
			if c.Status == StatusFailed && rr.StoppedAt == "" {
				rr.StoppedAt, rr.Status = c.ID, StatusFailed
			}
		}
		if rr.Status == StatusOK && anyPathStatus(checks, StatusUnknown) {
			rr.Status = StatusUnknown
		}
		// 無効なルールと、無効なエージェントのルールは、宣言どおりの状態であり故障ではない
		// (設計文書 10.2a 節)。どちらも下流の検査はすべて skipped なので、ここに来るのは
		// ok のときだけである。
		if rr.Status == StatusOK && (!r.Enabled || agentDisabledIn(checks)) {
			rr.Status = StatusSkipped
		}
		rep.Checks = append(rep.Checks, checks...)
		rep.Rules = append(rep.Rules, rr)
	}
	rep.Checks = append(rep.Checks, DataplaneCheck(in))
	for _, c := range rep.Checks {
		if c.Status == StatusFailed && !c.offPath {
			rep.Status = StatusFailed
		}
	}
	rep.NotTested = notTestedList(rules, in)
	return rep
}

// notTestedList は、この診断が試していない範囲を返す。何も壊れていない実行でも必ず出す。
// 黙っていると運用者が沈黙を健全と読むためである(設計文書 10.2a 節)。
func notTestedList(rules []proto.Rule, in Input) []NotTested {
	ports := "the rules' listen ports"
	if len(rules) == 1 {
		ports = string(rules[0].Proto) + " " + rules[0].ListenPort.String()
	}
	out := []NotTested{
		{"from outside", "whether the internet reaches " + ports + " on this VPS. DNAT applies to input from outside, so the " +
			"server cannot reach its own public port from itself. Test it from another host: nc -vz <vps> <port>. Invisible here: " +
			"the provider's security group, this host's input firewall, the ISP, and, in userspace mode, a listen port inside the " +
			"ephemeral range; see docs/setup.md."},
		{"udp end to end", "a UDP rule cannot be tested end to end, because a UDP send cannot tell success. It is judged from " +
			"what the agent reports about its listener alone, so while the agent reports its listener open, the target line " +
			"reads NOT TESTED, never OK. The line under it may show when this server last saw the target answer; " +
			"that is a passive observation and does not change the status."},
		{"mtu", "MTU and fragmentation. A tunnel that handshakes and carries small packets can still lose large datagrams, which " +
			"reads as healthy here and as \"it works sometimes\" to the user."},
		{"under load", "rate limits, the flow budget and the connection tracking table are read at one instant; a limit reached " +
			"only under load does not appear."},
		{"the service", "the application behind the target. Every check here connects and closes without speaking the protocol, " +
			"so a port that accepts while the service refuses, is full, or is the wrong service reads as healthy."},
		{"one-way tunnel", "the first " + HandshakeStale.String() + " of a tunnel that stopped receiving. Its handshake stays recent " +
			"for that long, so a check run inside that window calls it healthy."},
		// 10.2a 節の「agent doctor ができた時点で案内し直す」に従って向け直した案内である
		// (10.2c 節の「置き場所」)。
		{"the agent host", "the agent's own environment: its OS, its permissions, its interfaces and its name resolution. This " +
			"server sees only what the heartbeat carries. To see it, run wgft agent doctor on that host."},
	}
	// この項目は、診断の対象がすべて UDP のルールであれば出さない。UDP のルールは --probe を
	// 付けても管理用 API が確認そのものを拒むので、この項目の案内は意味を持たない。1 本でも
	// TCP のルールが混じっていれば、そのルールには --probe が今も意味を持つので出す(設計文書
	// 10.2a 節の改訂の記録、2026-09-23)。
	allUDP := len(rules) > 0
	for _, r := range rules {
		if r.Proto != proto.UDP {
			allUDP = false
			break
		}
	}
	if !in.Probed && !allUDP {
		out = append(out, NotTested{"inner path", "nothing was dialled. Add --probe to open one real TCP connection from this " +
			"server, through the tunnel and the agent, to the target."})
	}
	return out
}

// Diagnose は 1 本のルールの検査を経路の順に返す。検査どうしの優先順位は設計文書 10.2a 節に
// ある。要点は 3 つである。無効なルールは宣言どおりなので skipped にとどめて下流を試さない。
// ルールが有効でも持ち主のエージェントが無効なら、同じく宣言どおりなので、agent.enabled から
// 下流を agent_disabled の skipped にする。ルール自身の無効を先に示すのは、直す操作が違うため
// である(rule enable と agent enable)。エージェントの stream が切れている間は、そのエージェントが
// 報告した値(トンネルの状態、処理済み世代、ルールの状態)を今の値として扱わず、unknown と
// "last:" にする(5.2 節)。
func Diagnose(r proto.Rule, in Input) []Check {
	ai := findAgentInfo(in.Agents, r.Agent)
	if !r.Enabled {
		out := []Check{{
			ID: CheckEnabled, RuleID: r.ID, Group: GroupServer, Label: "enabled", Status: StatusSkipped,
			Reason: ReasonRuleDisabled,
			Detail: "the rule is disabled, so nothing is forwarded; that is a declared state, not a fault",
			Next:   "enable it: wgft rule enable " + ShortID(r.ID),
		}}
		for _, id := range checkOrder {
			if id == CheckEnabled || id == CheckDataplane {
				continue
			}
			out = append(out, Check{
				ID: id, RuleID: r.ID, Agent: agentOf(id, r), Group: checkGroup(id), Label: checkLabel(id, r),
				Status: StatusSkipped, Reason: ReasonRuleDisabled,
				Detail: "not tested: the rule is disabled",
				Next:   "enable it first: wgft rule enable " + ShortID(r.ID),
				// 無効なルールの下流は、同じ 1 つの理由を 11 回繰り返すだけなので既定では
				// 出さない。--verbose では出す。
				hideWhenUntested: true,
			})
		}
		return out
	}
	enabled := Check{ID: CheckEnabled, RuleID: r.ID, Group: GroupServer, Label: "enabled", Status: StatusOK,
		Detail: "the rule is enabled", hideWhenOK: true}
	if ai != nil && ai.Disabled {
		return agentDisabledChecks(enabled, r, ai, in)
	}
	return []Check{
		enabled,
		agentEnabledCheck(r, ai, in),
		publicPortCheck(r, in),
		sourceFilterCheck(r, in),
		handshakeCheck(r, ai, in),
		connectionCheck(r, ai, in),
		rulesReceivedCheck(r, ai, in),
		credentialsCheck(r, ai),
		resolveCheck(r, ai, in),
		withUDPReply(targetCheck(r, ai, in), r, in),
		flowBudgetCheck(r, in),
		probeCheck(r, in),
	}
}

// agentEnabledCheck は、持ち主のエージェントが無効でないルールの agent.enabled である。無効の
// 場合は agentDisabledChecks が組み立てる。登録の無いエージェントも ok にする。server は無効の
// 印の正本である自分のデータベースを読んでおり、そのルールを止める印が無いことを直接観測して
// いるためである(設計文書 10.2a 節)。この ok は既存の検査の結果も、ルールの総合判定も、
// 終了コードも動かさない。登録の有無は agent.connection が判定する。
func agentEnabledCheck(r proto.Rule, ai *adminapi.AgentInfo, in Input) Check {
	c := Check{ID: CheckAgentEnabled, RuleID: r.ID, Agent: r.Agent, Group: GroupServer, Label: "agent enabled",
		Status: StatusOK, ObservedAt: in.Now.UTC().Format(time.RFC3339), hideWhenOK: true}
	if ai == nil {
		c.Detail = fmt.Sprintf("no disable mark stops this rule: no agent named %q is registered, read just now", r.Agent)
		return c
	}
	c.Detail = fmt.Sprintf("agent %q is enabled, read just now", r.Agent)
	return c
}

// agentDisabledChecks は、有効なルールの持ち主のエージェントが無効なときの検査一式である
// (設計文書 5.1、10.2a 節)。agent.enabled を agent_disabled の skipped にし、下流もすべて同じ
// 理由の skipped にする。無効なエージェントのルールは VPS も自宅側も転送しないので、下流の
// 検査が何を観測しても、そのルールについての今の所見にはならない。
func agentDisabledChecks(enabled Check, r proto.Rule, ai *adminapi.AgentInfo, in Input) []Check {
	// 一覧の 1 行は detail の最初の句だけを出すので(cmd/wgft の firstClause)、無効であることを
	// 最初の句に置く。
	when := fmt.Sprintf("agent %q is disabled", r.Agent)
	if t, ok := ParseWhen(ai.DisabledAt); ok {
		when = fmt.Sprintf("agent %q was disabled %s ago", r.Agent, Since(in.Now, t))
	}
	detail := when + "; this rule forwards nothing until the agent is enabled. That is a declared state, not a fault"
	out := []Check{enabled, {
		ID: CheckAgentEnabled, RuleID: r.ID, Agent: r.Agent, Group: GroupServer, Label: "agent enabled",
		Status: StatusSkipped, Reason: ReasonAgentDisabled, ObservedAt: ai.DisabledAt,
		Detail: detail, Next: "enable the agent: wgft agent enable " + r.Agent,
	}}
	for _, id := range checkOrder {
		if id == CheckEnabled || id == CheckAgentEnabled || id == CheckDataplane {
			continue
		}
		out = append(out, Check{
			ID: id, RuleID: r.ID, Agent: agentOf(id, r), Group: checkGroup(id), Label: checkLabel(id, r),
			Status: StatusSkipped, Reason: ReasonAgentDisabled,
			Detail: fmt.Sprintf("not tested: agent %q is disabled", r.Agent),
			Next:   "enable the agent first: wgft agent enable " + r.Agent,
			// 無効なルールの下流と同じく、同じ 1 つの理由を繰り返すだけなので既定では出さない。
			hideWhenUntested: true,
		})
	}
	return out
}

// agentDisabledIn は、検査の中に agent.enabled の agent_disabled があるかどうかである。
func agentDisabledIn(checks []Check) bool {
	for _, c := range checks {
		if c.ID == CheckAgentEnabled && c.Reason == ReasonAgentDisabled {
			return true
		}
	}
	return false
}

// RuleAgentDisabled は、そのルールが有効で、持ち主のエージェントが無効であるために skipped に
// なったかどうかである。CLI と Web UI の結論の 1 行が、無効なルールの場合と書き分けるために読む。
func (rep Report) RuleAgentDisabled(ruleID string) bool {
	var checks []Check
	for _, c := range rep.Checks {
		if c.RuleID == ruleID {
			checks = append(checks, c)
		}
	}
	return agentDisabledIn(checks)
}

func agentOf(id string, r proto.Rule) string {
	if checkGroup(id) == GroupAgent || id == CheckHandshake || id == CheckAgentEnabled {
		return r.Agent
	}
	return ""
}

func checkGroup(id string) string {
	switch id {
	case CheckDataplane, CheckEnabled, CheckAgentEnabled, CheckPublicPort, CheckSourceFilter:
		return GroupServer
	case CheckHandshake:
		return GroupTunnel
	}
	return GroupAgent
}

func checkLabel(id string, r proto.Rule) string {
	switch id {
	case CheckDataplane:
		return "dataplane"
	case CheckEnabled:
		return "enabled"
	case CheckAgentEnabled:
		return "agent enabled"
	case CheckPublicPort:
		return "public port"
	case CheckSourceFilter:
		return "source filter"
	case CheckHandshake:
		return "WireGuard"
	case CheckConnection:
		// "connected DEGRADED" は 1 行の中で矛盾して読めるので、状態の語ではなく対象の名前にする。
		return "control connection"
	case CheckRulesReceived:
		return "rules received"
	case CheckCredentials:
		return "credentials"
	case CheckTargetResolve:
		return "target resolve"
	case CheckTarget:
		return "target"
	case CheckFlowBudget:
		return "flow budget"
	case CheckProbe:
		return "end-to-end probe"
	}
	return id
}

// anyPathStatus は、経路の上の検査に want の判定があるかを返す。経路の外の検査は数えない。
func anyPathStatus(checks []Check, want string) bool {
	for _, c := range checks {
		if !c.offPath && c.Status == want {
			return true
		}
	}
	return false
}

func findAgentInfo(agents []adminapi.AgentInfo, name string) *adminapi.AgentInfo {
	for i := range agents {
		if agents[i].Name == name {
			return &agents[i]
		}
	}
	return nil
}

// --- 判定の見せ方(CLI と Web UI が共有する) ---

// DisplayStatus は 1 つの検査を人向けの語にする。1 か所だけ、JSON の値と画面の語が意図して
// 食い違う(設計文書 10.2a 節)。制御の経路が切れていてトンネルが生きている状態は、JSON では
// unknown と `agent_disconnected` のままだが、画面には DEGRADED と出す。この状態は「判定に
// 足りない」のではなく「運用として劣化している」と読むほうが人には正確であり、終了コードが 0 で
// あっても出力が黙らないためである。機械はあくまで status と reason を読む。
//
// 条件はこの 1 つだけに絞る。他の unknown は UNKNOWN のまま出す。
func DisplayStatus(c Check) string {
	if c.ID == CheckConnection && c.Status == StatusUnknown && c.Reason == ReasonAgentDisconnected {
		return "DEGRADED"
	}
	return StatusWord(c.Status)
}

// StatusWord は判定を人向けの語にする。表そのものは保証の対象ではない(設計文書 7a.11 節)。
func StatusWord(s string) string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusFailed:
		return "FAILED"
	case StatusUnknown:
		return "UNKNOWN"
	case StatusNotTested:
		return "NOT TESTED"
	case StatusSkipped:
		return "SKIPPED"
	}
	return s
}

// OffPath は、その検査が転送の経路の上に無いかどうかである(設計文書 10.2a 節)。経路の外の
// 検査は、そのルールが今転送しているかどうかを述べないので、ルールの総合判定も終了コードも
// 動かさない。
func (c Check) OffPath() bool { return c.offPath }

// Hidden は、その検査を既定の表示から外すかどうかである。CLI の --verbose と、Web UI の
// 「既定で隠している検査」の区画が、同じ判定をこの 1 つから引く。
func (c Check) Hidden(verbose bool) bool {
	if verbose {
		return false
	}
	if c.Status == StatusOK && c.hideWhenOK {
		return true
	}
	return (c.Status == StatusNotTested || c.Status == StatusSkipped) && c.hideWhenUntested
}

// ChecksOf は 1 本のルールに属する検査を、公開側から自宅側への経路の順に返す。server 全体の
// 検査(dataplane)はどのルールの経路にも入るので必ず含める。CLI の 1 本の報告と Web UI の
// 1 本の画面が、同じ並びをこの 1 つから引く。
func (rep Report) ChecksOf(ruleID string) []Check {
	var out []Check
	for _, c := range rep.Checks {
		if c.ID == CheckDataplane || c.RuleID == ruleID {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return checkIndex(out[i].ID) < checkIndex(out[j].ID) })
	return out
}

func checkIndex(id string) int {
	for i, v := range checkOrder {
		if v == id {
			return i
		}
	}
	return len(checkOrder)
}

// AgentSummaries は、報告に現れるエージェントごとに 1 行ぶんの要約を作る。エージェントの接続の
// 検査をそのまま使い、同じ判定を 2 か所で作らない。Label はエージェントの名前に差し替える。
// 検査は AgentCheck と同じ規則で選ぶ。
func (rep Report) AgentSummaries() []Check {
	seen := map[string]bool{}
	var out []Check
	for _, c := range rep.Checks {
		if c.ID != CheckConnection || c.Agent == "" || seen[c.Agent] {
			continue
		}
		seen[c.Agent] = true
		c, _ = rep.AgentCheck(c.Agent, CheckConnection)
		c.Label = c.Agent
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Agent < out[j].Agent })
	return out
}

// AgentCheck は、エージェントに属する検査 id(tunnel.handshake、agent.connection など)を、
// そのエージェントを名指すルールの検査から 1 つ選ぶ。これらの検査はどの有効なルールにも同じ値で
// 入るが、無効なルールの検査は rule_disabled の skipped であり、エージェントの状態を述べない。
// そこで有効なルールの検査を先に採り、無ければ最初の検査を返す(設計文書 10.2a 節の改訂の
// 記録、2026-09-23)。
//
// 無効なエージェントのルールの検査は agent_disabled の skipped で、どの有効なルールでも同じ値に
// なる。これはエージェント自身の状態(無効)を述べるので、rule_disabled より先に採る。
func (rep Report) AgentCheck(agent, id string) (Check, bool) {
	var agentOff, first *Check
	for i, c := range rep.Checks {
		if c.ID != id || c.Agent != agent {
			continue
		}
		switch c.Reason {
		case ReasonRuleDisabled:
		case ReasonAgentDisabled:
			if agentOff == nil {
				agentOff = &rep.Checks[i]
			}
		default:
			return c, true
		}
		if first == nil {
			first = &rep.Checks[i]
		}
	}
	if agentOff != nil {
		return *agentOff, true
	}
	if first != nil {
		return *first, true
	}
	return Check{}, false
}

// --- 小さな補助 ---

// ParseWhen は管理用 API の RFC3339 のタイムスタンプを読む。観測していない値はフィールドごと
// 省かれる(設計文書 7a.11 節)ので、空文字は「観測していない」を意味する。
func ParseWhen(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// since は経過時間を秒までで表す。未来の時刻は 0s にする。
func Since(now, t time.Time) time.Duration {
	d := now.Sub(t)
	if d < 0 {
		d = 0
	}
	return d.Truncate(time.Second)
}

func ReasonOr(reason, fallback string) string {
	if strings.TrimSpace(reason) == "" {
		return fallback
	}
	return reason
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func uniq(in []string) []string {
	out := in[:0:0]
	for i, v := range in {
		if i == 0 || in[i-1] != v {
			out = append(out, v)
		}
	}
	return out
}

// ShortID はルール ID を短く表示する(先頭 12 文字)。CLI の findRule が前方一致で受けるので
// 選択には困らない。所見の中の "wgft rule enable <id>" のような次の一手も同じ形にする。
func ShortID(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}

// ResourceRefusalTotal は、そのルールに対する Resource Guard の拒否の総数(理由を問わない)。
// design.md 7a.10 節「拒否の報告」の値で、報告を持たない Backend や、その理由でまだ 1 度も
// 拒んでいないルールでは 0 になる。`rule ls` の REFUSED 列と rule.flow_budget の検査が同じ値を
// 読むよう、この 1 つを共有する。
func ResourceRefusalTotal(refusals map[string]map[string]uint64, ruleID string) uint64 {
	var total uint64
	for _, n := range refusals[ruleID] {
		total += n
	}
	return total
}

// FlowBudgetLine は、プロセス全体のフロー予算の要約(design.md 7a.10 節)。報告を持たない
// Backend では空文字を返し、何も出さない。kernel モードは UDP を Go 側で数えないので "udp" は
// 出ない。`rule ls` の世代の行と、診断の内部の値の行が同じ文を共有する。
func FlowBudgetLine(budget map[proto.Proto]adminapi.FlowBudget) string {
	if len(budget) == 0 {
		return ""
	}
	protos := make([]proto.Proto, 0, len(budget))
	for p := range budget {
		protos = append(protos, p)
	}
	sort.Slice(protos, func(i, j int) bool { return protos[i] < protos[j] })
	parts := make([]string, 0, len(protos))
	for _, p := range protos {
		b := budget[p]
		parts = append(parts, fmt.Sprintf("%s %d/%d", p, b.InUse, b.Limit))
	}
	return "flow budget: " + strings.Join(parts, ", ")
}

// pluralS returns "s" unless n is exactly 1.
func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// entryNoun returns "entry" for n == 1 and "entries" otherwise. "entry" does not pluralize with
// pluralS's plain "s".
func entryNoun(n int) string {
	if n == 1 {
		return "entry"
	}
	return "entries"
}

// wasWere returns "was" for n == 1 and "were" otherwise, for a sentence whose subject is a count
// of things this package names with pluralS (e.g. "N connections were refused").
func wasWere(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}
