package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは `wgft server doctor`(設計文書 10.2a 節)を持つ。転送経路を公開側から自宅側へ
// 順に調べ、どこまで通ってどこで止まったか、運用者が次に何を見るかを示す。判定は既存の管理用 API
// の応答だけから行い(7a.11 節の保証を変えない)、診断は diagnose という純粋な関数に閉じてある。
// コマンドの登録は cmd/wgft/server.go(Linux の build tag)が行う。

// 検査の識別子。JSON の "id" の値であり、機械向けの保証である(設計文書 10.2a 節)。開いた集合
// として扱い、項目を増やすことだけができる。名前の変更も意味の変更も互換ではない。
const (
	checkDataplane     = "server.dataplane"
	checkEnabled       = "rule.enabled"
	checkPublicPort    = "rule.public_port"
	checkSourceFilter  = "rule.source_filter"
	checkHandshake     = "tunnel.handshake"
	checkConnection    = "agent.connection"
	checkRulesReceived = "agent.rules_received"
	checkCredentials   = "agent.credentials"
	checkTargetResolve = "rule.target_resolve"
	checkTarget        = "rule.target"
	checkFlowBudget    = "rule.flow_budget"
	checkProbe         = "rule.probe"
)

// checkOrder は検査を、公開側から自宅側への経路の順に並べたものである。最初に failed になった
// 検査が、そのルールの止まった位置になる。
var checkOrder = []string{
	checkEnabled, checkPublicPort, checkSourceFilter, checkDataplane,
	checkHandshake,
	checkConnection, checkRulesReceived, checkCredentials, checkTargetResolve, checkTarget, checkFlowBudget, checkProbe,
}

// 検査の状態。JSON の "status" の値であり、5 つだけである(設計文書 10.2a 節)。
const (
	// statusOK は、その項目が成功することを実際に観測した状態である。検証していないものに
	// 使ってはならない。
	statusOK = "ok"
	// statusFailed は、その項目が失敗することを実際に観測した状態である。
	statusFailed = "failed"
	// statusUnknown は、証拠はあるが古い、食い違う、または判定に足りない状態である。
	statusUnknown = "unknown"
	// statusNotTested は、その到達性や条件をこのコマンドがそもそも試さない状態である。
	statusNotTested = "not_tested"
	// statusSkipped は、試せたはずだが、手前の失敗によって今回は試せなかった状態である。
	statusSkipped = "skipped"
)

// 理由の符号。JSON の "reason" の値であり、機械向けの保証である。開いた集合として扱い、
// 読み手は知らない値を「不明」として扱う(設計文書 10.2a、7a.11 節)。
const (
	reasonRuleDisabled        = "rule_disabled"
	reasonBindFailed          = "bind_failed"
	reasonNotPublished        = "not_published"
	reasonGenerationBehind    = "generation_behind"
	reasonAgentNotRegistered  = "agent_not_registered"
	reasonAgentDisconnected   = "agent_disconnected"
	reasonNoRecentHandshake   = "no_recent_handshake"
	reasonTunnelError         = "tunnel_error"
	reasonDeniedByDenyList    = "denied_by_deny_list"
	reasonNotInAllowList      = "not_in_allow_list"
	reasonTargetNotAllowed    = "target_not_allowed"
	reasonListenerBindFailed  = "listener_bind_failed"
	reasonResolveFailed       = "target_resolve_failed"
	reasonConnectionRefused   = "connection_refused"
	reasonTargetTimeout       = "target_timeout"
	reasonTargetError         = "target_error"
	reasonTargetUnreachable   = "target_unreachable"
	reasonAgentUnreachable    = "agent_unreachable"
	reasonNotReported         = "not_reported"
	reasonStaleReport         = "stale_report"
	reasonRepairFailed        = "repair_failed"
	reasonResourceRefusals    = "resource_refusals"
	reasonCredentialWarning   = "credential_warning"
	reasonNotIPv4             = "not_ipv4"
	reasonNoProbe             = "no_probe"
	reasonNoFrom              = "no_source_given"
	reasonNotReportedByServer = "not_reported_by_server"
	reasonUnknownValue        = "unknown_value"
	reasonExternalNotTested   = "external_not_tested"
	reasonResolvedByAgent     = "resolved_by_agent"
)

// 検査のまとまり。人向けの出力の見出しになる。保証の対象ではない。
const (
	groupServer = "Server"
	groupTunnel = "Tunnel"
	groupAgent  = "Agent"
)

// 証拠が古くなる閾値。項目ごとに違う値を選んである(設計文書 10.2a 節)。
const (
	// heartbeatStale は、エージェントの接続の観測が古くなる長さである。エージェントは 30 秒
	// ごとにハートビートを送る(設計文書 5.2 節)ので、3 回分の沈黙を越えたら、接続していると
	// いう表示を今の値として扱わない。
	heartbeatStale = 90 * time.Second
	// handshakeStale は、最終ハンドシェイクがトンネルの健全を示さなくなる長さである。健全な
	// トンネルの最終ハンドシェイクは 145 秒以内に必ず新しくなり(設計文書 7 節)、窃取検知も
	// 3 分以内のものだけを生きていると見なす(5.2 節)ので、同じ 3 分を使う。
	//
	// 他の 2 つの閾値と違い、これを越えた値は古い証拠ではなく、今読んだ現在の観測である
	// (10.2a 節)。`tunnel.handshake` は報告ではなく、server が WireGuard から今読む値なので、
	// 越えていれば FAILED になる。受信だけが死んだトンネルを見分けられない期間も同じ長さで
	// あり、別の定数を持たない。エージェントが device と netstack を作り直す 300 秒(7 節)は
	// エージェント側の watchdog の閾値であって、診断が気付けない期間ではない。1 つの数に
	// 2 つの定数を置いたことが、両者の取り違えを生んでいた。
	handshakeStale = 3 * time.Minute
	// targetReportStale は、エージェントが報告したルールの状態が古くなる長さである。TCP の
	// target への接続確認は 30 秒ごとに行われる(設計文書 5.2 節)ので、ハートビートと同じ
	// 90 秒を越えた報告は、今の値として扱わない。
	targetReportStale = 90 * time.Second
)

// doctorReport は 1 回の診断の結果全体である。JSON はこの形で出し、人向けの出力とは別の、
// 診断そのものの模型である(設計文書 10.2a 節)。最上位をオブジェクトにしてあるのは、後から
// 項目を加えても読み手が壊れないようにするためである(7a.11 節の加算の規則)。
type doctorReport struct {
	// Status は全体の判定である。failed の検査が 1 つでもあれば failed、それ以外は ok になる。
	Status    string `json:"status"`
	CheckedAt string `json:"checked_at"` // RFC3339
	// Probed は能動的な疎通確認を行ったかどうかである。
	Probed bool `json:"probed"`
	// Checks はこの実行が行った検査すべてである。ルールに属する検査は RuleID を持つ。
	Checks []checkReport `json:"checks"`
	// Rules は検査をルールごとにまとめた索引で、Checks の要約である。
	Rules []ruleReport `json:"rules"`
	// History は、この版が履歴を持たないことを明示する(設計文書 10.2a 節)。
	History historyReport `json:"history"`
	// NotTested は、この診断が試していない範囲である。何も壊れていない実行でも必ず載せる。
	NotTested []notTested `json:"not_tested"`
}

// checkReport は 1 つの検査である。
type checkReport struct {
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
	// hideWhenOK と hideWhenUntested は、既定の表示から外す条件である。JSON には常に載せる。
	// 経路の要になる検査(公開ポート、トンネル、接続、target)はどちらも立てない。
	hideWhenOK       bool
	hideWhenUntested bool
	// offPath は、転送の経路の上に無い検査である。運用者に見せる事実ではあるが、そのルールが
	// 今転送しているかどうかを述べないので、ルールの総合判定を動かさない(設計文書 10.2a 節)。
	offPath bool
}

// ruleReport は 1 本のルールの要約である。
type ruleReport struct {
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

// historyReport は履歴の有無である。この版は現在の状態しか見ない。
type historyReport struct {
	Available bool   `json:"available"`
	Detail    string `json:"detail"`
}

// notTested は試していない範囲 1 件である。
type notTested struct {
	ID     string `json:"id"`
	Detail string `json:"detail"`
}

// probeResult は 1 本のルールに対する能動的な疎通確認の結果である。Err は管理用 API が確認
// そのものを拒んだ場合(UDP のルール、無効なルール、未登録のエージェント)に入る。
type probeResult struct {
	Check *admin.ConnCheck
	Err   error
}

// doctorInput は診断が読む証拠をまとめたものである。純粋な関数として試験できるよう、
// 管理用 API の呼び出しと分けてある。
type doctorInput struct {
	Now     time.Time
	Rules   *admin.BatchResponse
	Agents  []admin.AgentInfo
	From    netip.Addr
	HasFrom bool
	Probed  bool
	Probes  map[string]probeResult
}

func newServerDoctorCmd() *cobra.Command {
	var (
		asJSON  bool
		probe   bool
		verbose bool
		from    string
	)
	cmd := &cobra.Command{
		Use:   "doctor [rule]",
		Short: "diagnose why traffic is not getting through; VPS side, reads the admin API",
		// 引数の数の誤りも「報告を作れなかった」失敗であり、終了コード 2 で終わる(設計文書
		// 10.2a 節)。cobra の Args をそのまま渡すと、その誤りだけが包まれずに exitCode へ届き、
		// 「壊れた検査があった」の 1 と見分けが付かなくなる。
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.MaximumNArgs(1)(cmd, args); err != nil {
				return unavailable(err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			if probe && len(args) == 0 {
				return unavailable(fmt.Errorf("--probe follows one rule at a time; give a rule, or drop --probe to survey every rule"))
			}
			in := doctorInput{Now: time.Now(), Probed: probe, Probes: map[string]probeResult{}}
			if from != "" {
				addr, err := netip.ParseAddr(from)
				if err != nil {
					return unavailable(fmt.Errorf("--from %q is not an IP address: %w", from, err))
				}
				in.From, in.HasFrom = addr, true
			}
			if in.Rules, err = c.Rules(); err != nil {
				return unavailable(err)
			}
			if in.Agents, err = c.Agents(); err != nil {
				return unavailable(err)
			}
			rules := in.Rules.Rules
			single := false
			if len(args) == 1 {
				r, err := findRule(c, args[0])
				if err != nil {
					return unavailable(err)
				}
				rules, single = []proto.Rule{*r}, true
			}
			if probe {
				res, err := c.CheckConnectivity(rules[0].ID)
				in.Probes[rules[0].ID] = probeResult{Check: res, Err: err}
			}
			rep := buildReport(rules, in)
			out := cmd.OutOrStdout()
			switch {
			case asJSON:
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rep); err != nil {
					return unavailable(err)
				}
			case single:
				writeRuleReport(out, rep, verbose)
			default:
				writeSurvey(out, rep, verbose)
			}
			return doctorExit(rep)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON; the stable diagnostic model of this command")
	cmd.Flags().BoolVar(&probe, "probe", false, "also open a real TCP connection through the tunnel to the target; one rule only")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "also print the internal detail: generations, apply state, endpoints, counters")
	cmd.Flags().StringVar(&from, "from", "", "client address to evaluate the deny and allow lists against")
	cmd.Flags().String("admin", "unix:///run/wgft/admin.sock", "admin API address, env WGFT_ADMIN")
	cmd.Flags().String("config", defaultConfigPath, "dotenv config file")
	// フラグの誤りも、引数の数の誤りと同じく「報告を作れなかった」失敗である(設計文書 10.2a 節)。
	// フラグの解析は Args の検査より前に行われるので、上の Args だけでは届かない。
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return unavailable(err) })
	return cmd
}

// doctorExit は報告を終了コードに写す。failed の検査が 1 つでもあれば誤りを返し、呼び出し元の
// exitCode が 1 にする。unknown と not_tested だけでは 0 のままにする(設計文書 10.2a 節)。
func doctorExit(rep doctorReport) error {
	if rep.Status != statusFailed {
		return nil
	}
	var bad []string
	for _, r := range rep.Rules {
		if r.Status == statusFailed {
			bad = append(bad, short(r.RuleID)+": "+r.StoppedAt)
		}
	}
	if len(bad) == 0 {
		return fmt.Errorf("the server itself has a failing check")
	}
	if len(bad) == 1 {
		return fmt.Errorf("traffic stops on rule %s", bad[0])
	}
	return fmt.Errorf("traffic stops on %d of %d rules: %s", len(bad), len(rep.Rules), strings.Join(bad, ", "))
}

// buildReport は検査一式と、ルールごとの要約と、試していない範囲を組み立てる。
func buildReport(rules []proto.Rule, in doctorInput) doctorReport {
	rep := doctorReport{CheckedAt: in.Now.UTC().Format(time.RFC3339), Probed: in.Probed, Status: statusOK}
	rep.History = historyReport{Detail: "this command only evaluates the current state. To find when a rule stopped working, read the server log (journalctl -u wgft) and the agent's log."}
	for _, r := range rules {
		checks := diagnose(r, in)
		rr := ruleReport{
			RuleID: r.ID, Agent: r.Agent, Proto: string(r.Proto), ListenPort: r.ListenPort.String(),
			Target: r.TargetDisplay(), Group: r.Group, Enabled: r.Enabled, Status: statusOK,
		}
		// ルールの総合判定は、経路の上の検査だけから決める(設計文書 10.2a 節)。経路の外の
		// 検査(累積の拒否、窃取の警告)は起動からの事実を述べるだけで、今転送しているかを
		// 述べないため、要約をいつまでも下げ続けないようにする。
		for _, c := range checks {
			if c.offPath {
				continue
			}
			if c.Status == statusFailed && rr.StoppedAt == "" {
				rr.StoppedAt, rr.Status = c.ID, statusFailed
			}
		}
		if rr.Status == statusOK && anyPathStatus(checks, statusUnknown) {
			rr.Status = statusUnknown
		}
		if rr.Status == statusOK && !r.Enabled {
			rr.Status = statusSkipped
		}
		rep.Checks = append(rep.Checks, checks...)
		rep.Rules = append(rep.Rules, rr)
	}
	rep.Checks = append(rep.Checks, dataplaneCheck(in))
	for _, c := range rep.Checks {
		if c.Status == statusFailed && !c.offPath {
			rep.Status = statusFailed
		}
	}
	rep.NotTested = notTestedList(rules, in)
	return rep
}

// notTestedList は、この診断が試していない範囲を返す。何も壊れていない実行でも必ず出す。
// 黙っていると運用者が沈黙を健全と読むためである(設計文書 10.2a 節)。
func notTestedList(rules []proto.Rule, in doctorInput) []notTested {
	ports := "the rules' listen ports"
	if len(rules) == 1 {
		ports = string(rules[0].Proto) + " " + rules[0].ListenPort.String()
	}
	out := []notTested{
		{"from outside", "whether the internet reaches " + ports + " on this VPS. DNAT applies to input from outside, so the " +
			"server cannot reach its own public port from itself. Test it from another host: nc -vz <vps> <port>. Invisible here: " +
			"the provider's security group, this host's input firewall, the ISP, and, in userspace mode, a listen port inside the " +
			"ephemeral range; see docs/setup.md."},
		{"udp end to end", "a UDP rule cannot be tested end to end, because a UDP send cannot tell success. It is judged from " +
			"what the agent reports about its listener alone."},
		{"mtu", "MTU and fragmentation. A tunnel that handshakes and carries small packets can still lose large datagrams, which " +
			"reads as healthy here and as \"it works sometimes\" to the user."},
		{"under load", "rate limits, the flow budget and the connection tracking table are read at one instant; a limit reached " +
			"only under load does not appear."},
		{"the service", "the application behind the target. Every check here connects and closes without speaking the protocol, " +
			"so a port that accepts while the service refuses, is full, or is the wrong service reads as healthy."},
		{"one-way tunnel", "the first " + handshakeStale.String() + " of a tunnel that stopped receiving. Its handshake stays recent " +
			"for that long, so a check run inside that window calls it healthy."},
		// TODO(agent-doctor): point at `wgft agent doctor` once that command exists (design 10.2a).
		{"the agent host", "the agent's own environment: its OS, its permissions, its interfaces and its name resolution. This " +
			"server sees only what the heartbeat carries. To see it, read the agent's own log on that host."},
	}
	if !in.Probed {
		out = append(out, notTested{"inner path", "nothing was dialled. Add --probe to open one real TCP connection from this " +
			"server, through the tunnel and the agent, to the target."})
	}
	return out
}

// diagnose は 1 本のルールの検査を経路の順に返す。検査どうしの優先順位は設計文書 10.2a 節に
// ある。要点は 2 つである。無効なルールは宣言どおりなので skipped にとどめて下流を試さない。
// エージェントの stream が切れている間は、そのエージェントが報告した値(トンネルの状態、
// 処理済み世代、ルールの状態)を今の値として扱わず、unknown と "last:" にする(5.2 節)。
func diagnose(r proto.Rule, in doctorInput) []checkReport {
	ai := findAgentInfo(in.Agents, r.Agent)
	if !r.Enabled {
		out := []checkReport{{
			ID: checkEnabled, RuleID: r.ID, Group: groupServer, Label: "enabled", Status: statusSkipped,
			Reason: reasonRuleDisabled,
			Detail: "the rule is disabled, so nothing is forwarded; that is a declared state, not a fault",
			Next:   "enable it: wgft rule enable " + short(r.ID),
		}}
		for _, id := range checkOrder {
			if id == checkEnabled || id == checkDataplane {
				continue
			}
			out = append(out, checkReport{
				ID: id, RuleID: r.ID, Agent: agentOf(id, r), Group: checkGroup(id), Label: checkLabel(id, r),
				Status: statusSkipped, Reason: reasonRuleDisabled,
				Detail: "not tested: the rule is disabled",
				Next:   "enable it first: wgft rule enable " + short(r.ID),
				// 無効なルールの下流は、同じ 1 つの理由を 11 回繰り返すだけなので既定では
				// 出さない。--verbose では出す。
				hideWhenUntested: true,
			})
		}
		return out
	}
	return []checkReport{
		{ID: checkEnabled, RuleID: r.ID, Group: groupServer, Label: "enabled", Status: statusOK,
			Detail: "the rule is enabled", hideWhenOK: true},
		publicPortCheck(r, in),
		sourceFilterCheck(r, in),
		handshakeCheck(r, ai, in),
		connectionCheck(r, ai, in),
		rulesReceivedCheck(r, ai, in),
		credentialsCheck(r, ai),
		resolveCheck(r, ai, in),
		targetCheck(r, ai, in),
		flowBudgetCheck(r, in),
		probeCheck(r, in),
	}
}

func agentOf(id string, r proto.Rule) string {
	if checkGroup(id) == groupAgent || id == checkHandshake {
		return r.Agent
	}
	return ""
}

func checkGroup(id string) string {
	switch id {
	case checkDataplane, checkEnabled, checkPublicPort, checkSourceFilter:
		return groupServer
	case checkHandshake:
		return groupTunnel
	}
	return groupAgent
}

func checkLabel(id string, r proto.Rule) string {
	switch id {
	case checkDataplane:
		return "dataplane"
	case checkEnabled:
		return "enabled"
	case checkPublicPort:
		return "public port"
	case checkSourceFilter:
		return "source filter"
	case checkHandshake:
		return "WireGuard"
	case checkConnection:
		// "connected DEGRADED" は 1 行の中で矛盾して読めるので、状態の語ではなく対象の名前にする。
		return "control connection"
	case checkRulesReceived:
		return "rules received"
	case checkCredentials:
		return "credentials"
	case checkTargetResolve:
		return "target resolve"
	case checkTarget:
		return "target"
	case checkFlowBudget:
		return "flow budget"
	case checkProbe:
		return "end-to-end probe"
	}
	return id
}

// anyPathStatus は、経路の上の検査に want の判定があるかを返す。経路の外の検査は数えない。
func anyPathStatus(checks []checkReport, want string) bool {
	for _, c := range checks {
		if !c.offPath && c.Status == want {
			return true
		}
	}
	return false
}

func findAgentInfo(agents []admin.AgentInfo, name string) *admin.AgentInfo {
	for i := range agents {
		if agents[i].Name == name {
			return &agents[i]
		}
	}
	return nil
}

// publicPortCheck は、server がこのルールの公開ポートを扱えているかを見る。扱えていても、
// 外から届くかどうかは試していないので ok にはしない(設計文書 10.2a 節の状態の定義)。
func publicPortCheck(r proto.Rule, in doctorInput) checkReport {
	c := checkReport{ID: checkPublicPort, RuleID: r.ID, Group: groupServer, Label: "public port"}
	res := in.Rules
	if res.RuleStates == nil {
		c.Status, c.Reason = statusUnknown, reasonNotReportedByServer
		c.Detail = "this server does not report whether it serves this port"
		c.Next = "read the server log for this rule, or upgrade the server to one that reports it"
		return c
	}
	st, ok := res.RuleStates[r.ID]
	if !ok {
		c.Status, c.Reason = statusUnknown, reasonNotReported
		c.Detail = "this server reports nothing about this port"
		c.Next = "re-run after the server's next change; if it stays silent, read the server log"
		return c
	}
	c.Internal = append(c.Internal, "apply_state "+st.ApplyState)
	if st.ActiveGeneration != nil {
		c.Internal = append(c.Internal, fmt.Sprintf("published at generation %d", *st.ActiveGeneration))
	}
	c.ObservedAt = in.Now.UTC().Format(time.RFC3339)
	switch st.ApplyState {
	case admin.ApplyActive:
		c.Status, c.Reason = statusNotTested, reasonExternalNotTested
		c.Detail = fmt.Sprintf("serving %s %s; reachability from outside was not tested", r.Proto, r.ListenPort)
		if d := driftNote(r.ID, res.Drift); d != "" {
			c.Detail += "; " + d
			c.Internal = append(c.Internal, "drift: "+d)
		}
		c.Next = "test it from another host: nc -vz <this vps> " + strings.Split(r.ListenPort.String(), "-")[0]
		return c
	case admin.ApplyNotActive:
		c.Status = statusFailed
		c.Reason = reasonNotPublished
		if strings.Contains(st.Reason, "bind failed") {
			c.Reason = reasonBindFailed
		}
		c.Detail = "the server does not handle this port: " + reasonOr(st.Reason, "no reason reported")
		c.Next = applyNextStep(st.Reason)
		return c
	case admin.ApplyPending:
		c.Status, c.Reason = statusFailed, reasonNotPublished
		c.Detail = "the server has not yet published this port: " + reasonOr(firstNonEmpty(st.Reason, res.ApplyError), "the last change failed as a whole")
		c.Next = "free whatever the reason names; the server retries every 30s. Which declaration the kernel is forwarding depends on where the apply failed; check it with wgft server nft."
		return c
	}
	c.Status, c.Reason = statusUnknown, reasonUnknownValue
	c.Detail = fmt.Sprintf("the server reports a state this build does not know: %q", st.ApplyState)
	c.Next = "upgrade this CLI to the server's version"
	return c
}

// dataplaneCheck は server 全体の公開の状態を見る(設計文書 7a.3 節)。
func dataplaneCheck(in doctorInput) checkReport {
	c := checkReport{ID: checkDataplane, Group: groupServer, Label: "dataplane", ObservedAt: in.Now.UTC().Format(time.RFC3339)}
	res := in.Rules
	if res.DesiredGeneration == nil && res.ApplyError == "" && res.RuleStates == nil {
		c.Status, c.Reason = statusUnknown, reasonNotReportedByServer
		c.Detail = "this server does not report its forwarding state"
		c.Next = "read the server log; an older server reports this only there"
		return c
	}
	c.Internal = append(c.Internal, fmt.Sprintf("generation %d", res.Generation))
	if res.DesiredGeneration != nil && res.ActiveGeneration != nil {
		c.Internal = append(c.Internal, fmt.Sprintf("desired %d, active %d", *res.DesiredGeneration, *res.ActiveGeneration))
	}
	if b := flowBudgetLine(res.FlowBudget); b != "" {
		c.Internal = append(c.Internal, b)
	}
	if gap := generationGap(res); gap != "" {
		c.Status, c.Reason = statusFailed, reasonNotPublished
		c.Detail = "the last change has not reached the forwarding path: " + gap
		if res.ApplyError != "" {
			c.Detail += "; apply error: " + res.ApplyError
		}
		c.Next = "free whatever the reason names; the server retries every 30s and publishes the change when it succeeds"
		return c
	}
	if res.ApplyError != "" {
		c.Status, c.Reason = statusUnknown, reasonRepairFailed
		c.Detail = "the rules are published, but a repair after that failed: " + res.ApplyError
		c.Next = "new traffic follows the current rules; connections that should have been cut may still run. The server retries every 30s."
		return c
	}
	c.Status = statusOK
	c.Detail = fmt.Sprintf("the server's forwarding matches the current rules, generation %d, read just now", res.Generation)
	return c
}

// generationGap は desired と active の世代の食い違いを 1 文で返す。差が無ければ空文字を返す。
func generationGap(res *admin.BatchResponse) string {
	if res.DesiredGeneration == nil || res.ActiveGeneration == nil || *res.ActiveGeneration >= *res.DesiredGeneration {
		return ""
	}
	return fmt.Sprintf("it forwards generation %d while the rules are at %d", *res.ActiveGeneration, *res.DesiredGeneration)
}

// driftNote は、このルールが宣言に無いまま転送に残っているかどうかを 1 文で返す。
func driftNote(id string, d *admin.Drift) string {
	if d == nil {
		return ""
	}
	for _, x := range d.ActiveOnly {
		if x.RuleID == id {
			return "it is also still forwarding although the rules no longer ask for it"
		}
	}
	for _, x := range d.Retiring {
		if x.RuleID == id {
			return "its previous value is retiring: it takes no new connections and keeps open ones until they end"
		}
	}
	return ""
}

// applyNextStep は、server が公開できない理由に応じた次の手である。bind の失敗はユーザー空間
// モードでエフェメラルポートと衝突する形が多いので、その可能性を名指しする(docs/setup.md)。
func applyNextStep(reason string) string {
	switch {
	case strings.Contains(reason, "bind failed"):
		return "another process on this VPS holds that port. In userspace mode the server binds every listen port, and a port inside " +
			"net.ipv4.ip_local_port_range, 32768-60999 by default, can be taken by any outbound connection or its TIME_WAIT. Move the " +
			"listen port outside that range, or reserve it with net.ipv4.ip_local_reserved_ports. The server retries every 30s."
	case strings.Contains(reason, "disabled"):
		return "enable it: wgft rule enable <rule>"
	case strings.Contains(reason, "not registered") || strings.Contains(reason, "unregistered"):
		return "register an agent under that name: wgft agent join-string --name <agent>"
	}
	return "fix what the reason names; the server retries every 30s on its own"
}

// sourceFilterCheck は、--from で示された接続元がこのルールの拒否・許可リストを通るかを見る
// (設計文書 5.3 節。拒否を先に評価する)。--from が無ければ試さない。
func sourceFilterCheck(r proto.Rule, in doctorInput) checkReport {
	c := checkReport{ID: checkSourceFilter, RuleID: r.ID, Group: groupServer, Label: "source filter", hideWhenUntested: true}
	c.Internal = append(c.Internal, fmt.Sprintf("%d deny, %d allow entries", len(r.SourceDeny), len(r.SourceAllow)))
	if !in.HasFrom {
		c.Status, c.Reason = statusNotTested, reasonNoFrom
		c.Detail = fmt.Sprintf("not tested: this rule has %d deny and %d allow entries, and no client address was given", len(r.SourceDeny), len(r.SourceAllow))
		c.Next = "add --from <client address> to see whether one client would be let in"
		return c
	}
	c.ObservedAt = in.Now.UTC().Format(time.RFC3339)
	if !in.From.Is4() {
		c.Status, c.Reason = statusUnknown, reasonNotIPv4
		c.Detail = in.From.String() + " is not IPv4; this version forwards IPv4 only and drops other sources before these lists"
		c.Next = "test with the IPv4 address the client actually reaches this VPS from"
		return c
	}
	for _, p := range r.SourceDeny {
		if p.Contains(in.From) {
			c.Status, c.Reason = statusFailed, reasonDeniedByDenyList
			c.Detail = "the deny list drops " + in.From.String() + ": it is inside " + p.String()
			c.Next = fmt.Sprintf("if that is wrong: wgft rule deny rm %s %s", short(r.ID), p)
			return c
		}
	}
	if len(r.SourceAllow) > 0 {
		for _, p := range r.SourceAllow {
			if p.Contains(in.From) {
				c.Status = statusOK
				c.Detail = in.From.String() + " is let in by " + p.String() + ", evaluated just now"
				return c
			}
		}
		c.Status, c.Reason = statusFailed, reasonNotInAllowList
		c.Detail = fmt.Sprintf("the allow list holds %d entries and none covers %s, so every other client is dropped", len(r.SourceAllow), in.From)
		c.Next = fmt.Sprintf("if that is wrong: wgft rule allow add %s %s/32", short(r.ID), in.From)
		return c
	}
	c.Status = statusOK
	c.Detail = in.From.String() + " is let in: no deny entry covers it and the allow list is empty, evaluated just now"
	return c
}

// tunnelHealth is doctor's `tunnel.handshake` judgment (design.md 10.2a 節), factored out of
// handshakeCheck below so `wgft status`(status.go の agentHealthOf、design.md 10.2b 節)can share
// the exact same freshness rule (handshakeStale、3 分)for its Agents row instead of reimplementing
// it. handshakeCheck stays the only caller that turns this into a checkReport, so this extraction
// changes nothing about doctor's own output; cmd/wgft/doctor_test.go's existing coverage of
// checkHandshake still exercises this function through handshakeCheck.
func tunnelHealth(ai *admin.AgentInfo, now time.Time) (status, reason, detail, observedAt string) {
	hs, ok := parseWhen(ai.LastHandshake)
	if ok {
		observedAt = ai.LastHandshake
	}
	if !ok || now.Sub(hs) > handshakeStale {
		detail = "no WireGuard handshake with this agent has ever been observed"
		if ok {
			detail = "handshake " + since(now, hs).String() + " ago; a live tunnel renews it within 145s"
		}
		return statusFailed, reasonNoRecentHandshake, detail, observedAt
	}
	age := "handshake " + since(now, hs).String() + " ago"
	if !ai.Connected {
		return statusOK, "", age + "; the agent's own tunnel report is last:" + tunnelStateText(ai.Tunnel) + ", not a current value", observedAt
	}
	if ai.Tunnel.State == proto.StatusError {
		return statusFailed, reasonTunnelError,
			"the agent reports its tunnel in error: " + reasonOr(ai.Tunnel.Reason, "no reason reported") + "; this VPS still saw a " + age,
			observedAt
	}
	if ai.Tunnel.State != "" && ai.Tunnel.State != proto.StatusOK {
		return statusUnknown, reasonUnknownValue, age + fmt.Sprintf("; the agent reports a tunnel state this build does not know: %q", ai.Tunnel.State), observedAt
	}
	return statusOK, "", age, observedAt
}

// handshakeCheck はトンネルを見る。最終ハンドシェイクは server が WireGuard から直接読む今の
// 値なので、stream が切れていても使える。エージェント自身のトンネルの報告はハートビート由来
// なので、切れている間は今の値として扱わない(設計文書 5.2 節)。判定そのものは tunnelHealth に
// 持つ。
func handshakeCheck(r proto.Rule, ai *admin.AgentInfo, in doctorInput) checkReport {
	c := checkReport{ID: checkHandshake, RuleID: r.ID, Agent: r.Agent, Group: groupTunnel, Label: "WireGuard"}
	if ai == nil {
		c.Status, c.Reason = statusSkipped, reasonAgentNotRegistered
		c.Detail = "not tested: no agent is registered under that name, so there is no tunnel yet"
		c.Next = "register one: wgft agent join-string --name " + r.Agent
		return c
	}
	if ai.WGEndpoint != "" {
		c.Internal = append(c.Internal, "peer endpoint "+ai.WGEndpoint)
	}
	c.Internal = append(c.Internal, "agent tunnel report: "+tunnelStateText(ai.Tunnel))
	c.Status, c.Reason, c.Detail, c.ObservedAt = tunnelHealth(ai, in.Now)
	switch c.Reason {
	case reasonNoRecentHandshake:
		c.Causes = handshakeCauses()
		c.Next = handshakeNext()
	case reasonTunnelError:
		c.Next = "read that reason on the agent host; the agent retries every 30s and rebuilds the tunnel after 300s without a handshake"
	case reasonUnknownValue:
		c.Next = "upgrade this CLI to the agent's version"
	}
	return c
}

// handshakeCauses は、ハンドシェイクが無いことから切り分けられない原因である。VPS の側からは
// どれか 1 つに決められない(設計文書 10.2a 節)。
func handshakeCauses() []string {
	return []string{
		"this VPS's WireGuard UDP port does not reach the agent's network",
		"the home firewall or the ISP drops the tunnel's UDP",
		"the agent is not running, or holds a different key",
		"something between the two drops it",
	}
}

func handshakeNext() string {
	return "settle it on the agent host: check that the agent runs, that its public key matches `wgft agent ls`, and that UDP to this VPS's WireGuard port leaves the home line"
}

func tunnelStateText(t admin.TunnelStatus) string {
	if t.State == "" {
		return "nothing reported"
	}
	if t.Reason == "" {
		return t.State
	}
	return t.State + ": " + t.Reason
}

// connectionCheck はエージェントの stream を見る。stream が切れているのにハンドシェイクが
// 新しい場合は、転送は続いているが新しいルールが届かない状態として名指しする。
func connectionCheck(r proto.Rule, ai *admin.AgentInfo, in doctorInput) checkReport {
	c := checkReport{ID: checkConnection, RuleID: r.ID, Agent: r.Agent, Group: groupAgent, Label: "control connection"}
	if ai == nil {
		c.Status, c.Reason = statusFailed, reasonAgentNotRegistered
		c.Detail = fmt.Sprintf("no agent named %q is registered, so this rule has nowhere to forward to", r.Agent)
		c.Causes = []string{"its credentials were revoked", "it has never registered", "the rule names an agent that does not exist"}
		c.Next = "register one under that name: wgft agent join-string --name " + r.Agent
		return c
	}
	if ai.StreamFrom != "" {
		c.Internal = append(c.Internal, "stream from "+ai.StreamFrom)
	}
	c.Internal = append(c.Internal, "last heartbeat "+orDash(ai.LastHeartbeat))
	hb, hbOK := parseWhen(ai.LastHeartbeat)
	if hbOK {
		c.ObservedAt = ai.LastHeartbeat
	}
	if !ai.Connected {
		c.Reason = reasonAgentDisconnected
		seen := ""
		if hbOK {
			seen = ", last seen " + since(in.Now, hb).String() + " ago"
		}
		if hs, ok := parseWhen(ai.LastHandshake); ok && in.Now.Sub(hs) < handshakeStale {
			// 制御の経路だけが切れていて、トンネルは生きている状態である。この検査が測るのは
			// 制御の経路の健全さであって、転送が止まった位置ではない(設計文書 10.2a 節)。
			// stream が切れていることは確かだが、このルールが今も転送しているかどうかは、この
			// 証拠からは決まらない。failed にすると、疎通確認が実際に target まで届いた場合でも
			// 「転送はここで止まった」と報告してしまう。
			c.Status = statusUnknown
			c.Detail = "the control connection is down" + seen + "; existing traffic can still flow, but rule changes will " +
				"not arrive. The tunnel handshook " + since(in.Now, hs).String() + " ago, so the rules the agent already holds may still be forwarding"
			c.Causes = []string{
				"the control connection dropped and the agent has not reconnected yet; it backs off up to 5 minutes",
				"the agent reached this server but was rejected; see the server log",
				"this server has not yet noticed a connection that is in fact alive",
			}
			// TODO(agent-doctor): point at `wgft agent doctor` once that command exists (design 10.2a).
			c.Next = "read this server's log for this agent's control connection, and the agent's own log on its host: " +
				"journalctl -u wgft-agent, or docker logs."
			// 既に疎通確認を行った実行に「--probe を付けよ」と言わない。今やったことを勧める行は
			// 読み手にとって雑音である。
			if !in.Probed {
				c.Next += " To see whether this rule still carries traffic, add --probe."
			}
			return c
		}
		// ハンドシェイクも新しくない。転送が止まったことは `tunnel.handshake` が failed として
		// 報告し、経路の順でそちらが先に来るので、ルールはトンネルで止まる。
		c.Status = statusFailed
		c.Detail = "the agent is not connected to this server"
		if hbOK {
			c.Detail = "last seen " + since(in.Now, hb).String() + " ago"
		}
		c.Causes = []string{"the agent is not running", "it cannot reach this VPS's agent API port", "the home line or the ISP is down"}
		// TODO(agent-doctor): point at `wgft agent doctor` once that command exists (design 10.2a).
		c.Next = "on the agent host: systemctl status wgft-agent and journalctl -u wgft-agent, or docker logs for a container, " +
			"then check that it can reach this VPS's agent API port"
		return c
	}
	if !hbOK {
		c.Status, c.Reason = statusUnknown, reasonNotReported
		c.Detail = "the agent is connected but has not sent a heartbeat yet"
		c.Next = "re-run in about 30 seconds; the agent reports every 30s"
		return c
	}
	age := since(in.Now, hb)
	if age > heartbeatStale {
		c.Status, c.Reason = statusUnknown, reasonStaleReport
		c.Detail = "heartbeat " + age.String() + " ago, past the 90s at which this server stops treating it as current; the agent sends one every 30s"
		c.Next = "re-run this command; if the heartbeat stays old, read the agent's log"
		return c
	}
	c.Status = statusOK
	c.Detail = "heartbeat " + age.String() + " ago"
	return c
}

// rulesReceivedCheck は、そのエージェントが今のルール集合を持っているかを見る。ルールを別の
// エージェントへ移した直後は、移った先がまだ受け取っていない状態として出る。
func rulesReceivedCheck(r proto.Rule, ai *admin.AgentInfo, in doctorInput) checkReport {
	c := checkReport{ID: checkRulesReceived, RuleID: r.ID, Agent: r.Agent, Group: groupAgent, Label: "rules received"}
	if ai == nil {
		c.Status, c.Reason = statusSkipped, reasonAgentNotRegistered
		c.Detail = "not tested: no agent is registered under that name"
		c.Next = "register one: wgft agent join-string --name " + r.Agent
		return c
	}
	cur := in.Rules.Generation
	c.Internal = append(c.Internal, fmt.Sprintf("agent generation %d, server generation %d", ai.Generation, cur))
	if !ai.Connected {
		c.Status, c.Reason = statusUnknown, reasonStaleReport
		c.ObservedAt = ai.LastHeartbeat
		c.Detail = fmt.Sprintf("last: it held rule set %d before it went away; this server now serves %d", ai.Generation, cur)
		c.Next = "the control connection line above says what to do; this value is history"
		return c
	}
	c.ObservedAt = ai.LastHeartbeat
	if ai.Generation == cur {
		c.Status = statusOK
		c.Detail = fmt.Sprintf("it holds rule set %d, this server's current one%s", cur, heartbeatAgeSuffix(ai, in))
		return c
	}
	c.Status, c.Reason = statusFailed, reasonGenerationBehind
	c.Detail = fmt.Sprintf("it still holds rule set %d while this server serves %d, so this rule has not reached it", ai.Generation, cur)
	c.Causes = []string{
		"the new rules are in flight and will be applied in a moment",
		"the agent is connected but is not applying them; see its log",
	}
	c.Next = "re-run in a few seconds; if it stays behind, read the agent's log. A rule moved to another agent carries no traffic until that agent takes the new rule set."
	return c
}

func heartbeatAgeSuffix(ai *admin.AgentInfo, in doctorInput) string {
	if hb, ok := parseWhen(ai.LastHeartbeat); ok {
		return ", as of its heartbeat " + since(in.Now, hb).String() + " ago"
	}
	return ""
}

// credentialsCheck は窃取検知の警告である(設計文書 5.2 節)。往復も食い違いも、第三者と
// ローミングを見分けられないので、警告があるときは unknown にする。
func credentialsCheck(r proto.Rule, ai *admin.AgentInfo) checkReport {
	c := checkReport{ID: checkCredentials, RuleID: r.ID, Agent: r.Agent, Group: groupAgent, Label: "credentials", hideWhenOK: true, offPath: true}
	if ai == nil {
		c.Status, c.Reason = statusSkipped, reasonAgentNotRegistered
		c.Detail = "not tested: no agent is registered under that name"
		c.Next = "register one: wgft agent join-string --name " + r.Agent
		return c
	}
	if len(ai.Warnings) == 0 {
		c.Status = statusOK
		c.Detail = "no open warning that these credentials are used from two places"
		return c
	}
	kinds := make([]string, 0, len(ai.Warnings))
	latest := ""
	for _, w := range ai.Warnings {
		kinds = append(kinds, w.Kind)
		if w.At > latest {
			latest = w.At
		}
	}
	sort.Strings(kinds)
	c.Status, c.Reason, c.ObservedAt = statusUnknown, reasonCredentialWarning, latest
	c.Detail = fmt.Sprintf("%d open warning%s that these credentials are used from two places: %s. They do not stop traffic",
		len(ai.Warnings), pluralS(len(ai.Warnings)), strings.Join(uniq(kinds), ", "))
	c.Causes = []string{"someone else holds the same credentials", "one agent moves between two lines and came back"}
	c.Next = "wgft agent warnings; dismiss it if the move was yours, revoke the agent if it was not"
	return c
}

// resolveCheck は target のホスト名の解決である。server は解決そのものを観測できず、失敗は
// エージェントの理由の文字列の中にしか現れない(設計文書 10.2a 節)。IP リテラルの target には
// 解決が無いので ok にする。
func resolveCheck(r proto.Rule, ai *admin.AgentInfo, in doctorInput) checkReport {
	c := checkReport{ID: checkTargetResolve, RuleID: r.ID, Agent: r.Agent, Group: groupAgent, Label: "target resolve"}
	host, _, err := net.SplitHostPort(r.Target)
	if err != nil {
		host = r.Target
	}
	if _, perr := netip.ParseAddr(host); perr == nil {
		c.Status = statusOK
		c.Detail = "the target is a literal address, so there is no name to resolve"
		c.hideWhenOK = true
		return c
	}
	if ai == nil {
		c.Status, c.Reason = statusSkipped, reasonAgentNotRegistered
		c.Detail = "not tested: no agent is registered under that name"
		c.Next = "register one: wgft agent join-string --name " + r.Agent
		return c
	}
	st, fresh := freshAgentRuleReport(r, in)
	switch {
	case fresh && st.State == proto.StatusError && looksLikeResolveFailure(st.Reason):
		c.Status, c.Reason, c.ObservedAt = statusFailed, reasonResolveFailed, st.At
		c.Detail = "the agent could not resolve " + host + ": " + st.Reason
		c.Next = "fix name resolution on the agent host, or point the rule at a literal address"
	case fresh && st.State == proto.StatusOK && r.Proto == proto.TCP:
		// TCP のルールが ok であることは、エージェントが target への接続を開けたことを意味する
		// (5.2 節)。名前への接続は解決を経るので、その時点で解決が成功したことを観測している。
		// UDP には同じことが言えない。UDP の ok はリスナーを開けたことしか意味せず、解決を伴わない。
		c.Status, c.ObservedAt = statusOK, st.At
		age, ok := reportAge(st.At, in.Now)
		c.Detail = "the agent resolved " + host + " and connected to it at its last check"
		if ok {
			c.Detail += " " + age.String() + " ago"
		}
		c.hideWhenOK = true
	default:
		// 証拠がまったく無い。server はエージェントの名前解決を観測しないので、判定に足りない
		// 古い証拠ではなく、そもそも試していない条件として扱う(10.2a 節の状態の定義)。
		c.Status, c.Reason = statusNotTested, reasonResolvedByAgent
		c.Detail = "not tested: the agent resolves " + host + " itself and this server never observes the result; only a failure reaches it, inside the reason on the target line below"
		// TODO(agent-doctor): point at `wgft agent doctor` once that command exists (design 10.2a).
		c.Next = "to see resolution itself, resolve " + host + " on the agent host, and read the agent's log for what it " +
			"reports about this rule"
	}
	return c
}

// freshAgentRuleReport は、このルールについてエージェントが今報告している内容である。接続中で、
// かつ targetReportStale より新しい報告だけを今の値として返す(設計文書 5.2、10.2a 節)。
// 鮮度の規則そのものは freshAgentRuleStatus に切り出してあり、`wgft status`(status.go の
// rulesStatusOf)もこの版から同じ規則を共有する(design.md 10.2b 節)。
func freshAgentRuleReport(r proto.Rule, in doctorInput) (admin.AgentRuleStatus, bool) {
	return freshAgentRuleStatus(in.Rules.AgentRuleStates[r.ID], in.Now)
}

// freshAgentRuleStatus は、1 件の agent_rule_states の項目が「今の値」として使えるかどうかを
// 判定する(設計文書 5.2、10.2a、10.2b 節)。接続中(Connected)であること、State が空でない
// こと(まだ 1 度も報告していない項目と区別する)、報告の時刻が targetReportStale より新しい
// ことの 3 つをすべて満たす場合だけ、その値をそのまま返す。1 つでも欠ければ、ゼロ値と false を
// 返す。ゼロ値の st(agent_rule_states にその行が無い呼び出し元も渡せる)を渡しても、Connected
// が false かつ State が空なので、この関数はそのまま false を返す。
func freshAgentRuleStatus(st admin.AgentRuleStatus, now time.Time) (admin.AgentRuleStatus, bool) {
	if !st.Connected || st.State == "" {
		return admin.AgentRuleStatus{}, false
	}
	age, ok := reportAge(st.At, now)
	if !ok || age > targetReportStale {
		return admin.AgentRuleStatus{}, false
	}
	return st, true
}

// looksLikeResolveFailure は、エージェントの理由が名前解決の失敗かどうかを見る。Go の net が
// 返す文言に依る判定なので確実ではない。外したときは決めつけず、target の誤りとして扱う。
func looksLikeResolveFailure(reason string) bool {
	for _, m := range []string{"no such host", "lookup ", "server misbehaving", "name resolution"} {
		if strings.Contains(reason, m) {
			return true
		}
	}
	return false
}

// targetCheck は、そのルールの持ち主のエージェント自身の報告である(設計文書 5.2、7a.11 節の
// agent_rule_states)。stream が切れている間の報告は履歴であり、今の原因として示してはならない
// ので unknown と "last:" にする。報告が 90 秒より古い場合も今の値として扱わない。この鮮度の
// 判定そのものは freshAgentRuleStatus と共有する。state・Connected・報告の有無で文言を出し
// 分ける場合分けは、この関数に残す(2026-09-22 の改訂まではここに同じ鮮度の条件を別のインライン
// のコードとして持っており、freshAgentRuleStatus を直しても追随しなかった。レビューの指摘)。
func targetCheck(r proto.Rule, ai *admin.AgentInfo, in doctorInput) checkReport {
	c := checkReport{ID: checkTarget, RuleID: r.ID, Agent: r.Agent, Group: groupAgent, Label: "target"}
	states := in.Rules.AgentRuleStates
	if states == nil {
		c.Status, c.Reason = statusUnknown, reasonNotReportedByServer
		c.Detail = "this server does not report what the agent says about each rule"
		c.Next = "wgft agent ls shows the same information for an older server"
		return c
	}
	st, ok := states[r.ID]
	if !ok {
		c.Status, c.Reason = statusUnknown, reasonNotReported
		c.Detail = "this server reports nothing the agent said about this rule"
		c.Next = "wgft agent ls shows what that agent last reported"
		return c
	}
	c.Internal = append(c.Internal, "agent_rule_states: state "+orDash(st.State)+", connected "+fmt.Sprint(st.Connected)+", at "+orDash(st.At))
	c.ObservedAt = st.At
	if !st.Connected {
		c.Status, c.Reason = statusUnknown, reasonStaleReport
		if st.State == "" {
			c.Detail = "last: the agent never reported this rule before it went away, so there is nothing to read"
		} else {
			c.Detail = "last: the agent reported " + agentStateText(st) + " before it went away; that is history, not the current cause"
		}
		c.Next = "the control connection line above says what to do; this value is not current"
		return c
	}
	if st.State == "" {
		c.Status, c.Reason = statusUnknown, reasonNotReported
		c.Detail = "the agent is connected but has not reported this rule yet"
		c.Next = "re-run in about 30 seconds; the agent reports every 30s, and at once after taking new rules"
		return c
	}
	reportAge, ageOK := reportAge(st.At, in.Now)
	// fresh は、この st がすでに Connected と State を満たしていることを前提に、報告の時刻だけを
	// freshAgentRuleStatus と同じ規則で判定する。呼び出す前に Connected・State を確かめ済みなので、
	// freshAgentRuleStatus の最初の条件は必ず通り、結果は下の ageOK・reportAge の計算と揃う。
	_, fresh := freshAgentRuleStatus(st, in.Now)
	switch st.State {
	case proto.StatusOK:
		if !fresh {
			c.Status, c.Reason = statusUnknown, reasonStaleReport
			c.Detail = "the agent last reported this rule ok, but that was " + staleAgeText(reportAge, ageOK) + ", so it is not a current observation"
			c.Next = "re-run this command; if the report stays old, read the control connection line above and the agent's log"
			return c
		}
		c.Status = statusOK
		if r.Proto == proto.TCP {
			c.Detail = "the agent reached " + r.TargetDisplay() + ", last check " + reportAge.String() + " ago, repeated every 30s"
		} else {
			c.Detail = "the agent has its listener open, last report " + reportAge.String() + " ago; for UDP that is all it can tell, since a send cannot prove the target answers"
		}
		return c
	case proto.StatusError:
		if !fresh {
			c.Status, c.Reason = statusUnknown, reasonStaleReport
			c.Detail = "the agent last reported an error on this rule: " + reasonOr(st.Reason, "no reason") + ", but that was " + staleAgeText(reportAge, ageOK) + ", so it is not a current observation"
			c.Next = "re-run this command; if the report stays old, read the control connection line above and the agent's log"
			return c
		}
		c.Status, c.Reason = statusFailed, targetReasonCode(st.Reason)
		c.Detail = "the agent could not use this rule: " + reasonOr(st.Reason, "no reason reported") + ", last check " + reportAge.String() + " ago"
		c.Next = agentRuleNextStep(st.Reason, r)
		return c
	}
	c.Status, c.Reason = statusUnknown, reasonUnknownValue
	c.Detail = fmt.Sprintf("the agent reports a state this build does not know: %q", st.State)
	c.Next = "upgrade this CLI to the agent's version"
	return c
}

func staleAgeText(age time.Duration, ok bool) string {
	if !ok {
		return "at an unknown time"
	}
	return age.String() + " ago"
}

func reportAge(at string, now time.Time) (time.Duration, bool) {
	t, ok := parseWhen(at)
	if !ok {
		return 0, false
	}
	return since(now, t), true
}

// targetReasonCode は、エージェントの人が読む理由を機械向けの符号に写す。文言に依る判定なので、
// 当てはまらないものは target_error にまとめる。符号は増やせるが、意味は変えない。
func targetReasonCode(reason string) string {
	switch {
	case strings.Contains(reason, allowtargets.Env) || strings.Contains(reason, "is not allowed"):
		return reasonTargetNotAllowed
	case strings.Contains(reason, "bind failed"):
		return reasonListenerBindFailed
	case looksLikeResolveFailure(reason):
		return reasonResolveFailed
	case strings.Contains(reason, "connection refused"):
		return reasonConnectionRefused
	case strings.Contains(reason, "timeout") || strings.Contains(reason, "timed out"):
		return reasonTargetTimeout
	case strings.Contains(reason, "no route to host") || strings.Contains(reason, "unreachable"):
		return reasonTargetUnreachable
	}
	return reasonTargetError
}

func agentStateText(st admin.AgentRuleStatus) string {
	if st.State == proto.StatusOK || st.Reason == "" {
		return st.State
	}
	return st.State + ": " + st.Reason
}

// agentRuleNextStep は、エージェントが返した理由に応じた次の手である。
func agentRuleNextStep(reason string, r proto.Rule) string {
	switch targetReasonCode(reason) {
	case reasonTargetNotAllowed:
		return "the agent refuses this target itself: " + allowtargets.Env + " on the agent host does not list it. Add the target there, or point the rule elsewhere."
	case reasonListenerBindFailed:
		return "the agent could not open its listener for this port. Find what else on the agent host binds it; the agent retries every 30s."
	case reasonResolveFailed:
		return "fix name resolution on the agent host, or point the rule at a literal address"
	}
	return "the tunnel and the agent are healthy up to this point. Check that a service is listening on " + r.TargetDisplay() +
		" and accepts connections from the agent host; the agent retries every 30s and clears the error on its own."
}

// flowBudgetCheck は Resource Guard の拒否である(設計文書 7a.10 節)。累積の値なので、拒否が
// あっても今そうであるとは言えず、unknown にする。
func flowBudgetCheck(r proto.Rule, in doctorInput) checkReport {
	c := checkReport{ID: checkFlowBudget, RuleID: r.ID, Group: groupAgent, Label: "flow budget", hideWhenOK: true, hideWhenUntested: true, offPath: true}
	res := in.Rules
	if res.ResourceRefusals == nil && res.FlowBudget == nil {
		c.Status, c.Reason = statusUnknown, reasonNotReportedByServer
		c.Detail = "this server does not report its flow budget"
		c.Next = "wgft rule ls shows the counters an older server does report"
		return c
	}
	refused := resourceRefusalTotal(res.ResourceRefusals, r.ID)
	if b := flowBudgetLine(res.FlowBudget); b != "" {
		c.Internal = append(c.Internal, b)
	}
	c.Internal = append(c.Internal, fmt.Sprintf("refused %d, dropped %d since the server started", refused, res.Drops[r.ID]))
	c.ObservedAt = in.Now.UTC().Format(time.RFC3339)
	if refused == 0 {
		c.Status = statusOK
		c.Detail = "no connection on this rule has been refused for want of wgft's own resources since the server started"
		return c
	}
	c.Status, c.Reason = statusUnknown, reasonResourceRefusals
	c.Detail = fmt.Sprintf("%d connections on this rule were refused for want of wgft's own resources since the server started; that is a total, and this command cannot tell whether it is happening now", refused)
	c.Next = "if that is recent, raise WGFT_MAX_TCP_FLOWS / WGFT_MAX_UDP_FLOWS on this server, or look for a flood holding connections open"
	return c
}

// probeCheck は能動的な疎通確認の結果である(設計文書 10.1 節の疎通確認)。--probe が無ければ
// 何も試していないことをそのまま出す。
func probeCheck(r proto.Rule, in doctorInput) checkReport {
	c := checkReport{ID: checkProbe, RuleID: r.ID, Agent: r.Agent, Group: groupAgent, Label: "end-to-end probe", hideWhenUntested: true}
	p, ok := in.Probes[r.ID]
	if !ok {
		c.Status, c.Reason = statusNotTested, reasonNoProbe
		c.Detail = "nothing was dialled"
		c.Next = "add --probe to open one real TCP connection from this server, through the tunnel and the agent, to the target"
		return c
	}
	c.ObservedAt = in.Now.UTC().Format(time.RFC3339)
	if p.Err != nil {
		c.Status, c.Reason = statusUnknown, reasonNotReported
		c.Detail = "the server declined to dial: " + p.Err.Error()
		c.Next = "read the target line above; it carries what the agent itself found"
		if r.Proto == proto.UDP {
			c.Status, c.Reason = statusNotTested, reasonNoProbe
			c.Detail = "a UDP rule cannot be dialled end to end, because a UDP send cannot tell success: " + p.Err.Error()
			c.Next = "judge a UDP rule from the target line above, and confirm the service from a real client"
		}
		return c
	}
	if p.Check == nil {
		c.Status, c.Reason = statusUnknown, reasonNotReported
		c.Detail = "the server returned no result"
		c.Next = "re-run with --verbose, and read the server log"
		return c
	}
	c.Internal = append(c.Internal, "reach "+p.Check.Reach+": "+p.Check.Detail)
	switch p.Check.Reach {
	case "target":
		c.Status = statusOK
		c.Detail = "connected to " + r.TargetDisplay() + " through the tunnel and the agent, observed just now. It was closed without speaking the protocol, so it does not prove the service itself is healthy"
		return c
	case "agent":
		c.Status, c.Reason = statusFailed, reasonTargetUnreachable
		c.Detail = "the connection reached the agent, but the agent could not reach " + r.TargetDisplay() + ": " + p.Check.Detail
		c.Next = "the tunnel and the agent are healthy. Check that a service is listening on " + r.TargetDisplay() + " and lets the agent host in."
		return c
	case "none":
		c.Status, c.Reason = statusFailed, reasonAgentUnreachable
		c.Detail = "the connection did not reach the agent's listener through the tunnel: " + p.Check.Detail
		c.Causes = []string{"the tunnel is down", "the agent has not opened this listener", "the agent is not running"}
		c.Next = "read the WireGuard and connected lines above; they name which of the three it is"
		return c
	}
	c.Status, c.Reason = statusUnknown, reasonUnknownValue
	c.Detail = fmt.Sprintf("the server reported a result this build does not know: %q, detail %s", p.Check.Reach, p.Check.Detail)
	c.Next = "upgrade this CLI to the server's version"
	return c
}

// --- 人向けの出力 ---

// displayStatus は 1 つの検査を人向けの語にする。1 か所だけ、JSON の値と画面の語が意図して
// 食い違う(設計文書 10.2a 節)。制御の経路が切れていてトンネルが生きている状態は、JSON では
// unknown と `agent_disconnected` のままだが、画面には DEGRADED と出す。この状態は「判定に
// 足りない」のではなく「運用として劣化している」と読むほうが人には正確であり、終了コードが 0 で
// あっても出力が黙らないためである。機械はあくまで status と reason を読む。
//
// 条件はこの 1 つだけに絞る。他の unknown は UNKNOWN のまま出す。
func displayStatus(c checkReport) string {
	if c.ID == checkConnection && c.Status == statusUnknown && c.Reason == reasonAgentDisconnected {
		return "DEGRADED"
	}
	return statusWord(c.Status)
}

// statusWord は判定を人向けの語にする。表そのものは保証の対象ではない(設計文書 7a.11 節)。
func statusWord(s string) string {
	switch s {
	case statusOK:
		return "OK"
	case statusFailed:
		return "FAILED"
	case statusUnknown:
		return "UNKNOWN"
	case statusNotTested:
		return "NOT TESTED"
	case statusSkipped:
		return "SKIPPED"
	}
	return s
}

// 人向けの出力の桁。表そのものは保証の対象ではない(設計文書 7a.11 節)。
const (
	labelWidth  = 18
	statusWidth = 11
	// inlineDetail は、判定の右にそのまま出せる detail の長さである。これを超える detail は
	// 次の行へ回し、判定の桁に揃える。
	inlineDetail = 46
)

// writeLine は 1 つの検査を出す。短い detail は判定の右に、長い detail は次の行に出す。
func writeLine(w io.Writer, label, status, detail string) {
	indent := 2 + labelWidth + 1
	if detail != "" && len(detail) <= inlineDetail {
		fmt.Fprintf(w, "  %-*s %-*s%s\n", labelWidth, label, statusWidth, status, detail)
		return
	}
	fmt.Fprintf(w, "  %-*s %s\n", labelWidth, label, status)
	if detail != "" {
		fmt.Fprintf(w, "%s%s\n", strings.Repeat(" ", indent), wrapAt(detail, indent))
	}
}

// hidden は、その検査を既定の表示から外すかどうかである。--verbose ではすべて出す。
func hidden(c checkReport, verbose bool) bool {
	if verbose {
		return false
	}
	if c.Status == statusOK && c.hideWhenOK {
		return true
	}
	return (c.Status == statusNotTested || c.Status == statusSkipped) && c.hideWhenUntested
}

// writeRuleReport は 1 本のルールの経路を、まとまりごとに出す。
func writeRuleReport(w io.Writer, rep doctorReport, verbose bool) {
	indent := 2 + labelWidth + 1
	for _, rr := range rep.Rules {
		name := short(rr.RuleID)
		if rr.Group != "" {
			name += ", group " + rr.Group
		}
		fmt.Fprintf(w, "%s  %s %s to %s\n\n", name, rr.Proto, rr.ListenPort, rr.Target)
		group := ""
		for _, c := range checksOfRule(rep, rr.RuleID) {
			if hidden(c, verbose) {
				continue
			}
			g := c.Group
			if g == groupAgent {
				g = fmt.Sprintf("Agent %q", rr.Agent)
			}
			if g != group {
				fmt.Fprintln(w, g)
				group = g
			}
			writeLine(w, c.Label, displayStatus(c), c.Detail)
			for _, cause := range c.Causes {
				fmt.Fprintf(w, "%s- %s\n", strings.Repeat(" ", indent), wrapAt(cause, indent+2))
			}
			if c.Next != "" && (c.Status != statusOK || verbose) {
				fmt.Fprintf(w, "%sCheck: %s\n", strings.Repeat(" ", indent), wrapAt(c.Next, indent+7))
			}
			writeInternal(w, c.Internal, verbose, indent)
		}
		fmt.Fprintln(w)
		switch rr.Status {
		case statusFailed:
			fmt.Fprintf(w, "Result: traffic stops at %q\n", checkLabelOf(rep, rr.RuleID, rr.StoppedAt))
		case statusSkipped:
			fmt.Fprintln(w, "Result: the rule is disabled, so nothing is forwarded")
		case statusUnknown:
			fmt.Fprintln(w, "Result: no failure found, but some evidence above is stale or untested")
		default:
			fmt.Fprintln(w, "Result: healthy as far as this command can see")
		}
	}
	writeHistory(w, rep)
	writeNotTested(w, rep)
}

func checksOfRule(rep doctorReport, ruleID string) []checkReport {
	var out []checkReport
	for _, c := range rep.Checks {
		if c.ID == checkDataplane || c.RuleID == ruleID {
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

func writeInternal(w io.Writer, lines []string, verbose bool, indent int) {
	if !verbose {
		return
	}
	for _, v := range lines {
		fmt.Fprintf(w, "%s[%s]\n", strings.Repeat(" ", indent), v)
	}
}

func checkLabelOf(rep doctorReport, ruleID, id string) string {
	for _, c := range rep.Checks {
		if c.ID == id && (c.RuleID == ruleID || c.RuleID == "") {
			return c.Label
		}
	}
	return id
}

func checkDetailOf(rep doctorReport, ruleID, id string) string {
	for _, c := range rep.Checks {
		if c.ID == id && (c.RuleID == ruleID || c.RuleID == "") {
			return c.Detail
		}
	}
	return ""
}

// writeSurvey は server、エージェント、全ルールを短く出す。
func writeSurvey(w io.Writer, rep doctorReport, verbose bool) {
	indent := 2 + labelWidth + 1
	dp := checkReport{}
	for _, c := range rep.Checks {
		if c.ID == checkDataplane {
			dp = c
		}
	}
	fmt.Fprintln(w, "Server")
	writeLine(w, dp.Label, displayStatus(dp), dp.Detail)
	if dp.Status != statusOK && dp.Next != "" {
		fmt.Fprintf(w, "%sCheck: %s\n", strings.Repeat(" ", indent), wrapAt(dp.Next, indent+7))
	}
	writeInternal(w, dp.Internal, verbose, indent)

	fmt.Fprintln(w, "\nAgents")
	agents := agentLines(rep)
	if len(agents) == 0 {
		fmt.Fprintln(w, "  no agent is named by any rule")
	}
	for _, a := range agents {
		writeLine(w, a.Label, displayStatus(a), a.Detail)
		if a.Status != statusOK && a.Next != "" {
			fmt.Fprintf(w, "%sCheck: %s\n", strings.Repeat(" ", indent), wrapAt(a.Next, indent+7))
		}
		writeInternal(w, a.Internal, verbose, indent)
	}

	fmt.Fprintln(w, "\nRules")
	if len(rep.Rules) == 0 {
		fmt.Fprintln(w, "  none")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, rr := range rep.Rules {
			why := "-"
			if rr.StoppedAt != "" {
				why = "stops at " + checkLabelOf(rep, rr.RuleID, rr.StoppedAt) + ": " + firstClause(checkDetailOf(rep, rr.RuleID, rr.StoppedAt))
			} else if rr.Status == statusUnknown || rr.Status == statusSkipped {
				why = firstClause(firstNotOKDetail(rep, rr.RuleID))
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s %s\t%s\t%s\n", statusWord(rr.Status), short(rr.RuleID), rr.Proto, rr.ListenPort, rr.Agent, why)
		}
		tw.Flush()
	}

	fmt.Fprintln(w)
	if rep.Status == statusFailed {
		fmt.Fprintf(w, "Result: %d of %d rules not carrying traffic\n", countStatus(rep.Rules, statusFailed), len(rep.Rules))
	} else {
		fmt.Fprintln(w, "Result: no failing check")
	}
	fmt.Fprintln(w, "\nrun `wgft server doctor <rule>` to follow one rule end to end")
	writeHistory(w, rep)
	writeNotTested(w, rep)
}

// agentLines は、報告に現れるエージェントごとに 1 行ぶんの要約を作る。エージェントの接続の
// 検査をそのまま使い、同じ判定を 2 か所で作らない。
func agentLines(rep doctorReport) []checkReport {
	seen := map[string]bool{}
	var out []checkReport
	for _, c := range rep.Checks {
		if c.ID != checkConnection || c.Agent == "" || seen[c.Agent] {
			continue
		}
		seen[c.Agent] = true
		c.Label = c.Agent
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Agent < out[j].Agent })
	return out
}

func firstNotOKDetail(rep doctorReport, ruleID string) string {
	for _, c := range checksOfRule(rep, ruleID) {
		if c.Status == statusUnknown || c.Status == statusSkipped {
			return c.Label + ": " + c.Detail
		}
	}
	return ""
}

func countStatus(rules []ruleReport, want string) int {
	n := 0
	for _, r := range rules {
		if r.Status == want {
			n++
		}
	}
	return n
}

func writeHistory(w io.Writer, rep doctorReport) {
	fmt.Fprintln(w, "\nHistory")
	writeLine(w, "when it broke", "NOT AVAILABLE", "")
	fmt.Fprintf(w, "%s%s\n", strings.Repeat(" ", 2+labelWidth+1), wrapAt(rep.History.Detail, 2+labelWidth+1))
}

func writeNotTested(w io.Writer, rep doctorReport) {
	fmt.Fprintln(w, "\nNot tested by this command")
	for _, n := range rep.NotTested {
		fmt.Fprintf(w, "  %-16s %s\n", n.ID, wrapAt(n.Detail, 19))
	}
}

// firstClause は 1 行に収まるよう、最初の句だけを返す。
func firstClause(s string) string {
	for _, sep := range []string{". ", "; ", ", which", " (the "} {
		if i := strings.Index(s, sep); i > 0 {
			s = s[:i]
		}
	}
	if len(s) > 58 {
		s = s[:57] + "…"
	}
	return s
}

// wrapAt は、indent 文字ぶん字下げした桁に折り返した本文を返す。1 行目の字下げは呼び出し元が出す。
func wrapAt(s string, indent int) string {
	const width = 96
	limit := width - indent
	if limit < 20 {
		limit = 20
	}
	var out []string
	line := ""
	for _, word := range strings.Fields(s) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= limit:
			line += " " + word
		default:
			out = append(out, line)
			line = word
		}
	}
	if line != "" {
		out = append(out, line)
	}
	return strings.Join(out, "\n"+strings.Repeat(" ", indent))
}

// --- 小さな補助 ---

// parseWhen は管理用 API の RFC3339 のタイムスタンプを読む。観測していない値はフィールドごと
// 省かれる(設計文書 7a.11 節)ので、空文字は「観測していない」を意味する。
func parseWhen(s string) (time.Time, bool) {
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
func since(now, t time.Time) time.Duration {
	d := now.Sub(t)
	if d < 0 {
		d = 0
	}
	return d.Truncate(time.Second)
}

func reasonOr(reason, fallback string) string {
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
