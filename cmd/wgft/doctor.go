package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/textsafe"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは `wgft server doctor`(設計文書 10.2a 節)のコマンドと、その人向けの出力を持つ。
// 判定そのものは internal/vpsd/doctor にあり、Web UI の診断の画面(10.2d 節)と共有する。この
// ファイルに残るのは、コマンドの組み立て、終了コードへの写し、端末の桁に合わせた表示である。
// コマンドの登録は cmd/wgft/server.go(Linux の build tag)が行う。

// 判定の型と語は internal/vpsd/doctor が持つ。ここでは切り出しの前と同じ名前で参照できるよう
// 別名を置く。`wgft agent doctor`(10.2c 節)の出力もこの名前の一部を使う(agentdoctor.go)。
type (
	// checkReport は 1 つの検査である。
	checkReport = doctor.Check
	// doctorReport は 1 回の診断の結果全体であり、--json はこの形で出す。
	doctorReport = doctor.Report
	// doctorInput は診断が読む証拠一式である。
	doctorInput = doctor.Input
	// probeResult は 1 本のルールに対する能動的な疎通確認の結果である。
	probeResult = doctor.ProbeResult
	// ruleReport は 1 本のルールの要約である。
	ruleReport = doctor.RuleReport
)

// 検査の状態(設計文書 10.2a 節の 5 つ)。
const (
	statusOK        = doctor.StatusOK
	statusFailed    = doctor.StatusFailed
	statusUnknown   = doctor.StatusUnknown
	statusNotTested = doctor.StatusNotTested
	statusSkipped   = doctor.StatusSkipped
)

// checkDataplane は server 全体の検査、groupAgent はエージェントのまとまりである。人向けの
// 出力だけがこの 2 つを名指しする。
const (
	checkDataplane = doctor.CheckDataplane
	groupAgent     = doctor.GroupAgent
)

// notTested は試していない範囲 1 件である。判定が返す doctor.NotTested と同じ形だが、この
// package の型として残してある。`wgft agent doctor`(10.2c 節)が同じ writeNotTested に自分で
// 組み立てた一覧を渡すためである(agentdoctor.go)。
type notTested struct {
	ID     string
	Detail string
}

// notTestedLines は、判定が返す試していない範囲をその型に写す。
func notTestedLines(items []doctor.NotTested) []notTested {
	out := make([]notTested, 0, len(items))
	for _, n := range items {
		out = append(out, notTested{ID: n.ID, Detail: n.Detail})
	}
	return out
}

// buildReport は証拠から報告を組み立てる(internal/vpsd/doctor)。
var buildReport = doctor.BuildReport

// statusWord、displayStatus、hidden、checksOfRule、agentLines は判定の見せ方であり、Web UI の
// 画面と共有する(設計文書 10.2d 節)。ここは名前を保つための呼び出しだけを置く。
func statusWord(s string) string { return doctor.StatusWord(s) }

func displayStatus(c checkReport) string { return doctor.DisplayStatus(c) }

func hidden(c checkReport, verbose bool) bool { return c.Hidden(verbose) }

func checksOfRule(rep doctorReport, ruleID string) []checkReport { return rep.ChecksOf(ruleID) }

func agentLines(rep doctorReport) []checkReport { return rep.AgentSummaries() }

// parseWhen と since は、この package の他の出力(status.go)も同じ規則で時刻を読むための
// 呼び出しである。
func parseWhen(s string) (time.Time, bool) { return doctor.ParseWhen(s) }

func since(now, t time.Time) time.Duration { return doctor.Since(now, t) }
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
			// --from は証拠を読む前に解釈する。読めない値は、管理用 API が応答するかどうかに
			// 関わらず、報告を作れなかった失敗として同じ終了コードで止まる(設計文書 10.2a 節)。
			var source netip.Addr
			hasSource := false
			if from != "" {
				addr, err := netip.ParseAddr(from)
				if err != nil {
					return unavailable(fmt.Errorf("--from %q is not an IP address: %w", from, err))
				}
				source, hasSource = addr, true
			}
			// 証拠の読み取りは Web UI と同じ経路を通る(設計文書 10.2d 節)。*admin.Client が
			// そのまま doctor.Evidence を満たすので、この経路に読み取りを足すと画面にも同じ
			// 値が届く。
			in, err := doctor.Read(c, time.Now())
			if err != nil {
				return unavailable(err)
			}
			in.From, in.HasFrom = source, hasSource
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
				in.AddProbe(c, rules[0].ID)
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
			// 終了の 1 行は、次に `server doctor <rule>` へ貼る ID を名指すので、完全な ID を
			// 使う(設計文書 10.2 節)。
			bad = append(bad, r.RuleID+" at "+r.StoppedAt)
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

// --- 人向けの出力 ---
// 人向けの出力の桁。表そのものは保証の対象ではない(設計文書 7a.11 節)。
const (
	labelWidth  = 18
	statusWidth = 11
	// inlineDetail は、判定の右にそのまま出せる detail の長さである。これを超える detail は
	// 次の行へ回し、判定の桁に揃える。
	inlineDetail = 46
)

// writeLine は 1 つの検査を出す。短い detail は判定の右に、長い detail は次の行に出す。
//
// detail can carry text an agent's heartbeat contributed (design.md 5.2, 11 節: the agent tunnel
// and rule checks read doctor.TunnelHealth and similar). `group`・`label`・`detail`・`next` are
// explicitly not part of `server doctor --json`'s guarantee (design.md 10.2a 節: "これらは人向けの
// 文であり、保証の対象ではない"), so sanitizing here would not by itself touch any guaranteed value
// either way. It is done here, at the one place every check's human text passes through, rather
// than where checks.go builds Detail, to keep internal/vpsd/doctor a pure judgment layer that does
// not need to import internal/textsafe, and because the Web UI (10.2d 節) already has its own,
// separate escaping (html/template) for the same values.
func writeLine(w io.Writer, label, status, detail string) {
	detail = textsafe.SanitizeForTerminal(detail)
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
			// UDP の宛先の応答の観測は、判定とは別の補足の 1 行である(設計文書 10.2a 節)
			if c.ReplyLine != "" {
				fmt.Fprintf(w, "%s%s\n", strings.Repeat(" ", indent), wrapAt(c.ReplyLine, indent))
			}
			if c.Next != "" && (c.Status != statusOK || verbose) {
				writeNext(w, c.Next, indent)
			}
			writeInternal(w, c.Internal, verbose, indent)
		}
		fmt.Fprintln(w)
		switch rr.Status {
		case statusFailed:
			fmt.Fprintf(w, "Result: traffic stops at %q\n", checkLabelOf(rep, rr.RuleID, rr.StoppedAt))
		case statusSkipped:
			// skipped は、ルール自身が無効な場合と、ルールは有効で持ち主のエージェントが無効な
			// 場合の 2 つである(設計文書 10.2a 節)。直す操作が違うので書き分ける。
			if rep.RuleAgentDisabled(rr.RuleID) {
				fmt.Fprintf(w, "Result: the rule's agent %q is disabled, so nothing is forwarded\n", rr.Agent)
			} else {
				fmt.Fprintln(w, "Result: the rule is disabled, so nothing is forwarded")
			}
		case statusUnknown:
			// 名前の解決に失敗して直前の解決の結果で転送を続けているルールは、そのことを結論にする
			// (設計文書 10.2a 節)
			if note := rep.RuleResultNote(rr.RuleID); note != "" {
				fmt.Fprintf(w, "Result: %s\n", wrapAt(note, len("Result: ")))
				break
			}
			fmt.Fprintln(w, "Result: no failure found, but some evidence above is stale or untested")
		default:
			fmt.Fprintln(w, "Result: healthy as far as this command can see")
		}
	}
	writeHistory(w, rep.History.Detail)
	writeNotTested(w, notTestedLines(rep.NotTested))
}

// writeNext prints a check's "Check: ..." follow-up line. Next can carry text derived from
// something outside the trust boundary too (design.md 11 節: a kernel-mode agent doctor check,
// agentdoctorkernel.go, puts ki.ServerAddress, read from agent.json, into some of its own Next
// text), and like Detail it is not part of any --json guarantee, so it is sanitized here, at the
// one place every caller in this file and agentdoctor.go prints it.
func writeNext(w io.Writer, next string, indent int) {
	fmt.Fprintf(w, "%sCheck: %s\n", strings.Repeat(" ", indent), wrapAt(textsafe.SanitizeForTerminal(next), indent+7))
}

func writeInternal(w io.Writer, lines []string, verbose bool, indent int) {
	if !verbose {
		return
	}
	for _, v := range lines {
		// Check.Internal can carry agent-supplied text too (checks.go's handshakeCheck puts
		// "agent tunnel report is ..." here), and, like Detail and Next, is not part of any
		// --json guarantee. Sanitized here rather than at the source, matching writeLine.
		fmt.Fprintf(w, "%s[%s]\n", strings.Repeat(" ", indent), textsafe.SanitizeForTerminal(v))
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
			return textsafe.SanitizeForTerminal(c.Detail)
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
		writeNext(w, dp.Next, indent)
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
			writeNext(w, a.Next, indent)
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
	writeHistory(w, rep.History.Detail)
	writeNotTested(w, notTestedLines(rep.NotTested))
}
func firstNotOKDetail(rep doctorReport, ruleID string) string {
	for _, c := range checksOfRule(rep, ruleID) {
		if c.Status == statusUnknown || c.Status == statusSkipped {
			return c.Label + ": " + textsafe.SanitizeForTerminal(c.Detail)
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

// writeHistory は、このコマンドが履歴を持たないことを出す。detail を引数に取るのは、`agent doctor`
// (設計文書 10.2c 節)が同じ形の History を、別の文で出すためである。
func writeHistory(w io.Writer, detail string) {
	fmt.Fprintln(w, "\nHistory")
	writeLine(w, "when it broke", "NOT AVAILABLE", "")
	fmt.Fprintf(w, "%s%s\n", strings.Repeat(" ", 2+labelWidth+1), wrapAt(textsafe.SanitizeForTerminal(detail), 2+labelWidth+1))
}

// writeNotTested は試していない範囲を出す。項目を引数に取るのは History と同じ理由である。
func writeNotTested(w io.Writer, items []notTested) {
	fmt.Fprintln(w, "\nNot tested by this command")
	for _, n := range items {
		fmt.Fprintf(w, "  %-16s %s\n", n.ID, wrapAt(textsafe.SanitizeForTerminal(n.Detail), 19))
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
