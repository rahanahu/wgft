package admin

import (
	"fmt"
	"strings"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/doctor"
)

// このファイルは診断の画面の経路の図(設計文書 10.2d 節)を組み立てる。判定は作らない。
// internal/vpsd/doctor の検査の状態と RuleReport.StoppedAt を、図の節点に写すだけである。
//
// 写し方の規則は 3 つある(10.2d 節の改訂の記録、2026-09-23)。
//
//  1. 節点の状態は、その節点に入る検査のうち最も悪いものである。順序は
//     failed > unknown > skipped > not_tested > ok とする。not_tested を ok より悪くするのは、
//     試していない検査を含む節点を ✓ と言わないためである。
//  2. StoppedAt の検査が入る節点が止まった節点で、それより後ろの節点は、中の状態を問わず
//     「届いていない」として描く。元の状態は代替テキストと検査の一覧に残す。
//  3. 無効なルールと、持ち主のエージェントが無効なルールは、すべての節点を「届いていない」
//     として描く。どちらも宣言どおりの状態であり、故障の色にしない(設計文書 5.1 節)。
//
// 表示のためだけの読み替えは 1 つだけある。`rule.probe` の not_tested(疎通の確認を試していない)は
// 節点に数えない。数えると、probe を押していない TCP のルールの宛先が常に ◌ になるためである。
//
// UDP のルールの `rule.target` は、判定そのものが not_tested(理由 udp_listener_only)なので、
// 読み替えずにそのまま数え、節点に「リスナーは開いているが宛先は試していない」旨の 1 文を添える。
// 2026-09-24 までは判定が ok を返し、この図だけが not_tested に読み替えていた(設計文書 10.2a 節、
// 同日の改訂の記録)。

// doctorNodeDef は経路の節点 1 つと、そこに入る検査の ID である。節点の名前は検査の見出しと
// 同じく英語のままにし、訳さない(10.2d 節)。並びは doctor の checkOrder と同じ向きで、
// 公開側から宛先へ進む。
type doctorNodeDef struct {
	Name string
	IDs  []string
}

// doctorNodeDefs はルールの経路の節点である。listener と target は 1 つの節点にまとめる。
// 分けるには `rule.target` の reason で振り分ける表が要り、その根拠をまだラボで確かめて
// いないためである(10.2d 節の改訂の記録)。`server.dataplane` はどのルールの検査でもないので
// 節点に入れず、図の上の帯に出す。経路の外の検査(credentials、flow budget)も入れない。
var doctorNodeDefs = []doctorNodeDef{
	{"public port", []string{doctor.CheckEnabled, doctor.CheckAgentEnabled, doctor.CheckPublicPort, doctor.CheckSourceFilter}},
	{"WireGuard", []string{doctor.CheckHandshake}},
	{"agent", []string{doctor.CheckConnection, doctor.CheckRulesReceived}},
	{"listener / target", []string{doctor.CheckTargetResolve, doctor.CheckTarget, doctor.CheckProbe}},
}

// doctorAgentNodeDefs はエージェントの行の節点である。エージェントには StoppedAt が無いので、
// 状態はそのまま出し、「届いていない」への置き換えも集約もしない。
var doctorAgentNodeDefs = []doctorNodeDef{
	{"tunnel", []string{doctor.CheckHandshake}},
	{"stream", []string{doctor.CheckConnection}},
	{"rules", []string{doctor.CheckRulesReceived}},
}

// 節点の描き方の種類。styles.css の .node の修飾子と同じ名前である。
const (
	nodeOK        = "ok"
	nodeFailed    = "failed"
	nodeUnknown   = "unknown"
	nodeUntested  = "untested"
	nodeSkipped   = "skipped"
	nodeUnreached = "unreached"
)

// doctorNodeView は経路の図の節点 1 つである。
type doctorNodeView struct {
	Name string
	// Labels は節点に入る検査の見出しで、どの検査を 1 つの節点にまとめたかを画面から読める
	// ようにする。
	Labels []string
	// LabelsText は Labels を 1 行にしたもので、1 本のルールの画面の折りたたみの見出しに出す。
	LabelsText string
	// Badge は折りたたみの見出しの状態の語の色で、doctorBadge と同じ語彙である。
	Badge string
	// State は描き方の種類で、Symbol は図形の中の記号である。記号は aria-hidden にし、読み上げは
	// Alt が担う。
	State  string
	Symbol string
	// Word は節点の下に見える語である。状態の語(英語)か、画面の枠の語の「届いていない」である。
	Word string
	// Stop は止まった節点の下に出す札で、検査の見出し、reason、経過の時間から作る。
	Stop string
	// Note は UDP の宛先の節点に添える 1 文である。
	Note string
	// ReplyNote は UDP の宛先の節点に添える 2 つ目の控えめな 1 文で、server 自身が見た宛先の応答の
	// 観測である(設計文書 10.2a 節「UDP の応答の観測」)。節点の状態は変えない。
	ReplyNote string
	// Alt は .sr-only と title に入れる文である。英語の状態の語を必ず含む。
	Alt string
	// AfterStop は止まった節点より後ろにあることである。線を点線にする。
	AfterStop bool
	// Open は 1 本のルールの画面で、節点の検査の折りたたみを既定で開くかどうかである。
	Open bool
	// Rows は 1 本のルールの画面で節点の下に並べる検査の行である。一覧の画面では使わない。
	Rows []doctorCheckView
	// checkWords は中の検査それぞれの状態で、代替テキストに入れる。
	checkWords []string
}

// doctorPathView は 1 本のルールの経路の図である。
type doctorPathView struct {
	// Aria は図全体の <ol> の aria-label である。
	Aria  string
	Nodes []doctorNodeView
	// Caption は一覧の画面で図の横に出す札で、止まった節点の Stop か、無効なルールの札である。
	Caption string
	// Stop は止まった節点の位置で、止まっていなければ -1 である。StoppedAt の検査が入る節点を
	// doctorPath が決めた値そのものであり、ダッシュボードの印(doctorMark)が同じ節点を指すために
	// 外へ出す。
	Stop int
}

// doctorSeverity は節点を集約するときの状態の重さである。
func doctorSeverity(status string) int {
	switch status {
	case doctor.StatusFailed:
		return 4
	case doctor.StatusUnknown:
		return 3
	case doctor.StatusSkipped:
		return 2
	case doctor.StatusNotTested:
		return 1
	}
	return 0
}

// doctorStopLabel は止まった節点の札である。新しい短文の表は持たず、検査の見出しと reason と
// 経過の時間から作る。経過は観測の時刻から 1 秒以上たっているときだけ添える。
func doctorStopLabel(c doctor.Check, now time.Time) string {
	s := c.Label + " / " + c.Reason
	if t, ok := doctor.ParseWhen(c.ObservedAt); ok {
		if d := doctor.Since(now, t); d >= time.Second {
			s += " · " + d.String()
		}
	}
	return s
}

// doctorCheckWord は検査 1 件の状態を、代替テキストに入れる形にする。
func doctorCheckWord(c doctor.Check) string {
	s := c.Label + " " + doctor.DisplayStatus(c)
	if c.Reason != "" {
		s += " / " + c.Reason
	}
	return s
}

// doctorPath はルール 1 本の経路の図を作る。checks はそのルールの検査で、ChecksOf の結果を
// そのまま渡してよい。
func doctorPath(rr doctor.RuleReport, checks []doctor.Check, now time.Time, locale string) doctorPathView {
	byID := map[string]doctor.Check{}
	for _, c := range checks {
		if c.RuleID == rr.RuleID {
			byID[c.ID] = c
		}
	}
	p := doctorPathView{Aria: T(locale, "doctorPathAria"), Stop: -1}
	stop := -1
	for i, def := range doctorNodeDefs {
		n, stopped := doctorNode(def, byID, rr, now, locale)
		if stopped {
			stop = i
		}
		p.Nodes = append(p.Nodes, n)
	}
	agentOff := byID[doctor.CheckAgentEnabled].Reason == doctor.ReasonAgentDisabled
	switch {
	case !rr.Enabled:
		for i := range p.Nodes {
			doctorUnreach(&p.Nodes[i], T(locale, "doctorDisabledAlt"), locale)
		}
		if c, ok := byID[doctor.CheckEnabled]; ok {
			p.Caption = c.Label + " / " + c.Reason
			p.Nodes[0].Stop = p.Caption
		}
	case agentOff:
		for i := range p.Nodes {
			doctorUnreach(&p.Nodes[i], T(locale, "doctorAgentDisabledAlt"), locale)
		}
		c := byID[doctor.CheckAgentEnabled]
		p.Caption = c.Label + " / " + c.Reason
		p.Nodes[0].Stop = p.Caption
	case stop >= 0:
		p.Nodes[stop].Open = true
		p.Caption = p.Nodes[stop].Stop
		for i := stop + 1; i < len(p.Nodes); i++ {
			doctorUnreach(&p.Nodes[i], T(locale, "doctorAfterStopAlt"), locale)
			p.Nodes[i].AfterStop = true
		}
	}
	for i := range p.Nodes {
		doctorFinishNode(&p.Nodes[i])
	}
	p.Stop = stop
	return p
}

// doctorFinishNode は見出し用の値を埋める。
func doctorFinishNode(n *doctorNodeView) {
	n.LabelsText = strings.Join(n.Labels, " · ")
	switch n.State {
	case nodeOK:
		n.Badge = "success"
	case nodeFailed:
		n.Badge = "danger"
	case nodeUnknown:
		n.Badge = "warning"
	default:
		n.Badge = "neutral"
	}
}

// doctorNode は節点 1 つを、中の検査の最も悪い状態から作る。2 つ目の戻り値は、その節点が
// StoppedAt の検査を含むかどうかである。
func doctorNode(def doctorNodeDef, byID map[string]doctor.Check, rr doctor.RuleReport, now time.Time, locale string) (doctorNodeView, bool) {
	n := doctorNodeView{Name: def.Name}
	stopped := false
	var worst doctor.Check
	worstSev := -1
	for _, id := range def.IDs {
		c, ok := byID[id]
		if !ok {
			continue
		}
		n.Labels = append(n.Labels, c.Label)
		n.checkWords = append(n.checkWords, doctorCheckWord(c))
		if id == rr.StoppedAt {
			stopped = true
			n.Stop = doctorStopLabel(c, now)
		}
		// 表示のための読み替え(ファイルの先頭の説明を参照)。
		if id == doctor.CheckProbe && c.Status == doctor.StatusNotTested {
			continue
		}
		if id == doctor.CheckTarget && c.Status == doctor.StatusNotTested && c.Reason == doctor.ReasonUDPListenerOnly {
			n.Note = T(locale, "doctorUDPTargetNote")
		}
		if id == doctor.CheckTarget {
			n.ReplyNote = doctorReplyNote(c, now, locale)
		}
		if sev := doctorSeverity(c.Status); sev > worstSev {
			worst, worstSev = c, sev
		}
	}
	if worstSev < 0 {
		n.State, n.Word = nodeUnreached, T(locale, "doctorNotReached")
		n.Alt = n.Name + ": " + n.Word
		return n, stopped
	}
	doctorSetState(&n, worst)
	alt := n.Name + ": " + n.Word
	if worst.Reason != "" {
		alt += " / " + worst.Reason
	}
	if n.Note != "" {
		alt += ". " + n.Note
	}
	if n.ReplyNote != "" {
		alt += ". " + n.ReplyNote
	}
	// 検査が 1 つだけで見出しが節点の名前と同じなら、同じ語を繰り返さない。
	if len(n.Labels) > 1 || n.Labels[0] != n.Name {
		alt += ". " + strings.Join(n.checkWords, "; ")
	}
	n.Alt = alt
	return n, stopped
}

// doctorReplyNote は rule.target が持つ UDP の宛先の応答の観測を、節点の 2 つ目の注記にする。
// 観測を持たない検査(TCP のルール、観測を報告しない server)では空である。
func doctorReplyNote(c doctor.Check, now time.Time, locale string) string {
	if c.ReplyNotObserved != "" {
		return fmt.Sprintf(T(locale, "doctorUDPNotObserved"), c.ReplyNotObserved)
	}
	if t, ok := doctor.ParseWhen(c.LastReplyAt); ok {
		return fmt.Sprintf(T(locale, "doctorUDPLastReply"), agoDur(doctor.Since(now, t), locale))
	}
	if t, ok := doctor.ParseWhen(c.ReplySince); ok {
		return fmt.Sprintf(T(locale, "doctorUDPNoReply"), agoDur(doctor.Since(now, t), locale))
	}
	return ""
}

// doctorSetState は検査 1 件の状態を、節点の描き方と記号と語に写す。
func doctorSetState(n *doctorNodeView, c doctor.Check) {
	n.Word = doctor.DisplayStatus(c)
	switch c.Status {
	case doctor.StatusOK:
		n.State, n.Symbol = nodeOK, "✓"
	case doctor.StatusFailed:
		n.State, n.Symbol = nodeFailed, "✕"
	case doctor.StatusUnknown:
		n.State, n.Symbol, n.Open = nodeUnknown, "?", true
	case doctor.StatusNotTested:
		n.State = nodeUntested
	default:
		n.State = nodeSkipped
	}
}

// doctorUnreach は節点を「届いていない」に置き換える。why は置き換えた理由で、代替テキストには
// 中の検査の元の状態を併せて書く。図が情報を隠さないようにするためである。
func doctorUnreach(n *doctorNodeView, why, locale string) {
	n.State, n.Symbol, n.Word, n.Note, n.ReplyNote, n.Stop, n.Open = nodeUnreached, "", T(locale, "doctorNotReached"), "", "", "", false
	n.Alt = n.Name + ": " + n.Word + ", " + why + ". " + strings.Join(n.checkWords, "; ")
}

// doctorNodeIndex は検査の ID が入る経路の節点の位置を返す。節点に入らない検査は -1 である。
func doctorNodeIndex(id string) int {
	for i, def := range doctorNodeDefs {
		for _, v := range def.IDs {
			if v == id {
				return i
			}
		}
	}
	return -1
}

// doctorMarkView はダッシュボードのルール一覧の 1 行に置く診断の印である(設計文書 10.1、10.2d 節)。
// doctorPath が作った図から 1 つを選ぶだけで、判定も写し方も持たない。
type doctorMarkView struct {
	// State と Symbol は経路の図の節点と同じ描き方と記号である。記号は aria-hidden にし、
	// 読み上げは Alt が担う。
	State, Symbol string
	// Node は印に添える語である。FAILED なら止まった節点の名前、UNKNOWN なら図の上で最初の
	// UNKNOWN の節点の名前(どちらも英語のまま)、持ち主のエージェントが未登録なら画面の枠の語の
	// 「エージェント未登録」である。OK と SKIPPED では空である。
	Node string
	// Alt は .sr-only と title に入れる文である。状態の語は英語のまま入れる。
	Alt string
	// Failed はヘッダの全体ヘルスとグループの見出しの error の件数に数える印であることである。
	// 件数は印と同じこの値から数え、赤い ✕ の行が「エラー 0 件」の下に並ばないようにする。
	Failed bool
}

// doctorMark は 1 本のルールの印を選ぶ。形と記号は、ルールの総合判定(rr.Status)を
// doctorSetState に通して節点と同じ表から取る。印のために別の記号の表は持たない。
//
// 添える節点の名前は次の規則で選ぶ。
//
//   - FAILED:doctorPath が StoppedAt から決めた止まった節点(p.Stop)。一覧の図と 1 本のルールの
//     画面が止まった位置として描く節点と同じである
//   - UNKNOWN:図を公開側から見て最初に UNKNOWN になる節点。StoppedAt と違って doctor が持つ値
//     ではなく、画面が図から選ぶ唯一の値である。向きは StoppedAt が「経路の順で最初の failed」で
//     あるのと揃えてある
//
// 持ち主のエージェントが登録されていないルールは、`server doctor` では `agent.connection` が
// FAILED `agent_not_registered` になるが、Web UI では故障ではなく登録を待つ状態として灰色で示し、
// エラーの数に含めない(設計文書 5.1、10.1 節)。その判別は、同じ診断の検査の reason の符号で行う。
func doctorMark(rr doctor.RuleReport, checks []doctor.Check, p doctorPathView, locale string) doctorMarkView {
	var n doctorNodeView
	doctorSetState(&n, doctor.Check{Status: rr.Status})
	m := doctorMarkView{State: n.State, Symbol: n.Symbol}
	for _, c := range checks {
		if c.RuleID == rr.RuleID && c.ID == doctor.CheckConnection && c.Reason == doctor.ReasonAgentNotRegistered {
			m.State, m.Symbol, m.Node = nodeSkipped, "", T(locale, "dashDiagUnregistered")
			m.Alt = fmt.Sprintf(T(locale, "dashDiagAlt"), m.Node)
			return m
		}
	}
	switch rr.Status {
	case doctor.StatusFailed:
		m.Failed = true
		if p.Stop >= 0 && p.Stop < len(p.Nodes) {
			m.Node = p.Nodes[p.Stop].Name
		}
	case doctor.StatusUnknown:
		for _, node := range p.Nodes {
			if node.State == nodeUnknown {
				m.Node = node.Name
				break
			}
		}
	}
	word := doctor.StatusWord(rr.Status)
	if m.Node != "" {
		word += " at " + m.Node
	}
	m.Alt = fmt.Sprintf(T(locale, "dashDiagAlt"), word)
	return m
}

// doctorAgentPath はエージェント 1 つの行の図を作る。検査は doctor.Report.AgentCheck で選び、
// CLI の Agents の行と同じ規則にする。2 つ目の戻り値は、図の節点と同じ順の検査である。
func doctorAgentPath(agent string, rep doctor.Report, locale string) (doctorPathView, []doctor.Check) {
	p := doctorPathView{Aria: T(locale, "doctorAgentPathAria") + " " + agent}
	var checks []doctor.Check
	for _, def := range doctorAgentNodeDefs {
		n := doctorNodeView{Name: def.Name}
		if c, ok := rep.AgentCheck(agent, def.IDs[0]); ok {
			n.Labels = []string{c.Label}
			doctorSetState(&n, c)
			n.Alt = n.Name + ": " + doctorCheckWord(c)
			checks = append(checks, c)
		} else {
			n.State, n.Word, n.Alt = nodeSkipped, "-", n.Name+": -"
		}
		doctorFinishNode(&n)
		p.Nodes = append(p.Nodes, n)
	}
	return p, checks
}
