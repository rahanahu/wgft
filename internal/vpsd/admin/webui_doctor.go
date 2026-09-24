package admin

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/adminapi"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは Web UI の診断の画面(設計文書 10.2d 節)を持つ。判定は internal/vpsd/doctor に
// あり、`wgft server doctor`(10.2a 節)と同じ証拠から同じ検査を組み立てる。ここが持つのは、
// 証拠をこのプロセスの中から読む経路と、判定を画面に写すところだけである。
//
// 画面の文言のうち、検査の見出し、状態の語、群の名前は日英で切り替えず英語のままにする
// (10.2d 節)。`server doctor --json` の checks[].id と checks[].status に出る語と同じものを
// 使い、画面で見た語で機械向けの出力を引けるようにするためである。所見の自由文も英語のまま
// である。画面の枠の語(見出し、ボタン、注記)だけを i18n.go で切り替える。
//
// 疎通の確認は、画面を開いたときには呼ばない。運用者が明示的に操作したとき、つまり 1 本の
// ルールの画面で probe のリンクを押したときだけ呼ぶ(10.2d 節)。既存の接続テストのボタン
// (webui_rule.go の uiCheck)と同じ形である。

// doctorEvidence は、判定が読む証拠をこのプロセスの中の Backend から読む(design.md 10.2d 節)。
// CLI は同じ 3 つを admin.Client 越しに管理用 API から読む。どちらの経路でも判定は同じ値を見る。
type doctorEvidence struct{ s *Server }

// Rules は GET /api/v1/rules と同じ本文を、HTTP を経ずに組み立てる。
func (d doctorEvidence) Rules() (*adminapi.BatchResponse, error) {
	resp, err := d.s.rulesResponse()
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Agents は GET /api/v1/agents と同じ一覧である。
func (d doctorEvidence) Agents() ([]adminapi.AgentInfo, error) { return d.s.backend.Agents() }

// CheckConnectivity は POST /api/v1/rules/{id}/check と同じ確認である。運用者が明示的に
// 操作したときだけ呼ばれる。
func (d doctorEvidence) CheckConnectivity(ruleID string) (*adminapi.ConnCheck, error) {
	res, err := d.s.backend.CheckConnectivity(ruleID)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// ---- ビューモデル ----

// doctorCheckView は検査 1 件の行である。Label、Status、Group は英語のままで、訳さない。
// Locale は行の中の折りたたみの見出しにだけ使う。
type doctorCheckView struct {
	Locale string
	Label  string
	Status string
	Badge  string
	Detail string
	Causes []string
	Next   string
	Agent  string
	RuleID string
	// ScreenNote は、Next が画面から実行できない検査に画面の側から添える 1 文である。判定が
	// 持つ所見は CLI と共有しており、同じ事実を 2 つの面で違う文にすると、どちらが正しいかを
	// 読み手が確かめられなくなるので、共有の文は書き換えない(design.md 10.2d 節)。
	ScreenNote string
	// Internal は wgft 自身を追うときだけ要る値である。CLI の --verbose が出すものと同じで、
	// 画面では行ごとの折りたたみの中に入れる。
	Internal []string
}

// doctorAgentRowView は一覧の画面のエージェントの 1 行である。図は tunnel、stream、rules の
// 3 つの節点で、状態はそのまま出す(webui_doctor_path.go)。
type doctorAgentRowView struct {
	Name   string
	Status string
	Badge  string
	Detail string
	Path   doctorPathView
	// Checks は tunnel、stream、rules の検査の行で、行ごとの折りたたみに入れる。Causes、Next、
	// Internal を一覧の画面から読めるようにするためである。
	Checks []doctorCheckView
	// Open は折りたたみを既定で開くかどうかで、どれかの検査が OK でないときに開く。
	Open bool
}

// doctorRuleRowView は一覧の 1 行であり、1 本のルールの画面の見出しでもある。
type doctorRuleRowView struct {
	ID         string
	Short      string
	ProtoUpper string
	ProtoClass string
	Ports      string
	Agent      string
	Target     string
	Group      string
	Status     string
	Badge      string
	Why        string
	// Path は経路の図である(webui_doctor_path.go)。
	Path doctorPathView
}

// doctorPageData は診断の画面のビューである。一覧の画面と 1 本のルールの画面が同じ型を使う。
type doctorPageData struct {
	Locale    string
	CheckedAt string
	// 一覧の画面
	Server doctorCheckView
	Agents []doctorAgentRowView
	Rules  []doctorRuleRowView
	// 1 本のルールの画面。経路の上の検査の行は Rule.Path の節点の下に入る。
	Rule *doctorRuleRowView
	// Banner は server.dataplane が OK でないときだけ、図の上に帯として出す検査である。
	Banner *doctorCheckView
	// OffPath は経路の図の節点に入らない検査(dataplane、credentials、flow budget)の行である。
	OffPath  []doctorCheckView
	Hidden   []doctorCheckView
	CanProbe bool
	// AgentDisabled は、ルールは有効で持ち主のエージェントが無効であることである。疎通の確認を
	// 使えない理由を、無効なルールや UDP のルールと書き分けるために持つ。
	AgentDisabled bool
	Probed        bool
	// 両方
	Result    string
	History   string
	NotTested []doctorNotTestedView
}

// doctorNotTestedView は試していない範囲 1 件である。ID も自由文も英語のままである。
type doctorNotTestedView struct {
	ID     string
	Detail string
}

// doctorBadge は状態を既存の一覧と同じ色の語彙に写す(styles.css の .badge)。状態の語そのものは
// doctor.DisplayStatus が返す英語をそのまま出す。
func doctorBadge(status string) string {
	switch status {
	case doctor.StatusOK:
		return "success"
	case doctor.StatusFailed:
		return "danger"
	case doctor.StatusUnknown:
		return "warning"
	}
	return "neutral"
}

func doctorCheckToView(c doctor.Check, locale string) doctorCheckView {
	return doctorCheckView{
		Locale: locale,
		Label:  c.Label, Status: doctor.DisplayStatus(c), Badge: doctorBadge(c.Status),
		Detail: c.Detail, Causes: c.Causes, Next: c.Next, Agent: c.Agent, RuleID: c.RuleID,
		Internal: c.Internal,
	}
}

// doctorScreenNote は、CLI のために書かれた次の一手を画面で読んだときに補う 1 文を返す。
// 1 本のルールの画面だけが使う。対象は次のとおりである(design.md 10.2d 節の改訂の記録)。
//
//   - `rule.source_filter` は --from を付け直すよう案内するが、画面には接続元アドレスの入力欄が
//     無い。入力欄を設けることは画面から管理用 API を呼び直す新しい操作になるので、この版では
//     CLI の実行の形を画面に示すだけにする。
//
// `rule.probe` はかつて、疎通の確認を試していない UDP のルールに「--probe を付けよ」と勧め、
// 画面にボタンが無いのに CLI の操作を勧める食い違いを補う 1 文をここで足していた。共有の次の
// 一手が UDP のルールにはもう --probe を勧めなくなったので(design.md 10.2a 節の改訂の記録、
// 2026-09-23)、この画面固有の 1 文は要らなくなった。ボタンが無い理由は Probe の節の
// doctorProbeUnavailable が別に説明する。
func doctorScreenNote(c doctor.Check, locale string) string {
	switch {
	case c.ID == doctor.CheckSourceFilter && c.Reason == doctor.ReasonNoFrom:
		return T(locale, "doctorSourceFilterNote")
	}
	return ""
}

func doctorRuleToView(rr doctor.RuleReport, rep doctor.Report) doctorRuleRowView {
	v := doctorRuleRowView{
		ID: rr.RuleID, Short: doctor.ShortID(rr.RuleID), ProtoUpper: strings.ToUpper(rr.Proto),
		ProtoClass: rr.Proto, Ports: rr.ListenPort, Agent: rr.Agent, Target: rr.Target,
		Group: rr.Group, Status: doctor.StatusWord(rr.Status), Badge: doctorBadge(rr.Status),
	}
	v.ProtoClass = "tcp"
	if rr.Proto == string(proto.UDP) {
		v.ProtoClass = "udp"
	}
	v.Why = doctorWhy(rr, rep)
	return v
}

// doctorWhy は一覧の 1 行に添える理由である。止まった検査があればその見出しと所見を、無ければ
// 最初の ok でない検査の所見を出す。CLI の一覧が同じ規則で 1 行に畳む(cmd/wgft/doctor.go)。
func doctorWhy(rr doctor.RuleReport, rep doctor.Report) string {
	for _, c := range rep.ChecksOf(rr.RuleID) {
		if c.ID == rr.StoppedAt {
			return c.Label + ": " + c.Detail
		}
	}
	if rr.Status == doctor.StatusOK {
		return ""
	}
	for _, c := range rep.ChecksOf(rr.RuleID) {
		if c.Status == doctor.StatusUnknown || c.Status == doctor.StatusSkipped {
			return c.Label + ": " + c.Detail
		}
	}
	return ""
}

func doctorNotTestedViews(items []doctor.NotTested) []doctorNotTestedView {
	out := make([]doctorNotTestedView, 0, len(items))
	for _, n := range items {
		out = append(out, doctorNotTestedView{ID: n.ID, Detail: n.Detail})
	}
	return out
}

// ---- ハンドラ ----

// uiDoctor は配置全体の診断である。server、エージェント、全ルールを 1 行ずつ出す。疎通の確認は
// 呼ばない(design.md 10.2d 節)。
func (s *Server) uiDoctor(w http.ResponseWriter, r *http.Request) {
	locale := resolveLocale(w, r)
	in, err := doctor.Read(doctorEvidence{s}, time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rep := doctor.BuildReport(in.Rules.Rules, in)
	d := doctorPageData{
		Locale: locale, CheckedAt: rep.CheckedAt,
		History: rep.History.Detail, NotTested: doctorNotTestedViews(rep.NotTested),
	}
	for _, c := range rep.Checks {
		if c.ID == doctor.CheckDataplane {
			d.Server = doctorCheckToView(c, locale)
		}
	}
	for _, a := range rep.AgentSummaries() {
		path, checks := doctorAgentPath(a.Agent, rep, locale)
		row := doctorAgentRowView{
			Name: a.Agent, Status: doctor.DisplayStatus(a), Badge: doctorBadge(a.Status), Detail: a.Detail, Path: path,
		}
		for _, c := range checks {
			row.Checks = append(row.Checks, doctorCheckToView(c, locale))
			if c.Status != doctor.StatusOK {
				row.Open = true
			}
		}
		d.Agents = append(d.Agents, row)
	}
	failed := 0
	for _, rr := range rep.Rules {
		if rr.Status == doctor.StatusFailed {
			failed++
		}
		v := doctorRuleToView(rr, rep)
		v.Path = doctorPath(rr, rep.ChecksOf(rr.RuleID), in.Now, locale)
		d.Rules = append(d.Rules, v)
	}
	d.Result = "no failing check"
	if rep.Status == doctor.StatusFailed {
		d.Result = fmt.Sprintf("%d of %d rules not carrying traffic", failed, len(rep.Rules))
	}
	s.renderDoctorPage(w, locale, "doctorsummary", d)
}

// uiDoctorRule は 1 本のルールを公開側から宛先まで順に出す。?probe=1 が付いた実行だけが、
// 運用者の明示の操作として疎通の確認を呼ぶ(design.md 10.2d 節)。
func (s *Server) uiDoctorRule(w http.ResponseWriter, r *http.Request) {
	locale := resolveLocale(w, r)
	rule, ok := s.findRuleOr404(w, r.PathValue("id"))
	if !ok {
		return
	}
	in, err := doctor.Read(doctorEvidence{s}, time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if r.URL.Query().Get("probe") == "1" {
		in.AddProbe(doctorEvidence{s}, rule.ID)
	}
	rep := doctor.BuildReport([]proto.Rule{rule}, in)
	agentOff := rep.RuleAgentDisabled(rule.ID)
	d := doctorPageData{
		Locale: locale, CheckedAt: rep.CheckedAt, Probed: in.Probed,
		// 管理用 API は無効なエージェントのルールの疎通の確認を拒むので、ボタンを出さない
		// (設計文書 5.1 節)。
		CanProbe:      rule.Enabled && rule.Proto == proto.TCP && !agentOff,
		AgentDisabled: agentOff,
		History:       rep.History.Detail, NotTested: doctorNotTestedViews(rep.NotTested),
	}
	if len(rep.Rules) == 1 {
		head := doctorRuleToView(rep.Rules[0], rep)
		head.Path = doctorPath(rep.Rules[0], rep.ChecksOf(rule.ID), in.Now, locale)
		d.Rule = &head
		d.Result = doctorResultLine(rep.Rules[0], rep)
	}
	for _, c := range rep.ChecksOf(rule.ID) {
		v := doctorCheckToView(c, locale)
		v.ScreenNote = doctorScreenNote(c, locale)
		if c.Hidden(false) {
			d.Hidden = append(d.Hidden, v)
			continue
		}
		if c.ID == doctor.CheckDataplane && c.Status != doctor.StatusOK {
			banner := v
			d.Banner = &banner
		}
		if i := doctorNodeIndex(c.ID); i >= 0 && d.Rule != nil {
			d.Rule.Path.Nodes[i].Rows = append(d.Rule.Path.Nodes[i].Rows, v)
			continue
		}
		d.OffPath = append(d.OffPath, v)
	}
	s.renderDoctorPage(w, locale, "doctorrule", d)
}

// doctorResultLine は 1 本のルールの結論である。CLI の `Result:` の行と同じ場合に分ける
// (design.md 10.2a 節)。skipped は、ルール自身の無効と持ち主のエージェントの無効を書き分ける。
func doctorResultLine(rr doctor.RuleReport, rep doctor.Report) string {
	switch rr.Status {
	case doctor.StatusFailed:
		for _, c := range rep.ChecksOf(rr.RuleID) {
			if c.ID == rr.StoppedAt {
				return fmt.Sprintf("traffic stops at %q", c.Label)
			}
		}
		return "traffic stops at " + rr.StoppedAt
	case doctor.StatusSkipped:
		if rep.RuleAgentDisabled(rr.RuleID) {
			return fmt.Sprintf("the rule's agent %q is disabled, so nothing is forwarded", rr.Agent)
		}
		return "the rule is disabled, so nothing is forwarded"
	case doctor.StatusUnknown:
		// 名前の解決に失敗して直前の解決の結果で転送を続けているルールは、そのことを結論にする
		// (design.md 10.2a 節)。CLI の Result: の行と同じ文である。
		if note := rep.RuleResultNote(rr.RuleID); note != "" {
			return note
		}
		return "no failure found, but some evidence above is stale or untested"
	}
	return "healthy as far as this diagnosis can see"
}

// doctorMaxWidth は診断の画面の枠の最大幅 (px) である。
const doctorMaxWidth = 1200

// renderDoctorPage は診断の画面を、ルール詳細ページより広い枠で描く。診断の画面は経路の図と
// 表が横に並ぶので、広い画面では幅を使う方が読みやすい。ルール詳細ページと読み込みの確認ページは
// フォームが自前の最大幅を持つので、枠を広げても余白が増えるだけであり、900px のまま残す。
func (s *Server) renderDoctorPage(w http.ResponseWriter, locale, body string, d doctorPageData) {
	var inner strings.Builder
	if err := uiTmpl.ExecuteTemplate(&inner, body, d); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderHTML(w, "page", map[string]any{
		"Locale": locale, "Title": T(locale, "doctorTitle"), "Body": template.HTML(inner.String()), "Wide": true,
		"MaxWidth": doctorMaxWidth, "Crumbs": doctorCrumbs(locale, d),
	})
}

// doctorCrumbs は診断の画面のパンくずを返す。一覧の画面は「ダッシュボード / 診断」、1 本のルールの
// 画面は「ダッシュボード / 診断 / ルール」である。
func doctorCrumbs(locale string, d doctorPageData) []pageCrumb {
	dash := dashboardCrumb(locale)
	if d.Rule == nil {
		return []pageCrumb{dash, {Label: T(locale, "doctorTitle")}}
	}
	return []pageCrumb{dash, {Label: T(locale, "doctorTitle"), Href: "/ui/doctor"}, {Label: ruleCrumbLabel(d.Rule.ProtoUpper, d.Rule.Ports, d.Rule.Agent)}}
}
