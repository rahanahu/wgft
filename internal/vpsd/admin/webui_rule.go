package admin

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/rahanahu/wgft/proto"
)

// このファイルはルールの追加フォームと、ルール詳細ページ(/ui/rules/{id}。仕様 10.1 節)の
// 設定(group、note、レート制限を 1 つの保存ボタンでまとめて保存する)、拒否/許可リスト、
// 有効無効、削除を持つ。分割・統合は webui_splitmerge.go、適用状態の判定は webui_state.go に分ける。

var rateUnits = []string{string(proto.PerSecond), string(proto.PerMinute), string(proto.PerHour), string(proto.PerDay), string(proto.PerWeek)}

// rateUnitKeys は proto.RateUnit の値(second など、フォームに送信する値そのもの)を、
// 表示用の訳語キー(秒など)に対応させる。
var rateUnitKeys = map[string]string{
	string(proto.PerSecond): "unitSecond",
	string(proto.PerMinute): "unitMinute",
	string(proto.PerHour):   "unitHour",
	string(proto.PerDay):    "unitDay",
	string(proto.PerWeek):   "unitWeek",
}

// unitLabel はレート単位の表示語を返す(テンプレート関数 UnitLabel)。送信する value 属性は
// proto.RateUnit の値のままで変えない(10.1 節)。
func unitLabel(locale, unit string) string {
	if key, ok := rateUnitKeys[unit]; ok {
		return T(locale, key)
	}
	return unit
}

// serverMode は現在の転送方式(kernel / userspace)。ServerInfo が引けなければ kernel とみなす
// (仕様 9 節。記録の無い既存の状態は kernel とみなす規則に合わせる)。
func (s *Server) serverMode() string {
	info, err := s.backend.ServerInfo()
	if err != nil || info.Mode == "" {
		return string(proto.ModeKernel)
	}
	return info.Mode
}

// existingGroups は既存ルールのグループ名(重複なし・ソート済み)。フォームの候補(datalist)に
// 使うだけの補助で、無ければ入力を妨げない。読み取りが失敗したら候補を出さずログに残す
// (design.md 10.5 節。ページ全体を止めるほどの読み取りではない)。
func (s *Server) existingGroups() []string {
	rules, err := s.backend.Rules()
	if err != nil {
		log.Printf("add-rule form: reading groups: %v", err)
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for i := range rules {
		g := rules[i].Group
		if g != "" && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) uiAddRuleForm(w http.ResponseWriter, r *http.Request) {
	agents, err := s.backend.Agents()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderPage(w, r, "addRuleTitle", "addrule", map[string]any{"Agents": agents, "Groups": s.existingGroups(), "Mode": s.serverMode()})
}

// renderAddRuleError re-renders the add-rule form with a validation/save error. The agent
// dropdown must reflect the real agent list, not a silent empty one (design.md 10.5 節): if
// Agents() itself fails here, this answers 500 instead of a form that looks like no agents exist.
func (s *Server) renderAddRuleError(w http.ResponseWriter, r *http.Request, mode, formErr string) {
	agents, err := s.backend.Agents()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderPage(w, r, "addRuleTitle", "addrule", map[string]any{"Agents": agents, "Groups": s.existingGroups(), "Mode": mode, "Error": formErr})
}

func (s *Server) uiAddRule(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	mode := s.serverMode()
	lp, err := proto.ParsePortRange(r.FormValue("listen_port"))
	if err != nil {
		s.renderAddRuleError(w, r, mode, err.Error())
		return
	}
	rule := proto.Rule{
		ID: "r_" + newULID(), Agent: r.FormValue("agent"), Proto: proto.Proto(r.FormValue("proto")),
		Group: strings.TrimSpace(r.FormValue("group")), Note: strings.TrimSpace(r.FormValue("note")),
		ListenPort: lp, Target: r.FormValue("target"), VPSMode: proto.VPSMode(r.FormValue("vps_mode")),
		ProxyProtocol: r.FormValue("proxy_protocol") == "1", Enabled: r.FormValue("disabled") != "1",
		SourceAllow: []netip.Prefix{}, SourceDeny: []netip.Prefix{},
	}
	if _, err := s.backend.Batch(BatchRequest{Upsert: []proto.Rule{rule}, Force: r.FormValue("force") == "1", Op: "ui add"}); err != nil {
		s.renderAddRuleError(w, r, mode, err.Error())
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---- ルール詳細ページ(仕様 10.1 節) ----

// ruleDetailData はルール詳細ページ(/ui/rules/{id})のビュー(仕様 10.1 節)。
type ruleDetailData struct {
	Locale                 string
	ID, Ports              string
	ProtoUpper, ProtoClass string
	Agent, Target, Mode    string
	Enabled                bool
	StateBadge, StateLabel string
	StateReason            string
	HeadNote               string // 要約に添える保存済みの note(設定の入力欄の値とは別)
	Groups                 []string

	// 設定の区画(group、note、レート制限)。1 つのフォームでまとめて保存する。Group/Note と
	// Rates の Count/Unit/NoLimit は入力欄の値で、描き直しでは利用者の入力を残す。Orig* と
	// rateFieldView.Orig は、そのフォームを描いた時点の保存値で、hidden で送り返させる。
	// 保存はこれと比べて利用者が変えた欄だけを当てはめる(uiSaveSettings)。
	Note, Group                 string
	OrigGroup, OrigNote         string
	GroupConflict, NoteConflict string
	SettingsError               string
	Rates                       rateFormView
	Units                       []string
	ShowPacketNote              bool
	Dropped                     string // このルールの累積 drop 数(一覧の「拒否数」と同じ値。レート制限の見出しに添える)

	// アクセス制御の区画(拒否/許可リスト)。追加と削除はその場で保存する。
	DenyList               []sourceItemView
	DenyInput, DenyError   string
	AllowList              []sourceItemView
	AllowInput, AllowError string
	AllowConfirmAdd        bool

	// 分割。範囲でないルールでは CanSplit が false になり、区画そのものを出さない。
	CanSplit           bool
	SplitPorts         []uint16 // at に選べるポート(範囲の 2 番目から末尾まで)
	ListenLo, ListenHi uint16
	TargetHost         string
	TargetPort         uint16
	SplitError         string

	// 統合。候補が無ければ、隣接する(が統合できない)ルールのうち近い方の理由を出す。
	MergeCandidates []mergeCandidateView
	MergeBlocked    *mergeCandidateView // 候補が無いときの、理由付きの隣接ルール(無ければ nil)
	MergeError      string
}

// sourceItemView は拒否/許可リストの 1 行。Confirm はこの行を外す操作に確認を要るかどうか
// (許可リストの最後の 1 件だけ。仕様 10.1 節)。
type sourceItemView struct {
	CIDR    string
	Confirm bool
}

// rateFormView はレート制限区画の 3 つの入力欄。
type rateFormView struct {
	PerSource, NewFlow, Packet rateFieldView
}

// rateFieldView は 1 つのレート欄。NoLimit なら Count/Unit は表示のみで保存に使わない。
// Orig はフォームを描いた時点の保存値(proto.Rate.String() の形、制限なしなら空)、
// Error はこの欄の入力の誤り、Conflict は別の場所で変わった今の値の表示。
type rateFieldView struct {
	Count    string
	Unit     string
	NoLimit  bool
	Orig     string
	Error    string
	Conflict string
}

// ruleDetailView はルール詳細ページのビューを組み立てる。RuleDrops/Generation/Agents/Rules の
// いずれかが読めなければ、拒否数・適用状態・統合候補を捏造せずエラーを返す(design.md 10.5 節)。
func (s *Server) ruleDetailView(rule proto.Rule, locale string) (ruleDetailData, error) {
	mode := string(rule.VPSMode)
	serverMode := s.serverMode()
	if serverMode == "userspace" {
		mode = "userspace"
	}
	protoClass := "tcp"
	if rule.Proto == proto.UDP {
		protoClass = "udp"
	}
	d := ruleDetailData{
		Locale: locale, ID: rule.ID, Ports: rule.ListenPort.String(),
		ProtoUpper: strings.ToUpper(string(rule.Proto)), ProtoClass: protoClass,
		Agent: rule.Agent, Target: rule.TargetDisplay(), Mode: mode, Enabled: rule.Enabled,
		HeadNote: rule.Note, Groups: s.existingGroups(),
		Note: rule.Note, Group: rule.Group, OrigNote: rule.Note, OrigGroup: rule.Group,
		DenyList:        sourceItems(rule.SourceDeny, false),
		AllowList:       sourceItems(rule.SourceAllow, len(rule.SourceAllow) == 1),
		AllowConfirmAdd: len(rule.SourceAllow) == 0,
		Rates:           rateFormFrom(rule),
		Units:           rateUnits,
		// packet_rate は UDP のデータグラムだけに効く。TCP のルールに packet_rate が
		// 保存されているときだけ、効かない旨を出す(design.md 7a.9 節。CLI 側の
		// 判定と文言を揃える)。
		ShowPacketNote: rule.Proto == proto.TCP && rule.PacketRate != nil,
	}
	drops, err := s.backend.RuleDrops()
	if err != nil {
		return ruleDetailData{}, err
	}
	d.Dropped = strconv.FormatUint(drops[rule.ID], 10)
	gen, err := s.backend.Generation()
	if err != nil {
		return ruleDetailData{}, err
	}
	agents, err := s.backend.Agents()
	if err != nil {
		return ruleDetailData{}, err
	}
	d.StateBadge, d.StateLabel, d.StateReason = ruleRunState(&rule, gen, buildAgentIndex(agents), s.serverApply(), locale)

	d.CanSplit = rule.ListenPort.IsRange()
	if d.CanSplit {
		d.ListenLo, d.ListenHi = rule.ListenPort.Lo, rule.ListenPort.Hi
		// int で回す。p を uint16 のまま Hi(最大 65535)まで回すと、p が 65535 に達した
		// 直後の p++ が 0 に折り返り、p <= Hi が恒に真になって無限ループになる
		// (listen_port=65534-65535 のようなルールの詳細ページを開くと再現する)。
		for p := int(rule.ListenPort.Lo) + 1; p <= int(rule.ListenPort.Hi); p++ {
			d.SplitPorts = append(d.SplitPorts, uint16(p))
		}
		if host, portStr, err := net.SplitHostPort(rule.Target); err == nil {
			if port, err := strconv.ParseUint(portStr, 10, 16); err == nil {
				d.TargetHost, d.TargetPort = host, uint16(port)
			}
		}
	}

	rules, err := s.backend.Rules()
	if err != nil {
		return ruleDetailData{}, err
	}
	d.MergeCandidates, d.MergeBlocked = mergeSection(rule, rules, locale)
	return d, nil
}

// renderRuleDetailOrError builds the rule detail view and either answers 500 (returning ok=false)
// or hands the caller the built data to render or amend (e.g. to add a form error and redraw).
func (s *Server) renderRuleDetailOrError(w http.ResponseWriter, locale string, rule proto.Rule) (ruleDetailData, bool) {
	d, err := s.ruleDetailView(rule, locale)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return ruleDetailData{}, false
	}
	return d, true
}

func sourceItems(list []netip.Prefix, confirmEach bool) []sourceItemView {
	out := make([]sourceItemView, 0, len(list))
	for _, p := range list {
		out = append(out, sourceItemView{CIDR: p.String(), Confirm: confirmEach})
	}
	return out
}

func rateFieldFrom(r *proto.Rate) rateFieldView {
	if r == nil {
		return rateFieldView{Unit: string(proto.PerSecond), NoLimit: true}
	}
	return rateFieldView{Count: strconv.FormatUint(r.Count, 10), Unit: string(r.Unit), Orig: r.String()}
}

// rateString は保存値の比較に使う形(proto.Rate.String()。制限なしなら空)。
func rateString(r *proto.Rate) string {
	if r == nil {
		return ""
	}
	return r.String()
}

func rateFormFrom(rule proto.Rule) rateFormView {
	return rateFormView{
		PerSource: rateFieldFrom(rule.PerSourceRate),
		NewFlow:   rateFieldFrom(rule.NewFlowRate),
		Packet:    rateFieldFrom(rule.PacketRate),
	}
}

// renderDetailPage はルール詳細ページを描画する(page テンプレートの Wide 版)。
func (s *Server) renderDetailPage(w http.ResponseWriter, locale string, data ruleDetailData) {
	var inner bytes.Buffer
	if err := uiTmpl.ExecuteTemplate(&inner, "ruledetail", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderHTML(w, "page", map[string]any{"Locale": locale, "Title": T(locale, "ruleDetailTitle"), "Body": template.HTML(inner.String()), "Wide": true})
}

func (s *Server) uiRuleDetail(w http.ResponseWriter, r *http.Request) {
	locale := resolveLocale(w, r)
	rule, ok := s.findRuleOr404(w, r.PathValue("id"))
	if !ok {
		return
	}
	d, ok := s.renderRuleDetailOrError(w, locale, rule)
	if !ok {
		return
	}
	s.renderDetailPage(w, locale, d)
}

// ---- 設定の区画(group、note、レート制限。仕様 10.1 節) ----

// settingsOrigFields は設定フォームが hidden で送り返す、描いた時点の保存値の欄。
var settingsOrigFields = []string{"orig_group", "orig_note", "orig_per_source", "orig_new_flow", "orig_packet"}

// settingsRateFields は設定フォームのレート欄。name は入力欄の接頭辞(<name>_count、<name>_unit、
// <name>_nolimit、orig_<name>)、rule と view は proto.Rule とビューの対応する欄を返す。
var settingsRateFields = []struct {
	name string
	rule func(*proto.Rule) **proto.Rate
	view func(*rateFormView) *rateFieldView
}{
	{"per_source", func(r *proto.Rule) **proto.Rate { return &r.PerSourceRate }, func(v *rateFormView) *rateFieldView { return &v.PerSource }},
	{"new_flow", func(r *proto.Rule) **proto.Rate { return &r.NewFlowRate }, func(v *rateFormView) *rateFieldView { return &v.NewFlow }},
	{"packet", func(r *proto.Rule) **proto.Rate { return &r.PacketRate }, func(v *rateFormView) *rateFieldView { return &v.Packet }},
}

// settingsInput は送られてきた設定フォームの入力そのもの。描き直しで利用者の入力を失わない
// ために、前後の空白も含めて受け取ったままを持つ。
type settingsInput struct {
	Group, Note         string
	OrigGroup, OrigNote string
	Rates               rateFormView
}

func settingsInputFrom(r *http.Request) settingsInput {
	in := settingsInput{
		Group: r.FormValue("group"), Note: r.FormValue("note"),
		OrigGroup: r.FormValue("orig_group"), OrigNote: r.FormValue("orig_note"),
	}
	for _, f := range settingsRateFields {
		*f.view(&in.Rates) = rateFieldView{
			Count: r.FormValue(f.name + "_count"), Unit: r.FormValue(f.name + "_unit"),
			NoLimit: r.FormValue(f.name+"_nolimit") == "1", Orig: r.FormValue("orig_" + f.name),
		}
	}
	return in
}

// settingsEdit は設定の 1 つの欄を比べるための 3 つの値。group と note は formText の形、
// レートは rateString の形で持つ。user は利用者の入力、orig はフォームを描いた時点の
// 保存値、cur は今の保存値。
type settingsEdit struct {
	user, orig, cur string
}

// changed は利用者がこの欄を、フォームを描いた時点の値から変えたかどうか。
func (e settingsEdit) changed() bool { return e.user != e.orig }

// conflict は、利用者が変えた欄が、フォームを描いた後に別の場所でも変わっていて、しかも
// 利用者の値と違うかどうか。同じ値への変更は食い違いとみなさない。
func (e settingsEdit) conflict() bool { return e.changed() && e.cur != e.orig && e.cur != e.user }

// uiSaveSettings は設定の区画(group、note、3 つのレート)を 1 つのフォームで保存する
// (仕様 10.1 節)。フォームを描いた時点の保存値を hidden(orig_*)で送り返させ、利用者が
// それから変えた欄だけを今のルールに当てはめる。比べる単位は Rule の欄(group、note、
// per_source_rate、new_flow_rate、packet_rate)で、レートは回数と単位を 1 つの値として扱う。
//   - 入力の誤り(値の無いレート欄など)があれば何も保存せず、その欄に誤りを示し、すべての
//     欄の入力を残して描き直す
//   - 利用者が変えた欄が、描いた後に別の場所(CLI や別のタブ)でも変わっていれば、上書き
//     せず何も保存しない。今の値をその欄に示し、利用者の入力を残して描き直す。hidden の
//     保存値は今の値に改めるので、確かめてから保存し直すと利用者の値が入る
//   - 利用者が変えていない欄は、描いた後に別の場所で変わっていても今の値のまま残す
//
// 保存はバッチ 1 回で、今読んだルール集合のハッシュを ExpectedDigest に渡し、読み取りから
// 確定までの間の割り込みも拒む。
func (s *Server) uiSaveSettings(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	locale := resolveLocale(w, r)
	for _, k := range settingsOrigFields {
		if _, ok := r.PostForm[k]; !ok {
			http.Error(w, "the settings form has no "+k+" field; reload the rule page and save again", http.StatusBadRequest)
			return
		}
	}
	rules, err := s.backend.Rules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	idx := slices.IndexFunc(rules, func(x proto.Rule) bool { return x.ID == id })
	if idx < 0 {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	cur := rules[idx]
	in := settingsInputFrom(r)

	group := settingsEdit{user: formText(in.Group), orig: formText(in.OrigGroup), cur: formText(cur.Group)}
	note := settingsEdit{user: formText(in.Note), orig: formText(in.OrigNote), cur: formText(cur.Note)}
	rateEdits := make([]settingsEdit, len(settingsRateFields))
	rateValues := make([]*proto.Rate, len(settingsRateFields))
	invalid := false
	for i, f := range settingsRateFields {
		v := f.view(&in.Rates)
		rate, err := parseRateInput(*v, locale)
		if err != nil {
			v.Error, invalid = err.Error(), true
			continue
		}
		rateValues[i] = rate
		rateEdits[i] = settingsEdit{user: rateString(rate), orig: v.Orig, cur: rateString(*f.rule(&cur))}
	}
	if invalid {
		s.renderSettingsInput(w, locale, cur, in, T(locale, "settingsInvalid"))
		return
	}

	if group.conflict() || note.conflict() || slices.ContainsFunc(rateEdits, settingsEdit.conflict) {
		s.renderSettingsConflict(w, locale, cur, in, group, note, rateEdits)
		return
	}

	updated := cur
	if group.changed() {
		updated.Group = group.user
	}
	if note.changed() {
		updated.Note = note.user
	}
	for i, f := range settingsRateFields {
		if rateEdits[i].changed() {
			*f.rule(&updated) = rateValues[i]
		}
	}
	_, err = s.backend.Batch(BatchRequest{Upsert: []proto.Rule{updated}, ExpectedDigest: proto.RulesDigest(rules), Op: "ui edit"})
	switch {
	case errors.Is(err, ErrBatchConflict):
		// 読み取りから確定までの間の割り込み。どの欄が変わったかは分からないので、入力と
		// hidden の保存値を送られたまま残す。保存し直せば、その時点の値と改めて比べる。
		s.renderSettingsInput(w, locale, cur, in, T(locale, "settingsRaced"))
	case err != nil:
		s.renderSettingsInput(w, locale, cur, in, err.Error())
	default:
		http.Redirect(w, r, "/ui/rules/"+cur.ID, http.StatusSeeOther)
	}
}

// formText は group と note を比べるための形にする。ブラウザは <input type="text"> の値から
// 改行を取り除き、hidden の値の改行は送信時に CRLF に揃えるので、保存値に改行や前後の空白が
// あると、そのままでは利用者が触れていない欄でも入力と保存値が食い違う。入力、描いた時点の
// 保存値、今の保存値の 3 つを同じ形(CR と LF を除き、前後の空白を除く)にしてから比べる。
// 保存するのは利用者が変えた欄だけなので、触れていない欄の保存値はバイト単位でそのまま残る。
func formText(s string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", "", "\n", "").Replace(s))
}

// parseRateInput は 1 つのレート欄の入力を解釈する。「制限しない」なら nil を返す。
func parseRateInput(v rateFieldView, locale string) (*proto.Rate, error) {
	if v.NoLimit {
		return nil, nil
	}
	count := strings.TrimSpace(v.Count)
	if count == "" {
		return nil, errors.New(T(locale, "rateRequired"))
	}
	rate, err := proto.ParseRate(count + "/" + v.Unit)
	if err != nil {
		return nil, err
	}
	return &rate, nil
}

// renderSettingsInput は詳細ページを描き直し、設定の区画には送られてきた入力と hidden の
// 保存値をそのまま入れる(入力の誤りと保存の失敗のとき)。
func (s *Server) renderSettingsInput(w http.ResponseWriter, locale string, cur proto.Rule, in settingsInput, msg string) {
	d, ok := s.renderRuleDetailOrError(w, locale, cur)
	if !ok {
		return
	}
	d.Group, d.Note, d.OrigGroup, d.OrigNote, d.Rates = in.Group, in.Note, in.OrigGroup, in.OrigNote, in.Rates
	d.SettingsError = msg
	s.renderDetailPage(w, locale, d)
}

// renderSettingsConflict は、利用者が変えた欄が別の場所でも変わっていたときの描き直し。
// hidden の保存値はすべて今の値にする。利用者が変えた欄は入力を残し、食い違った欄には
// 今の値を添える。利用者が変えていない欄は今の値を出す。
func (s *Server) renderSettingsConflict(w http.ResponseWriter, locale string, cur proto.Rule, in settingsInput, group, note settingsEdit, rateEdits []settingsEdit) {
	d, ok := s.renderRuleDetailOrError(w, locale, cur)
	if !ok {
		return
	}
	current := func(v string) string {
		if v == "" {
			v = T(locale, "listEmpty")
		}
		return fmt.Sprintf(T(locale, "settingsCurrentFmt"), v)
	}
	if group.changed() {
		d.Group = in.Group
		if group.conflict() {
			d.GroupConflict = current(cur.Group)
		}
	}
	if note.changed() {
		d.Note = in.Note
		if note.conflict() {
			d.NoteConflict = current(cur.Note)
		}
	}
	for i, f := range settingsRateFields {
		if !rateEdits[i].changed() {
			continue
		}
		v := f.view(&d.Rates)
		orig := v.Orig
		*v = *f.view(&in.Rates)
		v.Orig = orig
		if rateEdits[i].conflict() {
			v.Conflict = fmt.Sprintf(T(locale, "settingsCurrentFmt"), rateDisplay(*f.rule(&cur), locale))
		}
	}
	d.SettingsError = T(locale, "settingsConflict")
	s.renderDetailPage(w, locale, d)
}

// rateDisplay はレートの保存値を画面の語で表す(「10 / 分」、制限なしなら「制限しない」)。
func rateDisplay(r *proto.Rate, locale string) string {
	if r == nil {
		return T(locale, "noLimit")
	}
	return fmt.Sprintf("%d / %s", r.Count, unitLabel(locale, string(r.Unit)))
}

// uiDenyAdd / uiDenyRm / uiAllowAdd / uiAllowRm は拒否・許可リストの追加・削除を扱う。
// 複数行を一括で受け、不正な行が 1 つでもあれば何も保存せず入力を残す(仕様 10.1 節)。
func (s *Server) uiDenyAdd(w http.ResponseWriter, r *http.Request)  { s.uiSourceAdd(w, r, false) }
func (s *Server) uiDenyRm(w http.ResponseWriter, r *http.Request)   { s.uiSourceRm(w, r, false) }
func (s *Server) uiAllowAdd(w http.ResponseWriter, r *http.Request) { s.uiSourceAdd(w, r, true) }
func (s *Server) uiAllowRm(w http.ResponseWriter, r *http.Request)  { s.uiSourceRm(w, r, true) }

func (s *Server) uiSourceAdd(w http.ResponseWriter, r *http.Request, allow bool) {
	r.ParseForm()
	locale := resolveLocale(w, r)
	rule, ok := s.findRuleOr404(w, r.PathValue("id"))
	if !ok {
		return
	}
	input := r.FormValue("cidrs")
	ps, err := proto.ParseSourceLines(input)
	if err != nil {
		s.renderSourceError(w, locale, rule, allow, input, err)
		return
	}
	updated := rule
	if allow {
		updated.SourceAllow = proto.AddSources(rule.SourceAllow, ps)
	} else {
		updated.SourceDeny = proto.AddSources(rule.SourceDeny, ps)
	}
	if _, err := s.backend.Batch(BatchRequest{Upsert: []proto.Rule{updated}, Op: "ui edit"}); err != nil {
		s.renderSourceError(w, locale, rule, allow, input, err)
		return
	}
	http.Redirect(w, r, "/ui/rules/"+rule.ID, http.StatusSeeOther)
}

func (s *Server) uiSourceRm(w http.ResponseWriter, r *http.Request, allow bool) {
	r.ParseForm()
	rule, ok := s.findRuleOr404(w, r.PathValue("id"))
	if !ok {
		return
	}
	p, err := proto.ParseSource(r.FormValue("cidr"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	updated := rule
	if allow {
		updated.SourceAllow = proto.RemoveSources(rule.SourceAllow, []netip.Prefix{p})
	} else {
		updated.SourceDeny = proto.RemoveSources(rule.SourceDeny, []netip.Prefix{p})
	}
	_, err = s.backend.Batch(BatchRequest{Upsert: []proto.Rule{updated}, Op: "ui edit"})
	s.redirectOrErrorTo(w, r, "/ui/rules/"+rule.ID, err)
}

func (s *Server) renderSourceError(w http.ResponseWriter, locale string, rule proto.Rule, allow bool, input string, err error) {
	d, ok := s.renderRuleDetailOrError(w, locale, rule)
	if !ok {
		return
	}
	if allow {
		d.AllowError, d.AllowInput = err.Error(), input
	} else {
		d.DenyError, d.DenyInput = err.Error(), input
	}
	s.renderDetailPage(w, locale, d)
}

func (s *Server) uiCheck(w http.ResponseWriter, r *http.Request) {
	locale := resolveLocale(w, r)
	id := r.PathValue("id")
	res, err := s.backend.CheckConnectivity(id)
	data := map[string]any{"RuleLabel": id, "Agent": ""}
	if err != nil {
		data["OK"], data["ReachLabel"], data["Detail"] = false, T(locale, "checkFailed"), err.Error()
	} else {
		data["OK"], data["Detail"] = res.OK, res.Detail
		data["ReachLabel"] = reachLabel(res.Reach, locale)
	}
	s.renderPage(w, r, "checkTitle", "checkresult", data)
}

func reachLabel(reach, locale string) string {
	switch reach {
	case "agent":
		return T(locale, "reachAgent")
	case "none":
		return T(locale, "reachNone")
	}
	return T(locale, "reachOther")
}

func (s *Server) uiRuleEnable(w http.ResponseWriter, r *http.Request)  { s.setEnabled(w, r, true) }
func (s *Server) uiRuleDisable(w http.ResponseWriter, r *http.Request) { s.setEnabled(w, r, false) }

func (s *Server) setEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	op := "ui disable"
	if enabled {
		op = "ui enable"
	}
	id := r.PathValue("id")
	rules, err := s.backend.Rules()
	if err == nil {
		for i := range rules {
			if rules[i].ID == id {
				rules[i].Enabled = enabled
				_, err = s.backend.Batch(BatchRequest{Upsert: []proto.Rule{rules[i]}, Op: op})
				break
			}
		}
	}
	s.redirectOrError(w, r, err)
}

func (s *Server) uiRuleDelete(w http.ResponseWriter, r *http.Request) {
	_, err := s.backend.Batch(BatchRequest{Delete: []string{r.PathValue("id")}, Op: "ui delete"})
	s.redirectOrError(w, r, err)
}
