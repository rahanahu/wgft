package admin

import (
	"bytes"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/rahanahu/wgft/proto"
)

// このファイルはルールの追加フォームと、ルール詳細ページ(/ui/rules/{id}。仕様 10.1 節)の
// メタ情報(group/note)、拒否/許可リスト、レート制限、有効無効、削除を持つ。分割・統合は
// webui_splitmerge.go、適用状態の判定は webui_state.go に分ける。

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

// existingGroups は既存ルールのグループ名(重複なし・ソート済み)。フォームの候補に使う。
func (s *Server) existingGroups() []string {
	rules, _ := s.backend.Rules()
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
	s.renderPage(w, r, "addRuleTitle", "addrule", map[string]any{"Agents": s.agentsOrNil(), "Groups": s.existingGroups(), "Mode": s.serverMode()})
}

func (s *Server) uiAddRule(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	mode := s.serverMode()
	lp, err := proto.ParsePortRange(r.FormValue("listen_port"))
	if err != nil {
		s.renderPage(w, r, "addRuleTitle", "addrule", map[string]any{"Agents": s.agentsOrNil(), "Groups": s.existingGroups(), "Mode": mode, "Error": err.Error()})
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
		s.renderPage(w, r, "addRuleTitle", "addrule", map[string]any{"Agents": s.agentsOrNil(), "Groups": s.existingGroups(), "Mode": mode, "Error": err.Error()})
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
	Note, Group            string
	Groups                 []string
	MetaError              string
	DenyList               []sourceItemView
	DenyInput, DenyError   string
	AllowList              []sourceItemView
	AllowInput, AllowError string
	AllowConfirmAdd        bool
	Rates                  rateFormView
	RateError              string
	Units                  []string
	ShowPacketNote         bool
	Dropped                string // このルールの累積 drop 数(一覧の「拒否数」と同じ値。レート制限の見出しに添える)

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

// rateFieldView は 1 つのレート欄。NoLimit なら Count/Unit は表示のみで送信されない。
type rateFieldView struct {
	Count   string
	Unit    string
	NoLimit bool
}

// ruleDetailView はルール詳細ページのビューを組み立てる。
func (s *Server) ruleDetailView(rule proto.Rule, locale string) ruleDetailData {
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
		Note: rule.Note, Group: rule.Group, Groups: s.existingGroups(),
		DenyList:        sourceItems(rule.SourceDeny, false),
		AllowList:       sourceItems(rule.SourceAllow, len(rule.SourceAllow) == 1),
		AllowConfirmAdd: len(rule.SourceAllow) == 0,
		Rates:           rateFormFrom(rule),
		Units:           rateUnits,
		// packet_rate は UDP のデータグラムだけに効く。kernel モードは移行の途中で、
		// TCP のルールにもまだ packet の行を付けているが、旨の表示はその行の削除を
		// 待たずに入れる(design.md 7a.9 節。CLI 側の判定と文言を揃える)。
		ShowPacketNote: rule.Proto == proto.TCP,
	}
	if drops, err := s.backend.RuleDrops(); err == nil {
		d.Dropped = strconv.FormatUint(drops[rule.ID], 10)
	}
	gen, _ := s.backend.Generation()
	agents, _ := s.backend.Agents()
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

	rules, _ := s.backend.Rules()
	d.MergeCandidates, d.MergeBlocked = mergeSection(rule, rules, locale)
	return d
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
	return rateFieldView{Count: strconv.FormatUint(r.Count, 10), Unit: string(r.Unit)}
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
	s.renderDetailPage(w, locale, s.ruleDetailView(rule, locale))
}

func (s *Server) uiEditMeta(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	locale := resolveLocale(w, r)
	rule, ok := s.findRuleOr404(w, r.PathValue("id"))
	if !ok {
		return
	}
	updated := rule
	updated.Group = strings.TrimSpace(r.FormValue("group"))
	updated.Note = strings.TrimSpace(r.FormValue("note"))
	if _, err := s.backend.Batch(BatchRequest{Upsert: []proto.Rule{updated}, Op: "ui edit"}); err != nil {
		d := s.ruleDetailView(rule, locale)
		d.MetaError, d.Group, d.Note = err.Error(), updated.Group, updated.Note
		s.renderDetailPage(w, locale, d)
		return
	}
	http.Redirect(w, r, "/ui/rules/"+rule.ID, http.StatusSeeOther)
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
	d := s.ruleDetailView(rule, locale)
	if allow {
		d.AllowError, d.AllowInput = err.Error(), input
	} else {
		d.DenyError, d.DenyInput = err.Error(), input
	}
	s.renderDetailPage(w, locale, d)
}

// uiSetRates はレート制限の 3 欄を 1 フォームで保存する。値が無く「制限しない」も外れている欄は
// 誤りとして扱い、何も保存しない。
func (s *Server) uiSetRates(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	locale := resolveLocale(w, r)
	rule, ok := s.findRuleOr404(w, r.PathValue("id"))
	if !ok {
		return
	}
	renderRatesError := func(err error) {
		d := s.ruleDetailView(rule, locale)
		d.RateError, d.Rates = err.Error(), s.rateFormFromRequest(r)
		s.renderDetailPage(w, locale, d)
	}
	perSource, errPS := s.parseRateField(r, "per_source", T(locale, "ratePerSourceHead"), locale)
	newFlow, errNF := s.parseRateField(r, "new_flow", T(locale, "rateNewFlowHead"), locale)
	packet, errPkt := s.parseRateField(r, "packet", T(locale, "ratePacketHead"), locale)
	if err := firstErr(errPS, errNF, errPkt); err != nil {
		renderRatesError(err)
		return
	}
	updated := rule
	updated.PerSourceRate, updated.NewFlowRate, updated.PacketRate = perSource, newFlow, packet
	if _, err := s.backend.Batch(BatchRequest{Upsert: []proto.Rule{updated}, Op: "ui edit"}); err != nil {
		renderRatesError(err)
		return
	}
	http.Redirect(w, r, "/ui/rules/"+rule.ID, http.StatusSeeOther)
}

// parseRateField は 1 つのレート欄(<prefix>_count、<prefix>_unit、<prefix>_nolimit)を解釈する。
// label はエラーメッセージに使う、その欄の訳済みの見出し。
func (s *Server) parseRateField(r *http.Request, prefix, label, locale string) (*proto.Rate, error) {
	if r.FormValue(prefix+"_nolimit") == "1" {
		return nil, nil
	}
	count := strings.TrimSpace(r.FormValue(prefix + "_count"))
	if count == "" {
		return nil, fmt.Errorf("%s: %s", label, T(locale, "rateRequired"))
	}
	rate, err := proto.ParseRate(count + "/" + r.FormValue(prefix+"_unit"))
	if err != nil {
		return nil, err
	}
	return &rate, nil
}

func (s *Server) rateFormFromRequest(r *http.Request) rateFormView {
	field := func(prefix string) rateFieldView {
		return rateFieldView{Count: r.FormValue(prefix + "_count"), Unit: r.FormValue(prefix + "_unit"), NoLimit: r.FormValue(prefix+"_nolimit") == "1"}
	}
	return rateFormView{PerSource: field("per_source"), NewFlow: field("new_flow"), Packet: field("packet")}
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
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
