package admin

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

func newULID() string { return ulid.Make().String() }

//go:embed webui/templates/*.gohtml
var tmplFS embed.FS

//go:embed webui/static/*
var staticFS embed.FS

var uiTmpl = template.Must(template.New("").Funcs(template.FuncMap{"T": T}).ParseFS(tmplFS, "webui/templates/*.gohtml"))

// registerUI は Web UI のルートを mux に足す(認証は ServeHTTP でかかる)。
func (s *Server) registerUI() {
	staticSub, _ := fs.Sub(staticFS, "webui/static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticSub)))
	s.mux.HandleFunc("GET /{$}", s.uiDashboard)
	s.mux.HandleFunc("GET /ui/agents", s.uiAgentsPartial)
	s.mux.HandleFunc("GET /ui/warnings", s.uiWarningsPartial)
	s.mux.HandleFunc("GET /ui/add-rule", s.uiAddRuleForm)
	s.mux.HandleFunc("POST /ui/add-rule", s.uiAddRule)
	s.mux.HandleFunc("GET /ui/add-agent", s.uiAddAgentForm)
	s.mux.HandleFunc("POST /ui/add-agent", s.uiAddAgent)
	s.mux.HandleFunc("GET /ui/rules/{id}/check", s.uiCheck)
	s.mux.HandleFunc("GET /ui/rules/{id}", s.uiRuleDetail)
	s.mux.HandleFunc("POST /ui/rules/{id}/meta", s.uiEditMeta)
	s.mux.HandleFunc("POST /ui/rules/{id}/deny/add", s.uiDenyAdd)
	s.mux.HandleFunc("POST /ui/rules/{id}/deny/rm", s.uiDenyRm)
	s.mux.HandleFunc("POST /ui/rules/{id}/allow/add", s.uiAllowAdd)
	s.mux.HandleFunc("POST /ui/rules/{id}/allow/rm", s.uiAllowRm)
	s.mux.HandleFunc("POST /ui/rules/{id}/rates", s.uiSetRates)
	s.mux.HandleFunc("POST /ui/rules/{id}/enable", s.uiRuleEnable)
	s.mux.HandleFunc("POST /ui/rules/{id}/disable", s.uiRuleDisable)
	s.mux.HandleFunc("POST /ui/rules/{id}/delete", s.uiRuleDelete)
	s.mux.HandleFunc("POST /ui/agents/{name}/revoke", s.uiRevoke)
	s.mux.HandleFunc("POST /ui/agents/{name}/dismiss-warning", s.uiDismissWarning)
}

// ---- ビューモデル ----

type dashData struct {
	Locale       string
	Server       serverView
	Health       healthView
	Agents       []agentView
	RuleGroups   []ruleGroupView
	RuleCount    int
	Warnings     []warnView
	Generation   uint64
	FirewallText string
}

type healthView struct {
	OK      bool
	Class   string
	Title   string
	Summary string
}

type agentView struct {
	Name, Address, StreamFrom, WGEndpoint string
	Connected                             bool
	Generation                            uint64
	StateBadge, StateLabel                string
	TunnelClass, TunnelLabel              string
	ShowIPCompare                         bool
	IPCompareClass, IPCompareLabel        string
	Pending                               bool
	HeartbeatAgo, HeartbeatClass          string
	HandshakeAgo                          string
	PublicKey, PublicKeyShort             string
	WarnCount                             int
	Attention                             bool
}

type ruleView struct {
	ID, Agent, Target, Mode          string
	ProtoUpper, ProtoClass, Ports    string
	ProxyProtocol, Enabled, CanCheck bool
	StateBadge, StateLabel           string
	StateReason                      string
	Dropped                          string
	Restriction                      string
	Note                             string
}

// ruleGroupView は一覧のグループ 1 つ分。ErrorCount はグループが畳まれていても見出しに
// 出す error 状態のルール数(仕様 10.1 節)。
type ruleGroupView struct {
	Group      string
	Label      string
	Rules      []ruleView
	ErrorCount int
}

type warnView struct {
	Agent, Kind, Title, Body, Detail, Ago, AlertClass string
}

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

var rateUnits = []string{string(proto.PerSecond), string(proto.PerMinute), string(proto.PerHour), string(proto.PerDay), string(proto.PerWeek)}

func (s *Server) buildDash(locale string) (dashData, error) {
	agents, err := s.backend.Agents()
	if err != nil {
		return dashData{}, err
	}
	rules, err := s.backend.Rules()
	if err != nil {
		return dashData{}, err
	}
	gen, _ := s.backend.Generation()
	drops, _ := s.backend.RuleDrops()
	warns, _ := s.backend.Warnings()

	d := dashData{Locale: locale, Generation: gen, FirewallText: firewallText(locale)}
	if info, e := s.backend.ServerInfo(); e == nil {
		d.Server = serverToView(info, locale)
	}
	online := 0
	for _, a := range agents {
		if a.Connected {
			online++
		}
		d.Agents = append(d.Agents, agentToView(a, gen, locale))
	}
	agentIdx := buildAgentIndex(agents)
	d.RuleCount = len(rules)
	var ruleErrors int
	d.RuleGroups, ruleErrors = groupRules(rules, drops, locale, d.Server.Mode, gen, agentIdx)
	for _, w := range warns {
		d.Warnings = append(d.Warnings, warnToView(w, locale))
	}
	d.Health = health(len(agents), online, len(rules), len(warns), ruleErrors, locale)
	return d, nil
}

func health(total, online, rules, warnings, ruleErrors int, locale string) healthView {
	switch {
	case ruleErrors > 0 && warnings > 0:
		return healthView{OK: false, Title: T(locale, "healthWarn"), Summary: fmt.Sprintf(T(locale, "summaryErrWarn"), online, total, rules, ruleErrors, warnings)}
	case ruleErrors > 0:
		return healthView{OK: false, Title: T(locale, "healthWarn"), Summary: fmt.Sprintf(T(locale, "summaryErr"), online, total, rules, ruleErrors)}
	case warnings > 0:
		return healthView{OK: false, Title: T(locale, "healthWarn"), Summary: fmt.Sprintf(T(locale, "summaryWarn"), online, total, rules, warnings)}
	default:
		return healthView{OK: true, Class: "success", Title: T(locale, "healthOK"), Summary: fmt.Sprintf(T(locale, "summaryOK"), online, total, rules)}
	}
}

// ruleAgentStatus はエージェント 1 台の直近のハートビートから引く、ルールの適用状態の
// 判定に要る部分だけの写し(仕様 10.1 節)。
type ruleAgentStatus struct {
	Connected  bool
	Generation uint64
	Rules      map[string]proto.RuleStatus
}

// buildAgentIndex はエージェント名 → ruleAgentStatus の表を作る。ruleRunState がこれで
// ルールの持ち主のエージェントを引く。
func buildAgentIndex(agents []AgentInfo) map[string]ruleAgentStatus {
	idx := make(map[string]ruleAgentStatus, len(agents))
	for _, a := range agents {
		rs := make(map[string]proto.RuleStatus, len(a.Rules))
		for _, r := range a.Rules {
			rs[r.ID] = r
		}
		idx[a.Name] = ruleAgentStatus{Connected: a.Connected, Generation: a.Generation, Rules: rs}
	}
	return idx
}

// ruleRunState はルールの適用状態を、持ち主のエージェントの直近のハートビートから
// 判定する(仕様 10.1 節)。無効なルールはエージェントへ配らないので、
// ハートビートの内容に関わらず disabled のままにする。判定の優先順位は、
// エージェント未登録・未接続が最優先、次に世代の古さ(反映待ち)、最後にエージェントが
// 報告したそのルールの状態(ok/error)である。世代が最新なのにエージェントがまだその
// ルールを報告していない場合(追加直後など)も反映待ちとして扱う。
func ruleRunState(r *proto.Rule, latestGen uint64, agents map[string]ruleAgentStatus, locale string) (badge, label, reason string) {
	if !r.Enabled {
		return "neutral", T(locale, "disabled"), ""
	}
	a, ok := agents[r.Agent]
	if !ok || !a.Connected {
		return "neutral", T(locale, "agentOffline"), ""
	}
	if latestGen > 0 && a.Generation != latestGen {
		return "warning", T(locale, "pending"), ""
	}
	rs, reported := a.Rules[r.ID]
	switch {
	case !reported:
		return "warning", T(locale, "pending"), ""
	case rs.State == proto.StatusError:
		return "danger", T(locale, "stateError"), rs.Reason
	default:
		return "success", T(locale, "applied"), ""
	}
}

func agentToView(a AgentInfo, latestGen uint64, locale string) agentView {
	v := agentView{Name: a.Name, Address: a.Address, StreamFrom: a.StreamFrom, WGEndpoint: a.WGEndpoint,
		Connected: a.Connected, Generation: a.Generation, WarnCount: len(a.Warnings)}
	if a.Connected {
		v.StateBadge, v.StateLabel = "success", T(locale, "online")
	} else {
		v.StateBadge, v.StateLabel = "neutral", T(locale, "offline")
		v.Attention = true
	}
	switch a.Tunnel.State {
	case proto.StatusOK:
		v.TunnelClass, v.TunnelLabel = "success-text", T(locale, "tunnelOK")
	case proto.StatusError:
		v.TunnelClass, v.TunnelLabel, v.Attention = "danger-text", T(locale, "tunnelError"), true
	default:
		v.TunnelClass, v.TunnelLabel = "muted", T(locale, "tunnelNone")
	}
	// stream の接続元 IP と WG エンドポイント IP の食い違い(窃取の兆候)
	sIP, wIP := ipOnly(a.StreamFrom), ipOnly(a.WGEndpoint)
	if sIP != "" && wIP != "" {
		v.ShowIPCompare = true
		if sIP == wIP {
			v.IPCompareClass, v.IPCompareLabel = "success-text", T(locale, "ipMatch")
		} else {
			v.IPCompareClass, v.IPCompareLabel, v.Attention = "warning-text", T(locale, "ipMismatch"), true
		}
	}
	if a.Connected && latestGen > 0 && a.Generation != latestGen {
		v.Pending, v.Attention = true, true
	}
	v.HeartbeatAgo = agoStr(a.LastHeartbeat, locale)
	if a.Connected && staleHeartbeat(a.LastHeartbeat) {
		v.HeartbeatClass = "warning-text"
	}
	v.HandshakeAgo = agoStr(a.LastHandshake, locale)
	v.PublicKey = a.PublicKey
	v.PublicKeyShort = pubKeyShort(a.PublicKey)
	if len(a.Warnings) > 0 {
		v.Attention = true
	}
	return v
}

// pubKeyShort は公開鍵の先頭だけを一覧に出す用に切る(全体は title 属性に持たせる。
// `agent pubkey` の出力と見比べられれば足りるので、これで確定はしない)。
func pubKeyShort(key string) string {
	const n = 12
	if len(key) <= n {
		return key
	}
	return key[:n] + "…"
}

// ruleToView は 1 件のビューを作る。serverMode が "userspace" のときは、ルールごとの
// vps_mode(kernel/proxy)に意味が無い(仕様 6.3 節。全ルールが server 経由で中継される)ので、
// 一覧の方式欄は一律 "userspace" にし、PROXY protocol の有無だけを添える。適用状態は
// ruleRunState がエージェントの直近のハートビートから判定する(仕様 10.1 節)。
func ruleToView(r *proto.Rule, drops map[string]uint64, locale, serverMode string, latestGen uint64, agents map[string]ruleAgentStatus) ruleView {
	mode := string(r.VPSMode)
	if serverMode == "userspace" {
		mode = "userspace"
	}
	v := ruleView{ID: r.ID, Agent: r.Agent, Target: r.TargetDisplay(), Mode: mode,
		ProxyProtocol: r.ProxyProtocol, Enabled: r.Enabled, Ports: r.ListenPort.String()}
	v.ProtoUpper = strings.ToUpper(string(r.Proto))
	if r.Proto == proto.UDP {
		v.ProtoClass = "udp"
	} else {
		v.ProtoClass = "tcp"
	}
	v.StateBadge, v.StateLabel, v.StateReason = ruleRunState(r, latestGen, agents, locale)
	v.CanCheck = r.Enabled && r.Proto == proto.TCP
	v.Dropped = strconv.FormatUint(drops[r.ID], 10)
	v.Restriction = restrictionSummary(r, locale)
	v.Note = r.Note
	return v
}

// groupRules は一覧をグループごとにまとめる。空グループ(その他)は最後(仕様 10.1)。
// 戻り値の 2 つ目は全体の error 状態のルール数(ヘッダの全体ヘルスに使う)。
func groupRules(rules []proto.Rule, drops map[string]uint64, locale, serverMode string, latestGen uint64, agents map[string]ruleAgentStatus) ([]ruleGroupView, int) {
	idx := map[string]int{}
	var out []ruleGroupView
	totalErrors := 0
	for i := range rules {
		g := rules[i].Group
		j, ok := idx[g]
		if !ok {
			j = len(out)
			idx[g] = j
			label := g
			if label == "" {
				label = T(locale, "ungrouped")
			}
			out = append(out, ruleGroupView{Group: g, Label: label})
		}
		v := ruleToView(&rules[i], drops, locale, serverMode, latestGen, agents)
		if v.StateBadge == "danger" {
			out[j].ErrorCount++
			totalErrors++
		}
		out[j].Rules = append(out[j].Rules, v)
	}
	sort.SliceStable(out, func(a, b int) bool {
		if (out[a].Group == "") != (out[b].Group == "") {
			return out[b].Group == ""
		}
		return out[a].Group < out[b].Group
	})
	return out, totalErrors
}

func restrictionSummary(r *proto.Rule, locale string) string {
	var parts []string
	if len(r.SourceDeny) > 0 {
		parts = append(parts, fmt.Sprintf(T(locale, "denyN"), len(r.SourceDeny)))
	}
	if len(r.SourceAllow) > 0 {
		parts = append(parts, fmt.Sprintf(T(locale, "allowN"), len(r.SourceAllow)))
	}
	for label, rate := range map[string]*proto.Rate{T(locale, "rateNewFlow"): r.NewFlowRate, T(locale, "ratePkt"): r.PacketRate, T(locale, "rateSource"): r.PerSourceRate} {
		if rate != nil {
			parts = append(parts, label+" "+rate.String())
		}
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return T(locale, "allowAll")
	}
	return strings.Join(parts, " / ")
}

func warnToView(w Warning, locale string) warnView {
	v := warnView{Agent: w.Agent, Kind: w.Kind, Detail: w.Detail, Ago: agoStr(w.At, locale), AlertClass: "danger-alert"}
	switch w.Kind {
	case store.WarnIPMismatch:
		v.Title, v.Body = T(locale, "warnMismatchTitle"), T(locale, "warnMismatchBody")
	case store.WarnIPFlapping:
		v.Title, v.Body = T(locale, "warnFlappingTitle"), T(locale, "warnFlappingBody")
	default:
		v.Title = w.Kind
	}
	return v
}

// ---- ハンドラ ----

func (s *Server) uiDashboard(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildDash(resolveLocale(w, r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderHTML(w, "dashboard", d)
}

func (s *Server) uiAgentsPartial(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildDash(resolveLocale(w, r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderHTML(w, "agents", d)
}

func (s *Server) uiWarningsPartial(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildDash(resolveLocale(w, r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderHTML(w, "warnings", d)
}

func (s *Server) uiAddRuleForm(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, r, "addRuleTitle", "addrule", map[string]any{"Agents": s.agentsOrNil(), "Groups": s.existingGroups(), "Mode": s.serverMode()})
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
	if _, err := s.backend.Batch(BatchRequest{Upsert: []proto.Rule{rule}, Force: r.FormValue("force") == "1"}); err != nil {
		s.renderPage(w, r, "addRuleTitle", "addrule", map[string]any{"Agents": s.agentsOrNil(), "Groups": s.existingGroups(), "Mode": mode, "Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// findRule は ID で 1 件返す。
func (s *Server) findRule(id string) (proto.Rule, bool) {
	rules, _ := s.backend.Rules()
	for _, r := range rules {
		if r.ID == id {
			return r, true
		}
	}
	return proto.Rule{}, false
}

// ---- ルール詳細ページ(仕様 10.1 節) ----

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
		ShowPacketNote:  serverMode == "userspace" && rule.Proto == proto.TCP,
	}
	gen, _ := s.backend.Generation()
	agents, _ := s.backend.Agents()
	d.StateBadge, d.StateLabel, d.StateReason = ruleRunState(&rule, gen, buildAgentIndex(agents), locale)
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
	rule, ok := s.findRule(r.PathValue("id"))
	if !ok {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	s.renderDetailPage(w, locale, s.ruleDetailView(rule, locale))
}

func (s *Server) uiEditMeta(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	locale := resolveLocale(w, r)
	rule, ok := s.findRule(r.PathValue("id"))
	if !ok {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	updated := rule
	updated.Group = strings.TrimSpace(r.FormValue("group"))
	updated.Note = strings.TrimSpace(r.FormValue("note"))
	if _, err := s.backend.Batch(BatchRequest{Upsert: []proto.Rule{updated}}); err != nil {
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
	rule, ok := s.findRule(r.PathValue("id"))
	if !ok {
		http.Error(w, "rule not found", http.StatusNotFound)
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
	if _, err := s.backend.Batch(BatchRequest{Upsert: []proto.Rule{updated}}); err != nil {
		s.renderSourceError(w, locale, rule, allow, input, err)
		return
	}
	http.Redirect(w, r, "/ui/rules/"+rule.ID, http.StatusSeeOther)
}

func (s *Server) uiSourceRm(w http.ResponseWriter, r *http.Request, allow bool) {
	r.ParseForm()
	rule, ok := s.findRule(r.PathValue("id"))
	if !ok {
		http.Error(w, "rule not found", http.StatusNotFound)
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
	_, err = s.backend.Batch(BatchRequest{Upsert: []proto.Rule{updated}})
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
	rule, ok := s.findRule(r.PathValue("id"))
	if !ok {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	perSource, errPS := s.parseRateField(r, "per_source", T(locale, "ratePerSourceHead"), locale)
	newFlow, errNF := s.parseRateField(r, "new_flow", T(locale, "rateNewFlowHead"), locale)
	packet, errPkt := s.parseRateField(r, "packet", T(locale, "ratePacketHead"), locale)
	if err := firstErr(errPS, errNF, errPkt); err != nil {
		d := s.ruleDetailView(rule, locale)
		d.RateError, d.Rates = err.Error(), s.rateFormFromRequest(r)
		s.renderDetailPage(w, locale, d)
		return
	}
	updated := rule
	updated.PerSourceRate, updated.NewFlowRate, updated.PacketRate = perSource, newFlow, packet
	if _, err := s.backend.Batch(BatchRequest{Upsert: []proto.Rule{updated}}); err != nil {
		d := s.ruleDetailView(rule, locale)
		d.RateError, d.Rates = err.Error(), s.rateFormFromRequest(r)
		s.renderDetailPage(w, locale, d)
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

func (s *Server) uiAddAgentForm(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, r, "addAgentTitle", "addagent", map[string]any{})
}

func (s *Server) uiAddAgent(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	res, err := s.backend.JoinString(r.FormValue("name"))
	if err != nil {
		s.renderPage(w, r, "addAgentTitle", "addagent", map[string]any{"Error": err.Error()})
		return
	}
	s.renderPage(w, r, "addAgentTitle", "addagent", map[string]any{"JoinString": res.JoinString, "ExpiresAt": res.ExpiresAt})
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

func (s *Server) uiRuleEnable(w http.ResponseWriter, r *http.Request)  { s.setEnabled(w, r, true) }
func (s *Server) uiRuleDisable(w http.ResponseWriter, r *http.Request) { s.setEnabled(w, r, false) }

func (s *Server) setEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	id := r.PathValue("id")
	rules, err := s.backend.Rules()
	if err == nil {
		for i := range rules {
			if rules[i].ID == id {
				rules[i].Enabled = enabled
				_, err = s.backend.Batch(BatchRequest{Upsert: []proto.Rule{rules[i]}})
				break
			}
		}
	}
	s.redirectOrError(w, r, err)
}

func (s *Server) uiRuleDelete(w http.ResponseWriter, r *http.Request) {
	_, err := s.backend.Batch(BatchRequest{Delete: []string{r.PathValue("id")}})
	s.redirectOrError(w, r, err)
}

func (s *Server) uiRevoke(w http.ResponseWriter, r *http.Request) {
	s.redirectOrError(w, r, s.backend.Revoke(r.PathValue("name")))
}
func (s *Server) uiDismissWarning(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	s.redirectOrError(w, r, s.backend.DismissWarning(r.PathValue("name"), r.FormValue("kind"), r.FormValue("detail")))
}

// ---- 補助 ----

func (s *Server) agentsOrNil() []AgentInfo {
	a, _ := s.backend.Agents()
	return a
}

func (s *Server) renderHTML(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := uiTmpl.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

func (s *Server) renderPage(w http.ResponseWriter, r *http.Request, titleKey, body string, data map[string]any) {
	locale := resolveLocale(w, r)
	data["Locale"] = locale
	var inner bytes.Buffer
	if err := uiTmpl.ExecuteTemplate(&inner, body, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderHTML(w, "page", map[string]any{"Locale": locale, "Title": T(locale, titleKey), "Body": template.HTML(inner.String())})
}

func (s *Server) redirectOrError(w http.ResponseWriter, r *http.Request, err error) {
	s.redirectOrErrorTo(w, r, "/", err)
}

// redirectOrErrorTo は redirectOrError の宛先を選べる版(ルール詳細ページへ戻すときに使う)。
func (s *Server) redirectOrErrorTo(w http.ResponseWriter, r *http.Request, to string, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// serverView はダッシュボード上部の「サーバー」帯。
type serverView struct {
	Version, Uptime, Mode, Endpoint, WG, AgentAPI, MTU, Kernel, NFT, IPForward, Conntrack string
}

func serverToView(info ServerInfo, locale string) serverView {
	v := serverView{
		Version:   orDash(info.Version),
		Mode:      orDash(info.Mode),
		Endpoint:  orDash(info.WGEndpoint),
		WG:        fmt.Sprintf("%s %s :%d", info.WGInterface, info.WGAddress, info.WGPort),
		AgentAPI:  ":" + orDash(info.AgentAPIPort),
		MTU:       strconv.Itoa(info.MTU),
		Kernel:    orDash(info.Kernel),
		NFT:       orDash(info.NFT),
		Conntrack: fmt.Sprintf("%d / %d s", info.UDPTimeout, info.UDPTimeoutStream),
	}
	if t, err := time.Parse(time.RFC3339, info.StartedAt); err == nil {
		v.Uptime = uptimeStr(time.Since(t), locale)
	} else {
		v.Uptime = "-"
	}
	if info.IPForwardSetAt != "" {
		v.IPForward = T(locale, "ipfBywgft")
	} else {
		v.IPForward = T(locale, "ipfDefault")
	}
	return v
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func uptimeStr(d time.Duration, locale string) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if locale == "en" {
		switch {
		case days > 0:
			return fmt.Sprintf("%dd %dh", days, hours)
		case hours > 0:
			return fmt.Sprintf("%dh %dm", hours, mins)
		default:
			return fmt.Sprintf("%dm", mins)
		}
	}
	switch {
	case days > 0:
		return fmt.Sprintf("%d日 %d時間", days, hours)
	case hours > 0:
		return fmt.Sprintf("%d時間 %d分", hours, mins)
	default:
		return fmt.Sprintf("%d分", mins)
	}
}

func firewallText(locale string) string {
	out, err := exec.Command("nft", "list", "table", "inet", "wgft").CombinedOutput()
	if err != nil {
		return T(locale, "noNftTable")
	}
	return string(out)
}

func ipOnly(hostport string) string {
	if hostport == "" {
		return ""
	}
	if h, _, err := splitHostPortLoose(hostport); err == nil {
		return h
	}
	return hostport
}

func splitHostPortLoose(s string) (string, string, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, "", nil
	}
	return s[:i], s[i+1:], nil
}

func agoStr(rfc3339, locale string) string {
	if rfc3339 == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return rfc3339
	}
	d := time.Since(t)
	if locale == "en" {
		switch {
		case d < time.Minute:
			return fmt.Sprintf("%ds ago", int(d.Seconds()))
		case d < time.Hour:
			return fmt.Sprintf("%dm ago", int(d.Minutes()))
		default:
			return fmt.Sprintf("%dh ago", int(d.Hours()))
		}
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d秒前", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d分前", int(d.Minutes()))
	default:
		return fmt.Sprintf("%d時間前", int(d.Hours()))
	}
}

func staleHeartbeat(rfc3339 string) bool {
	t, err := time.Parse(time.RFC3339, rfc3339)
	return err == nil && time.Since(t) > 90*time.Second
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
