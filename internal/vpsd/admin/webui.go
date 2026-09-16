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
	s.mux.HandleFunc("GET /ui/rules/{id}/meta", s.uiEditMetaForm)
	s.mux.HandleFunc("POST /ui/rules/{id}/meta", s.uiEditMeta)
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
	WarnCount                             int
	Attention                             bool
}

type ruleView struct {
	ID, Agent, Target, Mode          string
	ProtoUpper, ProtoClass, Ports    string
	ProxyProtocol, Enabled, CanCheck bool
	StateBadge, StateLabel           string
	Dropped                          string
	Restriction                      string
	Note                             string
}

// ruleGroupView は一覧のグループ 1 つ分。
type ruleGroupView struct {
	Group string
	Label string
	Rules []ruleView
}

type warnView struct {
	Agent, Kind, Title, Body, Detail, Ago, AlertClass string
}

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
	d.RuleCount = len(rules)
	d.RuleGroups = groupRules(rules, drops, locale)
	for _, w := range warns {
		d.Warnings = append(d.Warnings, warnToView(w, locale))
	}
	d.Health = health(len(agents), online, len(rules), len(warns), locale)
	return d, nil
}

func health(total, online, rules, warnings int, locale string) healthView {
	if warnings > 0 {
		return healthView{OK: false, Class: "", Title: T(locale, "healthWarn"), Summary: fmt.Sprintf(T(locale, "summaryWarn"), online, total, rules, warnings)}
	}
	return healthView{OK: true, Class: "success", Title: T(locale, "healthOK"), Summary: fmt.Sprintf(T(locale, "summaryOK"), online, total, rules)}
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
	if len(a.Warnings) > 0 {
		v.Attention = true
	}
	return v
}

func ruleToView(r *proto.Rule, drops map[string]uint64, locale string) ruleView {
	v := ruleView{ID: r.ID, Agent: r.Agent, Target: r.Target, Mode: string(r.VPSMode),
		ProxyProtocol: r.ProxyProtocol, Enabled: r.Enabled, Ports: r.ListenPort.String()}
	v.ProtoUpper = strings.ToUpper(string(r.Proto))
	if r.Proto == proto.UDP {
		v.ProtoClass = "udp"
	} else {
		v.ProtoClass = "tcp"
	}
	switch {
	case !r.Enabled:
		v.StateBadge, v.StateLabel = "neutral", T(locale, "disabled")
	default:
		// 適用状態はエージェントのハートビート由来だが、UI 一覧では有効=適用済みとして扱い、
		// error はエージェント一覧側で見せる(簡潔さのため)。将来、ルールごとの error を引き当てる
		v.StateBadge, v.StateLabel = "success", T(locale, "applied")
	}
	v.CanCheck = r.Enabled && r.Proto == proto.TCP
	v.Dropped = strconv.FormatUint(drops[r.ID], 10)
	v.Restriction = restrictionSummary(r, locale)
	v.Note = r.Note
	return v
}

// groupRules は一覧をグループごとにまとめる。空グループ(その他)は最後(仕様 10.1)。
func groupRules(rules []proto.Rule, drops map[string]uint64, locale string) []ruleGroupView {
	idx := map[string]int{}
	var out []ruleGroupView
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
		out[j].Rules = append(out[j].Rules, ruleToView(&rules[i], drops, locale))
	}
	sort.SliceStable(out, func(a, b int) bool {
		if (out[a].Group == "") != (out[b].Group == "") {
			return out[b].Group == ""
		}
		return out[a].Group < out[b].Group
	})
	return out
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
	s.renderPage(w, r, "addRuleTitle", "addrule", map[string]any{"Agents": s.agentsOrNil(), "Groups": s.existingGroups()})
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
	lp, err := proto.ParsePortRange(r.FormValue("listen_port"))
	if err != nil {
		s.renderPage(w, r, "addRuleTitle", "addrule", map[string]any{"Agents": s.agentsOrNil(), "Groups": s.existingGroups(), "Error": err.Error()})
		return
	}
	rule := proto.Rule{
		ID: "r_" + newULID(), Agent: r.FormValue("agent"), Proto: proto.Proto(r.FormValue("proto")),
		Group: strings.TrimSpace(r.FormValue("group")), Note: strings.TrimSpace(r.FormValue("note")),
		ListenPort: lp, Target: r.FormValue("target"), VPSMode: proto.VPSMode(r.FormValue("vps_mode")),
		ProxyProtocol: r.FormValue("proxy_protocol") == "1", Enabled: true,
		SourceAllow: []netip.Prefix{}, SourceDeny: []netip.Prefix{},
	}
	if _, err := s.backend.Batch(BatchRequest{Upsert: []proto.Rule{rule}, Force: r.FormValue("force") == "1"}); err != nil {
		s.renderPage(w, r, "addRuleTitle", "addrule", map[string]any{"Agents": s.agentsOrNil(), "Groups": s.existingGroups(), "Error": err.Error()})
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

func (s *Server) metaData(rule proto.Rule, extra map[string]any) map[string]any {
	d := map[string]any{"ID": rule.ID, "Ports": rule.ListenPort.String(), "Group": rule.Group, "Note": rule.Note, "Groups": s.existingGroups()}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

func (s *Server) uiEditMetaForm(w http.ResponseWriter, r *http.Request) {
	rule, ok := s.findRule(r.PathValue("id"))
	if !ok {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	s.renderPage(w, r, "editMetaTitle", "editmeta", s.metaData(rule, nil))
}

func (s *Server) uiEditMeta(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	rule, ok := s.findRule(r.PathValue("id"))
	if !ok {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	rule.Group = strings.TrimSpace(r.FormValue("group"))
	rule.Note = strings.TrimSpace(r.FormValue("note"))
	if _, err := s.backend.Batch(BatchRequest{Upsert: []proto.Rule{rule}}); err != nil {
		s.renderPage(w, r, "editMetaTitle", "editmeta", s.metaData(rule, map[string]any{"Error": err.Error()}))
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
