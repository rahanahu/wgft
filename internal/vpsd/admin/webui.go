package admin

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは Web UI のルーティング、ダッシュボードの組み立てと描画、および
// renderHTML/renderPage/redirectOrError のような、他のページも使う共通の補助を持つ。
// ルール追加・詳細ページ(meta、拒否/許可リスト、レート、有効無効)は webui_rule.go、
// 分割・統合は webui_splitmerge.go、ルールの適用状態の判定は webui_state.go、
// エージェントの追加・無効化・警告の削除は webui_agent.go、ルールの書き出し・読み込みは
// webui_import.go に分ける。

func newULID() string { return ulid.Make().String() }

//go:embed webui/templates/*.gohtml
var tmplFS embed.FS

//go:embed webui/static/*
var staticFS embed.FS

var uiTmpl = template.Must(template.New("").Funcs(template.FuncMap{"T": T, "UnitLabel": unitLabel}).ParseFS(tmplFS, "webui/templates/*.gohtml"))

// registerUI は Web UI のルートを mux に足す(認証は ServeHTTP でかかる)。
func (s *Server) registerUI() {
	staticSub, _ := fs.Sub(staticFS, "webui/static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticSub)))
	s.mux.HandleFunc("GET /{$}", s.uiDashboard)
	s.mux.HandleFunc("GET /ui/agents", s.uiAgentsPartial)
	s.mux.HandleFunc("GET /ui/warnings", s.uiWarningsPartial)
	s.mux.HandleFunc("GET /ui/rules", s.uiRulesPartial)
	s.mux.HandleFunc("GET /ui/health", s.uiHealthPartial)
	s.mux.HandleFunc("GET /ui/add-rule", s.uiAddRuleForm)
	s.mux.HandleFunc("POST /ui/add-rule", s.uiAddRule)
	s.mux.HandleFunc("GET /ui/add-agent", s.uiAddAgentForm)
	s.mux.HandleFunc("POST /ui/add-agent", s.uiAddAgent)
	s.mux.HandleFunc("GET /ui/rules/export", s.uiRulesExport)
	s.mux.HandleFunc("GET /ui/rules/import", s.uiImportForm)
	s.mux.HandleFunc("POST /ui/rules/import", s.uiImportConfirm)
	s.mux.HandleFunc("POST /ui/rules/import/apply", s.uiImportApply)
	s.mux.HandleFunc("GET /ui/rules/{id}/check", s.uiCheck)
	s.mux.HandleFunc("GET /ui/rules/{id}", s.uiRuleDetail)
	s.mux.HandleFunc("POST /ui/rules/{id}/meta", s.uiEditMeta)
	s.mux.HandleFunc("POST /ui/rules/{id}/deny/add", s.uiDenyAdd)
	s.mux.HandleFunc("POST /ui/rules/{id}/deny/rm", s.uiDenyRm)
	s.mux.HandleFunc("POST /ui/rules/{id}/allow/add", s.uiAllowAdd)
	s.mux.HandleFunc("POST /ui/rules/{id}/allow/rm", s.uiAllowRm)
	s.mux.HandleFunc("POST /ui/rules/{id}/rates", s.uiSetRates)
	s.mux.HandleFunc("POST /ui/rules/{id}/split", s.uiRuleSplit)
	s.mux.HandleFunc("POST /ui/rules/{id}/merge", s.uiRuleMerge)
	s.mux.HandleFunc("POST /ui/rules/{id}/enable", s.uiRuleEnable)
	s.mux.HandleFunc("POST /ui/rules/{id}/disable", s.uiRuleDisable)
	s.mux.HandleFunc("POST /ui/rules/{id}/delete", s.uiRuleDelete)
	s.mux.HandleFunc("POST /ui/agents/{name}/revoke", s.uiRevoke)
	s.mux.HandleFunc("POST /ui/agents/{name}/dismiss-warning", s.uiDismissWarning)
}

// ---- ビューモデル(ダッシュボード) ----

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

func (s *Server) buildDash(locale string) (dashData, error) {
	agents, err := s.backend.Agents()
	if err != nil {
		return dashData{}, err
	}
	rules, err := s.backend.Rules()
	if err != nil {
		return dashData{}, err
	}
	// generation/drops/warnings もダッシュボードの本体データであり、Agents/Rules と同じく
	// 失敗を 0 件・世代 0 のような値に変えて描いてはならない(design.md 10.5 節)。
	gen, err := s.backend.Generation()
	if err != nil {
		return dashData{}, err
	}
	drops, err := s.backend.RuleDrops()
	if err != nil {
		return dashData{}, err
	}
	warns, err := s.backend.Warnings()
	if err != nil {
		return dashData{}, err
	}

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
	d.RuleGroups, ruleErrors = groupRules(rules, drops, locale, d.Server.Mode, gen, agentIdx, s.serverApply())
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

func agentToView(a AgentInfo, latestGen uint64, locale string) agentView {
	v := agentView{Name: a.Name, Address: a.Address, StreamFrom: a.StreamFrom, WGEndpoint: a.WGEndpoint,
		Connected: a.Connected, Generation: a.Generation, WarnCount: len(a.Warnings)}
	if a.Connected {
		v.StateBadge, v.StateLabel = "success", T(locale, "online")
	} else {
		v.StateBadge, v.StateLabel = "neutral", T(locale, "offline")
		v.Attention = true
	}
	// a.Tunnel と a.StreamFrom/a.WGEndpoint は stream が切れても最後のハートビートの値を
	// 残したままなので(design.md 5.2 節)、Connected を見ずに描くと何日も前の "OK" や
	// IP の一致がそのまま今の状態に見える。切断していれば、その値を最後の報告として
	// 古いままの色(muted)で示す。ok に見える描画はしない
	switch {
	case !a.Connected:
		v.TunnelClass, v.TunnelLabel = "muted", T(locale, "tunnelStale")
	case a.Tunnel.State == proto.StatusOK:
		v.TunnelClass, v.TunnelLabel = "success-text", T(locale, "tunnelOK")
	case a.Tunnel.State == proto.StatusError:
		v.TunnelClass, v.TunnelLabel, v.Attention = "danger-text", T(locale, "tunnelError"), true
	default:
		v.TunnelClass, v.TunnelLabel = "muted", T(locale, "tunnelNone")
	}
	// stream の接続元 IP と WG エンドポイント IP の食い違い(窃取の兆候)。切断していれば
	// 両方とも履歴の値なので、比較そのものを出さない(IP match/mismatch のどちらも今を語らない)
	if a.Connected {
		sIP, wIP := ipOnly(a.StreamFrom), ipOnly(a.WGEndpoint)
		if sIP != "" && wIP != "" {
			v.ShowIPCompare = true
			if sIP == wIP {
				v.IPCompareClass, v.IPCompareLabel = "success-text", T(locale, "ipMatch")
			} else {
				v.IPCompareClass, v.IPCompareLabel, v.Attention = "warning-text", T(locale, "ipMismatch"), true
			}
		}
	}
	if a.Connected && latestGen > 0 && a.Generation != latestGen {
		v.Pending, v.Attention = true, true
	}
	v.HeartbeatAgo = agoStr(a.LastHeartbeat, locale)
	if staleHeartbeat(a.LastHeartbeat) {
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
func ruleToView(r *proto.Rule, drops map[string]uint64, locale, serverMode string, latestGen uint64, agents map[string]ruleAgentStatus, server map[string]RuleApply) ruleView {
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
	v.StateBadge, v.StateLabel, v.StateReason = ruleRunState(r, latestGen, agents, server, locale)
	v.CanCheck = r.Enabled && r.Proto == proto.TCP
	v.Dropped = strconv.FormatUint(drops[r.ID], 10)
	v.Restriction = restrictionSummary(r, locale)
	v.Note = r.Note
	return v
}

// groupRules は一覧をグループごとにまとめる。空グループ(その他)は最後(仕様 10.1)。
// 戻り値の 2 つ目は全体の error 状態のルール数(ヘッダの全体ヘルスに使う)。
func groupRules(rules []proto.Rule, drops map[string]uint64, locale, serverMode string, latestGen uint64, agents map[string]ruleAgentStatus, server map[string]RuleApply) ([]ruleGroupView, int) {
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
		v := ruleToView(&rules[i], drops, locale, serverMode, latestGen, agents, server)
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
	// 単位は詳細ページと同じく訳す(日本語で "10/second" と英語が混ざらないように)
	for key, rate := range map[string]*proto.Rate{"rateNewFlow": r.NewFlowRate, "ratePkt": r.PacketRate, "rateSource": r.PerSourceRate} {
		if rate != nil {
			parts = append(parts, fmt.Sprintf(T(locale, key), rate.Count, unitLabel(locale, string(rate.Unit))))
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

// ---- ハンドラ(ダッシュボードとその部分更新) ----

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

func (s *Server) uiRulesPartial(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildDash(resolveLocale(w, r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderHTML(w, "rules", d)
}

func (s *Server) uiHealthPartial(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildDash(resolveLocale(w, r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderHTML(w, "health", d)
}

// findRule は ID で 1 件返す。ルール一覧そのものが読めなければ、無いルールと区別するため
// エラーを返す(design.md 10.5 節。読み取りの失敗を「無い」に変えて見せない)。
func (s *Server) findRule(id string) (proto.Rule, bool, error) {
	rules, err := s.backend.Rules()
	if err != nil {
		return proto.Rule{}, false, err
	}
	for _, r := range rules {
		if r.ID == id {
			return r, true, nil
		}
	}
	return proto.Rule{}, false, nil
}

// findRuleOr404 は findRule の応答つき版。ルール詳細ページの各ハンドラ(meta、
// deny/allow、rates、split、merge の self 側)が繰り返す「無ければ 404 を書いて戻る」を
// まとめる。呼び出し側は ok を見て return するのは変わらず、分岐そのものは隠さない。
// ルール一覧が読めない場合は 404 ではなく 500 にする(store の障害を「そのルールは無い」と
// 見せてはならない)。
func (s *Server) findRuleOr404(w http.ResponseWriter, id string) (proto.Rule, bool) {
	rule, ok, err := s.findRule(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return proto.Rule{}, false
	}
	if !ok {
		http.Error(w, "rule not found", http.StatusNotFound)
	}
	return rule, ok
}

// ---- 補助(ページ描画・リダイレクト。他のページも使う) ----

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
