package admin

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// このファイルはエージェントの追加(接続文字列の発行)、詳細ページ、無効化と有効化、削除、警告の削除の
// ハンドラを持つ。エージェント一覧の表示側(agentToView)はダッシュボードの一部として webui.go にある。

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

// ---- エージェントの詳細ページ(設計文書 10.1 節) ----

// agentDetailData はエージェントの詳細ページ(/ui/agents/{name})のビューである。行と同じ見せ方は
// agentToView の結果(Row)をそのまま使い、一覧と詳細ページで状態の描き方が分かれないようにする。
type agentDetailData struct {
	Locale     string
	Row        agentView
	CreatedAt  string
	DisabledAt string
	Rules      []agentRuleLink
	// Error はこのページに戻した操作の誤りである。空なら出さない。
	Error string
	// ConfirmName は、削除の名前の入力が一致しなかったときに、入力を残して描き直すための値である。
	ConfirmName string
}

// agentRuleLink は詳細ページのルールの一覧の 1 行で、ルールの詳細ページへのリンクになる。
type agentRuleLink struct {
	ID, Label, Target, Note string
	Enabled                 bool
}

// findAgent は名前で 1 台を返す。一覧そのものが読めなければ、無いエージェントと区別するため
// エラーを返す(design.md 10.5 節。読み取りの失敗を「無い」に変えて見せない)。
func (s *Server) findAgent(name string) (AgentInfo, bool, error) {
	agents, err := s.backend.Agents()
	if err != nil {
		return AgentInfo{}, false, err
	}
	for _, a := range agents {
		if a.Name == name {
			return a, true, nil
		}
	}
	return AgentInfo{}, false, nil
}

// agentDetailView は詳細ページのビューを組み立てる。ルールか世代か確認済みの組が読めなければ、
// 空の一覧を捏造せずエラーを返す。
func (s *Server) agentDetailView(a AgentInfo, locale string) (agentDetailData, error) {
	gen, err := s.backend.Generation()
	if err != nil {
		return agentDetailData{}, err
	}
	var acks []store.Ack
	all, err := s.backend.IPMismatchAcks()
	if err != nil {
		return agentDetailData{}, err
	}
	for _, ack := range all {
		if ack.Agent == a.Name {
			acks = append(acks, ack)
		}
	}
	rules, err := s.backend.Rules()
	if err != nil {
		return agentDetailData{}, err
	}
	d := agentDetailData{Locale: locale, Row: agentToView(a, gen, locale, acks), CreatedAt: orDash(a.CreatedAt), DisabledAt: a.DisabledAt}
	for _, r := range rules {
		if r.Agent != a.Name {
			continue
		}
		d.Rules = append(d.Rules, agentRuleLink{ID: r.ID, Label: ruleCrumbLabel(strings.ToUpper(string(r.Proto)), r.ListenPort.String(), r.Agent),
			Target: r.TargetDisplay(), Note: r.Note, Enabled: r.Enabled})
	}
	return d, nil
}

func (s *Server) uiAgentDetail(w http.ResponseWriter, r *http.Request) {
	s.renderAgentDetail(w, r, http.StatusOK, "", "")
}

// renderAgentDetail は詳細ページを status で描く。errMsg と confirmName は、操作の誤りをこのページに
// 戻して示すときだけ渡す。エージェントが無ければ 404 にする。
func (s *Server) renderAgentDetail(w http.ResponseWriter, r *http.Request, status int, errMsg, confirmName string) {
	locale := resolveLocale(w, r)
	name := r.PathValue("name")
	a, ok, err := s.findAgent(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		// 操作の誤りを示しに来たが、エージェントが既に無い場合(削除は保存したが公開に失敗した、など)は、
		// 誤りをそのまま返す。404 にすると誤りの文が失われる。
		if errMsg != "" {
			http.Error(w, errMsg, status)
			return
		}
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}
	d, err := s.agentDetailView(a, locale)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d.Error, d.ConfirmName = errMsg, confirmName
	var inner bytes.Buffer
	if err := uiTmpl.ExecuteTemplate(&inner, "agentdetail", d); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	crumbs := []pageCrumb{dashboardCrumb(locale), {Label: fmt.Sprintf(T(locale, "agentCrumbFmt"), a.Name)}}
	var page bytes.Buffer
	if err := uiTmpl.ExecuteTemplate(&page, "page", map[string]any{"Locale": locale, "Title": T(locale, "agentDetailTitle"), "Body": template.HTML(inner.String()), "Wide": true, "Crumbs": crumbs}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	page.WriteTo(w)
}

// ---- 無効化と有効化(設計文書 5.1、10.1 節) ----

func (s *Server) uiAgentDisable(w http.ResponseWriter, r *http.Request) {
	s.uiAgentChange(w, r, s.backend.DisableAgent)
}

func (s *Server) uiAgentEnable(w http.ResponseWriter, r *http.Request) {
	s.uiAgentChange(w, r, s.backend.EnableAgent)
}

// uiAgentChange は無効化か有効化を行い、成功すれば元のページへ戻す。フォームの return が "detail"
// なら詳細ページへ、それ以外はダッシュボードへ戻す。戻り先は固定の 2 つだけで、任意の URL は受けない。
//
// 失敗は管理用 API と同じ分け方をする(admin.go の agentChange)。不明な名前は 404、書き込みの時の
// 検査の拒否と、保存は済んだが公開していない場合は 422 で、どちらかを i18n の文で詳細ページに示す。
// それ以外は 500 である。
func (s *Server) uiAgentChange(w http.ResponseWriter, r *http.Request, op func(string) (AgentDisabledResponse, error)) {
	r.ParseForm()
	name := r.PathValue("name")
	_, err := op(name)
	if err == nil {
		to := "/"
		if r.FormValue("return") == "detail" {
			to = "/ui/agents/" + url.PathEscape(name)
		}
		http.Redirect(w, r, to, http.StatusSeeOther)
		return
	}
	var ce *AgentChangeError
	switch {
	case errors.Is(err, store.ErrAgentNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.As(err, &ce):
		lead := T(resolveLocale(w, r), "agentChangeNotSaved")
		if ce.Saved {
			lead = T(resolveLocale(w, r), "agentChangeNotApplied")
		}
		s.renderAgentDetail(w, r, http.StatusUnprocessableEntity, lead+" "+err.Error(), "")
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ---- 削除(設計文書 5.1、10.1 節) ----

// uiRevoke はエージェントを削除する。フォームの confirm_name がエージェントの名前と一致したときだけ
// 削除する。詳細ページの「危険な操作」では利用者が名前を入力し、警告のバナーでは確認のダイアログの後に
// 名前を hidden で送る。照合はこの server 側で行い、ブラウザの JavaScript には頼らない。一致しなければ
// 何も削除せず、入力を残して詳細ページに誤りを示す。
func (s *Server) uiRevoke(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := r.PathValue("name")
	locale := resolveLocale(w, r)
	typed := r.FormValue("confirm_name")
	if typed != name {
		s.renderAgentDetail(w, r, http.StatusUnprocessableEntity, T(locale, "agentDeleteMismatch"), typed)
		return
	}
	if err := s.backend.Revoke(name); err != nil {
		s.renderAgentDetail(w, r, http.StatusUnprocessableEntity, T(locale, "agentDeleteFailed")+" "+err.Error(), "")
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) uiDismissWarning(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	s.redirectOrError(w, r, s.backend.DismissWarning(r.PathValue("name"), r.FormValue("kind"), r.FormValue("detail")))
}
