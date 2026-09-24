package admin

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
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
	// RulesDigest はページを描いた時点のルール集合全体のハッシュ(proto.RulesDigest)である。ルールも
	// 削除する削除のフォームが送り返し、server はそれと違う集合からは何も削除しない。
	RulesDigest string
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
	d := agentDetailData{Locale: locale, Row: agentToView(a, gen, locale, acks), CreatedAt: orDash(a.CreatedAt), DisabledAt: a.DisabledAt,
		RulesDigest: proto.RulesDigest(rules)}
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
	writePage(w, status, map[string]any{"Locale": locale, "Title": T(locale, "agentDetailTitle"), "Body": template.HTML(inner.String()), "Wide": true, "Crumbs": crumbs})
}

// writePage は共通の枠(page テンプレート)を status で書く。操作の誤りを 200 以外の状態で示すページに
// 使う。描けなければ 500 にする。
func writePage(w http.ResponseWriter, status int, data map[string]any) {
	var page bytes.Buffer
	if err := uiTmpl.ExecuteTemplate(&page, "page", data); err != nil {
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
//
// 削除が誤りを返しても、エージェントの行は既に消えていることがある。server は行を消してから
// dataplane へ公開し、公開の失敗を誤りとして返すためである(internal/vpsd の Daemon.Revoke)。そこで
// 誤りの後にエージェントを読み直し、居なければ「削除は済んだが、転送への反映はまだ」と示す。
// 居れば削除できなかったとして詳細ページに誤りを示す。
//
// delete_rules が "1" なら、エージェントを削除した後に、そのエージェントを持ち主とするルールを
// ルールのバッチ 1 回で削除する(設計文書 5.1 節)。フォームの rules_digest は詳細ページを描いた時点の
// ルール集合のハッシュ(proto.RulesDigest)で、削除の前に今の集合と比べ、違えば何もしない。バッチにも
// ExpectedDigest として渡し、比べた後からバッチまでの間の変更も、バッチのトランザクションの内側で拒む。
// 確かめた本数より多いルールを消さないためである。2 つの操作は 1 つのトランザクションではない。ルールの
// 削除だけが失敗すると、ルールは未登録のエージェントのルールとして残り、転送しない。その場合は、
// エージェントは削除したことと、ダッシュボードの未登録のエージェントの帯から削除し直せることを示す。
func (s *Server) uiRevoke(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := r.PathValue("name")
	locale := resolveLocale(w, r)
	typed := r.FormValue("confirm_name")
	if typed != name {
		s.renderAgentDetail(w, r, http.StatusUnprocessableEntity, T(locale, "agentDeleteMismatch"), typed)
		return
	}
	withRules := r.FormValue("delete_rules") == "1"
	digest := r.FormValue("rules_digest")
	if withRules {
		rules, err := s.backend.Rules()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if digest == "" || proto.RulesDigest(rules) != digest {
			s.renderAgentDetail(w, r, http.StatusConflict, T(locale, "agentRulesChanged"), typed)
			return
		}
	}
	if err := s.backend.Revoke(name); err != nil {
		if s.revokedAnyway(name) {
			log.Printf("ui: agent %s revoked, but applying the change failed: %v", name, err)
			msg := T(locale, "agentRevokedNotApplied") + " " + err.Error()
			if withRules {
				msg += " " + T(locale, "agentRulesNotDeleted")
			}
			s.renderNotice(w, r, http.StatusUnprocessableEntity, msg)
			return
		}
		s.renderAgentDetail(w, r, http.StatusUnprocessableEntity, T(locale, "agentDeleteFailed")+" "+err.Error(), "")
		return
	}
	if withRules {
		if err := s.deleteRulesOf(name, digest, "ui revoke with rules"); err != nil {
			log.Printf("ui: agent %s revoked, but deleting its rules failed: %v", name, err)
			s.renderNotice(w, r, http.StatusUnprocessableEntity, T(locale, "agentRulesLeft")+" "+err.Error())
			return
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// revokedAnyway は、誤りを返した削除の後に、エージェントの行が既に無いかを返す。読み直せなければ
// false を返し、呼び出し側は削除できなかったとして扱う。
func (s *Server) revokedAnyway(name string) bool {
	_, ok, err := s.findAgent(name)
	return err == nil && !ok
}

// rulesOf は、そのエージェントを持ち主とするルールの ID を返す。ルールの有効無効は問わない。
func (s *Server) rulesOf(agent string) ([]string, error) {
	rules, err := s.backend.Rules()
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, r := range rules {
		if r.Agent == agent {
			ids = append(ids, r.ID)
		}
	}
	return ids, nil
}

// deleteRulesOf は、そのエージェントを持ち主とするルールをルールのバッチ 1 回で削除する。digest は
// 利用者が確かめた時点のルール集合のハッシュで、バッチはそれと今の集合が違えば何も変えず
// ErrBatchConflict を返す。1 本も無ければ何もしない。
func (s *Server) deleteRulesOf(agent, digest, op string) error {
	ids, err := s.rulesOf(agent)
	if err != nil || len(ids) == 0 {
		return err
	}
	_, err = s.backend.Batch(BatchRequest{Delete: ids, ExpectedDigest: digest, Op: op})
	return err
}

// uiDeleteOrphanRules は、未登録のエージェントの帯のボタンから、そのエージェントを参照するルールを
// ルールのバッチ 1 回でまとめて削除する(設計文書 10.1 節)。次の場合は何も削除しない。
//
//   - エージェントが登録されている:帯を描いた後に同じ名前で登録し直した場合に、動いているエージェントの
//     ルールを消さないためである
//   - フォームの count(帯が示した本数)が今の本数と違う
//   - フォームの rules_digest(帯を描いた時点のルール集合のハッシュ)が今の集合と違う。照合はバッチの
//     ExpectedDigest で、バッチのトランザクションの内側で行う
//
// 後の 2 つは、確かめたより多いルールや、確かめた後に変わったルールを消さないためである。登録の確認と
// バッチの間に同じ名前で登録し直す場合は見分けない。登録はルール集合を変えないので、ハッシュでは
// 捉えられない。その間は登録の確認からバッチまでのごく短い時間であり、そこで消えるのは利用者が
// 削除を確かめたルールそのものなので、受け入れる。
func (s *Server) uiDeleteOrphanRules(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := r.PathValue("name")
	locale := resolveLocale(w, r)
	_, registered, err := s.findAgent(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if registered {
		s.renderNotice(w, r, http.StatusConflict, fmt.Sprintf(T(locale, "orphanRegistered"), name))
		return
	}
	ids, err := s.rulesOf(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	digest := r.FormValue("rules_digest")
	if n, err := strconv.Atoi(r.FormValue("count")); err != nil || n != len(ids) || digest == "" {
		s.renderNotice(w, r, http.StatusConflict, T(locale, "orphanChanged"))
		return
	}
	if len(ids) > 0 {
		_, err := s.backend.Batch(BatchRequest{Delete: ids, ExpectedDigest: digest, Op: "ui delete rules of unregistered agent"})
		switch {
		case errors.Is(err, ErrBatchConflict):
			s.renderNotice(w, r, http.StatusConflict, T(locale, "orphanChanged"))
			return
		case err != nil:
			s.renderNotice(w, r, http.StatusUnprocessableEntity, T(locale, "orphanDeleteFailed")+" "+err.Error())
			return
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// renderNotice は、操作の結果の文 1 つとダッシュボードへのリンクを、共通の枠で status のページとして描く。
// 戻る先のページが無い操作(削除したエージェントなど)の結果に使う。
func (s *Server) renderNotice(w http.ResponseWriter, r *http.Request, status int, msg string) {
	locale := resolveLocale(w, r)
	var inner bytes.Buffer
	if err := uiTmpl.ExecuteTemplate(&inner, "notice", map[string]any{"Locale": locale, "Message": msg}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	crumbs := []pageCrumb{dashboardCrumb(locale), {Label: T(locale, "noticeTitle")}}
	writePage(w, status, map[string]any{"Locale": locale, "Title": T(locale, "noticeTitle"), "Body": template.HTML(inner.String()), "Crumbs": crumbs})
}

func (s *Server) uiDismissWarning(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	s.redirectOrError(w, r, s.backend.DismissWarning(r.PathValue("name"), r.FormValue("kind"), r.FormValue("detail")))
}
