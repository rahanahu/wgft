package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/rahanahu/wgft/proto"
)

// importMaxBytes はアップロードの上限(仕様 10.1 節)。管理用 API の JSON ボディの
// 上限(admin.go の postBatch)と同じ 1 MiB を使う。
const importMaxBytes = 1 << 20

// importApplyMaxBytes は確認ページの適用(uiImportApply)が受ける POST 本体の上限。
// 確認ページはアップロードした内容を hidden の "content" フィールドに
// application/x-www-form-urlencoded で入れて送り返すため、content 中の `"` `{` `:` `/` の
// ような文字は 1 バイトが %XX の 3 バイトに膨れる。importMaxBytes 分の内容が全部膨れた場合
// (3 倍)に、force・generation・digest の分の余裕(64 KiB)を足した値を本体の上限にする。
// デコード後の content 自身が importMaxBytes に収まることは uiImportApply が別途見る。
const importApplyMaxBytes = 3*importMaxBytes + 64<<10

// importChangeView は読み込みの確認ページの 1 行(仕様 10.1 節)。
type importChangeView struct {
	Kind    string // added / changed / deleted / unchanged(CSS のクラスにも使う)
	Symbol  string
	Summary string
	Details []string
	Note    string // deleted 行にだけ付く、セッションが切れる旨の注記
}

// importConfirmData は読み込みの確認ページ(POST /ui/rules/import の応答)のビュー。
type importConfirmData struct {
	Locale                             string
	FileName                           string
	Added, Changed, Deleted, Unchanged int
	Changes                            []importChangeView
	Issues                             []string
	CanApply                           bool
	HasDeletions                       bool
	Force                              bool
	Content, Generation, Digest        string
}

// uiRulesExport は現在の全ルールを、CLI の `rule import` が読む配列と同じ形の JSON で
// ダウンロードさせる(仕様 10.1 節)。
func (s *Server) uiRulesExport(w http.ResponseWriter, r *http.Request) {
	rules, err := s.backend.Rules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rules == nil {
		rules = []proto.Rule{}
	}
	b, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="rules.json"`)
	w.Write(b)
}

func (s *Server) uiImportForm(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, r, "importTitle", "importform", map[string]any{})
}

// uiImportConfirm はアップロードされた JSON を解釈し、まだ適用せずに差分の確認ページを
// 表示する(仕様 10.1 節)。空 ID のルールには CLI の `rule import` と同じ形で ID を
// 割り当てる。
func (s *Server) uiImportConfirm(w http.ResponseWriter, r *http.Request) {
	locale := resolveLocale(w, r)
	r.Body = http.MaxBytesReader(w, r.Body, importMaxBytes)
	if err := r.ParseMultipartForm(importMaxBytes); err != nil {
		s.renderPage(w, r, "importTitle", "importform", map[string]any{"Error": err.Error()})
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		s.renderPage(w, r, "importTitle", "importform", map[string]any{"Error": T(locale, "importChooseFileError")})
		return
	}
	defer file.Close()
	body, err := io.ReadAll(file)
	if err != nil {
		s.renderPage(w, r, "importTitle", "importform", map[string]any{"Error": err.Error()})
		return
	}
	var desired []proto.Rule
	if err := json.Unmarshal(body, &desired); err != nil {
		s.renderPage(w, r, "importTitle", "importform", map[string]any{"Error": "JSON: " + err.Error()})
		return
	}
	for i := range desired {
		if desired[i].ID == "" {
			desired[i].ID = "r_" + newULID()
		}
	}
	s.renderImportConfirm(w, locale, header.Filename, desired, r.FormValue("force") == "1")
}

// renderImportConfirm builds and renders the confirmation page for a parsed, ID-assigned
// desired rule set (called both from uiImportConfirm and, on a stale re-check failure,
// nowhere else -- the apply handler re-renders "importstale" instead, per design 10.1).
func (s *Server) renderImportConfirm(w http.ResponseWriter, locale, filename string, desired []proto.Rule, force bool) {
	current, err := s.backend.Rules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	gen, _ := s.backend.Generation()
	agents, _ := s.backend.Agents()
	agentNames := make(map[string]bool, len(agents))
	for _, a := range agents {
		agentNames[a.Name] = true
	}
	content, err := json.Marshal(desired)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := importConfirmData{
		Locale: locale, FileName: filename, Force: force,
		Content: string(content), Generation: strconv.FormatUint(gen, 10), Digest: proto.RulesDigest(current),
		Issues: importIssues(desired, current, agentNames),
	}
	for _, c := range proto.DiffRules(current, desired) {
		switch c.Kind {
		case proto.ChangeAdded:
			data.Added++
		case proto.ChangeChanged:
			data.Changed++
		case proto.ChangeDeleted:
			data.Deleted++
			data.HasDeletions = true
		case proto.ChangeUnchanged:
			data.Unchanged++
			continue // 一覧には出さない。件数だけ数える
		}
		data.Changes = append(data.Changes, importChangeToView(c, locale))
	}
	data.CanApply = len(data.Issues) == 0

	s.renderImportPage(w, locale, "importConfirmTitle", "importconfirm", data)
}

// importIssues は、適用ボタンを出さない条件(仕様 10.1 節)を集める。未登録の
// エージェントを指すルールと、Rule.Validate / 全体の重複・重なりに落ちるルールである。
// Rule.Validate は、適用時のバッチ(proto.ValidateUpsert)と同じく、current から変わって
// いない行には掛けない。後から増えた検査に落ちる古い行(例:proxy の範囲)があっても、
// その行を変えない読み込みは CLI と同じく適用できる。
func importIssues(desired, current []proto.Rule, agents map[string]bool) []string {
	var out []string
	unchanged := proto.UnchangedIDs(desired, current)
	for _, r := range desired {
		if !unchanged[r.ID] {
			if err := r.Validate(); err != nil {
				out = append(out, fmt.Sprintf("rule %s: %v", r.ID, err))
				continue
			}
		}
		if !agents[r.Agent] {
			out = append(out, fmt.Sprintf("rule %s: agent %q is not registered", r.ID, r.Agent))
		}
	}
	// 行ごとの誤りが無いときだけ全体の検査(ID の重複、重なり)を足す。行ごとの誤りを
	// 全体の検査がもう一度報告して、同じ行が 2 回出るのを避ける
	if len(out) == 0 {
		if err := proto.ValidateUpsert(desired, current, nil); err != nil {
			out = append(out, err.Error())
		}
	}
	return out
}

func importChangeToView(c proto.RuleChange, locale string) importChangeView {
	v := importChangeView{Kind: string(c.Kind), Summary: ruleChangeSummary(c.Rule)}
	switch c.Kind {
	case proto.ChangeAdded:
		v.Symbol = "+"
	case proto.ChangeChanged:
		v.Symbol = "~"
		for _, fc := range c.FieldChanges {
			v.Details = append(v.Details, fieldChangeText(fc, locale))
		}
	case proto.ChangeDeleted:
		v.Symbol = "-"
		v.Note = T(locale, "importDeletedNote")
	}
	return v
}

func ruleChangeSummary(r proto.Rule) string {
	return fmt.Sprintf("%s %s → %s %s", strings.ToUpper(string(r.Proto)), r.ListenPort.String(), r.Agent, r.TargetDisplay())
}

// diffFieldLabelKey は proto.FieldChange.Field(英語の固定キー)から i18n キーへの対応。
var diffFieldLabelKey = map[string]string{
	"agent":           "diffFieldAgent",
	"group":           "diffFieldGroup",
	"note":            "diffFieldNote",
	"proto":           "diffFieldProto",
	"listen_port":     "diffFieldListenPort",
	"target":          "diffFieldTarget",
	"vps_mode":        "diffFieldMode",
	"proxy_protocol":  "diffFieldProxyProtocol",
	"source_deny":     "diffFieldDenyList",
	"source_allow":    "diffFieldAllowList",
	"new_flow_rate":   "diffFieldNewFlowRate",
	"packet_rate":     "diffFieldPacketRate",
	"per_source_rate": "diffFieldPerSourceRate",
	"enabled":         "diffFieldEnabled",
}

// fieldChangeText はルールごとの変更点 1 つを、確認ページに出す訳済みの短い文にする
// (仕様 10.1 節)。
func fieldChangeText(fc proto.FieldChange, locale string) string {
	label := T(locale, diffFieldLabelKey[fc.Field])
	switch fc.Field {
	case "source_deny", "source_allow":
		return fmt.Sprintf(T(locale, "diffSetFmt"), label, sourceSetDiffText(fc.Old, fc.New))
	case "group", "note":
		return fmt.Sprintf(T(locale, "diffValueFmt"), label, orNoneLabel(fc.Old, locale), orNoneLabel(fc.New, locale))
	case "proxy_protocol", "enabled":
		return fmt.Sprintf(T(locale, "diffValueFmt"), label, boolLabel(fc.Old, locale), boolLabel(fc.New, locale))
	case "new_flow_rate", "packet_rate", "per_source_rate":
		return fmt.Sprintf(T(locale, "diffValueFmt"), label, orNoLimitLabel(fc.Old, locale), orNoLimitLabel(fc.New, locale))
	default:
		return fmt.Sprintf(T(locale, "diffValueFmt"), label, fc.Old, fc.New)
	}
}

// sourceSetDiffText は proto.FieldChange の Old/New(拒否/許可リストなら、CIDR をソートして
// ", " でつないだ一覧。proto.joinPrefixes が作る)を前後で比べ、"+追加された CIDR -外れた CIDR"
// の短い一覧にする。件数が同じ入れ替え(例:203.0.113.0/24 を 198.51.100.0/24 に差し替え)でも
// 内容の変化がそのまま見えるようにするための表示専用の整形である。
func sourceSetDiffText(oldCSV, newCSV string) string {
	oldSet, newSet := splitCIDRSet(oldCSV), splitCIDRSet(newCSV)
	var added, removed []string
	for _, p := range newSet {
		if !containsStr(oldSet, p) {
			added = append(added, "+"+p)
		}
	}
	for _, p := range oldSet {
		if !containsStr(newSet, p) {
			removed = append(removed, "-"+p)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return strings.Join(append(added, removed...), " ")
}

func splitCIDRSet(csv string) []string {
	if csv == "" {
		return nil
	}
	return strings.Split(csv, ", ")
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func orNoneLabel(s, locale string) string {
	if s == "" {
		return T(locale, "listEmpty")
	}
	return s
}

func orNoLimitLabel(s, locale string) string {
	if s == "" {
		return T(locale, "noLimit")
	}
	return s
}

func boolLabel(s, locale string) string {
	if s == "true" {
		return T(locale, "boolYes")
	}
	return T(locale, "boolNo")
}

// uiImportApply は確認ページの適用(仕様 10.1 節)。確認ページを描いた時点の世代と
// ルール集合全体のハッシュ(proto.RulesDigest)を、適用時の今の値と比べる事前照合を、
// バッチを組み立てる前に安価に行い、食い違いがあれば分かりやすい再アップロードの案内を
// 出す。group、note、接続元制限、レートだけの変更は世代を上げない(5.3 節)ため、
// 世代だけの照合では見逃すのでハッシュも見る。
//
// この事前照合と Batch の呼び出しの間には、他経路の変更が割り込む狭い窓が残る
// (読み取りと変更が 1 つのロック/トランザクションでないため)。実際に見逃さない保証は
// Batch に渡す BatchRequest.ExpectedDigest が持つ。Batch はこれを、変更しようとしている
// 今のルール集合の読み取りと同じトランザクション/ロックの内側で照合するため、
// 事前照合をすり抜けた食い違いも ErrBatchConflict で拒む。ここではその誤りを、
// 事前照合が拒んだときと同じ「再アップロードを求める」画面に写す。
func (s *Server) uiImportApply(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, importApplyMaxBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	locale := resolveLocale(w, r)
	if len(r.FormValue("content")) > importMaxBytes {
		http.Error(w, "import content exceeds the 1 MiB limit", http.StatusRequestEntityTooLarge)
		return
	}
	var desired []proto.Rule
	if err := json.Unmarshal([]byte(r.FormValue("content")), &desired); err != nil {
		http.Error(w, "invalid import content: "+err.Error(), http.StatusBadRequest)
		return
	}
	current, err := s.backend.Rules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	gen, _ := s.backend.Generation()
	digest := r.FormValue("digest")
	stale := func() {
		s.renderImportPage(w, locale, "importConfirmTitle", "importstale", map[string]any{"Locale": locale})
	}
	if strconv.FormatUint(gen, 10) != r.FormValue("generation") || proto.RulesDigest(current) != digest {
		stale()
		return
	}
	del := proto.DeletedIDs(proto.DiffRules(current, desired))
	if _, err := s.backend.Batch(BatchRequest{Upsert: desired, Delete: del, Force: r.FormValue("force") == "1", ExpectedDigest: digest, Op: "ui import"}); err != nil {
		if errors.Is(err, ErrBatchConflict) {
			stale()
			return
		}
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// renderImportPage は importconfirm / importstale のような、構造体をそのままビューに
// 使うページを描く(page テンプレートの Wide 版。renderPage は map[string]any 専用なので
// ここでは使えない)。
func (s *Server) renderImportPage(w http.ResponseWriter, locale, titleKey, tmplName string, data any) {
	var inner bytes.Buffer
	if err := uiTmpl.ExecuteTemplate(&inner, tmplName, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderHTML(w, "page", map[string]any{"Locale": locale, "Title": T(locale, titleKey), "Body": template.HTML(inner.String()), "Wide": true})
}
