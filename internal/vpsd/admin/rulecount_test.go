package admin

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// limitRule は、agent を持ち主とする UDP の単一ポートのルールである。target のポートを listen_port と
// そろえるので、隣り合う 2 本は統合できる。
func limitRule(id, agent string, port uint16) proto.Rule {
	return proto.Rule{ID: id, Agent: agent, Proto: proto.UDP, ListenPort: proto.PortRange{Lo: port, Hi: port},
		Target: fmt.Sprintf("192.168.1.20:%d", port), VPSMode: proto.ModeKernel, Enabled: true}
}

// limitRules は agent の n 本のルールを、ID prefix0000 から、ポート base から作る。
func limitRules(agent, prefix string, base, n int) []proto.Rule {
	out := make([]proto.Rule, n)
	for i := range out {
		out[i] = limitRule(fmt.Sprintf("%s%04d", prefix, i), agent, uint16(base+i))
	}
	return out
}

// insertStoredRules は、上限の検査の前に保存されたデータを模して、rules を検査を通さずに SQL で直接書く。
func insertStoredRules(t *testing.T, path string, rules []proto.Rule) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range rules {
		js, _ := json.Marshal(r)
		if _, err := tx.Exec("INSERT INTO rules (id, position, json) VALUES (?, ?, ?)", r.ID, 1000+i, string(js)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// newLimitServer は home と other を登録したサーバを立て、stored を SQL で直接書く。
func newLimitServer(t *testing.T, stored []proto.Rule) (*httptest.Server, *store.Store, *fakeBackend) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.sqlite")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	insertStoredRules(t, path, stored)
	b := &fakeBackend{st: st, agents: []AgentInfo{{Name: "home"}, {Name: "other"}}}
	srv := httptest.NewServer(New(b))
	t.Cleanup(srv.Close)
	return srv, st, b
}

func agentCount(t *testing.T, st *store.Store, agent string) int {
	t.Helper()
	rules, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	return proto.RuleCountsByAgent(rules)[agent]
}

const overLimit = "over the limit of 512 rules per agent"

// TestBatchAPIAgentRuleLimit は、管理用 API のルールのバッチが、エージェントあたりのルールの数の上限
// (仕様 5.3、5.4 節)を既存の 422 で示し、何も保存しないことを確かめる。512 本目は通り、513 本目は
// 拒まれる。持ち主を移すバッチは移した先で判定する。
// 変異の確認:ValidateUpsert から数の判定を外すと、513 本目と移し替えが 200 になって落ちる。
func TestBatchAPIAgentRuleLimit(t *testing.T) {
	srv, st, _ := newLimitServer(t, limitRules("home", "r_h", 10000, 511))
	if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{limitRule("r_512", "home", 3000)}}); code != http.StatusOK {
		t.Fatalf("the 512th rule = %d %s, want 200", code, body)
	}
	code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{limitRule("r_513", "home", 3001)}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, `agent \"home\" would have 513 rules, `+overLimit+`; delete rules or move them to another agent first`) {
		t.Errorf("the 513th rule = %d %s, want 422 with the limit", code, body)
	}
	// 本数を変えない置き換えは通る
	if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{limitRule("r_new", "home", 3002)}, Delete: []string{"r_512"}}); code != http.StatusOK {
		t.Errorf("replacing one rule at the limit = %d %s, want 200", code, body)
	}
	// other の 1 本を home へ移すと home が 513 本になる
	if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{limitRule("r_o", "other", 4000)}}); code != http.StatusOK {
		t.Fatalf("a rule for other = %d %s", code, body)
	}
	if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{limitRule("r_o", "home", 4000)}}); code != http.StatusUnprocessableEntity || !strings.Contains(body, "would have 513 rules") {
		t.Errorf("moving a rule to home at the limit = %d %s, want 422", code, body)
	}
	// home の 1 本を other へ移すのは通る
	if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{limitRule("r_h0000", "other", 10000)}}); code != http.StatusOK {
		t.Errorf("moving a rule from home to other = %d %s, want 200", code, body)
	}
	if got := agentCount(t, st, "home"); got != 511 {
		t.Errorf("home has %d rules, want 511", got)
	}
}

// TestWebUIAgentRuleLimit は、Web UI の追加と分割が上限で拒まれ、本数を変えない無効化と、統合と削除が
// 通ることを確かめる。
// 変異の確認:ValidateUpsert から数の判定を外すと、追加と分割が通って落ちる。
func TestWebUIAgentRuleLimit(t *testing.T) {
	rules := limitRules("home", "r_h", 10000, 512)
	rules[0].ListenPort = proto.PortRange{Lo: 9000, Hi: 9001}
	rules[0].Target = "192.168.1.20:9000"
	srv, st, _ := newLimitServer(t, rules)

	resp, body := postForm(t, srv.URL+"/ui/add-rule?lang=en", url.Values{"agent": {"home"}, "proto": {"udp"}, "listen_port": {"3000"},
		"target": {"192.168.1.20:3000"}, "vps_mode": {"kernel"}}, nil)
	if resp.StatusCode == http.StatusSeeOther || !strings.Contains(html.UnescapeString(body), overLimit) {
		t.Errorf("Web UI add at the limit = %d, want the form with the limit error", resp.StatusCode)
	}
	resp, body = postForm(t, srv.URL+"/ui/rules/r_h0000/split?lang=en", url.Values{"at": {"9001"}}, nil)
	if resp.StatusCode == http.StatusSeeOther || !strings.Contains(html.UnescapeString(body), overLimit) {
		t.Errorf("Web UI split at the limit = %d, want the detail page with the limit error", resp.StatusCode)
	}
	if got := agentCount(t, st, "home"); got != 512 {
		t.Fatalf("home has %d rules after refused changes, want 512", got)
	}
	if resp, body := postForm(t, srv.URL+"/ui/rules/r_h0001/disable", url.Values{}, nil); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Web UI disable at the limit = %d %s, want 303", resp.StatusCode, body)
	}
	if resp, body := postForm(t, srv.URL+"/ui/rules/r_h0002/merge", url.Values{"other": {"r_h0003"}}, nil); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Web UI merge at the limit = %d %s, want 303", resp.StatusCode, body)
	}
	if resp, body := postForm(t, srv.URL+"/ui/rules/r_h0004/delete", url.Values{}, nil); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Web UI delete at the limit = %d %s, want 303", resp.StatusCode, body)
	}
	if got := agentCount(t, st, "home"); got != 510 {
		t.Errorf("home has %d rules, want 510", got)
	}
}

// TestOverLimitDataStaysUsable は、上限の導入の前に 512 本を超えて保存されたエージェントのデータ
// (仕様 5.4 節)で、管理用 API と Web UI が開き、一覧が全部を返し、本数を減らす変更と本数を変えない
// 変更が通り、増やす変更だけが拒まれることを確かめる。
// 変異の確認:判定を「後の本数 > 上限」だけにすると、無効化、統合、削除、置き換え、移し替えが落ちる。
func TestOverLimitDataStaysUsable(t *testing.T) {
	srv, st, b := newLimitServer(t, limitRules("home", "r_h", 10000, 600))

	resp, err := http.Get(srv.URL + "/api/v1/rules")
	if err != nil {
		t.Fatal(err)
	}
	var list BatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(list.Rules) != 600 {
		t.Fatalf("GET /api/v1/rules = %d with %d rules, want 200 with 600", resp.StatusCode, len(list.Rules))
	}
	for _, path := range []string{"/", "/ui/rules", "/ui/rules/r_h0000", "/ui/agents/home"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, resp.StatusCode)
		}
	}

	if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{limitRule("r_x", "home", 3000)}}); code != http.StatusUnprocessableEntity || !strings.Contains(body, "would have 601 rules") {
		t.Errorf("adding over the limit = %d %s, want 422", code, body)
	}
	if resp, body := postForm(t, srv.URL+"/ui/rules/r_h0000/disable", url.Values{}, nil); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Web UI disable over the limit = %d %s, want 303", resp.StatusCode, body)
	}
	if resp, body := postForm(t, srv.URL+"/ui/rules/r_h0001/merge", url.Values{"other": {"r_h0002"}}, nil); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Web UI merge over the limit = %d %s, want 303", resp.StatusCode, body)
	}
	if resp, body := postForm(t, srv.URL+"/ui/rules/r_h0003/delete", url.Values{}, nil); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Web UI delete over the limit = %d %s, want 303", resp.StatusCode, body)
	}
	if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{limitRule("r_h0004", "other", 10004)}}); code != http.StatusOK {
		t.Errorf("moving a rule to other = %d %s, want 200", code, body)
	}
	if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{limitRule("r_y", "home", 3001)}, Delete: []string{"r_h0005"}}); code != http.StatusOK {
		t.Errorf("replacing one rule = %d %s, want 200", code, body)
	}
	if got := agentCount(t, st, "home"); got != 597 {
		t.Fatalf("home has %d rules, want 597", got)
	}

	// home の登録を外すと、ダッシュボードの帯の一括削除で 597 本を 1 回で消せる
	b.agents = []AgentInfo{{Name: "other"}}
	rules, _ := st.Rules()
	resp, body := postForm(t, srv.URL+"/ui/agents/home/delete-rules", url.Values{"count": {"597"}, "rules_digest": {proto.RulesDigest(rules)}}, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("bulk delete of an unregistered agent's 597 rules = %d %s, want 303", resp.StatusCode, body)
	}
	if got := agentCount(t, st, "home"); got != 0 {
		t.Errorf("home has %d rules after the bulk delete, want 0", got)
	}
}

// TestWebUIImportAgentRuleLimit は、Web UI の読み込みの確認画面が、本数を増やす読み込みに上限の理由を
// 示して適用のボタンを出さないこと、上限を超えたデータを同じ本数で置き換える読み込みと移し替えには
// 何も示さず適用できることを確かめる。確認画面と適用は PreflightBatch と保存の経路の同じ判定を使う。
// 変異の確認:ValidateUpsert から数の判定を外すと、本数を増やす読み込みに理由が出ず落ちる。
func TestWebUIImportAgentRuleLimit(t *testing.T) {
	stored := limitRules("home", "r_h", 10000, 600)
	srv, st, _ := newLimitServer(t, stored)
	upload := func(rules []proto.Rule) string {
		t.Helper()
		js, _ := json.Marshal(rules)
		resp := multipartUpload(t, srv.URL+"/ui/rules/import?lang=en", "rules.json", js)
		defer resp.Body.Close()
		page, _ := io.ReadAll(resp.Body)
		return string(page)
	}

	grown := append(append([]proto.Rule(nil), stored...), limitRule("r_x", "home", 3000))
	page := upload(grown)
	if s := html.UnescapeString(page); !strings.Contains(s, "Cannot apply") || !strings.Contains(s, `agent "home" would have 601 rules`) {
		t.Errorf("import confirm of 601 rules must show the limit and offer no apply")
	}

	// 1 本を other へ移し、残りを別の ID で置き換える
	repl := limitRules("home", "r_n", 20000, 599)
	repl = append(repl, limitRule("r_o", "other", 30000))
	page = upload(repl)
	if strings.Contains(page, "Cannot apply") {
		t.Fatalf("import confirm of a count-neutral replacement must offer apply")
	}
	fields := extractHiddenFields(t, page)
	resp, err := http.PostForm(srv.URL+"/ui/rules/import/apply", url.Values{
		"content": {fields["content"]}, "generation": {fields["generation"]}, "digest": {fields["digest"]},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := agentCount(t, st, "home"); got != 599 {
		t.Errorf("home has %d rules after the import, want 599", got)
	}
}

// TestPreflightBatchAgentRuleLimit は、CLI の --dry-run と Web UI の読み込みの確認が使う PreflightBatch
// が、保存の経路と同じ上限の誤りを返すことを確かめる。
func TestPreflightBatchAgentRuleLimit(t *testing.T) {
	current := limitRules("home", "r_h", 10000, 512)
	agents := map[string]bool{"home": true}
	add := []proto.Rule{limitRule("r_x", "home", 3000)}
	set := MergeBatch(current, BatchRequest{Upsert: add}).Rules
	errs := PreflightBatch(add, current, set, agents, nil)
	var le *proto.AgentRuleLimitError
	if len(errs) != 1 || !errors.As(errs[0], &le) || le.Agent != "home" || le.After != 513 {
		t.Errorf("PreflightBatch of the 513th rule = %v, want the limit error", errs)
	}
	if errs := PreflightBatch(nil, current, current, agents, nil); len(errs) != 0 {
		t.Errorf("PreflightBatch of an unchanged set at the limit = %v, want none", errs)
	}
}

// TestStoredLongTargetKeepsWorking は、target の検査(仕様 5.3 節)の前に保存された、260 バイト以上の
// target の行の扱い(仕様 5.4 節)を管理用 API と Web UI で確かめる。新しい行は 422 で拒む。保存済みの行は
// 一覧に出て、無関係な追加と、集合をそのまま戻すバッチを妨げない。その target のままの無効化は拒み、
// target を正しい値に変える書き換えと削除は通る。
// 変異の確認:ValidateUpsert が変わらない行の検査を飛ばさないようにすると、無関係な追加が落ちる。
func TestStoredLongTargetKeepsWorking(t *testing.T) {
	long := strings.Repeat("a", 300) + ":80"
	legacy := limitRule("r_long", "home", 3002)
	legacy.Target = long
	legacy2 := limitRule("r_long2", "home", 3004)
	legacy2.Target = long
	srv, st, _ := newLimitServer(t, []proto.Rule{legacy, legacy2})

	fresh := limitRule("r_new", "home", 3003)
	fresh.Target = long
	if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{fresh}}); code != http.StatusUnprocessableEntity || !strings.Contains(body, "target is 303 bytes long; the limit is 259 bytes") {
		t.Errorf("a new rule with a 303-byte target = %d %s, want 422", code, body)
	}
	if rules, _ := st.Rules(); len(rules) != 2 || rules[0].Target != long {
		t.Fatalf("rules = %+v, want the stored rows unchanged", rules)
	}
	if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{limitRule("r_other", "home", 4000)}}); code != http.StatusOK {
		t.Errorf("an unrelated add = %d %s, want 200", code, body)
	}
	if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{legacy, legacy2}}); code != http.StatusOK {
		t.Errorf("upserting the stored rows unchanged = %d %s, want 200", code, body)
	}
	if resp, body := postForm(t, srv.URL+"/ui/rules/r_long/disable", url.Values{}, nil); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "target is 303 bytes long") {
		t.Errorf("Web UI disable of the stored row = %d %s, want 422", resp.StatusCode, body)
	}
	fixed := legacy
	fixed.Target = "192.168.1.20:3002"
	fixed.Enabled = false
	if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{fixed}}); code != http.StatusOK {
		t.Errorf("fixing the target = %d %s, want 200", code, body)
	}
	if resp, body := postForm(t, srv.URL+"/ui/rules/r_long2/delete", url.Values{}, nil); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Web UI delete of the stored row = %d %s, want 303", resp.StatusCode, body)
	}
	rules, _ := st.Rules()
	if len(rules) != 2 || findRuleT(t, st, "r_long").Target != "192.168.1.20:3002" {
		t.Errorf("rules = %+v, want r_long fixed and r_other", rules)
	}
}
