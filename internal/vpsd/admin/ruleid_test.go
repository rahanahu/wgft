package admin

import (
	"bytes"
	"database/sql"
	"encoding/json"
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

// badIDRule は、ID の検査(仕様 5.3 節)に落ちる ID を持つ、ほかは正しいルールである。
func badIDRule(id string, port uint16) proto.Rule {
	return proto.Rule{ID: id, Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: port, Hi: port},
		Target: "192.168.1.20:3001", VPSMode: proto.ModeKernel, Enabled: true}
}

// badRuleIDs は、ID の検査が拒む値と、拒むときの文言の一部である。
var badRuleIDs = []struct{ id, want string }{
	{strings.Repeat("x", 129), "id is 129 bytes long; the limit is 128 bytes"},
	{"r_a\nr_b", "id contains U+000A"},
	{"週末\u3000サーバ", "id contains U+3000"},
}

// insertStoredRule は、ID の検査の前に保存された行を模して、検査を通さずに SQL で直接書く。
func insertStoredRule(t *testing.T, path string, r proto.Rule) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	js, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO rules (id, position, json) VALUES (?, 100, ?)", r.ID, string(js)); err != nil {
		t.Fatal(err)
	}
}

func postBatch(t *testing.T, srvURL string, req BatchRequest) (int, string) {
	t.Helper()
	body, _ := json.Marshal(req)
	resp, err := http.Post(srvURL+"/api/v1/rules/batch", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestBatchAPIRefusesBadRuleIDs は、管理用 API のルールのバッチが、長すぎるか表示できない文字を
// 含む ID のルールを 422 で拒み、何も保存しないことを確かめる。
// 変異の確認:Rule.Validate から ID の検査を外すと、バッチが通って落ちる。
func TestBatchAPIRefusesBadRuleIDs(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer(New(&fakeBackend{st: st}))
	defer srv.Close()
	for _, c := range badRuleIDs {
		code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{badIDRule(c.id, 3001)}})
		if code != http.StatusUnprocessableEntity || !strings.Contains(body, c.want) {
			t.Errorf("batch with id %q = %d %s, want 422 containing %q", c.id, code, body, c.want)
		}
	}
	if rules, _ := st.Rules(); len(rules) != 0 {
		t.Errorf("refused batches stored rules: %+v", rules)
	}
}

// TestStoredBadRuleIDKeepsWorking は、ID の検査の前に保存された、長すぎるか表示できない文字を含む
// ID の行が、管理用 API と Web UI で次のとおり扱われることを確かめる(仕様 5.4 節)。一覧に出る。
// 無関係なルールの追加と、今の集合をそのまま戻すバッチは通る。同じ ID のまま変える管理用 API の
// バッチと Web UI の無効化は 422 で拒み、Web UI の分割も拒む。正しい ID への置き換えと削除は、管理用 API でも Web UI でも
// 通る。
// 変異の確認:ValidateUpsert が変わらない行の検査を飛ばさないようにすると、無関係な追加と、
// 集合をそのまま戻すバッチが落ちる。
func TestStoredBadRuleIDKeepsWorking(t *testing.T) {
	for _, c := range badRuleIDs {
		path := filepath.Join(t.TempDir(), "s.sqlite")
		st, err := store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		legacy := badIDRule(c.id, 3002)
		legacy.ListenPort.Hi = 3003
		insertStoredRule(t, path, legacy)
		srv := httptest.NewServer(New(&fakeBackend{st: st}))

		resp, err := http.Get(srv.URL + "/api/v1/rules")
		if err != nil {
			t.Fatal(err)
		}
		var list BatchResponse
		if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if len(list.Rules) != 1 || list.Rules[0].ID != c.id {
			t.Fatalf("id %q: GET /api/v1/rules = %+v, want the stored row", c.id, list.Rules)
		}

		if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{badIDRule("r_other", 4000)}}); code != http.StatusOK {
			t.Errorf("id %q: an unrelated add = %d %s, want 200", c.id, code, body)
		}
		if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{legacy}}); code != http.StatusOK {
			t.Errorf("id %q: upserting the stored row unchanged = %d %s, want 200", c.id, code, body)
		}
		changed := legacy
		changed.Enabled = false
		if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{changed}}); code != http.StatusUnprocessableEntity || !strings.Contains(body, c.want) {
			t.Errorf("id %q: changing the stored row = %d %s, want 422 containing %q", c.id, code, body, c.want)
		}
		uiResp, uiBody := postForm(t, srv.URL+"/ui/rules/"+url.PathEscape(c.id)+"/disable", url.Values{}, nil)
		if uiResp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(uiBody, c.want) {
			t.Errorf("id %q: Web UI disable = %d %s, want 422 containing %q", c.id, uiResp.StatusCode, uiBody, c.want)
		}
		uiResp, uiBody = postForm(t, srv.URL+"/ui/rules/"+url.PathEscape(c.id)+"/split", url.Values{"at": {"3003"}}, nil)
		if uiResp.StatusCode == http.StatusSeeOther || !strings.Contains(html.UnescapeString(uiBody), c.want) {
			t.Errorf("id %q: Web UI split = %d, want the detail page with an error containing %q", c.id, uiResp.StatusCode, c.want)
		}
		if rules, _ := st.Rules(); len(rules) != 2 || !ruleEnabled(rules, c.id) {
			t.Errorf("id %q: a refused change altered the rules: %+v", c.id, rules)
		}

		// 管理用 API で、同じ設定のまま正しい ID へ 1 回のバッチで置き換える
		fixed := legacy
		fixed.ID = "r_fixed"
		if code, body := postBatch(t, srv.URL, BatchRequest{Upsert: []proto.Rule{fixed}, Delete: []string{c.id}}); code != http.StatusOK {
			t.Errorf("id %q: replacing the stored row with a valid id = %d %s, want 200", c.id, code, body)
		}

		// もう 1 本作り直して、Web UI の削除のボタンの経路で消す
		insertStoredRule(t, path, legacy)
		uiResp, uiBody = postForm(t, srv.URL+"/ui/rules/"+url.PathEscape(c.id)+"/delete", url.Values{}, nil)
		if uiResp.StatusCode != http.StatusSeeOther {
			t.Errorf("id %q: Web UI delete = %d %s, want 303", c.id, uiResp.StatusCode, uiBody)
		}
		if rules, _ := st.Rules(); len(rules) != 2 || ruleEnabled(rules, c.id) {
			t.Errorf("id %q: rules after the Web UI delete = %+v, want r_other and r_fixed", c.id, rules)
		}
		srv.Close()
		st.Close()
	}
}

// ruleEnabled は rules に id の有効なルールがあるかを返す。
func ruleEnabled(rules []proto.Rule, id string) bool {
	for _, r := range rules {
		if r.ID == id {
			return r.Enabled
		}
	}
	return false
}

// TestImportIssuesRuleIDs は、Web UI の読み込みの確認画面が、新しい行と変えた行の ID の違反を示し、
// 保存済みの行をそのまま戻す読み込みには何も示さないことを確かめる。
// 変異の確認:Rule.Validate から ID の検査を外すと、新しい行の違反が示されず落ちる。
func TestImportIssuesRuleIDs(t *testing.T) {
	agents := map[string]bool{"home": true}
	for _, c := range badRuleIDs {
		if got := importIssues([]proto.Rule{badIDRule(c.id, 3001)}, nil, agents, nil); len(got) != 1 || !strings.Contains(got[0], c.want) {
			t.Errorf("import adding id %q: issues = %v, want one containing %q", c.id, got, c.want)
		}
		legacy := badIDRule(c.id, 3002)
		current := []proto.Rule{legacy}
		if got := importIssues([]proto.Rule{legacy, badIDRule("r_new", 4000)}, current, agents, nil); len(got) != 0 {
			t.Errorf("import keeping the stored row %q unchanged: issues = %v, want none", c.id, got)
		}
		changed := legacy
		changed.Note = "touched"
		if got := importIssues([]proto.Rule{changed}, current, agents, nil); len(got) != 1 || !strings.Contains(got[0], c.want) {
			t.Errorf("import changing the stored row %q: issues = %v, want one containing %q", c.id, got, c.want)
		}
	}
}
