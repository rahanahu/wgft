package admin

import (
	"errors"
	"fmt"
	"html"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、削除したエージェントのルールの扱い(設計文書 5.1、10.1 節)を確かめる。エージェントの
// 削除の確認でルールも削除する選択と、ルールが残っている未登録のエージェントごとの帯と、その帯からの
// 一括削除である。

// batchFailBackend は Batch だけを失敗させる。
type batchFailBackend struct {
	*fakeBackend
	err error
}

func (b *batchFailBackend) Batch(BatchRequest) (*store.BatchResult, error) { return nil, b.err }

// orphanFixture は、登録済みの home(ルール 3 本、うち r_home3 は無効)と、未登録の gone(ルール 3 本、
// うち r_gone3 は無効)と ghost(ルール 1 本)を持つ。home は接続していて、有効なルールは転送している。
// 無効なルールも持ち主のエージェントのルールとして数え、削除の対象にする。
func orphanFixture(t *testing.T) *fakeBackend {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rule := func(id, agent string, port uint16, enabled bool) proto.Rule {
		return proto.Rule{ID: id, Agent: agent, Proto: proto.TCP, ListenPort: proto.PortRange{Lo: port, Hi: port},
			Target: fmt.Sprintf("192.168.1.20:%d", port), VPSMode: proto.ModeKernel, Enabled: enabled}
	}
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, rule("r_home1", "home", 3001, true), rule("r_home2", "home", 3002, true), rule("r_home3", "home", 3006, false),
			rule("r_gone1", "gone", 3003, true), rule("r_gone2", "gone", 3004, true), rule("r_gone3", "gone", 3007, false),
			rule("r_ghost", "ghost", 3005, true)), nil
	}); err != nil {
		t.Fatal(err)
	}
	gen, err := st.Generation()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Format(time.RFC3339)
	agents := []AgentInfo{{Name: "home", Connected: true, Generation: gen, LastHeartbeat: now, LastHandshake: now,
		Tunnel: TunnelStatus{State: proto.StatusOK},
		Rules:  []proto.RuleStatus{{ID: "r_home1", State: proto.StatusOK}, {ID: "r_home2", State: proto.StatusOK}}}}
	return &fakeBackend{st: st, agents: agents, warnings: []Warning{}}
}

const allFixtureRules = "r_ghost,r_gone1,r_gone2,r_gone3,r_home1,r_home2,r_home3"

// ruleIDs は保存されているルールの ID を並べて返す。
func ruleIDs(t *testing.T, b *fakeBackend) string {
	t.Helper()
	rules, err := b.st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range rules {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

// digestOf は今のルール集合のハッシュを返す。フォームが描いた時点の値として送る。
func digestOf(t *testing.T, b *fakeBackend) string {
	t.Helper()
	rules, err := b.st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	return proto.RulesDigest(rules)
}

// addRule はルールを 1 本加える。ページを描いた後の別の経路からの変更を模す。
func addRule(t *testing.T, b *fakeBackend, id, agent string) {
	t.Helper()
	if _, err := b.Batch(BatchRequest{Upsert: []proto.Rule{{ID: id, Agent: agent, Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 3900, Hi: 3900},
		Target: "192.168.1.20:3900", VPSMode: proto.ModeKernel, Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
}

// TestOrphanBands は、ルールが残っている未登録のエージェントごとに帯が 1 本、名前の順に出て、
// 名前と本数と一括削除のボタンを持つことを確かめる。本数は無効なルールも含む。帯は 5 秒ごとに描き直す
// ルール一覧の中にあり、描いた時点のルール集合のハッシュを持つ。
func TestOrphanBands(t *testing.T) {
	b := orphanFixture(t)
	srv := httptest.NewServer(New(b))
	defer srv.Close()
	digest := digestOf(t, b)
	for _, lang := range []string{"ja", "en"} {
		for _, path := range []string{"/?lang=", "/ui/rules?lang="} {
			body := getBody(t, srv.URL+path+lang)
			bands := strings.Split(body, `<article class="alert neutral-alert orphan-band">`)[1:]
			if len(bands) != 2 {
				t.Fatalf("%s %s: %d bands, want 2 (ghost, gone):\n%s", lang, path, len(bands), body)
			}
			for i, want := range []struct {
				agent string
				n     int
			}{{"ghost", 1}, {"gone", 3}} {
				band := bands[i]
				for _, s := range []string{
					html.EscapeString(fmt.Sprintf(T(lang, "orphanBandFmt"), want.agent, want.n)),
					`action="/ui/agents/` + want.agent + `/delete-rules"`,
					`data-confirm="` + html.EscapeString(fmt.Sprintf(T(lang, "confirmOrphanDelete"), want.agent, want.n)) + `"`,
					fmt.Sprintf(`<input type="hidden" name="count" value="%d">`, want.n),
					`<input type="hidden" name="rules_digest" value="` + digest + `">`,
					`>` + T(lang, "orphanDelete") + `</button>`,
				} {
					if !strings.Contains(band, s) {
						t.Errorf("%s %s: band %d is missing %q:\n%s", lang, path, i, s, band)
					}
				}
			}
			if strings.Contains(body, `/ui/agents/home/delete-rules`) {
				t.Errorf("%s %s: a registered agent must not get a band", lang, path)
			}
		}
	}
	if got := fmt.Sprintf(T("ja", "orphanBandFmt"), "home", 10); got != "home は削除済みです。このエージェントを参照するルール: 10 本" {
		t.Errorf("ja band text = %q", got)
	}
}

// TestNoOrphanBandWithoutOrphans は、未登録のエージェントのルールが無ければ帯を出さないことを確かめる。
func TestNoOrphanBandWithoutOrphans(t *testing.T) {
	b := orphanFixture(t)
	if _, err := b.Batch(BatchRequest{Delete: []string{"r_gone1", "r_gone2", "r_gone3", "r_ghost"}}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(b))
	defer srv.Close()
	if body := getBody(t, srv.URL+"/?lang=en"); strings.Contains(body, "orphan-band") {
		t.Errorf("no band is expected:\n%s", body)
	}
}

// TestOrphanRulesAreGreyAndNotCounted は、未登録のエージェントの有効なルールが、Web UI では横棒を添えた
// 灰色の「エージェント未登録」で示され、ヘッダの全体ヘルスにもグループの見出しにもエラーとして数えられない
// ことを確かめる(設計文書 5.1、10.1 節)。`server doctor` はこれらを FAILED のままにする。
func TestOrphanRulesAreGreyAndNotCounted(t *testing.T) {
	srv := httptest.NewServer(New(orphanFixture(t)))
	defer srv.Close()
	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/?lang="+lang)
		for _, id := range []string{"r_gone1", "r_gone2", "r_ghost"} {
			cell := stateCell(t, body, id)
			want := `<span class="badge neutral"><span aria-hidden="true">` + stateIconIdle + `</span> ` + T(lang, "agentUnregistered") + `</span>`
			if !strings.Contains(cell, want) || strings.Contains(cell, "failed") || strings.Contains(cell, "danger") {
				t.Errorf("%s %s: the state cell must be the grey %q only:\n%s", lang, id, want, cell)
			}
		}
		health := getBody(t, srv.URL+"/ui/health?lang="+lang)
		sep := T(lang, "summarySep")
		want := fmt.Sprintf(T(lang, "summaryOnline"), 1, 1) + sep + fmt.Sprintf(T(lang, "summaryRules"), 7) + "</small>"
		if !strings.Contains(health, want) || !strings.Contains(health, T(lang, "healthOK")) {
			t.Errorf("%s: rules of an unregistered agent must not count as errors; health:\n%s", lang, health)
		}
		if strings.Contains(body, `<span class="count danger">`) {
			t.Errorf("%s: no group heading may count an error", lang)
		}
	}
}

// TestDeleteOrphanRules は、帯の一括削除が、そのエージェントを参照するルールだけを、無効なルールも含めて
// ルールのバッチ 1 回で削除し、ダッシュボードへ戻すことを確かめる。
func TestDeleteOrphanRules(t *testing.T) {
	b := orphanFixture(t)
	srv := httptest.NewServer(New(b))
	defer srv.Close()
	resp, _ := postForm(t, srv.URL+"/ui/agents/gone/delete-rules", url.Values{"count": {"3"}, "rules_digest": {digestOf(t, b)}}, nil)
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/" {
		t.Fatalf("status %d Location %q, want 303 /", resp.StatusCode, resp.Header.Get("Location"))
	}
	if got := ruleIDs(t, b); got != "r_ghost,r_home1,r_home2,r_home3" {
		t.Errorf("rules after the bulk delete = %s", got)
	}
}

// TestDeleteOrphanRulesRefuses は、一括削除が次の場合に何も削除しないことを確かめる。エージェントが
// 登録されている場合(帯を描いた後に登録し直した場合を含む)、帯が示した本数と今の本数が違う場合、
// 帯を描いた後にルールが変わった場合(本数が同じでも)、バッチが失敗した場合、他オリジン発の場合である。
func TestDeleteOrphanRulesRefuses(t *testing.T) {
	for _, tc := range []struct {
		name, agent, count string
		staleDigest        bool
		noDigest           bool
		change             func(t *testing.T, b *fakeBackend)
		headers            map[string]string
		batchErr           error
		status             int
		text               string
	}{
		{name: "registered agent", agent: "home", count: "3", status: 409, text: fmt.Sprintf(T("en", "orphanRegistered"), "home")},
		{name: "fewer than shown", agent: "gone", count: "2", status: 409, text: T("en", "orphanChanged")},
		{name: "more than shown", agent: "gone", count: "4", status: 409, text: T("en", "orphanChanged")},
		{name: "no count", agent: "gone", count: "", status: 409, text: T("en", "orphanChanged")},
		{name: "no digest", agent: "gone", count: "3", noDigest: true, status: 409, text: T("en", "orphanChanged")},
		// 本数は同じまま、帯を描いた後に別のルールが加わった。ハッシュが違うので何も削除しない。
		{name: "stale digest", agent: "gone", count: "3", staleDigest: true, status: 409, text: T("en", "orphanChanged")},
		{name: "batch fails", agent: "gone", count: "3", batchErr: errors.New("nft: busy"), status: 422, text: T("en", "orphanDeleteFailed") + " nft: busy"},
		{name: "cross-site", agent: "gone", count: "3", headers: map[string]string{"Sec-Fetch-Site": "cross-site"}, status: 403},
		{name: "foreign origin", agent: "gone", count: "3", headers: map[string]string{"Origin": "https://evil.example"}, status: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := orphanFixture(t)
			digest := digestOf(t, b)
			want := allFixtureRules
			if tc.staleDigest {
				addRule(t, b, "r_new", "home")
				want = "r_ghost,r_gone1,r_gone2,r_gone3,r_home1,r_home2,r_home3,r_new"
			}
			if tc.noDigest {
				digest = ""
			}
			var backend Backend = b
			if tc.batchErr != nil {
				backend = &batchFailBackend{fakeBackend: b, err: tc.batchErr}
			}
			srv := httptest.NewServer(New(backend))
			defer srv.Close()
			resp, body := postForm(t, srv.URL+"/ui/agents/"+tc.agent+"/delete-rules?lang=en", url.Values{"count": {tc.count}, "rules_digest": {digest}}, tc.headers)
			if resp.StatusCode != tc.status {
				t.Errorf("status %d, want %d; body:\n%s", resp.StatusCode, tc.status, body)
			}
			if tc.text != "" && !strings.Contains(body, html.EscapeString(tc.text)) {
				t.Errorf("the page must say %q:\n%s", tc.text, body)
			}
			if got := ruleIDs(t, b); got != want {
				t.Errorf("nothing may be deleted, but the rules are %s", got)
			}
		})
	}
}

// TestRevokeOffersToDeleteTheRules は、詳細ページの削除の確認が、既定では選ばない「このエージェントの
// ルール N 本も削除する」と、描いた時点のルール集合のハッシュを持ち、ルールの無いエージェントでは
// 出さないことを確かめる。本数は無効なルールも含む。
func TestRevokeOffersToDeleteTheRules(t *testing.T) {
	b := orphanFixture(t)
	b.agents = append(b.agents, AgentInfo{Name: "empty"})
	srv := httptest.NewServer(New(b))
	defer srv.Close()
	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/ui/agents/home?lang="+lang)
		for _, want := range []string{
			`<input type="checkbox" name="delete_rules" value="1"> ` + html.EscapeString(fmt.Sprintf(T(lang, "agentDeleteRulesN"), 3)),
			`<input type="hidden" name="rules_digest" value="` + digestOf(t, b) + `">`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the danger zone is missing %q:\n%s", lang, want, body)
			}
		}
		if strings.Contains(body, "checked") {
			t.Errorf("%s: the option must be off by default", lang)
		}
		if strings.Contains(getBody(t, srv.URL+"/ui/agents/empty?lang="+lang), `name="delete_rules"`) {
			t.Errorf("%s: an agent without rules offers no option to delete them", lang)
		}
	}
	if got := fmt.Sprintf(T("ja", "agentDeleteRulesN"), 10); got != "このエージェントのルール 10 本も削除する" {
		t.Errorf("ja option = %q", got)
	}
}

// changeOnRevokeBackend は、削除の後、ルールの削除の前に、別の経路からルールを 1 本加える。ハッシュを
// 比べた後からバッチまでの間の変更を模す。
type changeOnRevokeBackend struct {
	*fakeBackend
	t *testing.T
}

func (b *changeOnRevokeBackend) Revoke(name string) error {
	err := b.fakeBackend.Revoke(name)
	addRule(b.t, b.fakeBackend, "r_new", "ghost")
	return err
}

// TestRevokeWithRules は、削除の確認でルールも削除する選択をしたときだけ、エージェントを削除した後に
// そのエージェントのルールを、無効なルールも含めて削除することを確かめる。選択の値は "1" だけを受ける。
// ページを描いた後にルールが変わっていれば、エージェントもルールも削除しない。削除は済んだが反映が
// まだの場合と、ルールの削除だけが失敗した場合は、エージェントは削除したことと、ルールが残ったことを示す。
// 名前が一致しなければ、どちらも行わない。
func TestRevokeWithRules(t *testing.T) {
	const kept = allFixtureRules
	for _, tc := range []struct {
		name        string
		form        url.Values
		staleDigest bool
		batchErr    error
		revokeErr   bool
		changeAfter bool
		status      int
		revoked     string
		rules       string
		texts       []string
	}{
		{name: "kept by default", form: url.Values{"confirm_name": {"home"}}, status: 303, revoked: "home", rules: kept},
		{name: "kept for a value other than 1", form: url.Values{"confirm_name": {"home"}, "delete_rules": {"0"}}, status: 303, revoked: "home", rules: kept},
		{name: "kept for on", form: url.Values{"confirm_name": {"home"}, "delete_rules": {"on"}}, status: 303, revoked: "home", rules: kept},
		{name: "deleted when chosen", form: url.Values{"confirm_name": {"home"}, "delete_rules": {"1"}}, status: 303, revoked: "home",
			rules: "r_ghost,r_gone1,r_gone2,r_gone3"},
		{name: "name mismatch", form: url.Values{"confirm_name": {"hom"}, "delete_rules": {"1"}}, status: 422, revoked: "",
			rules: kept, texts: []string{T("en", "agentDeleteMismatch")}},
		{name: "rules changed since the page", form: url.Values{"confirm_name": {"home"}, "delete_rules": {"1"}}, staleDigest: true,
			status: 409, revoked: "", rules: kept + ",r_new", texts: []string{T("en", "agentRulesChanged")}},
		{name: "no digest", form: url.Values{"confirm_name": {"home"}, "delete_rules": {"1"}, "rules_digest": {""}},
			status: 409, revoked: "", rules: kept, texts: []string{T("en", "agentRulesChanged")}},
		{name: "rules changed during the revoke", form: url.Values{"confirm_name": {"home"}, "delete_rules": {"1"}}, changeAfter: true,
			status: 422, revoked: "home", rules: "r_ghost,r_gone1,r_gone2,r_gone3,r_home1,r_home2,r_home3,r_new",
			texts: []string{T("en", "agentRulesLeft"), ErrBatchConflict.Error()}},
		{name: "rules fail after the revoke", form: url.Values{"confirm_name": {"home"}, "delete_rules": {"1"}}, batchErr: errors.New("nft: busy"),
			status: 422, revoked: "home", rules: kept, texts: []string{T("en", "agentRulesLeft") + " nft: busy"}},
		{name: "revoked but not applied", form: url.Values{"confirm_name": {"home"}, "delete_rules": {"1"}}, revokeErr: true,
			status: 422, revoked: "home", rules: kept, texts: []string{T("en", "agentRevokedNotApplied") + " nft: busy", T("en", "agentRulesNotDeleted")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := orphanFixture(t)
			if _, ok := tc.form["rules_digest"]; !ok {
				tc.form.Set("rules_digest", digestOf(t, b))
			}
			if tc.staleDigest {
				addRule(t, b, "r_new", "ghost")
			}
			if tc.revokeErr {
				b.revokeErr, b.revokeDropsRow = errors.New("nft: busy"), true
			}
			var backend Backend = b
			switch {
			case tc.batchErr != nil:
				backend = &batchFailBackend{fakeBackend: b, err: tc.batchErr}
			case tc.changeAfter:
				backend = &changeOnRevokeBackend{fakeBackend: b, t: t}
			}
			srv := httptest.NewServer(New(backend))
			defer srv.Close()
			resp, body := postForm(t, srv.URL+"/ui/agents/home/revoke?lang=en", tc.form, nil)
			if resp.StatusCode != tc.status {
				t.Errorf("status %d, want %d; body:\n%s", resp.StatusCode, tc.status, body)
			}
			if got := strings.Join(b.revoked, ","); got != tc.revoked {
				t.Errorf("revoked %q, want %q", got, tc.revoked)
			}
			if got := ruleIDs(t, b); got != tc.rules {
				t.Errorf("rules %s, want %s", got, tc.rules)
			}
			for _, text := range tc.texts {
				if !strings.Contains(body, html.EscapeString(text)) {
					t.Errorf("the page must say %q:\n%s", text, body)
				}
			}
		})
	}
}
