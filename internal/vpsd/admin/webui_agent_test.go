package admin

import (
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
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、Web UI のエージェントの無効化と有効化、詳細ページ、名前の入力で確かめる削除
// (設計文書 5.1、10.1 節)を確かめる。

// agentUIFixture は、有効で接続している home、無効で切断している paused、有効で切断している
// office の 3 台と、それぞれのルールを持つ Web UI を立てる。paused のトンネルは最後の報告が error で、
// ハートビートは 1 時間前である。無効なエージェントの行はそれでも故障や警告の色にしない。
func agentUIFixture(t *testing.T) (*fakeBackend, *httptest.Server) {
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
		return append(rules,
			rule("r_home", "home", 2001, true),
			rule("r_paused_a", "paused", 2002, true),
			rule("r_paused_b", "paused", 2003, false),
			rule("r_office", "office", 2004, true),
		), nil
	}); err != nil {
		t.Fatal(err)
	}
	gen, err := st.Generation()
	if err != nil {
		t.Fatal(err)
	}
	ago := func(d time.Duration) string { return time.Now().Add(-d).Format(time.RFC3339) }
	agents := []AgentInfo{
		{Name: "home", Address: "10.200.0.2", Connected: true, Generation: gen, LastHeartbeat: ago(5 * time.Second),
			LastHandshake: ago(20 * time.Second), Tunnel: TunnelStatus{State: proto.StatusOK},
			StreamFrom: "203.0.113.10:1", WGEndpoint: "203.0.113.10:51820",
			Rules: []proto.RuleStatus{{ID: "r_home", State: proto.StatusOK}}},
		{Name: "paused", Address: "10.200.0.3", Disabled: true, DisabledAt: "2026-09-24T10:00:00+09:00",
			Connected: false, Generation: gen - 1, LastHeartbeat: ago(time.Hour), LastHandshake: ago(time.Hour),
			Tunnel: TunnelStatus{State: proto.StatusError}, CreatedAt: "2026-09-01T10:00:00+09:00"},
		{Name: "office", Address: "10.200.0.4", Connected: false, Generation: gen, LastHeartbeat: ago(time.Hour)},
	}
	b := &fakeBackend{st: st, agents: agents, warnings: []Warning{}}
	srv := httptest.NewServer(New(b))
	t.Cleanup(srv.Close)
	return b, srv
}

// noRedirect は応答をそのまま返すクライアントである。303 の行き先を確かめるために使う。
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// postForm はフォームを送り、状態と本文を返す。headers は Sec-Fetch-Site などを加えるときに使う。
func postForm(t *testing.T, target string, form url.Values, headers map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// TestAgentRowActions は、一覧の行の操作が有効なエージェントには確認つきの「無効化」、無効な
// エージェントには「有効化」であり、行に削除を置かないこと、名前が詳細ページへのリンクであることを
// 確かめる(設計文書 10.1 節)。
func TestAgentRowActions(t *testing.T) {
	_, srv := agentUIFixture(t)
	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/ui/agents?lang="+lang)
		if strings.Contains(body, "/revoke") {
			t.Errorf("%s: the agent rows must not carry a revoke form:\n%s", lang, body)
		}
		home := agentRow(t, body, "home")
		confirm := html.EscapeString(fmt.Sprintf(T(lang, "confirmAgentDisable"), "home"))
		for _, want := range []string{
			`action="/ui/agents/home/disable"`,
			`data-confirm="` + confirm + `"`,
			`>` + T(lang, "disable") + `</button>`,
		} {
			if !strings.Contains(home, want) {
				t.Errorf("%s: the enabled agent's row is missing %q:\n%s", lang, want, home)
			}
		}
		paused := agentRow(t, body, "paused")
		if !strings.Contains(paused, `action="/ui/agents/paused/enable"`) || !strings.Contains(paused, `>`+T(lang, "enable")+`</button>`) {
			t.Errorf("%s: the disabled agent's row must offer Enable:\n%s", lang, paused)
		}
		if strings.Contains(paused, "data-confirm") || strings.Contains(paused, "/disable") {
			t.Errorf("%s: enabling asks no confirmation and a disabled agent offers no Disable:\n%s", lang, paused)
		}
	}
	// 確認の文は、止まるもの、残るもの、戻し方を言う。日本語は所有者が決めた文そのものである。
	if got := fmt.Sprintf(T("ja", "confirmAgentDisable"), "home"); got != "エージェント home を無効化します。このエージェントのルールはすべて転送を止め、通信中のセッションも切れます。登録、鍵、ルールの設定は残り、有効化で元に戻ります。よいですか?" {
		t.Errorf("ja disable confirmation = %q", got)
	}
}

// TestDisabledAgentRowIsNeutral は、無効なエージェントの行が故障の色でない「無効」を示し、要対応に
// ならず、切断していても、トンネルが error でも、ハートビートが古くても、赤や黄にならないことを確かめる。
// 反映待ちの印も出さない。比べるために、同じく切断している有効な office は要対応の行のままである。
func TestDisabledAgentRowIsNeutral(t *testing.T) {
	_, srv := agentUIFixture(t)
	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/ui/agents?lang="+lang)
		row := agentRow(t, body, "paused")
		if !strings.Contains(row, `<span class="badge neutral">● `+T(lang, "disabled")+`</span>`) {
			t.Errorf("%s: the disabled agent's state must be a neutral %q:\n%s", lang, T(lang, "disabled"), row)
		}
		for _, wrong := range []string{"attention-row", "danger", "warning", "success", T(lang, "pending")} {
			if strings.Contains(row, wrong) {
				t.Errorf("%s: the disabled agent's row must be muted, but it has %q:\n%s", lang, wrong, row)
			}
		}
		if !strings.Contains(row, `class="muted">`+agoStr(time.Now().Add(-time.Hour).Format(time.RFC3339), lang)+`<`) {
			t.Errorf("%s: the disabled agent's heartbeat must be muted:\n%s", lang, row)
		}
		if !strings.Contains(row, `class="stack muted"`) {
			t.Errorf("%s: the disabled agent's tunnel must be muted:\n%s", lang, row)
		}
		if !strings.Contains(agentRow(t, body, "office"), "attention-row") {
			t.Errorf("%s: an enabled, disconnected agent stays an attention row", lang)
		}
	}
}

// TestDisabledAgentWithWarningNeedsAttention は、窃取の警告を持つ無効なエージェントの行が要対応に
// なることを確かめる。無効の間も恒久トークンは使えるためである(設計文書 10.1 節)。
func TestDisabledAgentWithWarningNeedsAttention(t *testing.T) {
	b, srv := agentUIFixture(t)
	b.agents[1].Warnings = []Warning{{Agent: "paused", Kind: store.WarnIPMismatch}}
	row := agentRow(t, getBody(t, srv.URL+"/ui/agents?lang=en"), "paused")
	if !strings.Contains(row, "attention-row") {
		t.Errorf("a disabled agent with a theft warning must be an attention row:\n%s", row)
	}
}

// TestHeaderHealthLeavesDisabledAgentsOut は、ヘッダの全体ヘルスの要約が、オンラインの分母から無効な
// エージェントを外し、1 台以上あるときだけ「無効 N」を添えることを確かめる(設計文書 10.1 節)。
// 無効なエージェントのルールはエラーに数えない。
func TestHeaderHealthLeavesDisabledAgentsOut(t *testing.T) {
	b, srv := agentUIFixture(t)
	for _, lang := range []string{"ja", "en"} {
		sep := T(lang, "summarySep")
		want := fmt.Sprintf(T(lang, "summaryOnline"), 1, 2) + sep + fmt.Sprintf(T(lang, "summaryDisabled"), 1) + sep + fmt.Sprintf(T(lang, "summaryRules"), 4)
		health := getBody(t, srv.URL+"/ui/health?lang="+lang)
		// office は切断していてハンドシェイクも無いので、そのルールは WireGuard で止まる。エラーは
		// その 1 件だけで、paused のルールは数えない。
		want += sep + fmt.Sprintf(T(lang, "summaryErrors"), 1)
		if !strings.Contains(health, want) {
			t.Errorf("%s: the header health is not %q:\n%s", lang, want, health)
		}
	}

	// 無効なエージェントが 0 台なら「無効」の項目を出さない。
	b.agents[1].Disabled = false
	health := getBody(t, srv.URL+"/ui/health?lang=ja")
	if strings.Contains(health, "無効") {
		t.Errorf("with no disabled agent the summary must not name one:\n%s", health)
	}
	if !strings.Contains(health, fmt.Sprintf(T("ja", "summaryOnline"), 1, 3)) {
		t.Errorf("with every agent enabled the denominator is all 3 agents:\n%s", health)
	}
}

// TestHealthSummaryParts は、要約の各項目が、数が 0 のときに出ないものと常に出るものに分かれることを
// 確かめる。
func TestHealthSummaryParts(t *testing.T) {
	for _, tc := range []struct {
		c    healthCounts
		want string
		ok   bool
	}{
		{healthCounts{Enabled: 2, Online: 2, Rules: 3}, "2 / 2 online · 3 rules", true},
		{healthCounts{Enabled: 2, Online: 1, Disabled: 1, Rules: 3}, "1 / 2 online · 1 disabled · 3 rules", true},
		{healthCounts{Enabled: 0, Online: 0, Disabled: 2, Rules: 3}, "0 / 0 online · 2 disabled · 3 rules", true},
		{healthCounts{Enabled: 2, Online: 2, Rules: 3, RuleErrors: 1}, "2 / 2 online · 3 rules · 1 errors", false},
		{healthCounts{Enabled: 2, Online: 2, Disabled: 1, Rules: 3, RuleErrors: 1, Warnings: 2}, "2 / 2 online · 1 disabled · 3 rules · 1 errors · 2 warnings", false},
	} {
		h := health(tc.c, "en")
		if h.Summary != tc.want || h.OK != tc.ok {
			t.Errorf("health(%+v) = %q ok=%v, want %q ok=%v", tc.c, h.Summary, h.OK, tc.want, tc.ok)
		}
	}
	if got := health(healthCounts{Enabled: 2, Online: 1, Disabled: 1, Rules: 3}, "ja").Summary; got != "オンライン 1 / 2 ・ 無効 1 ・ ルール 3 件" {
		t.Errorf("ja summary = %q", got)
	}
}

// TestAgentDisableEnableRoutes は、POST /ui/agents/{name}/disable と /enable が Backend を呼び、成功すれば
// ダッシュボードか詳細ページへ戻し、失敗を管理用 API と同じ状態の番号に写すことを確かめる。
func TestAgentDisableEnableRoutes(t *testing.T) {
	b, srv := agentUIFixture(t)
	var calls []string
	var failWith error
	b.agentChange = func(op, name string) (AgentDisabledResponse, error) {
		calls = append(calls, op+" "+name)
		if failWith != nil {
			return AgentDisabledResponse{}, failWith
		}
		return AgentDisabledResponse{Name: name, Disabled: op == "disable", Changed: true}, nil
	}

	for _, tc := range []struct {
		op, ret, wantTo string
	}{
		{"disable", "", "/"},
		{"enable", "", "/"},
		{"disable", "detail", "/ui/agents/home"},
		{"enable", "detail", "/ui/agents/home"},
		// 戻り先は固定の 2 つだけで、任意の URL は受けない。
		{"disable", "https://evil.example/", "/"},
	} {
		calls = nil
		resp, _ := postForm(t, srv.URL+"/ui/agents/home/"+tc.op, url.Values{"return": {tc.ret}}, nil)
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != tc.wantTo {
			t.Errorf("%s return=%q: status %d Location %q, want 303 %q", tc.op, tc.ret, resp.StatusCode, resp.Header.Get("Location"), tc.wantTo)
		}
		if len(calls) != 1 || calls[0] != tc.op+" home" {
			t.Errorf("%s: backend calls = %v", tc.op, calls)
		}
	}

	for _, tc := range []struct {
		name     string
		err      error
		status   int
		wantText string
	}{
		{"unknown agent", fmt.Errorf("agent %q: %w", "home", store.ErrAgentNotFound), http.StatusNotFound, "not found"},
		{"refused, nothing saved", &AgentChangeError{Saved: false, Err: errors.New("tcp/2001 is bound on the VPS")}, http.StatusUnprocessableEntity, T("en", "agentChangeNotSaved") + " tcp/2001 is bound on the VPS"},
		{"saved, not published", &AgentChangeError{Saved: true, Err: errors.New("nft: busy")}, http.StatusUnprocessableEntity, T("en", "agentChangeNotApplied") + " nft: busy"},
		{"store failure", errors.New("disk I/O error"), http.StatusInternalServerError, "disk I/O error"},
	} {
		failWith = tc.err
		resp, body := postForm(t, srv.URL+"/ui/agents/home/enable?lang=en", nil, nil)
		if resp.StatusCode != tc.status || !strings.Contains(body, html.EscapeString(tc.wantText)) {
			t.Errorf("%s: status %d, want %d with %q; body:\n%s", tc.name, resp.StatusCode, tc.status, tc.wantText, body)
		}
	}
}

// TestAgentPostsRejectCrossOrigin は、無効化、有効化、削除の POST が、他の Web UI の POST と同じく
// 他オリジン発の変更の拒否を通ることを確かめる(設計文書 11 節)。拒んだ操作は Backend に届かない。
func TestAgentPostsRejectCrossOrigin(t *testing.T) {
	b, srv := agentUIFixture(t)
	var calls []string
	b.agentChange = func(op, name string) (AgentDisabledResponse, error) {
		calls = append(calls, op)
		return AgentDisabledResponse{}, nil
	}
	for _, path := range []string{"/ui/agents/home/disable", "/ui/agents/home/enable", "/ui/agents/home/revoke"} {
		for _, h := range []map[string]string{{"Sec-Fetch-Site": "cross-site"}, {"Origin": "https://evil.example"}} {
			resp, _ := postForm(t, srv.URL+path, url.Values{"confirm_name": {"home"}}, h)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s %v: status %d, want 403", path, h, resp.StatusCode)
			}
		}
	}
	if len(calls) != 0 || len(b.revoked) != 0 {
		t.Errorf("a refused cross-origin POST reached the backend: changes %v, revokes %v", calls, b.revoked)
	}
}

// TestAgentDetailPage は、詳細ページが状態、事実の一覧、このエージェントのルールだけの一覧、末尾の
// 「危険な操作」の区画を持つことを確かめる。無効なエージェントでは有効化を置く。
func TestAgentDetailPage(t *testing.T) {
	_, srv := agentUIFixture(t)
	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/ui/agents/paused?lang="+lang)
		for _, want := range []string{
			`<span aria-current="page">` + fmt.Sprintf(T(lang, "agentCrumbFmt"), "paused") + `</span>`,
			`<span class="badge neutral">● ` + T(lang, "disabled") + `</span>`,
			`action="/ui/agents/paused/enable"`,
			`<input type="hidden" name="return" value="detail">`,
			T(lang, "agentDisabledNote"),
			"10.200.0.3",
			"2026-09-24T10:00:00&#43;09:00",
			`href="/ui/rules/r_paused_a"`,
			`href="/ui/rules/r_paused_b"`,
			`<section class="detail-group danger-zone" id="agent-danger">`,
			`<h2>` + T(lang, "dangerZoneHead") + `</h2>`,
			`action="/ui/agents/paused/revoke" class="name-confirm-form" data-name="paused"`,
			`name="confirm_name"`,
			`<button class="btn danger-outline" type="submit">` + T(lang, "revokeAgent") + `</button>`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the detail page is missing %q", lang, want)
			}
		}
		for _, wrong := range []string{`href="/ui/rules/r_home"`, `href="/ui/rules/r_office"`, "attention"} {
			if strings.Contains(body, wrong) {
				t.Errorf("%s: the detail page of paused has %q", lang, wrong)
			}
		}
		// 危険な操作の区画はページの末尾にある。
		if i, j := strings.Index(body, `id="agent-danger"`), strings.Index(body, `id="agent-rules"`); i < j {
			t.Errorf("%s: the danger zone must come after the rules", lang)
		}
	}

	home := getBody(t, srv.URL+"/ui/agents/home?lang=en")
	if !strings.Contains(home, `action="/ui/agents/home/disable"`) || !strings.Contains(home, `data-confirm="`+html.EscapeString(fmt.Sprintf(T("en", "confirmAgentDisable"), "home"))+`"`) {
		t.Errorf("the enabled agent's detail page must offer Disable with its confirmation:\n%s", home)
	}

	resp, err := http.Get(srv.URL + "/ui/agents/nobody")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("an unknown agent's detail page: status %d, want 404", resp.StatusCode)
	}
}

// TestAgentRevokeChecksTheTypedName は、削除が server の側で名前の入力を照合することを確かめる。
// 空や違う名前では何も削除せず、入力を残して詳細ページに誤りを示す。一致すれば削除してダッシュボード
// へ戻す。警告のバナーの削除のフォームは、名前を hidden で送る。
func TestAgentRevokeChecksTheTypedName(t *testing.T) {
	b, srv := agentUIFixture(t)
	for _, typed := range []string{"", "Home", "home ", "paused", "<b>x</b>"} {
		resp, body := postForm(t, srv.URL+"/ui/agents/home/revoke?lang=en", url.Values{"confirm_name": {typed}}, nil)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("typed %q: status %d, want 422", typed, resp.StatusCode)
		}
		if !strings.Contains(body, html.EscapeString(T("en", "agentDeleteMismatch"))) {
			t.Errorf("typed %q: the page must say the name does not match:\n%s", typed, body)
		}
		if !strings.Contains(body, `name="confirm_name" value="`+html.EscapeString(typed)+`"`) {
			t.Errorf("typed %q: the page must keep the typed value:\n%s", typed, body)
		}
	}
	// フォームの値が無い送信も拒む(JavaScript を通らない送信)。
	if resp, _ := postForm(t, srv.URL+"/ui/agents/home/revoke", nil, nil); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("a revoke without confirm_name: status %d, want 422", resp.StatusCode)
	}
	if len(b.revoked) != 0 {
		t.Fatalf("a mismatched name reached Revoke: %v", b.revoked)
	}

	resp, _ := postForm(t, srv.URL+"/ui/agents/home/revoke", url.Values{"confirm_name": {"home"}}, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Errorf("a matching name: status %d Location %q, want 303 /", resp.StatusCode, resp.Header.Get("Location"))
	}
	if len(b.revoked) != 1 || b.revoked[0] != "home" {
		t.Errorf("Revoke calls = %v, want [home]", b.revoked)
	}

	b.revokeErr = errors.New("nft: busy")
	resp, body := postForm(t, srv.URL+"/ui/agents/home/revoke?lang=en", url.Values{"confirm_name": {"home"}}, nil)
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, T("en", "agentDeleteFailed")+" nft: busy") {
		t.Errorf("a failed revoke: status %d, want 422 with the reason; body:\n%s", resp.StatusCode, body)
	}
}

// TestWarningBannerRevokeSendsTheName は、警告のバナーの削除のボタンが残り、確認のダイアログと、
// server が照合する名前を持つことを確かめる(設計文書 5.2、10.1 節)。
func TestWarningBannerRevokeSendsTheName(t *testing.T) {
	b, srv := agentUIFixture(t)
	b.warnings = []Warning{{Agent: "home", Kind: store.WarnIPMismatch, Detail: "stream=9.9.9.9 wg=1.2.3.4"}}
	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/ui/warnings?lang="+lang)
		confirm := html.EscapeString(fmt.Sprintf(T(lang, "confirmRevoke"), "home"))
		for _, want := range []string{
			`action="/ui/agents/home/revoke"`,
			`data-confirm="` + confirm + `"`,
			`<input type="hidden" name="confirm_name" value="home">`,
			`>` + T(lang, "revokeAgent") + `</button>`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the warning banner is missing %q:\n%s", lang, want, body)
			}
		}
	}
}

// TestRuleDetailShowsTheAgentStateIcon は、ルールの詳細ページも、持ち主のエージェントが無効なルールを
// 一覧と同じ横棒を添えた「エージェント無効」で示すことを確かめる。
func TestRuleDetailShowsTheAgentStateIcon(t *testing.T) {
	_, srv := agentUIFixture(t)
	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/ui/rules/r_paused_a?lang="+lang)
		want := `<span class="badge neutral"><span aria-hidden="true">` + stateIconIdle + `</span> ` + T(lang, "agentDisabled") + `</span>`
		if !strings.Contains(body, want) {
			t.Errorf("%s: the rule detail page is missing %q", lang, want)
		}
		// 無効なルールは、持ち主のエージェントが無効でも ● の「無効」のままである。
		body = getBody(t, srv.URL+"/ui/rules/r_paused_b?lang="+lang)
		want = `<span class="badge neutral"><span aria-hidden="true">●</span> ` + T(lang, "disabled") + `</span>`
		if !strings.Contains(body, want) {
			t.Errorf("%s: a disabled rule of a disabled agent must read %q", lang, want)
		}
	}
}

// TestNoConnectionTestForRulesThatDoNotForward は、持ち主のエージェントが無効か未登録のルールに
// 接続テストのボタンを出さないことを確かめる。server がそのルールの疎通確認を拒むためである
// (設計文書 5.1、10.1 節)。有効なエージェントの TCP のルールには出す。
func TestNoConnectionTestForRulesThatDoNotForward(t *testing.T) {
	b, srv := agentUIFixture(t)
	if _, err := b.Batch(BatchRequest{Upsert: []proto.Rule{{ID: "r_gone", Agent: "gone", Proto: proto.TCP,
		ListenPort: proto.PortRange{Lo: 2005, Hi: 2005}, Target: "192.168.1.20:2005", VPSMode: proto.ModeKernel, Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	body := getBody(t, srv.URL+"/?lang=en")
	for id, want := range map[string]bool{"r_home": true, "r_office": true, "r_paused_a": false, "r_gone": false} {
		if got := strings.Contains(ruleRow(t, body, id), `href="/ui/rules/`+id+`/check"`); got != want {
			t.Errorf("%s: connection test offered = %v, want %v", id, got, want)
		}
	}
}
