package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// TestRuleRunState はルールの適用状態の判定(仕様 10.1 節)を、ハートビートの
// 組み合わせごとに確かめる。無効・エージェント未接続・世代の古さ・error・ok の優先順位と、
// ja/en の文言を両方見る。
func TestRuleRunState(t *testing.T) {
	rule := func(enabled bool) *proto.Rule {
		return &proto.Rule{ID: "r_a", Agent: "home", Enabled: enabled}
	}
	agents := func(a ruleAgentStatus) map[string]ruleAgentStatus {
		return map[string]ruleAgentStatus{"home": a}
	}

	cases := []struct {
		name       string
		rule       *proto.Rule
		latestGen  uint64
		agents     map[string]ruleAgentStatus
		wantBadge  string
		wantLabel  [2]string // ja, en
		wantReason string
	}{
		{
			name:      "disabled rule stays disabled regardless of heartbeat",
			rule:      rule(false),
			latestGen: 5,
			agents:    agents(ruleAgentStatus{Connected: true, Generation: 5, Rules: map[string]proto.RuleStatus{"r_a": {ID: "r_a", State: proto.StatusError, Reason: "should not surface"}}}),
			wantBadge: "neutral", wantLabel: [2]string{"無効", "Disabled"},
		},
		{
			name:      "agent not registered at all",
			rule:      rule(true),
			latestGen: 5,
			agents:    map[string]ruleAgentStatus{},
			wantBadge: "neutral", wantLabel: [2]string{"エージェント未接続", "Agent offline"},
		},
		{
			name:      "agent registered but not connected",
			rule:      rule(true),
			latestGen: 5,
			agents:    agents(ruleAgentStatus{Connected: false, Generation: 5, Rules: map[string]proto.RuleStatus{"r_a": {ID: "r_a", State: proto.StatusOK}}}),
			wantBadge: "neutral", wantLabel: [2]string{"エージェント未接続", "Agent offline"},
		},
		{
			name:      "agent generation older than latest is pending",
			rule:      rule(true),
			latestGen: 5,
			agents:    agents(ruleAgentStatus{Connected: true, Generation: 4, Rules: map[string]proto.RuleStatus{"r_a": {ID: "r_a", State: proto.StatusError, Reason: "stale"}}}),
			wantBadge: "warning", wantLabel: [2]string{"反映待ち", "Pending"},
		},
		{
			name:      "generation matches but the rule was not reported yet",
			rule:      rule(true),
			latestGen: 5,
			agents:    agents(ruleAgentStatus{Connected: true, Generation: 5, Rules: map[string]proto.RuleStatus{}}),
			wantBadge: "warning", wantLabel: [2]string{"反映待ち", "Pending"},
		},
		{
			name:      "agent reports ok",
			rule:      rule(true),
			latestGen: 5,
			agents:    agents(ruleAgentStatus{Connected: true, Generation: 5, Rules: map[string]proto.RuleStatus{"r_a": {ID: "r_a", State: proto.StatusOK}}}),
			wantBadge: "success", wantLabel: [2]string{"適用済み", "Applied"},
		},
		{
			name:      "agent reports error with a reason",
			rule:      rule(true),
			latestGen: 5,
			agents:    agents(ruleAgentStatus{Connected: true, Generation: 5, Rules: map[string]proto.RuleStatus{"r_a": {ID: "r_a", State: proto.StatusError, Reason: "bind: address already in use"}}}),
			wantBadge: "danger", wantLabel: [2]string{"エラー", "Error"},
			wantReason: "bind: address already in use",
		},
		{
			name:      "latestGen zero (unknown generation) never counts as stale",
			rule:      rule(true),
			latestGen: 0,
			agents:    agents(ruleAgentStatus{Connected: true, Generation: 0, Rules: map[string]proto.RuleStatus{"r_a": {ID: "r_a", State: proto.StatusOK}}}),
			wantBadge: "success", wantLabel: [2]string{"適用済み", "Applied"},
		},
	}

	for _, tc := range cases {
		for i, locale := range []string{"ja", "en"} {
			t.Run(tc.name+"/"+locale, func(t *testing.T) {
				badge, label, reason := ruleRunState(tc.rule, tc.latestGen, tc.agents, nil, locale)
				if badge != tc.wantBadge {
					t.Errorf("badge = %q, want %q", badge, tc.wantBadge)
				}
				if label != tc.wantLabel[i] {
					t.Errorf("label = %q, want %q", label, tc.wantLabel[i])
				}
				if reason != tc.wantReason {
					t.Errorf("reason = %q, want %q", reason, tc.wantReason)
				}
			})
		}
	}
}

// newStateTestServer はルール 3 件(ok、error、pending 相当のエージェント未接続)を持つ
// 管理 API サーバーを立てる。ダッシュボードとルール詳細ページの描画を確かめるために使う。
func newStateTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules,
			proto.Rule{ID: "r_ok", Agent: "home", Group: "g1", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 1, Hi: 1}, Target: "h:1", VPSMode: proto.ModeKernel, Enabled: true},
			proto.Rule{ID: "r_err", Agent: "home", Group: "g1", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2, Hi: 2}, Target: "h:2", VPSMode: proto.ModeKernel, Enabled: true},
			proto.Rule{ID: "r_off", Agent: "office", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 3, Hi: 3}, Target: "h:3", VPSMode: proto.ModeKernel, Enabled: true},
		), nil
	}); err != nil {
		t.Fatal(err)
	}
	gen, err := st.Generation()
	if err != nil {
		t.Fatal(err)
	}
	agents := []AgentInfo{
		{
			Name: "home", Connected: true, Generation: gen,
			PublicKey:     "wJ6znEXOTPMBUXW+3z2vqjaMYikBWi2gYGA9EI0PZXk=",
			LastHandshake: time.Now().Add(-30 * time.Second).Format(time.RFC3339),
			Rules: []proto.RuleStatus{
				{ID: "r_ok", State: proto.StatusOK},
				{ID: "r_err", State: proto.StatusError, Reason: "bind: address already in use"},
			},
		},
		{Name: "office", Connected: false},
	}
	srv := httptest.NewServer(New(&fakeBackend{st: st, agents: agents}))
	t.Cleanup(srv.Close)
	return srv
}
func getBody(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", url, resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// TestRuleStateOnDashboard は一覧の状態欄が ok/error/エージェント未接続を出し分け、
// error の理由が副題に出て、畳んだグループの見出しに error の件数が出ることを確かめる。
// ja/en 両方で見る。
func TestRuleStateOnDashboard(t *testing.T) {
	srv := newStateTestServer(t)

	for _, tc := range []struct {
		lang, wantApplied, wantError, wantOffline, wantReason, wantGroupErr string
	}{
		{"ja", "適用済み", "エラー", "エージェント未接続", "bind: address already in use", "エラー 1 件"},
		{"en", "Applied", "Error", "Agent offline", "bind: address already in use", "1 error(s)"},
	} {
		body := getBody(t, srv.URL+"/?lang="+tc.lang)
		if !strings.Contains(body, tc.wantApplied) {
			t.Errorf("%s: missing applied label %q", tc.lang, tc.wantApplied)
		}
		if !strings.Contains(body, tc.wantError) {
			t.Errorf("%s: missing error label %q", tc.lang, tc.wantError)
		}
		if !strings.Contains(body, tc.wantOffline) {
			t.Errorf("%s: missing agent-offline label %q", tc.lang, tc.wantOffline)
		}
		if !strings.Contains(body, tc.wantReason) {
			t.Errorf("%s: missing error reason %q", tc.lang, tc.wantReason)
		}
		if !strings.Contains(body, tc.wantGroupErr) {
			t.Errorf("%s: missing group error count %q", tc.lang, tc.wantGroupErr)
		}
	}
}

// TestRuleStateOnDetailPage は /ui/rules/{id} の要約にも一覧と同じ状態が出ることを確かめる。
func TestRuleStateOnDetailPage(t *testing.T) {
	srv := newStateTestServer(t)

	body := getBody(t, srv.URL+"/ui/rules/r_err?lang=en")
	if !strings.Contains(body, "Error") {
		t.Error("detail page: missing Error state")
	}
	if !strings.Contains(body, "bind: address already in use") {
		t.Error("detail page: missing error reason")
	}

	body = getBody(t, srv.URL+"/ui/rules/r_off?lang=en")
	if !strings.Contains(body, "Agent offline") {
		t.Error("detail page: missing Agent offline state for a rule on a disconnected agent")
	}
}

// TestAgentListShowsHandshakeAndPubKey は接続欄のハンドシェイク経過時間と、名前欄の下の
// 公開鍵の先頭(title 属性に全体)を確かめる。
func TestAgentListShowsHandshakeAndPubKey(t *testing.T) {
	srv := newStateTestServer(t)

	body := getBody(t, srv.URL+"/ui/agents?lang=en")
	if !strings.Contains(body, "Handshake:") {
		t.Error("missing handshake age label")
	}
	if !strings.Contains(body, "wJ6znEXOT") {
		t.Error("missing truncated public key")
	}
	// html/template HTML-escapes "+" to "&#43;" in attribute values, so check the part
	// of the key before it rather than the raw string.
	if !strings.Contains(body, `title="wJ6znEXOTPMBUXW`) {
		t.Error("missing full public key in the title attribute")
	}
}

// TestAgentListDisconnectedShowsStaleNotLive confirms that a disconnected agent's last
// heartbeat (design.md 5.2 節: `vpsd` keeps Tunnel/StreamFrom/WGEndpoint after Connected
// goes false, for diagnosis) is drawn as a stale last report, not as the current state.
// Before the fix: the tunnel switch and the IP comparison in agentToView (webui.go) ignored
// Connected, so a disconnected agent with a healthy last heartbeat and matching IPs showed a
// live "OK" tunnel and a live IP match; and the heartbeat staleness color required Connected
// to be true, so a very old heartbeat used the normal (non-stale) color. Checked in both
// languages since the labels are localized (i18n.go).
func TestAgentListDisconnectedShowsStaleNotLive(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	old := time.Now().Add(-3 * time.Hour).Format(time.RFC3339)
	agents := []AgentInfo{{
		Name: "office", Connected: false, LastHeartbeat: old,
		// Same IP on both sides: were Connected ignored, this would render as a live IP match.
		StreamFrom: "203.0.113.24:41220", WGEndpoint: "203.0.113.24:51820",
		Tunnel: TunnelStatus{State: proto.StatusOK},
	}}
	srv := httptest.NewServer(New(&fakeBackend{st: st, agents: agents}))
	defer srv.Close()

	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/?lang="+lang)
		if !strings.Contains(body, T(lang, "tunnelStale")) {
			t.Errorf("%s: disconnected agent's tunnel must show the stale-report label %q, body:\n%s", lang, T(lang, "tunnelStale"), body)
		}
		if strings.Contains(body, `stack success-text`) {
			t.Errorf("%s: disconnected agent's tunnel must not use the live-OK color (stack success-text)", lang)
		}
		if strings.Contains(body, T(lang, "ipMatch")) || strings.Contains(body, T(lang, "ipMismatch")) {
			t.Errorf("%s: disconnected agent must not show an IP comparison; both IPs are history", lang)
		}
		if !strings.Contains(body, `class="warning-text">`+agoStr(old, lang)+`<`) {
			t.Errorf("%s: disconnected agent's 3-hour-old heartbeat must show the stale color, body:\n%s", lang, body)
		}
	}
}

// TestOverallHealthIncludesRuleErrors はヘッダの全体ヘルスの要約に error のルール件数が
// 入ることを確かめる(仕様 10.1 節)。
func TestOverallHealthIncludesRuleErrors(t *testing.T) {
	srv := newStateTestServer(t)

	body := getBody(t, srv.URL+"/?lang=en")
	if !strings.Contains(body, "1 errors") {
		t.Errorf("dashboard health summary missing the rule error count; body did not contain %q", "1 errors")
	}
}

// TestDashboardWarningsLayout はダッシュボードの単一カラム化(仕様 10.1 節)のうち、
// 警告の出し分けを確かめる。0 件のときはバナーを描かず(全体ヘルスの見出しで件数を示すのに
// 十分)、リフレッシュ先の要素(#warnings)だけは残ること。1 件以上のときはバナーが出て、
// ヘッダの警告件数が #warnings へのリンクになることを見る。
func TestDashboardWarningsLayout(t *testing.T) {
	newSrv := func(t *testing.T, warns []Warning) *httptest.Server {
		t.Helper()
		st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		srv := httptest.NewServer(New(&fakeBackend{st: st, warnings: warns}))
		t.Cleanup(srv.Close)
		return srv
	}

	// 0 件:バナーは描かず、5 秒ごとの自動更新先の要素だけ残る
	body := getBody(t, newSrv(t, []Warning{}).URL+"/?lang=en")
	if !strings.Contains(body, `id="warnings" data-refresh="/ui/warnings"`) {
		t.Error("missing the #warnings refresh target when there are no warnings")
	}
	if strings.Contains(body, "warnings-banner") {
		t.Error("the warnings banner must not render when there are no warnings")
	}
	if strings.Contains(body, "warn-jump") {
		t.Error("the header must not link to #warnings when there are no warnings")
	}

	// 1 件以上:バナーが出て、ヘッダの件数が #warnings へのリンクになる
	body = getBody(t, newSrv(t, []Warning{{Agent: "home", Kind: store.WarnIPMismatch, Detail: "stream=9.9.9.9 wg=1.2.3.4"}}).URL+"/?lang=en")
	if !strings.Contains(body, "warnings-banner") {
		t.Error("the warnings banner must render when there is a warning")
	}
	if !strings.Contains(body, `class="badge danger warn-jump" href="#warnings"`) {
		t.Errorf("the header warning count must link to #warnings: %s", body)
	}
	if !strings.Contains(body, "1 warnings") {
		t.Errorf("missing the header warning count: %s", body)
	}
}

// TestRulesAndHealthAutoRefresh confirms the rules panel and the header health block now carry
// data-refresh (design.md 10.1 節), and that the partial routes backing them (GET /ui/rules,
// GET /ui/health) render exactly the fragment the full dashboard page embeds -- the same
// contract the pre-existing #agents/#warnings partials follow. Before this change, #rules had no
// data-refresh attribute and there was no /ui/rules route at all, so a rule that turned error (or
// recovered) after page load stayed at its load-time state/reason/dropped-count forever, and the
// header health summary (derived from the same rule-error count) was equally frozen.
func TestRulesAndHealthAutoRefresh(t *testing.T) {
	srv := newStateTestServer(t)

	full := getBody(t, srv.URL+"/?lang=en")
	if !strings.Contains(full, `id="rules" data-refresh="/ui/rules"`) {
		t.Error("the rules panel is missing data-refresh=\"/ui/rules\"")
	}
	if !strings.Contains(full, `id="health" data-refresh="/ui/health"`) {
		t.Error("the header health block is missing data-refresh=\"/ui/health\"")
	}

	rulesPartial := getBody(t, srv.URL+"/ui/rules?lang=en")
	if !strings.Contains(full, rulesPartial) {
		t.Errorf("GET /ui/rules must render exactly the fragment the full page embeds inside #rules\nfull:\n%s\npartial:\n%s", full, rulesPartial)
	}
	// 中身そのものも部分更新の対象になっていることを確かめる(状態欄、拒否数)。
	if !strings.Contains(rulesPartial, "Applied") || !strings.Contains(rulesPartial, "Error") {
		t.Error("the /ui/rules fragment is missing per-rule state badges")
	}

	healthPartial := getBody(t, srv.URL+"/ui/health?lang=en")
	if !strings.Contains(full, healthPartial) {
		t.Errorf("GET /ui/health must render exactly the fragment the full page embeds inside #health\nfull:\n%s\npartial:\n%s", full, healthPartial)
	}
	if !strings.Contains(healthPartial, "1 errors") {
		t.Error("the /ui/health fragment is missing the rule error count")
	}
}

// TestRestrictionSummaryUnits は、一覧の接続元制限の要約でレートの単位が表示言語に
// 合わせて訳され、日本語に "second" などの英語が混ざらないことを確かめる。
func TestRestrictionSummaryUnits(t *testing.T) {
	r := proto.Rule{
		PerSourceRate: &proto.Rate{Count: 10, Unit: proto.PerSecond},
		NewFlowRate:   &proto.Rate{Count: 100, Unit: proto.PerMinute},
		PacketRate:    &proto.Rate{Count: 5000, Unit: proto.PerSecond},
	}
	cases := map[string][]string{
		"ja": {"接続元ごと 10 本/秒", "全体 100 本/分", "パケット 5000 個/秒"},
		"en": {"per source 10/second", "whole rule 100/minute", "packets 5000/second"},
	}
	for locale, wants := range cases {
		got := restrictionSummary(&r, locale)
		for _, w := range wants {
			if !strings.Contains(got, w) {
				t.Errorf("%s: summary %q does not contain %q", locale, got, w)
			}
		}
		if locale == "ja" && strings.Contains(got, "second") {
			t.Errorf("ja: summary %q still has an English unit", got)
		}
	}
}
