package admin

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは Web UI の診断の画面(設計文書 10.2d 節)を確かめる。固定されているのは 3 つで
// ある。診断のロジックの置き場所、ラベルと状態の語を英語のままにすること、疎通の確認を画面を
// 開いたときには呼ばないことである。

// countingBackend は疎通の確認が呼ばれた回数を数える Backend である。画面を開いただけで
// CheckConnectivity が呼ばれると、その回数が 0 でなくなる。
type countingBackend struct {
	fakeBackend
	checks atomic.Int64
}

func (b *countingBackend) CheckConnectivity(ruleID string) (ConnCheck, error) {
	b.checks.Add(1)
	return ConnCheck{OK: true, Reach: "target", Detail: "opened a connection to 192.168.1.20:25565"}, nil
}

// ApplyStatus と AgentRuleStatuses は、本物の server が載せる加算の報告(design.md 7a.3、5.2 節)
// である。診断はこの 2 つを主な証拠にするので、画面の試験では fake でも返す。
func (b *countingBackend) ApplyStatus() (ApplyStatus, bool) {
	gen, err := b.st.Generation()
	if err != nil {
		return ApplyStatus{}, false
	}
	rules, err := b.st.Rules()
	if err != nil {
		return ApplyStatus{}, false
	}
	st := ApplyStatus{DesiredGeneration: gen, ActiveGeneration: gen, Rules: map[string]RuleApply{}}
	for _, r := range rules {
		st.Rules[r.ID] = RuleApply{ApplyState: ApplyActive, ActiveGeneration: &gen}
	}
	return st, true
}

func (b *countingBackend) AgentRuleStatuses(rules []proto.Rule) map[string]AgentRuleStatus {
	agents, _ := b.Agents()
	out := make(map[string]AgentRuleStatus, len(rules))
	for _, r := range rules {
		st := AgentRuleStatus{Agent: r.Agent}
		for _, a := range agents {
			if a.Name != r.Agent {
				continue
			}
			st.Connected = a.Connected
			for _, rs := range a.Rules {
				if rs.ID == r.ID {
					st.State, st.Reason, st.At = rs.State, rs.Reason, a.LastHeartbeat
				}
			}
		}
		out[r.ID] = st
	}
	return out
}

// newDoctorTestServer は、健全な TCP のルール、エージェントが error を報告している UDP のルール、
// エージェントが接続していないルールの 3 本を持つ管理 API サーバーを立てる。
func newDoctorTestServer(t *testing.T) (*httptest.Server, *countingBackend) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules,
			proto.Rule{ID: "r_ok", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 25565, Hi: 25565},
				Target: "192.168.1.20:25565", VPSMode: proto.ModeKernel, Enabled: true},
			proto.Rule{ID: "r_err", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2457},
				Target: "192.168.1.20:2456", VPSMode: proto.ModeKernel, Enabled: true},
			proto.Rule{ID: "r_off", Agent: "office", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 443, Hi: 443},
				Target: "192.168.1.30:443", VPSMode: proto.ModeKernel, Enabled: true},
		), nil
	}); err != nil {
		t.Fatal(err)
	}
	gen, err := st.Generation()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	agents := []AgentInfo{
		{
			Name: "home", Address: "10.200.0.2", Connected: true, Generation: gen,
			StreamFrom:    "203.0.113.9:51234",
			LastHeartbeat: now.Add(-10 * time.Second).Format(time.RFC3339),
			LastHandshake: now.Add(-30 * time.Second).Format(time.RFC3339),
			Tunnel:        TunnelStatus{State: proto.StatusOK},
			Rules: []proto.RuleStatus{
				{ID: "r_ok", State: proto.StatusOK},
				{ID: "r_err", State: proto.StatusError, Reason: "bind failed: address already in use"},
			},
		},
		{Name: "office", Connected: false},
	}
	b := &countingBackend{fakeBackend: fakeBackend{st: st, agents: agents}}
	srv := httptest.NewServer(New(b))
	t.Cleanup(srv.Close)
	return srv, b
}

// TestDoctorPageOpensWithoutProbing は、この節が固定した 3 つのうちの 1 つを確かめる。画面を
// 開いただけでは疎通の確認を呼ばない(設計文書 10.2d 節)。運用者が押したときだけ呼ぶ。
func TestDoctorPageOpensWithoutProbing(t *testing.T) {
	srv, b := newDoctorTestServer(t)

	for _, path := range []string{"/ui/doctor", "/ui/doctor/r_ok", "/ui/doctor/r_err", "/"} {
		getBody(t, srv.URL+path)
		if n := b.checks.Load(); n != 0 {
			t.Fatalf("GET %s dialled %d time(s); opening a page must never run the probe", path, n)
		}
	}

	// 明示の操作、つまり probe を押したときだけ呼ぶ。
	body := getBody(t, srv.URL+"/ui/doctor/r_ok?probe=1")
	if n := b.checks.Load(); n != 1 {
		t.Fatalf("the probe link dialled %d time(s), want exactly 1", n)
	}
	if !strings.Contains(body, "opened a connection to 192.168.1.20:25565") {
		t.Errorf("the probed page does not carry the server's own detail of the probe:\n%s", body)
	}
	if !strings.Contains(body, "end-to-end probe") {
		t.Errorf("the probed page is missing the end-to-end probe check:\n%s", body)
	}
	if !strings.Contains(body, "connected to 192.168.1.20:25565 through the tunnel and the agent") {
		t.Errorf("the probed page does not show what the probe found:\n%s", body)
	}
}

// TestDoctorPageKeepsTheDiagnosisVocabularyInEnglish は、検査の見出し、状態の語、群の名前を
// 日英で切り替えないことを確かめる(設計文書 10.2d 節)。画面で見た語で
// `server doctor --json` の checks[].id と checks[].status を引けるようにするためである。
func TestDoctorPageKeepsTheDiagnosisVocabularyInEnglish(t *testing.T) {
	srv, _ := newDoctorTestServer(t)

	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/ui/doctor/r_ok?lang="+lang)
		for _, want := range []string{
			// 検査の見出し(design.md 10.2a 節の一覧)
			"public port", "dataplane", "WireGuard", "control connection", "rules received", "target",
			// 群の名前
			"Server", "Tunnel", `Agent &#34;home&#34;`,
			// 状態の語
			"OK", "NOT TESTED",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the diagnosis page is missing the English %q:\n%s", lang, want, body)
			}
		}
		// 日本語の画面でも、判定の語そのものは訳さない。
		for _, unwanted := range []string{"公開ポート", "制御の接続", "未検査", "エージェントの接続"} {
			if strings.Contains(body, unwanted) {
				t.Errorf("%s: the diagnosis page translated a check label or a status word: %q", lang, unwanted)
			}
		}
	}

	// 画面の枠の語は切り替える。
	ja := getBody(t, srv.URL+"/ui/doctor?lang=ja")
	if !strings.Contains(ja, T("ja", "doctorTitle")) || !strings.Contains(ja, T("ja", "doctorIntro")) {
		t.Errorf("the ja page does not use the Japanese page chrome:\n%s", ja)
	}
	en := getBody(t, srv.URL+"/ui/doctor?lang=en")
	if !strings.Contains(en, T("en", "doctorIntro")) {
		t.Errorf("the en page does not use the English page chrome:\n%s", en)
	}
}

// TestDoctorPageShowsTheSameVerdictAsTheReport は、画面が判定を作り直さず、
// internal/vpsd/doctor の判定をそのまま出すことを確かめる。1 つの検査の判定をずらせば、画面の
// 状態も理由も一緒に動く。
func TestDoctorPageShowsTheSameVerdictAsTheReport(t *testing.T) {
	srv, _ := newDoctorTestServer(t)

	body := getBody(t, srv.URL+"/ui/doctor/r_err?lang=en")
	if !strings.Contains(body, "bind failed: address already in use") {
		t.Errorf("the page does not carry the agent's own reason:\n%s", body)
	}
	if !strings.Contains(body, "FAILED") {
		t.Errorf("a rule whose agent reports an error must read FAILED:\n%s", body)
	}
	if !strings.Contains(body, `traffic stops at &#34;target&#34;`) {
		t.Errorf("the page does not say where traffic stops:\n%s", body)
	}
	// FAILED の所見は必ず次に見るものを添える(10.2a 節)。
	if !strings.Contains(body, "Check:") {
		t.Errorf("a failing finding must say what to check next:\n%s", body)
	}

	// エージェントが接続していないルールは、経路の順でトンネルが先に来るので WireGuard で
	// 止まる(design.md 10.2a 節の検査どうしの優先順位)。切り分けられない原因も並べる。
	body = getBody(t, srv.URL+"/ui/doctor/r_off?lang=en")
	if !strings.Contains(body, `traffic stops at &#34;WireGuard&#34;`) {
		t.Errorf("a rule whose agent has never handshaken must stop at the tunnel:\n%s", body)
	}
	if !strings.Contains(body, "the agent is not running, or holds a different key") {
		t.Errorf("an unattributable finding must list the causes it cannot tell apart:\n%s", body)
	}

	// 一覧は 3 本とも出し、止まった位置を理由として添える。
	summary := getBody(t, srv.URL+"/ui/doctor?lang=en")
	for _, want := range []string{"25565", "2456-2457", "443", "rules not carrying traffic"} {
		if !strings.Contains(summary, want) {
			t.Errorf("the summary page is missing %q:\n%s", want, summary)
		}
	}
}

// TestDoctorPageDoesNotDrawAStaleReportAsCurrent は、stream が切れているエージェントの最後の
// 報告を、今の値として描かないことを確かめる(設計文書 5.2、10.2a 節)。トンネルが生きている
// 間は、この状態だけが画面で DEGRADED と読める。JSON は unknown のままである。
func TestDoctorPageDoesNotDrawAStaleReportAsCurrent(t *testing.T) {
	srv, b := newDoctorTestServer(t)
	agents, _ := b.Agents()
	agents[0].Connected = false
	b.agents = agents

	body := getBody(t, srv.URL+"/ui/doctor/r_ok?lang=en")
	if !strings.Contains(body, "DEGRADED") {
		t.Errorf("a live tunnel with a dropped control connection must read DEGRADED:\n%s", body)
	}
	if !strings.Contains(body, "last:") {
		t.Errorf("a disconnected agent's last report must be marked as history:\n%s", body)
	}
	if strings.Contains(body, "the agent reached 192.168.1.20:25565") {
		t.Errorf("a disconnected agent's last report must not be drawn as a current observation:\n%s", body)
	}
}

// TestDoctorPageAlwaysSaysWhatItDidNotTest は、何も壊れていない画面でも、試していない範囲と
// 履歴が無いことを必ず出すことを確かめる(設計文書 10.2a 節)。黙っていると運用者が沈黙を
// 健全と読む。
func TestDoctorPageAlwaysSaysWhatItDidNotTest(t *testing.T) {
	srv, _ := newDoctorTestServer(t)

	for _, path := range []string{"/ui/doctor", "/ui/doctor/r_ok"} {
		body := getBody(t, srv.URL+path+"?lang=en")
		for _, want := range []string{"from outside", "mtu", "under load", "the agent host", "NOT AVAILABLE"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s does not say it did not test %q:\n%s", path, want, body)
			}
		}
	}
}

// TestDoctorPageHidesTheNoisyChecksButKeepsThem は、既定で隠す検査(無効なルールの下流など)を
// 折りたたんだ区画に残すことを確かめる。CLI の --verbose と同じ判定を共有する。
func TestDoctorPageHidesTheNoisyChecksButKeepsThem(t *testing.T) {
	srv, _ := newDoctorTestServer(t)

	body := getBody(t, srv.URL+"/ui/doctor/r_ok?lang=en")
	if !strings.Contains(body, T("en", "doctorHiddenHead")) {
		t.Errorf("the page drops the checks that are hidden by default instead of collapsing them:\n%s", body)
	}
	// source filter は --from の無い実行では not_tested なので、折りたたみの中にある。
	if !strings.Contains(body, "source filter") {
		t.Errorf("a check hidden by default must still be reachable on the page:\n%s", body)
	}
}

// TestDoctorSummarySaysWhereTheProbeIs は、一覧の画面から疎通を試せることが読み取れるかを
// 確かめる。一覧の画面にボタンは無く、試していない範囲の inner path の行は CLI と同じ文なので、
// 画面だけを見る運用者には 1 本のルールの画面へ進む道が見えない。
func TestDoctorSummarySaysWhereTheProbeIs(t *testing.T) {
	srv, _ := newDoctorTestServer(t)

	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/ui/doctor?lang="+lang)
		if !strings.Contains(body, T(lang, "doctorProbeOnRulePage")) {
			t.Errorf("%s: the summary page does not say where the probe can be run:\n%s", lang, body)
		}
		if !strings.Contains(body, `href="/ui/doctor/r_ok"`) {
			t.Errorf("%s: the summary page does not link to a rule's own page:\n%s", lang, body)
		}
	}
}

// TestDoctorPageIsReachableFromTheDashboard は、入口を確かめる。ダッシュボードの見出しと、
// ルール詳細ページの要約の両方から開ける。
func TestDoctorPageIsReachableFromTheDashboard(t *testing.T) {
	srv, _ := newDoctorTestServer(t)

	dash := getBody(t, srv.URL+"/?lang=en")
	if !strings.Contains(dash, `href="/ui/doctor"`) {
		t.Errorf("the dashboard does not link to the diagnosis:\n%s", dash)
	}
	detail := getBody(t, srv.URL+"/ui/rules/r_ok?lang=en")
	if !strings.Contains(detail, `href="/ui/doctor/r_ok"`) {
		t.Errorf("the rule detail page does not link to that rule's diagnosis:\n%s", detail)
	}
}

// TestDoctorPageRefusesAnUnknownRule は、無いルールを 404 にすることを確かめる。読み取りの
// 失敗を「そのルールは無い」に変えて見せない(design.md 10.5 節)のは findRuleOr404 と同じである。
func TestDoctorPageRefusesAnUnknownRule(t *testing.T) {
	srv, _ := newDoctorTestServer(t)

	resp, err := http.Get(srv.URL + "/ui/doctor/r_nope")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// TestClientAndWebUIShareTheSameEvidenceInterface は、CLI と Web UI が同じ interface を通して
// 証拠を渡すことを型の上で固定する(設計文書 10.2d 節)。CLI は admin.Client 越しに管理用 API を
// 呼び、Web UI は同じプロセスの中で Backend を呼ぶ。判定はその違いを見ない。
func TestClientAndWebUIShareTheSameEvidenceInterface(t *testing.T) {
	var _ doctor.Evidence = (*Client)(nil)
	var _ doctor.Evidence = doctorEvidence{}
}
