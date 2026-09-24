package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは `wgft server doctor` の RunE そのものを、偽の管理用 API に対して通す。判定は
// doctor_test.go が合成した証拠に対して確かめているが、コマンドが証拠をどう読み、どの出力を
// 選び、どの終了コードを返すかを端から端まで通す経路は、この試験だけが通る。

// sinceNow は今から d だけ前の時刻である。doctor_test.go の at は固定した時刻を基準にするので、
// 実際の時計で判定するこの経路では使えない。
func sinceNow(d time.Duration) string { return time.Now().Add(-d).Format(time.RFC3339) }

// doctorRuneBackend は、健全な TCP のルールと、エージェントが error を報告している UDP の
// ルールを持つ Backend である。cmd/wgft からは internal/vpsd/admin の内部の fakeBackend を
// 使えないので、status_test.go の fakeStatusBackend をそのまま使う。
func doctorRuneBackend() *fakeStatusBackend {
	rules := []proto.Rule{
		{ID: "r_01J0000000000000000000AAA", Agent: "home", Proto: proto.TCP,
			ListenPort: proto.PortRange{Lo: 25565, Hi: 25565}, Target: "192.168.1.20:25565",
			VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_01J0000000000000000000BBB", Agent: "home", Proto: proto.UDP,
			ListenPort: proto.PortRange{Lo: 2456, Hi: 2457}, Target: "192.168.1.20:2456",
			VPSMode: proto.ModeKernel, Enabled: true},
	}
	states := map[string]admin.RuleApply{}
	agentStates := map[string]admin.AgentRuleStatus{}
	for _, r := range rules {
		states[r.ID] = admin.RuleApply{ApplyState: admin.ApplyActive}
		agentStates[r.ID] = admin.AgentRuleStatus{Agent: r.Agent, State: proto.StatusOK, Connected: true, At: sinceNow(10 * time.Second)}
	}
	bad := rules[1].ID
	agentStates[bad] = admin.AgentRuleStatus{Agent: "home", State: proto.StatusError,
		Reason: "bind failed: address already in use", Connected: true, At: sinceNow(10 * time.Second)}
	return &fakeStatusBackend{
		rules: rules,
		agents: []admin.AgentInfo{{Name: "home", Connected: true, Generation: 9,
			StreamFrom: "203.0.113.9:51234", LastHeartbeat: sinceNow(10 * time.Second), LastHandshake: sinceNow(30 * time.Second)}},
		apply:           admin.ApplyStatus{DesiredGeneration: 9, ActiveGeneration: 9, Rules: states},
		agentRuleStates: agentStates,
	}
}

// runServerDoctorCmd は `wgft server doctor` を偽の管理用 API に対して実行する。runStatusCmd
// (status_test.go)と同じ形で、根のコマンドではなくこのコマンドだけを動かす。
func runServerDoctorCmd(t *testing.T, adminURL string, args ...string) (stdout string, err error) {
	t.Helper()
	cmd := newServerDoctorCmd()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs(append([]string{"--admin", adminURL}, args...))
	err = cmd.Execute()
	return out.String(), err
}

// TestServerDoctorRunEReadsTheAdminAPI は、RunE が管理用 API から証拠を読み、粒度と出力の形を
// 選び、終了コードまで返すことを確かめる。
func TestServerDoctorRunEReadsTheAdminAPI(t *testing.T) {
	srv := httptest.NewServer(admin.New(doctorRuneBackend()))
	defer srv.Close()

	// 引数の無い実行は server、エージェント、全ルールを 1 行ずつ出し、失敗するルールがあるので
	// 終了コードは 1 になる。
	out, err := runServerDoctorCmd(t, srv.URL)
	for _, want := range []string{"Server", "Agents", "Rules", "home", "Result:", "Not tested by this command"} {
		if !strings.Contains(out, want) {
			t.Errorf("the survey is missing %q:\n%s", want, out)
		}
	}
	if err == nil || exitCode(err) != 1 {
		t.Errorf("a rule whose agent reports an error must exit 1, got err=%v", err)
	}

	// ルールを 1 本指定した実行は、そのルールを公開側から宛先まで順に出す。
	out, err = runServerDoctorCmd(t, srv.URL, "r_01J0000000000000000000BBB")
	for _, want := range []string{"public port", "WireGuard", "control connection", "target",
		"bind failed: address already in use", `Result: traffic stops at "target"`} {
		if !strings.Contains(out, want) {
			t.Errorf("the rule report is missing %q:\n%s", want, out)
		}
	}
	if err == nil || exitCode(err) != 1 {
		t.Errorf("exit code = %v, want 1", err)
	}

	// 健全なルールは終了コード 0 になる。
	if _, err := runServerDoctorCmd(t, srv.URL, "r_01J0000000000000000000AAA"); err != nil {
		t.Errorf("a healthy rule must exit 0, got %v", err)
	}
}

// TestServerDoctorRunEJSONShape は、`--json` が機械向けの模型を出すことを RunE の経路で
// 確かめる(設計文書 10.2a、7a.11 節)。
func TestServerDoctorRunEJSONShape(t *testing.T) {
	srv := httptest.NewServer(admin.New(doctorRuneBackend()))
	defer srv.Close()

	out, _ := runServerDoctorCmd(t, srv.URL, "--json")
	for _, want := range []string{`"status"`, `"checked_at"`, `"probed": false`, `"checks"`,
		`"id": "rule.target"`, `"reason": "listener_bind_failed"`, `"rules"`, `"not_tested"`} {
		if !strings.Contains(out, want) {
			t.Errorf("--json is missing %q:\n%s", want, out)
		}
	}
}

// TestServerDoctorRunEProbeNeedsARule は、`--probe` が 1 本のルールにしか付けられないこと
// (設計文書 10.2a 節)と、その誤りが終了コード 2 になることを確かめる。
func TestServerDoctorRunEProbeNeedsARule(t *testing.T) {
	srv := httptest.NewServer(admin.New(doctorRuneBackend()))
	defer srv.Close()

	_, err := runServerDoctorCmd(t, srv.URL, "--probe")
	if err == nil || exitCode(err) != 2 {
		t.Errorf("--probe without a rule must exit 2, got %v", err)
	}
	// --from の誤りも、証拠を読む前に終了コード 2 で止まる。
	_, err = runServerDoctorCmd(t, srv.URL, "--from", "not-an-address")
	if err == nil || exitCode(err) != 2 {
		t.Errorf("an unreadable --from must exit 2, got %v", err)
	}
}

// TestServerDoctorRunEHealthyUDPRule は、健全な UDP のルールの `rule.target` が、人向けの出力でも
// `--json` でも NOT TESTED(`not_tested`、理由 `udp_listener_only`)になり、それでもルールの
// 総合判定は ok で終了コードは 0 のままであることを、RunE の経路で確かめる(設計文書 10.2a 節、
// 2026-09-24 の改訂の記録)。以前は `rule.target` が `ok` を返していた。エージェントの報告は
// リスナーを開けたことしか示さないので、OK の定義に当たらない。
func TestServerDoctorRunEHealthyUDPRule(t *testing.T) {
	b := doctorRuneBackend()
	const udpID = "r_01J0000000000000000000BBB"
	b.agentRuleStates[udpID] = admin.AgentRuleStatus{Agent: "home", State: proto.StatusOK, Connected: true, At: sinceNow(10 * time.Second)}
	srv := httptest.NewServer(admin.New(b))
	defer srv.Close()

	out, err := runServerDoctorCmd(t, srv.URL, udpID)
	if err != nil {
		t.Errorf("a healthy UDP rule must exit 0, got %v (exit code %d)", err, exitCode(err))
	}
	if !regexp.MustCompile(`(?m)^  target +NOT TESTED`).MatchString(out) {
		t.Errorf("a healthy UDP rule's target line must read NOT TESTED:\n%s", out)
	}
	if regexp.MustCompile(`(?m)^  target +OK`).MatchString(out) {
		t.Errorf("a healthy UDP rule's target line must not read OK:\n%s", out)
	}
	if !strings.Contains(out, "Result: healthy as far as this command can see") {
		t.Errorf("NOT TESTED alone must leave the rule's result healthy:\n%s", out)
	}

	// 引数の無い実行も、全ルールが健全なので終了コード 0 のままである。
	if _, err := runServerDoctorCmd(t, srv.URL); err != nil {
		t.Errorf("the survey of healthy TCP and UDP rules must exit 0, got %v", err)
	}

	out, err = runServerDoctorCmd(t, srv.URL, udpID, "--json")
	if err != nil {
		t.Errorf("--json must not change the exit code of a healthy UDP rule, got %v", err)
	}
	var rep struct {
		Status string `json:"status"`
		Checks []struct {
			ID         string `json:"id"`
			Status     string `json:"status"`
			Reason     string `json:"reason"`
			ObservedAt string `json:"observed_at"`
		} `json:"checks"`
		Rules []struct {
			Status string `json:"status"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("--json did not parse: %v\n%s", err, out)
	}
	if rep.Status != statusOK {
		t.Errorf("status = %q, want %q", rep.Status, statusOK)
	}
	found := false
	for _, c := range rep.Checks {
		if c.ID != checkTarget {
			continue
		}
		found = true
		if c.Status != statusNotTested || c.Reason != "udp_listener_only" {
			t.Errorf("rule.target = %q/%q, want %q/%q", c.Status, c.Reason, statusNotTested, "udp_listener_only")
		}
		if c.ObservedAt == "" {
			t.Error("rule.target must keep the time of the agent's report as observed_at")
		}
	}
	if !found {
		t.Errorf("--json has no rule.target check:\n%s", out)
	}
	if len(rep.Rules) != 1 || rep.Rules[0].Status != statusOK {
		t.Errorf("rules = %+v, want one rule with status %q", rep.Rules, statusOK)
	}
}
