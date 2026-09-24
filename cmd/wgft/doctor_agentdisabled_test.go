package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、持ち主のエージェントが無効なルールと、持ち主のエージェントが登録されていない
// ルールの `server doctor` の判定(設計文書 5.1、10.2a 節)を確かめる。無効なエージェントの
// ルールは宣言どおりの状態なので、agent.enabled から下流を agent_disabled の skipped にし、
// 終了コードを 0 のままにする。登録されていないエージェントのルールは、agent.enabled が OK に
// なるだけで、既存の検査の結果も終了コードも動かさない。

const (
	checkAgentEnabled   = doctor.CheckAgentEnabled
	reasonAgentDisabled = doctor.ReasonAgentDisabled
)

// disabledAgentInput は、ルールは有効で持ち主の home が無効な証拠一式である。server は無効な
// エージェントのルールを dataplane から外すので、rule_states はそのルールを not_active と
// `agent "home" is disabled` で報告する(設計文書 5.1 節)。エージェントは接続したままで、
// トンネルも健全である。無効化は登録も stream も残すためである。
func disabledAgentInput(r proto.Rule) doctorInput {
	in := healthyInput(r)
	in.Agents[0].Disabled = true
	in.Agents[0].DisabledAt = at(3 * time.Minute)
	in.Rules.RuleStates[r.ID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: `agent "home" is disabled`}
	// 無効の間、エージェントはそのルールを enabled:false として受け取り、報告しない。
	delete(in.Rules.AgentRuleStates, r.ID)
	return in
}

// TestDisabledAgentsRuleIsSkippedNotFailed は、無効なエージェントのルールで、rule.enabled が OK、
// agent.enabled が agent_disabled の skipped、下流がすべて同じ理由の skipped になり、
// rule.public_port が FAILED `not_published` にならないことを確かめる(設計文書 10.2a 節)。
func TestDisabledAgentsRuleIsSkippedNotFailed(t *testing.T) {
	for _, r := range []proto.Rule{tcpRule(), udpRule()} {
		t.Run(string(r.Proto), func(t *testing.T) {
			in := disabledAgentInput(r)
			checks := diagnose(r, in)
			if len(checks) != len(checkOrder)-1 {
				t.Errorf("checks = %d, want one per rule check id (%d):%s", len(checks), len(checkOrder)-1, dumpChecks(checks))
			}
			for _, c := range checks {
				switch c.ID {
				case checkEnabled:
					if c.Status != statusOK {
						t.Errorf("rule.enabled = %s; the rule itself is enabled", c.Status)
					}
				case checkAgentEnabled:
					if c.Status != statusSkipped || c.Reason != reasonAgentDisabled {
						t.Errorf("agent.enabled = %s/%s, want %s/%s", c.Status, c.Reason, statusSkipped, reasonAgentDisabled)
					}
					if c.Agent != "home" || c.Group != doctor.GroupServer || c.Label != "agent enabled" {
						t.Errorf("agent.enabled agent/group/label = %q/%q/%q", c.Agent, c.Group, c.Label)
					}
					if !strings.Contains(c.Detail, `agent "home" was disabled 3m0s ago`) {
						t.Errorf("agent.enabled detail = %q, want it to say when the agent was disabled", c.Detail)
					}
					if c.Next != "enable the agent: wgft agent enable home" {
						t.Errorf("agent.enabled next = %q, want the agent enable command", c.Next)
					}
					if c.Hidden(false) {
						t.Error("agent.enabled is the finding itself and must not be hidden")
					}
				default:
					if c.Status != statusSkipped || c.Reason != reasonAgentDisabled {
						t.Errorf("%s = %s/%s, want %s/%s", c.ID, c.Status, c.Reason, statusSkipped, reasonAgentDisabled)
					}
					if strings.Contains(c.Next, "rule enable") || !strings.Contains(c.Next, "wgft agent enable home") {
						t.Errorf("%s next = %q; rule enable changes nothing here", c.ID, c.Next)
					}
					if !c.Hidden(false) || c.Hidden(true) {
						t.Errorf("%s: the downstream of a disabled agent is hidden by default and shown by --verbose", c.ID)
					}
				}
			}
			rep := buildReport([]proto.Rule{r}, in)
			if rep.Status != statusOK {
				t.Errorf("report status = %s, want ok", rep.Status)
			}
			if got := rep.Rules[0]; got.Status != statusSkipped || got.StoppedAt != "" {
				t.Errorf("rule status/stopped_at = %s/%q, want skipped with no stop", got.Status, got.StoppedAt)
			}
			if !rep.RuleAgentDisabled(r.ID) {
				t.Error("RuleAgentDisabled = false for a rule of a disabled agent")
			}
			if err := doctorExit(rep); err != nil {
				t.Errorf("a disabled agent's rule must exit 0, got %v", err)
			}
		})
	}
}

// TestDisabledRuleOfADisabledAgentShowsRuleDisabledFirst は、ルール自身も無効なら rule_disabled
// を先に示すことを確かめる。直す操作が rule enable と agent enable で違うためである(設計文書
// 10.2a 節)。
func TestDisabledRuleOfADisabledAgentShowsRuleDisabledFirst(t *testing.T) {
	r := tcpRule()
	r.Enabled = false
	in := disabledAgentInput(r)
	in.Rules.Rules = []proto.Rule{r}
	for _, c := range diagnose(r, in) {
		if c.Status != statusSkipped || c.Reason != reasonRuleDisabled {
			t.Errorf("%s = %s/%s, want %s/%s", c.ID, c.Status, c.Reason, statusSkipped, reasonRuleDisabled)
		}
	}
	rep := buildReport([]proto.Rule{r}, in)
	if rep.RuleAgentDisabled(r.ID) {
		t.Error("a rule disabled by its own setting must read as rule_disabled, not agent_disabled")
	}
	var b strings.Builder
	writeRuleReport(&b, rep, false)
	if !strings.Contains(b.String(), "Result: the rule is disabled, so nothing is forwarded") {
		t.Errorf("result line:\n%s", b.String())
	}
}

// TestEnabledAgentPassesAgentEnabledQuietly は、有効なエージェントのルールで agent.enabled が
// OK になり、既定では出さず、--verbose では出すことを確かめる。旧い版の server は disabled を
// 返さないので、同じく OK になる。
func TestEnabledAgentPassesAgentEnabledQuietly(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	c := checkOf(t, diagnose(r, in), checkAgentEnabled)
	if c.Status != statusOK || c.Reason != "" || c.ObservedAt == "" {
		t.Errorf("agent.enabled = %s/%q observed %q, want ok with no reason and an observation time", c.Status, c.Reason, c.ObservedAt)
	}
	if !c.Hidden(false) || c.Hidden(true) {
		t.Error("an ok agent.enabled is hidden by default and shown by --verbose")
	}
	rep := buildReport([]proto.Rule{r}, in)
	if rep.Rules[0].Status != statusOK || rep.RuleAgentDisabled(r.ID) {
		t.Errorf("a healthy rule of an enabled agent = %s", rep.Rules[0].Status)
	}
	var quiet, verbose strings.Builder
	writeRuleReport(&quiet, rep, false)
	writeRuleReport(&verbose, rep, true)
	if strings.Contains(quiet.String(), "agent enabled") {
		t.Errorf("the default output must not show an ok agent.enabled:\n%s", quiet.String())
	}
	if !strings.Contains(verbose.String(), "agent enabled") {
		t.Errorf("--verbose must show agent.enabled:\n%s", verbose.String())
	}
}

// TestUnregisteredAgentKeepsItsResults は、持ち主のエージェントが登録されていないルールで、
// agent.enabled が OK になり、既存の結果(rule.public_port の FAILED `not_published`、
// agent.connection の FAILED `agent_not_registered`、ルールの failed、終了コード 1)が
// 動かないことを確かめる(設計文書 5.1、10.2a 節)。
func TestUnregisteredAgentKeepsItsResults(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	in.Agents = nil
	in.Rules.RuleStates[r.ID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: `agent "home" is not registered`}
	delete(in.Rules.AgentRuleStates, r.ID)
	checks := diagnose(r, in)

	c := checkOf(t, checks, checkAgentEnabled)
	if c.Status != statusOK || c.Reason != "" {
		t.Errorf("agent.enabled = %s/%s, want ok: no disable mark stops this rule", c.Status, c.Reason)
	}
	if !strings.Contains(c.Detail, `no agent named "home" is registered`) {
		t.Errorf("agent.enabled detail = %q", c.Detail)
	}
	if c := checkOf(t, checks, checkPublicPort); c.Status != statusFailed || c.Reason != reasonNotPublished {
		t.Errorf("rule.public_port = %s/%s, want %s/%s", c.Status, c.Reason, statusFailed, reasonNotPublished)
	}
	if c := checkOf(t, checks, checkConnection); c.Status != statusFailed || c.Reason != reasonAgentNotRegistered {
		t.Errorf("agent.connection = %s/%s, want %s/%s", c.Status, c.Reason, statusFailed, reasonAgentNotRegistered)
	}
	for _, id := range []string{checkHandshake, checkRulesReceived, checkCredentials} {
		if c := checkOf(t, checks, id); c.Status != statusSkipped || c.Reason != reasonAgentNotRegistered {
			t.Errorf("%s = %s/%s, want %s/%s", id, c.Status, c.Reason, statusSkipped, reasonAgentNotRegistered)
		}
	}
	rep := buildReport([]proto.Rule{r}, in)
	if rep.Status != statusFailed || rep.Rules[0].Status != statusFailed || rep.Rules[0].StoppedAt != checkPublicPort {
		t.Errorf("report %s, rule %s stopped at %q; want failed at %s", rep.Status, rep.Rules[0].Status, rep.Rules[0].StoppedAt, checkPublicPort)
	}
	if code := exitCode(doctorExit(rep)); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// TestDisabledAgentHumanOutput は、無効なエージェントのルールの人向けの出力を確かめる。
// 1 本のルールの報告は agent.enabled の行と agent enable の案内を出し、結論は無効なルールと
// 書き分ける。一覧は、エージェントの行と、ルールの行の両方で無効を示す。
func TestDisabledAgentHumanOutput(t *testing.T) {
	r := tcpRule()
	in := disabledAgentInput(r)
	rep := buildReport([]proto.Rule{r}, in)

	var b strings.Builder
	writeRuleReport(&b, rep, false)
	out := b.String()
	for _, want := range []string{
		"agent enabled      SKIPPED",
		`agent "home" was disabled 3m0s ago; this rule forwards nothing`,
		"Check: enable the agent: wgft agent enable home",
		`Result: the rule's agent "home" is disabled, so nothing is forwarded`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the rule report is missing %q:\n%s", want, out)
		}
	}
	// 試していない範囲の一覧は公開ポートに触れるので、検査の部分だけを見る。
	checksPart := out[:strings.Index(out, "\nHistory")]
	for _, bad := range []string{"FAILED", "public port", "not_published", "rule enable"} {
		if strings.Contains(checksPart, bad) {
			t.Errorf("the rule report must not say %q:\n%s", bad, checksPart)
		}
	}

	// 一覧:無効な home のルールと、有効な office のルールを並べる。
	other := tcpRule()
	other.ID, other.Agent, other.ListenPort = "r_01M2R009OFFICEAAAAAAAAAAA", "office", proto.PortRange{Lo: 443, Hi: 443}
	in.Rules.Rules = []proto.Rule{r, other}
	in.Rules.RuleStates[other.ID] = admin.RuleApply{ApplyState: admin.ApplyActive, ActiveGeneration: u64(12)}
	in.Rules.AgentRuleStates[other.ID] = admin.AgentRuleStatus{Agent: "office", State: proto.StatusOK, At: at(10 * time.Second), Connected: true}
	office := healthyInput(other).Agents[0]
	office.Name = "office"
	in.Agents = append(in.Agents, office)
	rep = buildReport([]proto.Rule{r, other}, in)
	if rep.Status != statusOK {
		t.Errorf("survey status = %s, want ok", rep.Status)
	}
	if err := doctorExit(rep); err != nil {
		t.Errorf("survey exit = %v, want 0", err)
	}
	b.Reset()
	writeSurvey(&b, rep, false)
	out = b.String()
	if l := lineHolding(t, out, "  home "); !strings.Contains(l, "SKIPPED") || !strings.Contains(l, `agent "home" is disabled`) {
		t.Errorf("home's agent line = %q, want SKIPPED and the agent disabled", l)
	}
	if l := lineHolding(t, out, "  office "); !strings.Contains(l, "OK") {
		t.Errorf("office's agent line = %q, want OK", l)
	}
	if l := lineHolding(t, out, short(r.ID)); !strings.Contains(l, "SKIPPED") || !strings.Contains(l, `agent enabled: agent "home" was disabled 3m0s ago`) {
		t.Errorf("home's rule row = %q, want SKIPPED and the agent enabled finding", l)
	}
	if !strings.Contains(out, "Result: no failing check") {
		t.Errorf("survey result:\n%s", out)
	}
}

// TestDisabledAgentJSON は、--json の模型に agent.enabled の agent_disabled が載り、ルールの
// status が skipped、最上位の status が ok になることを確かめる(設計文書 10.2a、7a.11 節)。
func TestDisabledAgentJSON(t *testing.T) {
	r := tcpRule()
	data, err := json.Marshal(buildReport([]proto.Rule{r}, disabledAgentInput(r)))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Status string `json:"status"`
		Checks []struct {
			ID, RuleID, Agent, Status, Reason string
		} `json:"checks"`
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != statusOK {
		t.Errorf("status = %q, want ok", got.Status)
	}
	found := false
	for _, c := range got.Checks {
		if c.ID == checkAgentEnabled {
			found = true
			if c.Status != statusSkipped || c.Reason != reasonAgentDisabled || c.Agent != "home" {
				t.Errorf("agent.enabled = %+v", c)
			}
		}
		if c.Status == statusFailed {
			t.Errorf("no check may fail on a disabled agent's rule: %+v", c)
		}
	}
	if !found {
		t.Errorf("--json has no agent.enabled check: %s", data)
	}
	if len(got.Rules) != 1 || got.Rules[0]["status"] != statusSkipped {
		t.Errorf("rules = %v, want one skipped rule", got.Rules)
	}
	if _, ok := got.Rules[0]["stopped_at"]; ok {
		t.Errorf("a skipped rule has no stopped_at: %v", got.Rules[0])
	}
}

// TestServerDoctorRunEDisabledAgentExitsZero は、無効なエージェントのルールだけが止まっている
// 配置で、RunE を通した 1 本の報告、一覧、--json のどれもが終了コード 0 で終わることを確かめる。
func TestServerDoctorRunEDisabledAgentExitsZero(t *testing.T) {
	b := doctorRuneBackend()
	b.rules = b.rules[:1]
	id := b.rules[0].ID
	b.agents[0].Disabled = true
	b.apply.Rules[id] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: `agent "home" is disabled`}
	delete(b.agentRuleStates, id)
	srv := httptest.NewServer(admin.New(b))
	defer srv.Close()

	out, err := runServerDoctorCmd(t, srv.URL, id)
	if err != nil {
		t.Errorf("single rule: exit %d (%v), want 0", exitCode(err), err)
	}
	if !strings.Contains(out, `Result: the rule's agent "home" is disabled`) {
		t.Errorf("single rule output:\n%s", out)
	}
	if out, err = runServerDoctorCmd(t, srv.URL); err != nil {
		t.Errorf("survey: exit %d (%v), want 0\n%s", exitCode(err), err, out)
	}
	out, err = runServerDoctorCmd(t, srv.URL, "--json", id)
	if err != nil {
		t.Errorf("--json: exit %d (%v), want 0", exitCode(err), err)
	}
	for _, want := range []string{`"id": "agent.enabled"`, `"reason": "agent_disabled"`} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("--json is missing %s:\n%s", want, out)
		}
	}
}
