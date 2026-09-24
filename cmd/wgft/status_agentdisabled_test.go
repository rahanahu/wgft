package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、無効なエージェント(設計文書 5.1 節)の `wgft status` での数え方(10.2b 節)を
// 確かめる。agents.total と rules.total は意味を変えず、agents.disabled と rules.agent_disabled を
// 加える。healthy + degraded + unknown + disabled = agents.total、active + degraded + unknown +
// agent_disabled = rules.total が成り立ち、無効は終了コードを動かさない。

// withDisabledAgent は、healthyStatusInput に無効なエージェント off を加える。off は接続が
// 切れていて、有効なルール 3 本と、自分で無効なルール 1 本を持つ。無効なエージェントの有効な
// ルールは、server が not_active と `agent "off" is disabled` で報告する。自分で無効なルールは
// 今までどおり総数に数えない。
func withDisabledAgent(in statusInput) statusInput {
	for i := 0; i < 4; i++ {
		r := proto.Rule{
			ID: "r_0" + string(rune('a'+i)) + "offagent0", Agent: "off", Proto: proto.TCP, Enabled: i < 3,
			ListenPort: proto.PortRange{Lo: uint16(3000 + i), Hi: uint16(3000 + i)}, Target: "192.168.1.40:3000",
		}
		in.Rules.Rules = append(in.Rules.Rules, r)
		reason := `agent "off" is disabled`
		if !r.Enabled {
			reason = "disabled"
		}
		in.Rules.RuleStates[r.ID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: reason}
	}
	in.Agents = append(in.Agents, admin.AgentInfo{
		Name: "off", Disabled: true, DisabledAt: at(time.Hour), Connected: false, LastHeartbeat: at(time.Hour),
	})
	return in
}

func checkStatusInvariants(t *testing.T, rep statusReport) {
	t.Helper()
	a, r := rep.Agents, rep.Rules
	if a.Healthy+a.Degraded+a.Unknown+a.Disabled != a.Total {
		t.Errorf("agents: %d+%d+%d+%d != total %d", a.Healthy, a.Degraded, a.Unknown, a.Disabled, a.Total)
	}
	if r.Active+r.Degraded+r.Unknown+r.AgentDisabled != r.Total {
		t.Errorf("rules: %d+%d+%d+%d != total %d", r.Active, r.Degraded, r.Unknown, r.AgentDisabled, r.Total)
	}
}

// TestStatusCountsADisabledAgentApart は、無効なエージェントを healthy・degraded・unknown の
// どれにも数えず、そのルールを agent_disabled に数え、終了コードを 0 のままにすることを確かめる。
// 無効なエージェントは接続が切れていても degraded にならない。
func TestStatusCountsADisabledAgentApart(t *testing.T) {
	rep := buildStatusReport(withDisabledAgent(healthyStatusInput()))
	checkStatusInvariants(t, rep)
	if got := rep.Agents; got.Healthy != 2 || got.Degraded != 0 || got.Unknown != 0 || got.Disabled != 1 || got.Total != 3 || got.Detail != "" {
		t.Errorf("agents = %+v, want 2 healthy, 1 disabled, total 3, no detail", got)
	}
	if got := rep.Rules; got.Active != 8 || got.Degraded != 0 || got.Unknown != 0 || got.AgentDisabled != 3 || got.Total != 11 || got.Detail != "" {
		t.Errorf("rules = %+v, want 8 active, 3 agent disabled, total 11, no detail", got)
	}

	var buf bytes.Buffer
	writeStatusReport(&buf, rep)
	want := "Server        healthy\n" +
		"Agents        2 / 2 healthy, 1 disabled\n" +
		"Rules         8 active, 3 agent disabled / 11\n" +
		"Warnings      none\n"
	if got := buf.String(); got != want {
		t.Errorf("writeStatusReport =\n%s\nwant\n%s", got, want)
	}

	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	want2 := `{"server":{"status":"healthy"},"agents":{"healthy":2,"degraded":0,"unknown":0,"disabled":1,"total":3},"rules":{"active":8,"degraded":0,"unknown":0,"agent_disabled":3,"total":11},"warnings":{"count":0}}`
	if string(data) != want2 {
		t.Errorf("json = %s, want %s", data, want2)
	}
	if err := statusExit(rep); err != nil {
		t.Errorf("a disabled agent alone must exit 0, got %v", err)
	}
}

// TestStatusDisabledAgentBesideADegradedOne は、degraded な行があるときも、無効なエージェントを
// 健康の比から外して別に添え、無効なエージェントのルールを degraded と別に示すことを確かめる。
func TestStatusDisabledAgentBesideADegradedOne(t *testing.T) {
	rep := buildStatusReport(withDisabledAgent(statusExampleInput()))
	checkStatusInvariants(t, rep)
	var buf bytes.Buffer
	writeStatusReport(&buf, rep)
	want := "Server        healthy\n" +
		"Agents        1 healthy, 1 degraded / 2, 1 disabled   home2 last seen 4m12s ago\n" +
		"Rules         7 active, 1 degraded, 3 agent disabled / 11   r_01M335HMAB… bind failed: address already in use\n" +
		"Warnings      1              ip-flapping on home, 1m0s ago\n"
	if got := buf.String(); got != want {
		t.Errorf("writeStatusReport =\n%s\nwant\n%s", got, want)
	}
	if code := exitCode(statusExit(rep)); code != 1 {
		t.Errorf("exit = %d, want 1 for the degraded items; the disabled agent does not change it", code)
	}
	if err := statusExit(rep); err != nil && strings.Contains(err.Error(), "disabled") {
		t.Errorf("the exit error must not count the disabled agent: %v", err)
	}
}

// TestStatusUnregisteredAgentsRuleStaysDegraded は、持ち主のエージェントが登録されていない
// ルールを、今までどおり not_active として degraded に数え、agent_disabled に数えないことを
// 確かめる(設計文書 5.1、10.2b 節)。
func TestStatusUnregisteredAgentsRuleStaysDegraded(t *testing.T) {
	in := healthyStatusInput()
	r := proto.Rule{ID: "r_0gone000000", Agent: "gone", Proto: proto.TCP, Enabled: true,
		ListenPort: proto.PortRange{Lo: 4000, Hi: 4000}, Target: "192.168.1.50:4000"}
	in.Rules.Rules = append(in.Rules.Rules, r)
	in.Rules.RuleStates[r.ID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: `agent "gone" is not registered`}
	rep := buildStatusReport(in)
	checkStatusInvariants(t, rep)
	if got := rep.Rules; got.Active != 8 || got.Degraded != 1 || got.AgentDisabled != 0 || got.Total != 9 {
		t.Errorf("rules = %+v, want 8 active, 1 degraded, 0 agent disabled, total 9", got)
	}
	if got := rep.Agents; got.Disabled != 0 || got.Total != 2 {
		t.Errorf("agents = %+v, want 0 disabled of 2", got)
	}
	if code := exitCode(statusExit(rep)); code != 1 {
		t.Errorf("exit = %d, want 1 as before", code)
	}
}

// TestStatusAllAgentsDisabled は、有効なエージェントが 1 台も無い場合の人向けの行を確かめる。
func TestStatusAllAgentsDisabled(t *testing.T) {
	in := withDisabledAgent(healthyStatusInput())
	in.Agents = in.Agents[2:]
	in.Rules.Rules = in.Rules.Rules[len(rulesFixture()):]
	rep := buildStatusReport(in)
	checkStatusInvariants(t, rep)
	if got := agentsValue(rep.Agents); got != "0 / 0 healthy, 1 disabled" {
		t.Errorf("agents value = %q", got)
	}
	if got := rulesValue(rep.Rules); got != "0 active, 3 agent disabled / 3" {
		t.Errorf("rules value = %q", got)
	}
	if err := statusExit(rep); err != nil {
		t.Errorf("exit = %v, want 0", err)
	}
}

// TestStatusRunEDisabledAgent は、RunE を通した `status` と `status --json` が、無効なエージェント
// だけの差分で終了コード 0 を返し、--json が disabled と agent_disabled を持つことを確かめる。
func TestStatusRunEDisabledAgent(t *testing.T) {
	in := withDisabledAgent(healthyStatusInput())
	// RunE は実時計で鮮度を判定するので、時刻を今に寄せる。
	agentStates := map[string]admin.AgentRuleStatus{}
	for id, st := range in.Rules.AgentRuleStates {
		st.At = wallNow(5 * time.Second)
		agentStates[id] = st
	}
	for i := range in.Agents {
		if !in.Agents[i].Disabled {
			in.Agents[i].LastHeartbeat, in.Agents[i].LastHandshake = wallNow(5*time.Second), wallNow(5*time.Second)
		}
	}
	b := &fakeStatusBackend{
		rules: in.Rules.Rules, agents: in.Agents, agentRuleStates: agentStates,
		apply: admin.ApplyStatus{DesiredGeneration: 9, ActiveGeneration: 9, Rules: in.Rules.RuleStates},
	}
	srv := httptest.NewServer(admin.New(b))
	defer srv.Close()

	out, err := runStatusCmd(t, srv.URL)
	if err != nil {
		t.Errorf("status: exit %d (%v), want 0", exitCode(err), err)
	}
	for _, want := range []string{"2 / 2 healthy, 1 disabled", "8 active, 3 agent disabled / 11"} {
		if !strings.Contains(out, want) {
			t.Errorf("status is missing %q:\n%s", want, out)
		}
	}
	out, err = runStatusCmd(t, srv.URL, "--json")
	if err != nil {
		t.Errorf("status --json: exit %d (%v), want 0", exitCode(err), err)
	}
	var rep statusReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	checkStatusInvariants(t, rep)
	if rep.Agents.Disabled != 1 || rep.Rules.AgentDisabled != 3 {
		t.Errorf("--json = %+v", rep)
	}
}
