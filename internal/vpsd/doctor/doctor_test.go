package doctor

import "testing"

// TestAgentCheckFallsBackToFirstWhenEveryRuleIsDisabled は、AgentCheck の 2 つの分岐のうち、
// 有効なルールが 1 本も無い場合の分岐を固定する。AgentCheck はまず rule_disabled でない検査を
// 探し、見つからなければ最初に見た rule_disabled の検査を返す(doctor.go の AgentCheck)。この
// エージェントを名指すルールがすべて無効なら、後者の分岐に必ず入る。
func TestAgentCheckFallsBackToFirstWhenEveryRuleIsDisabled(t *testing.T) {
	rep := Report{Checks: []Check{
		{ID: CheckConnection, Agent: "a1", RuleID: "r1", Status: StatusSkipped, Reason: ReasonRuleDisabled},
		{ID: CheckConnection, Agent: "a1", RuleID: "r2", Status: StatusSkipped, Reason: ReasonRuleDisabled},
	}}
	c, ok := rep.AgentCheck("a1", CheckConnection)
	if !ok {
		t.Fatal("AgentCheck found no check for an agent named only by disabled rules; the fallback must still return one")
	}
	if c.RuleID != "r1" {
		t.Errorf("AgentCheck fallback returned rule %q, want the first rule seen, r1", c.RuleID)
	}
	if c.Status != StatusSkipped || c.Reason != ReasonRuleDisabled {
		t.Errorf("AgentCheck fallback = %s/%s, want %s/%s", c.Status, c.Reason, StatusSkipped, ReasonRuleDisabled)
	}
}

// TestAgentCheckPrefersAgentDisabledOverRuleDisabled は、無効なエージェントを名指すルールの
// 検査から 1 つ選ぶとき、エージェント自身の状態(無効)を述べる agent_disabled を、ルール自身の
// 無効を述べる rule_disabled より先に採ることを確かめる。一覧の Agents の行と Web UI の
// エージェントの行が、無効なルールが先に並んでいても「エージェントが無効」と示すためである。
func TestAgentCheckPrefersAgentDisabledOverRuleDisabled(t *testing.T) {
	rep := Report{Checks: []Check{
		{ID: CheckConnection, Agent: "a1", RuleID: "r1", Status: StatusSkipped, Reason: ReasonRuleDisabled},
		{ID: CheckConnection, Agent: "a1", RuleID: "r2", Status: StatusSkipped, Reason: ReasonAgentDisabled},
		{ID: CheckConnection, Agent: "a1", RuleID: "r3", Status: StatusSkipped, Reason: ReasonAgentDisabled},
	}}
	c, ok := rep.AgentCheck("a1", CheckConnection)
	if !ok || c.RuleID != "r2" || c.Reason != ReasonAgentDisabled {
		t.Errorf("AgentCheck = %s/%s from %q, want agent_disabled from r2", c.Status, c.Reason, c.RuleID)
	}
	// 有効なエージェントの有効なルールの検査があれば、それを最優先にする(従来どおり)。
	rep.Checks = append(rep.Checks, Check{ID: CheckConnection, Agent: "a1", RuleID: "r4", Status: StatusOK})
	if c, _ := rep.AgentCheck("a1", CheckConnection); c.RuleID != "r4" {
		t.Errorf("AgentCheck picked %q, want the enabled rule r4", c.RuleID)
	}
}
