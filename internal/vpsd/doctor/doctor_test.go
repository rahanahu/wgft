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
