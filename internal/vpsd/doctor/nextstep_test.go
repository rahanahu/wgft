package doctor

import (
	"strings"
	"testing"
)

// A rule whose agent is disabled (design.md 5.1 節) is not published with the reason
// `agent "home" is disabled`. Diagnose reports such a rule as agent.enabled skipped before
// rule.public_port is ever built, so this case is reached only when the agent was enabled between
// the rules read and the agents read. The agent is already enabled then, so the next step asks for
// a re-run rather than agent enable or rule enable; a rule disabled by its own setting still gets
// rule enable.
func TestApplyNextStepForADisabledAgent(t *testing.T) {
	got := applyNextStep(`agent "home" is disabled`)
	if !strings.Contains(got, "run it again") || strings.Contains(got, "agent enable") || strings.Contains(got, "rule enable") {
		t.Errorf("disabled agent: %q", got)
	}
	if got := applyNextStep("disabled"); got != "enable it: wgft rule enable <rule>" {
		t.Errorf("disabled rule: %q", got)
	}
	if got := applyNextStep(`agent "home" is not registered`); !strings.Contains(got, "join-string") {
		t.Errorf("unregistered agent: %q", got)
	}
}
