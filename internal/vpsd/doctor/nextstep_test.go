package doctor

import (
	"strings"
	"testing"
)

// A rule whose agent is disabled (design.md 5.1 節) is not published with the reason
// `agent "home" is disabled`. rule enable would change nothing there, so the next step names the
// agent instead; a rule disabled by its own setting still gets rule enable.
func TestApplyNextStepForADisabledAgent(t *testing.T) {
	got := applyNextStep(`agent "home" is disabled`)
	if !strings.Contains(got, "/api/v1/agents/<agent>/enable") || strings.Contains(got, "rule enable") {
		t.Errorf("disabled agent: %q", got)
	}
	if got := applyNextStep("disabled"); got != "enable it: wgft rule enable <rule>" {
		t.Errorf("disabled rule: %q", got)
	}
	if got := applyNextStep(`agent "home" is not registered`); !strings.Contains(got, "join-string") {
		t.Errorf("unregistered agent: %q", got)
	}
}
