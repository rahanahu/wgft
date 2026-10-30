package tcpharness

import "testing"

func scenarioNamed(t *testing.T, name string) Scenario {
	t.Helper()
	for _, s := range Scenarios {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no scenario %s", name)
	return Scenario{}
}

// TestLossResponseTeeth runs the loss-response family against modelSender: with the reference
// Linux's reductions every check passes, and each wrong reduction fails the check meant for it.
// gVisor cannot carry these faults the way the other teeth do, since it fails two of the checks
// on its own.
func TestLossResponseTeeth(t *testing.T) {
	scenarios := []string{"chained-recovery", "reorder-wait-recovery", "rto-after-burst"}
	t.Run("correct", func(t *testing.T) {
		for _, name := range scenarios {
			got := Record(t, modelEngine(ruleWindow), scenarioNamed(t, name), 1)
			for k, o := range got {
				for _, v := range o {
					if v != OutcomePass {
						t.Errorf("%s: outcome %q, want pass; all outcomes: %v", k, v, got)
					}
				}
			}
		}
	})
	for _, c := range []struct {
		name     string
		rule     modelRule
		scenario string
		key      string
	}{
		{"span-chained", ruleSpan, "chained-recovery", "chained-recovery/reduced"},
		{"span-reorder", ruleSpan, "reorder-wait-recovery", "reorder-wait-recovery/reduced"},
		{"none-chained", ruleNone, "chained-recovery", "chained-recovery/reduced"},
		{"none-reorder", ruleNone, "reorder-wait-recovery", "reorder-wait-recovery/reduced"},
		{"collapse", ruleCollapse, "rto-after-burst", "rto-after-burst/ssthresh.not-collapsed"},
		{"rto-span", ruleRTOSpan, "rto-after-burst", "rto-after-burst/ssthresh.not-above-window"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := Record(t, modelEngine(c.rule), scenarioNamed(t, c.scenario), 1)
			o := got[c.key]
			if len(o) == 0 || o[len(o)-1] != OutcomeFail {
				t.Errorf("%s: outcome %v, want fail; all outcomes: %v", c.key, o, got)
			}
		})
	}
}
