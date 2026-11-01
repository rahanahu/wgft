package wgstackdut

import (
	"testing"

	"github.com/rahanahu/wgft/internal/tcpharness"
)

// TestScriptsMatchGoFunctions runs each scenario that moved to a script side by side with the Go
// function it replaces, on wgstack and the harness's clock, and requires the same log: the same
// segments in and out, the same checks with the same observations, the same measured values
// (docs/design/v2/test-tooling.md, section 1, the conversion check).
func TestScriptsMatchGoFunctions(t *testing.T) {
	scripts := map[string]tcpharness.Scenario{}
	for _, s := range tcpharness.Scenarios {
		scripts[s.Name] = s
	}
	for _, legacy := range tcpharness.LegacyScenarios {
		t.Run(legacy.Name, func(t *testing.T) {
			s, ok := scripts[legacy.Name]
			if !ok {
				t.Fatalf("no scenario %s in the table", legacy.Name)
			}
			if s.Refs != legacy.Refs {
				t.Errorf("refs differ:\nscript %q\n    Go %q", s.Refs, legacy.Refs)
			}
			for seed := uint64(1); seed <= 5; seed++ {
				wantOut, want := tcpharness.RecordTrace(t, Engine(Known), legacy, seed)
				_, got := tcpharness.RecordTrace(t, Engine(Known), s, seed)
				if d := tcpharness.DiffLines(want, got); d != "" {
					t.Errorf("seed %d: %s", seed, d)
				}
				if !tcpharness.Passed(wantOut) {
					t.Errorf("seed %d: the Go function's run did not pass, so the pair shows nothing", seed)
				}
			}
		})
	}
}
