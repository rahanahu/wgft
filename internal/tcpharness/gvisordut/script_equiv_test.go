package gvisordut

import (
	"testing"

	"github.com/rahanahu/wgft/internal/tcpharness"
)

// TestScriptsMatchGoFunctions runs each scenario that moved to a script side by side with the Go
// function it replaces, on gVisor in real time, and requires the same checks with the same
// outcomes and observations and the same measured names (docs/design/v2/test-tooling.md,
// section 1, the conversion check). A real-time pair that differs runs again, up to three times,
// since a loaded machine can move one run of a timed check.
func TestScriptsMatchGoFunctions(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("real-time TCP scenarios; skipped with -short")
	}
	scripts := map[string]tcpharness.Scenario{}
	for _, s := range tcpharness.Scenarios {
		scripts[s.Name] = s
	}
	for _, legacy := range tcpharness.LegacyScenarios {
		t.Run(legacy.Name, func(t *testing.T) {
			t.Parallel()
			s := scripts[legacy.Name]
			for seed := uint64(1); seed <= 2; seed++ {
				var d string
				for k := range uint64(3) {
					goSeed := seed + k*attemptSeedStride
					wantOut, want, wantFailed := tcpharness.RecordTrace(t, Engine(Known), legacy, goSeed)
					_, got, _ := tcpharness.RecordTrace(t, Engine(Known), s, goSeed+pairSeedOffset)
					d = tcpharness.DiffLines(tcpharness.CheckLines(want), tcpharness.CheckLines(got))
					if d == "" && !tcpharness.Passed(wantOut, wantFailed) {
						d = "the Go function's run did not pass, so the pair shows nothing"
					}
					if d == "" {
						break
					}
					t.Logf("seed %d: %s; running the pair again", seed, d)
				}
				if d != "" {
					t.Errorf("seed %d: %s", seed, d)
				}
			}
		})
	}
}

// pairSeedOffset gives the script's run of a pair its own seed. Each run here gets a fresh gVisor
// stack, so the offset is 0; the Linux pair shares one namespace and needs another seed.
const pairSeedOffset = 0

// attemptSeedStride moves both seeds of a pair on each new attempt; 0 here, as pairSeedOffset.
const attemptSeedStride = 0
