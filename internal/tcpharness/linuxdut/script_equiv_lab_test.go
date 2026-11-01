//go:build linux && lab

package linuxdut

import (
	"testing"

	"github.com/rahanahu/wgft/internal/tcpharness"
)

// TestScriptsMatchGoFunctions runs each scenario that moved to a script side by side with the Go
// function it replaces, on the reference Linux, and requires the same checks with the same
// outcomes and observations and the same measured names (docs/design/v2/test-tooling.md,
// section 1, the conversion check). A pair that differs runs again, up to three times, as the
// gVisor one does. Run it in the lab VM:
//
//	lab/lab test internal/tcpharness/linuxdut vps -test.run=TestScriptsMatchGoFunctions
func TestScriptsMatchGoFunctions(t *testing.T) {
	if !inNetns(t, "^TestScriptsMatchGoFunctions$") {
		return
	}
	if err := PinReference(); err != nil {
		t.Fatalf("pinning the reference sysctls: %v", err)
	}
	scripts := map[string]tcpharness.Scenario{}
	for _, s := range tcpharness.Scenarios {
		scripts[s.Name] = s
	}
	for _, legacy := range tcpharness.LegacyScenarios {
		t.Run(legacy.Name, func(t *testing.T) {
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

// pairSeedOffset gives the script's run of a pair its own seed, and with it its own ports and
// ISS: the runs share one namespace, and the same four-tuple would meet the TIME-WAIT state the
// Go function's run left. The checks compared carry no seeded numbers.
const pairSeedOffset = 1000

// attemptSeedStride moves both seeds of a pair on each new attempt, so a pair run again does not
// meet the TIME-WAIT state of its earlier attempt.
const attemptSeedStride = 2000
