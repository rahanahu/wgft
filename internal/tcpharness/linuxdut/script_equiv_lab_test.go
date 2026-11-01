//go:build linux && lab

package linuxdut

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/rahanahu/wgft/internal/tcpharness"
)

// sideResult is what one side of the Linux side-by-side check records for a scenario.
type sideResult struct {
	Lines  []string `json:"lines"`  // tcpharness.CheckLines of the run
	Passed bool     `json:"passed"` // tcpharness.Passed of the run
}

// TestScriptsMatchGoFunctions runs each scenario that moved to a script side by side with the Go
// function it replaces, on the reference Linux, and requires the same check lines
// (tcpharness.CheckLines) from a Go run that passed (docs/design/v2/test-tooling.md, section 1,
// the conversion check).
//
// The two sides run in two processes, each in a fresh user and network namespace, so neither
// sees the state the other left in the kernel: TIME-WAIT four-tuples, IP reassembly queues keyed
// by the scripts' fixed IP IDs, and the ICMP rate limit, which a run moments before would use up.
// Within a side the scenarios run one after another, as TestConformance runs them. The scenarios
// whose sides differ run again, up to three times in all, each time in fresh namespaces. Run it
// in the lab VM:
//
//	lab/lab test internal/tcpharness/linuxdut vps -test.run=TestScriptsMatchGoFunctions
func TestScriptsMatchGoFunctions(t *testing.T) {
	if side := os.Getenv("WGFT_TEST_SIDE"); side != "" {
		runSide(t, side, strings.Split(os.Getenv("WGFT_TEST_SIDE_ONLY"), ","), os.Getenv("WGFT_TEST_SIDE_OUT"))
		return
	}
	t.Logf("kernel %s; the expected differences are recorded for the reference kernel %s", KernelRelease(), ReferenceRelease)
	var names []string
	for _, s := range tcpharness.LegacyScenarios {
		names = append(names, s.Name)
	}
	dir := t.TempDir()
	diffs := map[string]string{}
	for attempt := 1; attempt <= 3 && len(names) > 0; attempt++ {
		results := map[string]map[string]sideResult{}
		for _, side := range []string{"go", "script"} {
			out := filepath.Join(dir, fmt.Sprintf("%s-%d.json", side, attempt))
			if err := sideInNetns(t, side, names, out); err != nil {
				t.Fatalf("the %s side: %v", side, err)
			}
			b, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			var r map[string]sideResult
			if err := json.Unmarshal(b, &r); err != nil {
				t.Fatal(err)
			}
			results[side] = r
		}
		var again []string
		for _, n := range names {
			g, s := results["go"][n], results["script"][n]
			d := tcpharness.DiffLines(g.Lines, s.Lines)
			if d == "" && !g.Passed {
				d = "the Go function's run did not pass, so the pair shows nothing"
			}
			if d == "" {
				delete(diffs, n)
				continue
			}
			diffs[n] = d
			again = append(again, n)
			t.Logf("%s, attempt %d: %s", n, attempt, d)
		}
		names = again
	}
	for _, n := range names {
		t.Errorf("%s: %s", n, diffs[n])
	}
}

// runSide runs one side of the check inside its namespace and writes the results to out.
func runSide(t *testing.T, side string, names []string, out string) {
	if err := PinReference(); err != nil {
		t.Fatalf("pinning the reference sysctls: %v", err)
	}
	table := map[string]tcpharness.Scenario{}
	src := tcpharness.Scenarios
	if side == "go" {
		src = tcpharness.LegacyScenarios
	}
	for _, s := range src {
		table[s.Name] = s
	}
	results := map[string]sideResult{}
	for _, n := range names {
		s, ok := table[n]
		if !ok {
			t.Fatalf("no %s scenario %s", side, n)
		}
		outcome, lines, failed := tcpharness.RecordTrace(t, Engine(Known), s, 1)
		results[n] = sideResult{Lines: tcpharness.CheckLines(lines), Passed: tcpharness.Passed(outcome, failed)}
	}
	b, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// sideInNetns runs the test binary again in a new user and network namespace as one side.
func sideInNetns(t *testing.T, side string, names []string, out string) error {
	cmd := exec.Command(os.Args[0], "-test.run=^TestScriptsMatchGoFunctions$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), "WGFT_TEST_IN_NETNS=1", "WGFT_TEST_SIDE="+side,
		"WGFT_TEST_SIDE_ONLY="+strings.Join(names, ","), "WGFT_TEST_SIDE_OUT="+out)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	b, err := cmd.CombinedOutput()
	t.Logf("the %s side in a new user and network namespace:\n%s", side, b)
	return err
}
