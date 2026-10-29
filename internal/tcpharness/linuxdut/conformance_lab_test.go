//go:build linux && lab

package linuxdut

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/rahanahu/wgft/internal/tcpharness"
)

// Known lists where Linux, the reference, is known to differ from the scenarios' expectations.
var Known = map[string]string{}

// TestConformance runs the scenarios against the Linux kernel's TCP through a TUN device. It
// re-runs itself in a new user and network namespace, so the kernel's defaults for a new
// namespace apply and nothing outside the namespace is touched. Run it in the lab VM:
//
//	lab/lab test internal/tcpharness/linuxdut
func TestConformance(t *testing.T) {
	if os.Getenv("WGFT_TEST_IN_NETNS") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestConformance$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), "WGFT_TEST_IN_NETNS=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		}
		out, err := cmd.CombinedOutput()
		t.Logf("in a new user and network namespace:\n%s", out)
		var pe *os.PathError
		if errors.As(err, &pe) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL) {
			t.Fatalf("undetermined: cannot create a user and network namespace here: %v", err)
		}
		if err != nil {
			t.Fatalf("the scenarios failed in the namespace: %v", err)
		}
		return
	}
	tcpharness.Run(t, Engine(Known), tcpharness.Scenarios)
}
