//go:build linux && lab

package linuxdut

import (
	"errors"
	"flag"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/rahanahu/wgft/internal/tcpharness"
)

// Known lists where Linux, the reference, is known to differ from the scenarios' expectations.
// A scenario that checks a choice of wgstack's design beyond the RFCs keeps that check here.
var Known = map[string]tcpharness.Known{
	// limited-transmit runs at the testbench's near-zero RTT for RFC 3042 under the duplicate
	// threshold rule. From v6.17 Linux detects SACK losses only with RACK, RFC 8985, and
	// tcp_recovery=0 no longer turns it off. With a minimum RTT near zero its reorder window is
	// about zero, so the first SACK marks the first segment lost and Linux resends it before the
	// second duplicate ACK. limited-transmit-rack checks RFC 3042 on Linux on a 400 ms path.
	"limited-transmit/second-dupack.new-data": {
		Observed: "0 new segments",
		Reason: "Linux from v6.17 always runs RACK loss detection on SACK connections, and its reorder window " +
			"at a near-zero RTT marks the hole lost on the first SACK; RFC 8985 allows this, and " +
			"limited-transmit-rack covers RFC 3042 on Linux",
	},
	"limited-transmit/no-retransmit-before-third": {
		Observed: "1 retransmissions",
		Reason: "Linux from v6.17 always runs RACK loss detection on SACK connections, and its reorder window " +
			"at a near-zero RTT marks the hole lost on the first SACK, so it resends before the third " +
			"duplicate ACK; RFC 8985 allows this",
	},
	"icmp-frag-needed-source/ignored": {
		Observed: "applied: largest packet 1000 bytes",
		Reason: "Linux takes Fragmentation Needed from any router on the path: tcp_v4_err checks the quoted sequence " +
			"number but not the outer source, v6.1:net/ipv4/tcp_ipv4.c:473-554; packet-validation.md accepts an error only " +
			"from the quoted datagram's destination, since no router sits inside the tunnel",
	},
	"icmp-frag-needed-floor/ignored": {
		Observed: "applied: largest packet 552 bytes",
		Reason: "Linux sets the path MTU to min_pmtu, 552, locks it and then sends without DF, " +
			"v6.1:net/ipv4/route.c:1036-1038; packet-validation.md drops a Fragmentation Needed below 552, so the MTU stays",
	},
	"udp-datagram/reply.df-clear": {
		Observed: "DF set",
		Reason: "Linux's default IP_PMTUDISC_WANT sets DF on a UDP datagram that fits an unlocked path MTU, " +
			"v6.1:include/net/ip.h:416-421; wgstack.md sends UDP without DF, as gVisor does with path MTU discovery off",
	},
	"listener-close/half-open.rst-at-close": {
		Observed: "no RST at the close",
		Reason: "Linux drops a closed listener's request sockets without a RST; the final ACK then draws the closed " +
			"port's RST. wgstack.md resets them at the close",
	},
}

// TestConformance runs the scenarios against the Linux kernel's TCP through a TUN device. It
// re-runs itself in a new user and network namespace with the reference sysctls pinned, so
// nothing outside the namespace is touched. Run it in the lab VM:
//
//	lab/lab test internal/tcpharness/linuxdut
//	lab/lab test internal/tcpharness/linuxdut vps -test.run=TestConformance/paws
func TestConformance(t *testing.T) {
	if os.Getenv("WGFT_TEST_IN_NETNS") != "1" {
		release := KernelRelease()
		t.Logf("kernel %s; the expected differences are recorded for the reference kernel %s", release, ReferenceRelease)
		run := "^TestConformance$"
		if f := flag.Lookup("test.run"); f != nil && f.Value.String() != "" {
			run = f.Value.String() // the scenario filter passes through
		}
		cmd := exec.Command(os.Args[0], "-test.run="+run, "-test.v", "-test.count=1")
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
		if err != nil && release != ReferenceRelease {
			t.Fatalf("the scenarios failed in the namespace: %v; this kernel %s is not the reference %s, "+
				"and the expected differences are recorded for the reference kernel, so a failure here may "+
				"be a difference of this kernel rather than of the scenarios; run it on the lab's reference VM",
				err, release, ReferenceRelease)
		}
		if err != nil {
			t.Fatalf("the scenarios failed in the namespace: %v", err)
		}
		return
	}
	if err := PinReference(); err != nil {
		t.Fatalf("pinning the reference sysctls: %v", err)
	}
	for _, kv := range ReferenceSysctls {
		t.Logf("sysctl %s = %s", kv[0], kv[1])
	}
	tcpharness.Run(t, Engine(Known), tcpharness.Scenarios)
}
