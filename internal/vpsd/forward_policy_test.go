//go:build linux

package vpsd

import (
	"errors"
	"testing"

	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// findingsDataplane is a stubDataplane whose Inspect returns fixed findings, standing in for a
// kernel host with both an input and a forward finding.
type findingsDataplane struct {
	stubDataplane
	rep *linux.Report
	err error
}

func (d findingsDataplane) Inspect() (*linux.Report, error) { return d.rep, d.err }

// ForwardPolicy reports only the forward findings, with their suggestions, and only in kernel mode
// (design.md 6.1、10.2a 節). Input findings are server check's business and say nothing about
// forwarding.
func TestForwardPolicyReportsForwardFindingsOnly(t *testing.T) {
	rep := &linux.Report{Findings: []linux.Finding{
		{Hook: linux.HookInput, Where: "ip filter INPUT", Suggest: []string{"iptables -I INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"}},
		{Hook: linux.HookForward, Where: "ip filter FORWARD", Suggest: []string{"iptables -I DOCKER-USER -o wgft0 -j ACCEPT", "iptables -I DOCKER-USER -i wgft0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"}},
		{Where: "ip nat PREROUTING", Problem: "has a DNAT rule of unknown protocol"},
	}}
	d := &Daemon{opts: Options{Mode: store.ModeKernel}, dp: findingsDataplane{rep: rep}}
	st, ok := d.ForwardPolicy()
	if !ok {
		t.Fatal("a kernel-mode server must report forward_policy")
	}
	if len(st.Drops) != 1 || st.Drops[0].Where != "ip filter FORWARD" || len(st.Drops[0].Suggest) != 2 || st.Error != "" {
		t.Errorf("forward_policy = %+v, want only the forward finding with its two lines", st)
	}

	d = &Daemon{opts: Options{Mode: store.ModeKernel}, dp: findingsDataplane{err: errors.New("netlink: permission denied")}}
	if st, ok := d.ForwardPolicy(); !ok || st.Error != "netlink: permission denied" || len(st.Drops) != 0 {
		t.Errorf("a failed check = %+v ok=%v, want the error", st, ok)
	}

	d = &Daemon{opts: Options{Mode: store.ModeUserspace}, dp: findingsDataplane{rep: rep}}
	if _, ok := d.ForwardPolicy(); ok {
		t.Error("a userspace-mode server must not report forward_policy")
	}
}
