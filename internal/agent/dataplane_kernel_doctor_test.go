//go:build linux

package agent

import (
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/vpsd/adminapi"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// TestKernelStaleReasonIsReadByServerDoctor は、名前の解決に失敗して直前の解決の結果で転送を続けて
// いるルールの理由(staleReason、設計文書 7b.2 節)を、server doctor(internal/vpsd/doctor)が
// 人の読む文言から読み取れることを固定する。server doctor はこの文言で、このルールを「解決で止まった」
// ではなく「直前の解決の結果で転送を続けている」と判定する(10.2a 節)。文言をどちらかの側だけで
// 変えると、ここが落ちる。
func TestKernelStaleReasonIsReadByServerDoctor(t *testing.T) {
	const old = "192.168.1.30"
	dest := netip.MustParseAddrPort(old + ":25565")
	tcp := tcpRule("r1", "game.lan:25565", 25565, 25565)
	udp := proto.AgentRule{ID: "r2", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2456}, Target: "game.lan:2456", Enabled: true}

	for _, tc := range []struct {
		name       string
		rule       proto.AgentRule
		probeErr   error
		narrow     bool // 解決に失敗した後で、許可一覧が直前のアドレスを通さなくなる
		noForward  bool // ip_forward を 1 にできない
		wantStale  bool
		wantRest   string // StaleResolution の残りに含まれるべき文言
		wantResolv string // rule.target_resolve の状態
		wantTarget string // rule.target の状態
		wantReason string // rule.target の理由の符号
	}{
		{name: "tcp, the old address answers", rule: tcp,
			wantStale: true, wantResolv: doctor.StatusUnknown, wantTarget: doctor.StatusOK},
		{name: "tcp, the old address refuses", rule: tcp, probeErr: errors.New("connect: connection refused"),
			wantStale: true, wantRest: "connection refused", wantResolv: doctor.StatusUnknown,
			wantTarget: doctor.StatusFailed, wantReason: doctor.ReasonConnectionRefused},
		{name: "tcp, ip_forward cannot be set", rule: tcp, noForward: true,
			wantStale: true, wantRest: "ip_forward", wantResolv: doctor.StatusUnknown,
			wantTarget: doctor.StatusFailed, wantReason: doctor.ReasonTargetError},
		{name: "udp", rule: udp,
			wantStale: true, wantResolv: doctor.StatusUnknown, wantTarget: doctor.StatusNotTested, wantReason: doctor.ReasonUDPListenerOnly},
		{name: "the old address is not usable either", rule: tcp, narrow: true,
			wantResolv: doctor.StatusFailed, wantTarget: doctor.StatusFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {netip.MustParseAddr(old)}}}
			d := newTestKernel(t, k, nil, nil)
			rules := []proto.AgentRule{tc.rule}
			if _, err := d.applyRules(1, rules, nil); err != nil {
				t.Fatal(err)
			}
			k.dnsErr = errors.New("lookup game.lan on 127.0.0.53:53: no such host")
			if tc.probeErr != nil {
				k.probeErr = map[netip.AddrPort]error{dest: tc.probeErr}
			}
			if tc.noForward {
				k.forwardWriteEr = os.ErrPermission
				if err := d.enableForwarding(func() error { return nil }); err != nil {
					t.Fatal(err)
				}
			}
			if tc.narrow {
				narrow, err := allowtargets.Parse("192.168.2.0/24")
				if err != nil {
					t.Fatal(err)
				}
				d.allow = narrow
			}
			if _, err := d.applyRules(2, rules, nil); err != nil {
				t.Fatal(err)
			}
			st := statusOf(t, d, tc.rule.ID)
			if st.State != proto.StatusError {
				t.Fatalf("state = %+v, want an error", st)
			}
			addr, rest, stale := doctor.StaleResolution(st.Reason)
			if stale != tc.wantStale {
				t.Fatalf("StaleResolution(%q) = %v, want %v", st.Reason, stale, tc.wantStale)
			}
			if stale && addr != old {
				t.Errorf("StaleResolution(%q) read the address %q, want %q", st.Reason, addr, old)
			}
			if tc.wantRest == "" && rest != "" {
				t.Errorf("StaleResolution(%q) left %q after the stale part, want nothing", st.Reason, rest)
			}
			if tc.wantRest != "" && !strings.Contains(rest, tc.wantRest) {
				t.Errorf("StaleResolution(%q) left %q, want it to carry %q", st.Reason, rest, tc.wantRest)
			}

			// server doctor の判定まで通す。報告は接続中のエージェントの今の報告として渡す。
			now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
			at := now.Add(-5 * time.Second).Format(time.RFC3339)
			rule := proto.Rule{ID: tc.rule.ID, Agent: "home", Proto: tc.rule.Proto, ListenPort: tc.rule.ListenPort,
				Target: tc.rule.Target, Enabled: true}
			in := doctor.Input{Now: now,
				Rules: &adminapi.BatchResponse{AgentRuleStates: map[string]adminapi.AgentRuleStatus{
					rule.ID: {Agent: "home", State: st.State, Reason: st.Reason, At: at, Connected: true}}},
				Agents: []adminapi.AgentInfo{{Name: "home", Connected: true, LastHeartbeat: at, LastHandshake: at}},
			}
			got := map[string]doctor.Check{}
			for _, c := range doctor.Diagnose(rule, in) {
				got[c.ID] = c
			}
			if c := got[doctor.CheckTargetResolve]; c.Status != tc.wantResolv || c.Reason != doctor.ReasonResolveFailed {
				t.Errorf("rule.target_resolve = %s %s, want %s %s", c.Status, c.Reason, tc.wantResolv, doctor.ReasonResolveFailed)
			}
			c := got[doctor.CheckTarget]
			if c.Status != tc.wantTarget {
				t.Errorf("rule.target = %s %s (%s), want %s", c.Status, c.Reason, c.Detail, tc.wantTarget)
			}
			if tc.wantReason != "" && c.Reason != tc.wantReason {
				t.Errorf("rule.target reason = %s, want %s", c.Reason, tc.wantReason)
			}
		})
	}
}
