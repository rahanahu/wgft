//go:build linux

package agent

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// longTargetHost は、DNS の名前の長さの上限(253 バイト)のホスト名である。
var longTargetHost = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)

// カーネルモードのエージェントの理由である。偽のカーネルの上で実際に公開し、ハートビートと同じ
// ruleStatuses の理由を server doctor に読ませる。
func TestKernelReasonsAreReadByServerDoctor(t *testing.T) {
	narrow, err := allowtargets.Parse("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	type step int
	const (
		resolveThenFail step = iota + 1 // 1 回目は解決でき、2 回目の適用で解決に失敗する
		forwardOff                      // 適用の後、30 秒ごとの見直しで ip_forward が 0 と読める
		forwardUnset                    // 起動のときに ip_forward を 1 にできない
	)
	for _, tc := range []struct {
		name        string
		host        string // 名前の宛先なら、偽の DNS が引ける名前
		target      string
		addrs       []string // host の解決の結果
		neverResolv bool     // host は最初から解決できない
		allow       *allowtargets.List
		step        step
		wantResolve string // rule.target_resolve の状態。空なら見ない
		wantTarget  string // rule.target の理由の符号
	}{
		{name: "stale resolution", host: "game.lan", target: "game.lan:25565", addrs: []string{"192.168.1.30"}, step: resolveThenFail,
			wantResolve: doctor.StatusUnknown},
		{name: "never resolved", host: "game.lan", target: "game.lan:25565", neverResolv: true,
			wantResolve: doctor.StatusFailed, wantTarget: doctor.ReasonResolveFailed},
		{name: "literal target not in the allowlist", target: "192.168.9.9:25565", allow: narrow,
			wantTarget: doctor.ReasonTargetNotAllowed},
		{name: "every resolved address outside the allowlist", host: "multi.lan", target: "multi.lan:25565",
			addrs: []string{"192.168.9.9", "192.168.9.10"}, allow: narrow, wantTarget: doctor.ReasonTargetNotAllowed},
		{name: "loopback target", target: "127.0.0.1:25565", wantTarget: doctor.ReasonTargetLoopbackUnsupported},
		{name: "unspecified target", target: "0.0.0.0:25565", wantTarget: doctor.ReasonTargetLoopbackUnsupported},
		{name: "ip_forward reads 0", target: "192.168.1.20:25565", step: forwardOff, wantTarget: doctor.ReasonAgentIPForwardOff},
		{name: "ip_forward cannot be set", target: "192.168.1.20:25565", step: forwardUnset, wantTarget: doctor.ReasonAgentIPForwardOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &fakeKernel{forwardOn: true, dns: map[string][]netip.Addr{}}
			for _, a := range tc.addrs {
				k.dns[tc.host] = append(k.dns[tc.host], netip.MustParseAddr(a))
			}
			if tc.neverResolv {
				k.dnsErr = fmt.Errorf("lookup %s on 127.0.0.53:53: no such host", tc.host)
			}
			d := newTestKernel(t, k, nil, tc.allow)
			if tc.step == forwardUnset {
				k.forwardOn, k.forwardWriteEr = false, os.ErrPermission
				if err := d.enableForwarding(func() error { return nil }); err != nil {
					t.Fatal(err)
				}
			}
			rule := tcpRule("r1", tc.target, 25565, 25565)
			if _, err := d.applyRules(1, []proto.AgentRule{rule}, nil); err != nil {
				t.Fatal(err)
			}
			switch tc.step {
			case resolveThenFail:
				k.dnsErr = fmt.Errorf("lookup %s on 127.0.0.53:53: no such host", tc.host)
				if _, err := d.applyRules(2, []proto.AgentRule{rule}, nil); err != nil {
					t.Fatal(err)
				}
			case forwardOff:
				k.forwardOn = false
				d.refresh()
			}
			st := statusOf(t, d, rule.ID)
			if st.State != proto.StatusError {
				t.Fatalf("state = %+v, want an error", st)
			}
			got := serverDoctorReads(t, rule, st)
			if c := got[doctor.CheckTargetResolve]; tc.wantResolve != "" && (c.Status != tc.wantResolve || c.Reason != doctor.ReasonResolveFailed) {
				t.Errorf("reason %q: rule.target_resolve = %s %s, want %s %s", st.Reason, c.Status, c.Reason, tc.wantResolve, doctor.ReasonResolveFailed)
			}
			if c := got[doctor.CheckTarget]; tc.wantTarget != "" && c.Reason != tc.wantTarget {
				t.Errorf("reason %q: rule.target = %s %s, want %s", st.Reason, c.Status, c.Reason, tc.wantTarget)
			}
		})
	}
}

// 許可一覧の設定の名前を持たない拒否と、解決の結果の無いホスト名の理由である。エージェントは
// 許可一覧に必ず設定の名前を添えて公開するので、この 2 つ目までの文言は nft の公開の組み立て
// (nft.PlanAgent)を直接呼んで作る。
func TestKernelPlanReasonsAreReadByServerDoctor(t *testing.T) {
	refuseAll := func(netip.AddrPort) bool { return false }
	for _, tc := range []struct {
		name     string
		target   string
		resolved map[string]nft.Resolution
		cfg      nft.AgentConfig
		want     string
	}{
		{name: "one address, no source name", target: "192.168.9.9:25565",
			cfg: nft.AgentConfig{AllowTarget: refuseAll}, want: doctor.ReasonTargetNotAllowed},
		{name: "several addresses, no source name", target: "multi.lan:25565",
			resolved: map[string]nft.Resolution{"multi.lan": {Addrs: []netip.Addr{netip.MustParseAddr("192.168.9.9"), netip.MustParseAddr("192.168.9.10")}}},
			cfg:      nft.AgentConfig{AllowTarget: refuseAll}, want: doctor.ReasonTargetNotAllowed},
		{name: "several addresses, with the source name", target: "multi.lan:25565",
			resolved: map[string]nft.Resolution{"multi.lan": {Addrs: []netip.Addr{netip.MustParseAddr("192.168.9.9"), netip.MustParseAddr("192.168.9.10")}}},
			cfg:      nft.AgentConfig{AllowTarget: refuseAll, AllowTargetSource: allowtargets.Env}, want: doctor.ReasonTargetNotAllowed},
		{name: "no name resolution result", target: "game.lan:25565", want: doctor.ReasonResolveFailed},
		{name: "name resolution failed", target: "game.lan:25565",
			resolved: map[string]nft.Resolution{"game.lan": {Err: errors.New("server misbehaving")}}, want: doctor.ReasonResolveFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := tcpRule("r1", tc.target, 25565, 25565)
			res := nft.PlanAgent(nft.AgentInput{Generation: 1, Rules: []proto.AgentRule{rule}, Resolved: tc.resolved}, tc.cfg).Rules[0]
			if res.Reason == "" {
				t.Fatalf("PlanAgent published %+v, want a reason", res)
			}
			st := proto.RuleStatus{ID: rule.ID, State: proto.StatusError, Reason: res.Reason}
			if c := serverDoctorReads(t, rule, st)[doctor.CheckTarget]; c.Reason != tc.want {
				t.Errorf("reason %q: rule.target = %s %s, want %s", res.Reason, c.Status, c.Reason, tc.want)
			}
		})
	}
}

// 名前の解決に失敗して直前の解決の結果で転送を続けているルールの理由は、ホスト名を 2 回含む。
// ホスト名が長いと、hub の 512 バイトの切り詰めが目印 "; still forwarding to " を落とし、server
// doctor は「転送を続けている」(UNKNOWN)ではなく「解決できない」(FAILED)と判定する。
//
// 既知の問題(この試験より前からある): 転送は続いているのに、server doctor は止まったと示す。この
// 試験は今の挙動を固定するだけで、直すのは別の変更である。直したら、この試験の期待を UNKNOWN に
// 改める。
func TestKernelStaleReasonWithALongHostLosesTheMark(t *testing.T) {
	k := &fakeKernel{forwardOn: true, dns: map[string][]netip.Addr{longTargetHost: {netip.MustParseAddr("192.168.1.30")}}}
	d := newTestKernel(t, k, nil, nil)
	rule := tcpRule("r1", longTargetHost+":25565", 25565, 25565)
	if _, err := d.applyRules(1, []proto.AgentRule{rule}, nil); err != nil {
		t.Fatal(err)
	}
	k.dnsErr = fmt.Errorf("lookup %s on 127.0.0.53:53: no such host", longTargetHost)
	if _, err := d.applyRules(2, []proto.AgentRule{rule}, nil); err != nil {
		t.Fatal(err)
	}
	st := statusOf(t, d, rule.ID)
	if _, _, stale := doctor.StaleResolution(st.Reason); !stale {
		t.Fatalf("before the hub, StaleResolution(%q) = false, want true", st.Reason)
	}
	if len(st.Reason) <= 512 {
		t.Fatalf("reason is %d bytes; this case needs one past the hub's 512-byte cap", len(st.Reason))
	}
	c := serverDoctorReads(t, rule, st)[doctor.CheckTargetResolve]
	if c.Status != doctor.StatusFailed || c.Reason != doctor.ReasonResolveFailed {
		t.Errorf("rule.target_resolve = %s %s; the known issue reads %s %s here. If the mark now survives the cap, update this test",
			c.Status, c.Reason, doctor.StatusFailed, doctor.ReasonResolveFailed)
	}
}
