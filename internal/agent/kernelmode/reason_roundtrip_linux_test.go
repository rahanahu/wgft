//go:build linux

package kernelmode

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/controlapi"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/textsafe"
	"github.com/rahanahu/wgft/internal/vpsd/adminapi"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/internal/vpsd/stream"
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
	multicastAllowed, err := allowtargets.Parse("224.0.0.0/4,255.255.255.255")
	if err != nil {
		t.Fatal(err)
	}
	type step int
	const (
		resolveThenFail step = iota + 1 // 1 回目は解決でき、2 回目の適用で解決に失敗する
		forwardOff                      // 適用の後、30 秒ごとの見直しで ip_forward が 0 と読める
		forwardUnset                    // 起動のときに ip_forward を 1 にできない
		forwardUnknown                  // 起動のときに ip_forward を読めず、1 にもできない
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
		{name: "multicast target", target: "239.1.2.3:25565", wantTarget: doctor.ReasonTargetNotUnicast},
		{name: "limited broadcast target", target: "255.255.255.255:25565", wantTarget: doctor.ReasonTargetNotUnicast},
		{name: "host name resolving to multicast", host: "mc.lan", target: "mc.lan:25565", addrs: []string{"239.1.2.3"},
			wantTarget: doctor.ReasonTargetNotUnicast},
		// 許可一覧に入る宛先でも、許可一覧ではなく宛先の種類の符号になる
		{name: "multicast target the allowlist lets through", target: "239.1.2.3:25565", allow: multicastAllowed,
			wantTarget: doctor.ReasonTargetNotUnicast},
		{name: "ip_forward reads 0", target: "192.168.1.20:25565", step: forwardOff, wantTarget: doctor.ReasonAgentIPForwardOff},
		{name: "ip_forward cannot be set", target: "192.168.1.20:25565", step: forwardUnset, wantTarget: doctor.ReasonAgentIPForwardOff},
		{name: "ip_forward can be neither read nor set", target: "192.168.1.20:25565", step: forwardUnknown, wantTarget: doctor.ReasonAgentIPForwardOff},
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
			if tc.step == forwardUnknown {
				k.forwardReadEr, k.forwardWriteEr = os.ErrPermission, os.ErrPermission
				if err := d.enableForwarding(func() error { return nil }); err != nil {
					t.Fatal(err)
				}
			}
			rule := tcpRule("r1", tc.target, 25565, 25565)
			if _, err := d.ApplyRules(1, []proto.AgentRule{rule}, nil); err != nil {
				t.Fatal(err)
			}
			switch tc.step {
			case resolveThenFail:
				k.dnsErr = fmt.Errorf("lookup %s on 127.0.0.53:53: no such host", tc.host)
				if _, err := d.ApplyRules(2, []proto.AgentRule{rule}, nil); err != nil {
					t.Fatal(err)
				}
			case forwardOff:
				k.forwardOn = false
				d.Refresh()
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

// 名前の解決に失敗して直前の解決の結果で転送を続けているルールの理由は、ホスト名を 2 回含む。253 バイト
// のホスト名でも、目印 "; still forwarding to " が hub の 512 バイトの切り詰めの内に残り、server
// doctor が転送を続けている(UNKNOWN)と判定することを固定する。誤りの文面が長いときと、誤りの文面に
// 制御文字があるときも同じである。以前は目印が切り落とされ、server doctor は解決できない(FAILED)と
// 判定した。
func TestKernelStaleReasonWithALongHostKeepsTheMark(t *testing.T) {
	const noSuchHost = " on 127.0.0.53:53: no such host"
	for _, tc := range []struct {
		name   string
		host   string // 空なら longTargetHost
		addr   string // 直前に解決できたアドレス。空なら 192.168.1.30
		err    string // 解決の誤りの文面
		probe  string // 直前のアドレスへの試し接続の誤り。空なら応える
		target string // rule.target の理由の符号。空なら見ない
	}{
		{name: "resolver error repeats the host", err: "lookup " + longTargetHost + noSuchHost},
		{name: "resolver error is itself long", err: "lookup " + longTargetHost + ": " + strings.Repeat("x", 600)},
		// 予算が小さい長いホスト名では、無害化を外しても目印が残る。無害化の順序は予算の大きい短いホスト名で固定する
		{name: "short host, resolver error with control characters", host: "game.lan", err: strings.Repeat("\x1b", 300) + " lookup game.lan"},
		{name: "old address refuses", err: "lookup " + longTargetHost + noSuchHost,
			probe: "dial tcp 192.168.1.30:25565: connect: connection refused", target: doctor.ReasonConnectionRefused},
		{name: "old address times out", err: "lookup " + longTargetHost + noSuchHost,
			probe: "dial tcp 192.168.1.30:25565: i/o timeout", target: doctor.ReasonTargetTimeout},
		{name: "old address is unreachable", err: "lookup " + longTargetHost + noSuchHost,
			probe: "dial tcp 192.168.1.30:25565: connect: no route to host", target: doctor.ReasonTargetUnreachable},
		// doctor が分類する試し接続の誤りのうち最長のもの(95 バイト)。アドレスは最長の 15 文字で、
		// エージェントが拒むブロードキャストのアドレスではないもの
		{name: "longest probe error", addr: "223.255.255.254", err: "lookup " + longTargetHost + noSuchHost,
			probe: "dial tcp 223.255.255.254:65535: connect: network is unreachable", target: doctor.ReasonTargetUnreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, addr := tc.host, tc.addr
			if host == "" {
				host = longTargetHost
			}
			if addr == "" {
				addr = "192.168.1.30"
			}
			port := uint16(25565)
			if addr == "223.255.255.254" {
				port = 65535
			}
			k := &fakeKernel{forwardOn: true, dns: map[string][]netip.Addr{host: {netip.MustParseAddr(addr)}}}
			d := newTestKernel(t, k, nil, nil)
			rule := tcpRule("r1", fmt.Sprintf("%s:%d", host, port), port, port)
			if _, err := d.ApplyRules(1, []proto.AgentRule{rule}, nil); err != nil {
				t.Fatal(err)
			}
			k.dnsErr = errors.New(tc.err)
			if tc.probe != "" {
				k.probeErr = map[netip.AddrPort]error{netip.AddrPortFrom(netip.MustParseAddr(addr), port): errors.New(tc.probe)}
			}
			if _, err := d.ApplyRules(2, []proto.AgentRule{rule}, nil); err != nil {
				t.Fatal(err)
			}
			st := statusOf(t, d, rule.ID)
			if !strings.Contains(st.Reason, host) {
				t.Fatalf("reason %q does not name the host", st.Reason)
			}
			stored := storedReason(st.Reason)
			got, _, stale := doctor.StaleResolution(stored)
			if !stale || got != addr {
				t.Fatalf("after the hub, StaleResolution(%q) = %q, %v; want the mark to survive", stored, got, stale)
			}
			reads := serverDoctorReads(t, rule, st)
			if c := reads[doctor.CheckTargetResolve]; c.Status != doctor.StatusUnknown {
				t.Errorf("rule.target_resolve = %s %s, want %s (still forwarding)", c.Status, c.Reason, doctor.StatusUnknown)
			}
			if tc.target != "" {
				if c := reads[doctor.CheckTarget]; c.Status != doctor.StatusFailed || c.Reason != tc.target {
					t.Errorf("rule.target = %s %s, want %s %s; the probe error after the mark must survive the hub (reason %q)",
						c.Status, c.Reason, doctor.StatusFailed, tc.target, stored)
				}
			}
		})
	}
}

// staleReasonLimit は hub の上限の写しである。ずれれば、目印の後ろに残る長さが黙って変わる。agent doctor
// の応答の上限 controlapi.DoctorTextMaxBytes も同じ値である。
func TestStaleReasonLimitMatchesTheHub(t *testing.T) {
	long := strings.Repeat("a", 4096)
	if got, want := len(stream.HeartbeatReason(long)), staleReasonLimit+staleClipMark; got != want {
		t.Errorf("the hub keeps %d bytes of a long reason, staleReasonLimit says %d", got, want)
	}
	if staleReasonLimit != controlapi.DoctorTextMaxBytes {
		t.Errorf("staleReasonLimit = %d, controlapi.DoctorTextMaxBytes = %d; they are the same cap", staleReasonLimit, controlapi.DoctorTextMaxBytes)
	}
}

// 許可一覧がどのアドレスも通さないホスト名の理由は、解決のアドレスを先頭の数個だけ並べて残りを
// "and N more" と書く。253 バイトのホスト名と多数のアドレスでも、設定の名前か "is not allowed" を含む
// 後半が hub の 512 バイトの切り詰めの内に残り、server doctor が target_not_allowed と判定することを
// 固定する。以前はアドレスを全部並べたので、12 から 26 個で後半が切り落とされ、target_error になった。
// 最悪の長さとして、最長のアドレスと、ポート範囲全体が拒まれたときの追記も含める。
func TestKernelRefusedReasonWithManyAddressesKeepsTheClassification(t *testing.T) {
	refuseAll := func(netip.AddrPort) bool { return false }
	for _, host := range []string{longTargetHost, "multi.lan"} {
		for _, source := range []string{"", allowtargets.Env} {
			for n := 2; n <= 60; n++ {
				addrs := make([]netip.Addr, n)
				for i := range addrs {
					addrs[i] = netip.AddrFrom4([4]byte{250, 250, 250, byte(100 + i)})
				}
				rule := tcpRule("r1", host+":1", 1024, 65534)
				cfg := nft.AgentConfig{AllowTarget: refuseAll, AllowTargetSource: source}
				res := nft.PlanAgent(nft.AgentInput{Generation: 1, Rules: []proto.AgentRule{rule},
					Resolved: map[string]nft.Resolution{host: {Addrs: addrs}}}, cfg).Rules[0]
				if !strings.Contains(res.Reason, "ports are not published") {
					t.Fatalf("reason %q: want the range suffix, the longest case", res.Reason)
				}
				stored := storedReason(res.Reason)
				if stored != res.Reason {
					t.Fatalf("%d addresses, host %d bytes, source %q: the hub clips the reason (%d bytes)\n%q\nstored %q",
						n, len(host), source, len(res.Reason), res.Reason, stored)
				}
				st := proto.RuleStatus{ID: rule.ID, State: proto.StatusError, Reason: res.Reason}
				if c := serverDoctorReads(t, rule, st)[doctor.CheckTarget]; c.Reason != doctor.ReasonTargetNotAllowed {
					t.Fatalf("%d addresses, host %d bytes, source %q: rule.target = %s %s, want %s (reason %q)",
						n, len(host), source, c.Status, c.Reason, doctor.ReasonTargetNotAllowed, res.Reason)
				}
			}
		}
	}
}

// 解決のアドレスが少ないときの文言は変えない。多いときだけ、先頭の数個と "and N more" にする。
func TestKernelRefusedReasonText(t *testing.T) {
	refuseAll := func(netip.AddrPort) bool { return false }
	addrs := func(n int) []netip.Addr {
		out := make([]netip.Addr, n)
		for i := range out {
			out[i] = netip.AddrFrom4([4]byte{192, 168, 9, byte(10 + i)})
		}
		return out
	}
	for _, tc := range []struct {
		n      int
		source string
		want   string
	}{
		{2, "", `target host "multi.lan" resolved to 192.168.9.10, 192.168.9.11; each of them at port 25565 is not allowed`},
		{2, allowtargets.Env, `target host "multi.lan" resolved to 192.168.9.10, 192.168.9.11; none of them at port 25565 is in WGFT_AGENT_ALLOW_TARGETS`},
		{4, "", `target host "multi.lan" resolved to 192.168.9.10, 192.168.9.11, 192.168.9.12, 192.168.9.13; each of them at port 25565 is not allowed`},
		{5, "", `target host "multi.lan" resolved to 192.168.9.10, 192.168.9.11, 192.168.9.12, 192.168.9.13 and 1 more; each of them at port 25565 is not allowed`},
		{30, allowtargets.Env, `target host "multi.lan" resolved to 192.168.9.10, 192.168.9.11, 192.168.9.12, 192.168.9.13 and 26 more; none of them at port 25565 is in WGFT_AGENT_ALLOW_TARGETS`},
	} {
		rule := tcpRule("r1", "multi.lan:25565", 25565, 25565)
		res := nft.PlanAgent(nft.AgentInput{Generation: 1, Rules: []proto.AgentRule{rule},
			Resolved: map[string]nft.Resolution{"multi.lan": {Addrs: addrs(tc.n)}}},
			nft.AgentConfig{AllowTarget: refuseAll, AllowTargetSource: tc.source}).Rules[0]
		if res.Reason != tc.want {
			t.Errorf("%d addresses, source %q:\n got %q\nwant %q", tc.n, tc.source, res.Reason, tc.want)
		}
	}
}

// serverDoctorReads は、エージェントの 1 本のルールの状態を、接続中のエージェントの今の報告として
// server doctor に渡し、検査の ID ごとの結果を返す。理由は、エージェントが送る形(internal/agent の
// wireReason と同じ変換)にし、JSON の往復を通し、さらに hub が保存する形に通してから渡す(storedReason)。
// internal/agent の reason_roundtrip_test.go にある同じ名前の補助の写しである。この package の
// テストからはそちらに届かない。
func serverDoctorReads(t *testing.T, r proto.AgentRule, st proto.RuleStatus) map[string]doctor.Check {
	t.Helper()
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	at := now.Add(-5 * time.Second).Format(time.RFC3339)
	rule := proto.Rule{ID: r.ID, Agent: "home", Proto: r.Proto, ListenPort: r.ListenPort, Target: r.Target, Enabled: true}
	in := doctor.Input{Now: now,
		Rules: &adminapi.BatchResponse{AgentRuleStates: map[string]adminapi.AgentRuleStatus{
			rule.ID: {Agent: "home", State: st.State, Reason: storedReason(st.Reason), At: at, Connected: true}}},
		Agents: []adminapi.AgentInfo{{Name: "home", Connected: true, LastHeartbeat: at, LastHandshake: at}},
	}
	got := map[string]doctor.Check{}
	for _, c := range doctor.Diagnose(rule, in) {
		got[c.ID] = c
	}
	return got
}

// storedReason は、エージェントの理由 s を、エージェントが送る形(internal/agent の wireReason と同じ
// textsafe.ReplaceInvalidUTF8 と textsafe.SanitizeAndClip)にし、JSON の往復を通し、さらに hub が保存する
// 形に通した値である。
func storedReason(s string) string {
	b, err := json.Marshal(proto.RuleStatus{Reason: textsafe.SanitizeAndClip(textsafe.ReplaceInvalidUTF8(s), proto.ReasonMaxBytes)})
	if err != nil {
		panic(err)
	}
	var back proto.RuleStatus
	if err := json.Unmarshal(b, &back); err != nil {
		panic(err)
	}
	return stream.HeartbeatReason(back.Reason)
}
