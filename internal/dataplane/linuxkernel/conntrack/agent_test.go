//go:build linux

package conntrack

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/ti-mo/conntrack"
	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/proto"
)

var (
	agentLocal = netip.MustParseAddr("10.200.0.2")
	agentPeer  = netip.MustParseAddr("10.200.0.1")
	agentScope = AgentScope{Local: agentLocal, Peer: agentPeer}
)

// agentFlow は vpsd のトンネルアドレスから wgft0 のアドレスの dport へ入り、to へ DNAT されたフローである。
func agentFlow(protoNum uint8, dport uint16, to string) conntrack.Flow {
	return rawFlow(protoNum, "10.200.0.1", "10.200.0.2", dport, to, true)
}

// rawFlow は orig src:40000 -> dst:dport、reply src が to のフローである。dnat=true で DNAT の印を持つ。
func rawFlow(protoNum uint8, src, dst string, dport uint16, to string, dnat bool) conntrack.Flow {
	ap := netip.MustParseAddrPort(to)
	f := conntrack.Flow{}
	f.TupleOrig.IP.SourceAddress = netip.MustParseAddr(src)
	f.TupleOrig.IP.DestinationAddress = netip.MustParseAddr(dst)
	f.TupleOrig.Proto.Protocol = protoNum
	f.TupleOrig.Proto.SourcePort = 40000
	f.TupleOrig.Proto.DestinationPort = dport
	f.TupleReply.IP.SourceAddress = ap.Addr()
	f.TupleReply.IP.DestinationAddress = netip.MustParseAddr(src)
	f.TupleReply.Proto.Protocol = protoNum
	f.TupleReply.Proto.SourcePort = ap.Port()
	f.TupleReply.Proto.DestinationPort = 40000
	if dnat {
		f.Status |= conntrack.StatusDstNAT
	}
	return f
}

func rule(id string, p proto.Proto, lo, hi uint16, target string) proto.AgentRule {
	return proto.AgentRule{ID: id, Proto: p, ListenPort: proto.PortRange{Lo: lo, Hi: hi}, Target: target, Enabled: true}
}

// publish は、エージェントが公開するのと同じ判定(nft.PlanAgent)で公開の記録を作る。
func publish(resolved map[string]nft.Resolution, allow func(netip.AddrPort) bool, rules ...proto.AgentRule) nft.AgentPublication {
	return nft.PlanAgent(nft.AgentInput{Rules: rules, Resolved: resolved}, nft.AgentConfig{WGInterface: "wgft0", AllowTarget: allow})
}

func resolves(host string, addrs ...string) map[string]nft.Resolution {
	r := nft.Resolution{}
	for _, a := range addrs {
		r.Addrs = append(r.Addrs, netip.MustParseAddr(a))
	}
	return map[string]nft.Resolution{host: r}
}

func allowOnly(prefix string) func(netip.AddrPort) bool {
	p := netip.MustParsePrefix(prefix)
	return func(ap netip.AddrPort) bool { return p.Contains(ap.Addr()) }
}

func TestClassifyAgentFlow(t *testing.T) {
	mc := rule("r_mc", proto.TCP, 25565, 25565, "192.168.1.22:25565")
	vh := rule("r_vh", proto.UDP, 2456, 2457, "192.168.1.20:2456")
	web := rule("r_web", proto.TCP, 8443, 8443, "nas.lan:443")
	base := publish(resolves("nas.lan", "192.168.1.30"), nil, mc, vh, web)

	disabled := vh
	disabled.Enabled = false
	renamed := mc
	renamed.ID = "r_renamed"
	shifted := rule("r_vh", proto.UDP, 2457, 2458, "192.168.1.20:2456") // 2457 の実効宛先が 2457 から 2456 へ
	split1 := rule("r_vh", proto.UDP, 2456, 2456, "192.168.1.20:2456")
	split2 := rule("r_vh2", proto.UDP, 2457, 2457, "192.168.1.20:2457")
	other := rule("r_other", proto.TCP, 7000, 7000, "192.168.1.40:7000")
	webPort := web
	webPort.Target = "nas.lan:8443"
	webHost := web
	webHost.Target = "nas2.lan:443"
	mcPort := mc
	mcPort.Target = "192.168.1.22:25566"
	mcAddr := mc
	mcAddr.Target = "192.168.1.23:25565"
	mcZero := mc
	mcZero.Target = "192.168.1.22:0"
	vhAddr := vh
	vhAddr.Target = "192.168.1.21:2456"
	webTo80 := rule("r_web", proto.TCP, 8443, 8443, "nas.lan:80")
	web2To80 := rule("r_web", proto.TCP, 8443, 8443, "nas2.lan:80")
	litTo80 := rule("r_web", proto.TCP, 8443, 8443, "192.168.1.22:80")
	mcLoop := mc
	mcLoop.Target = "127.0.0.1:25565"

	tests := []struct {
		name string
		prev []nft.AgentPublication
		cur  nft.AgentPublication
		flow conntrack.Flow
		want agentVerdict
		// allow は今の許可一覧である。cur を組んだ一覧と同じものを与える
		allow func(netip.AddrPort) bool
	}{
		// 残す
		{"unchanged rule", []nft.AgentPublication{base}, base, agentFlow(6, 25565, "192.168.1.22:25565"), agentKeep, nil},
		{"unchanged range port with its offset", []nft.AgentPublication{base}, base, agentFlow(17, 2457, "192.168.1.20:2457"), agentKeep, nil},
		{"another rule added", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30"), nil, mc, vh, web, other), agentFlow(6, 25565, "192.168.1.22:25565"), agentKeep, nil},
		{"another rule deleted", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30"), nil, mc, web), agentFlow(6, 25565, "192.168.1.22:25565"), agentKeep, nil},
		{"only the rule ID changed", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30"), nil, renamed, vh, web), agentFlow(6, 25565, "192.168.1.22:25565"), agentKeep, nil},
		{"range split keeps each port's effective target", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30"), nil, mc, split1, split2, web), agentFlow(17, 2457, "192.168.1.20:2457"), agentKeep, nil},
		{"only the name resolution changed", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.31"), nil, mc, vh, web), agentFlow(6, 8443, "192.168.1.30:443"), agentKeep, nil},
		{"resolution failed, declaration unchanged", []nft.AgentPublication{base},
			publish(nil, nil, mc, vh, web), agentFlow(6, 8443, "192.168.1.30:443"), agentKeep, nil},
		{"flow to an address resolved two publications ago", []nft.AgentPublication{
			publish(resolves("nas.lan", "192.168.1.29"), nil, web), base},
			publish(resolves("nas.lan", "192.168.1.31"), nil, web), agentFlow(6, 8443, "192.168.1.29:443"), agentKeep, nil},
		{"new flow already on the current target", []nft.AgentPublication{base},
			publish(nil, nil, mcAddr), agentFlow(6, 25565, "192.168.1.23:25565"), agentKeep, nil},
		{"new flow on the current target, range port", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30"), nil, mc, vhAddr, web), agentFlow(17, 2457, "192.168.1.21:2457"), agentKeep, nil},
		{"target still allowed", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30"), allowOnly("192.168.1.0/24"), mc, vh, web), agentFlow(6, 25565, "192.168.1.22:25565"), agentKeep, allowOnly("192.168.1.0/24")},

		// 消す
		{"rule deleted", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30"), nil, vh, web), agentFlow(6, 25565, "192.168.1.22:25565"), agentRemoved, nil},
		{"rule disabled", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30"), nil, mc, disabled, web), agentFlow(17, 2456, "192.168.1.20:2456"), agentRemoved, nil},
		{"agent disabled", []nft.AgentPublication{base}, nft.AgentPublication{}, agentFlow(17, 2457, "192.168.1.20:2457"), agentRemoved, nil},
		{"target address changed", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30"), nil, mcAddr, vh, web), agentFlow(6, 25565, "192.168.1.22:25565"), agentRetargeted, nil},
		{"target port changed", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30"), nil, mcPort, vh, web), agentFlow(6, 25565, "192.168.1.22:25565"), agentRetargeted, nil},
		{"range shifted under the port", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30"), nil, mc, shifted, web), agentFlow(17, 2457, "192.168.1.20:2457"), agentRetargeted, nil},
		{"target host name changed", []nft.AgentPublication{base},
			publish(resolves("nas2.lan", "192.168.1.32"), nil, mc, vh, webHost), agentFlow(6, 8443, "192.168.1.30:443"), agentRetargeted, nil},
		{"host name kept, port changed", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30"), nil, mc, vh, webPort), agentFlow(6, 8443, "192.168.1.30:443"), agentRetargeted, nil},
		{"refused rule with a new target", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30"), nil, mcLoop, vh, web), agentFlow(6, 25565, "192.168.1.22:25565"), agentRetargeted, nil},
		{"target left the allow list", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30"), allowOnly("192.168.1.30/32"), mc, vh, web), agentFlow(6, 25565, "192.168.1.22:25565"), agentNotAllowed, allowOnly("192.168.1.30/32")},
		{"resolved address left the allow list", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30", "192.168.1.31"), allowOnly("192.168.1.31/32"), mc, vh, web), agentFlow(6, 8443, "192.168.1.30:443"), agentNotAllowed, allowOnly("192.168.1.31/32")},
		{"retargeted in an unconverged publication", []nft.AgentPublication{base,
			publish(resolves("nas.lan", "192.168.1.30"), nil, mcAddr, vh, web)},
			publish(resolves("nas.lan", "192.168.1.30"), nil, mcAddr, vh, web), agentFlow(6, 25565, "192.168.1.22:25565"), agentRetargeted, nil},
		{"another rule removed in an unconverged publication", []nft.AgentPublication{base,
			publish(resolves("nas.lan", "192.168.1.30"), nil, vh, web)},
			publish(resolves("nas.lan", "192.168.1.30"), nil, vh, web, renamed), agentFlow(17, 2456, "192.168.1.20:2456"), agentKeep, nil},
		{"removed in an unconverged publication, flow on the removed port", []nft.AgentPublication{base,
			publish(resolves("nas.lan", "192.168.1.30"), nil, vh, web)},
			publish(resolves("nas.lan", "192.168.1.30"), nil, vh, web, mcAddr), agentFlow(6, 25565, "192.168.1.22:25565"), agentRemoved, nil},

		// 触らない
		{"no previous publication", nil, nft.AgentPublication{}, agentFlow(6, 25565, "192.168.1.22:25565"), agentForeign, nil},
		{"not DNATed", []nft.AgentPublication{base}, nft.AgentPublication{},
			rawFlow(6, "10.200.0.1", "10.200.0.2", 25565, "192.168.1.22:25565", false), agentForeign, nil},
		{"source is not the server", []nft.AgentPublication{base}, nft.AgentPublication{},
			rawFlow(6, "192.168.1.50", "10.200.0.2", 25565, "192.168.1.22:25565", true), agentForeign, nil},
		{"destination is not the wgft0 address", []nft.AgentPublication{base}, nft.AgentPublication{},
			rawFlow(6, "10.200.0.1", "192.168.1.2", 25565, "192.168.1.22:25565", true), agentForeign, nil},
		{"other table's DNAT on a port wgft never declared", []nft.AgentPublication{base}, nft.AgentPublication{},
			agentFlow(6, 8080, "172.17.0.2:80"), agentForeign, nil},
		{"other table's DNAT on a port wgft declared", []nft.AgentPublication{base}, nft.AgentPublication{},
			agentFlow(6, 25565, "172.17.0.2:80"), agentForeign, nil},
		{"other table's DNAT to the declared address, other port", []nft.AgentPublication{base}, nft.AgentPublication{},
			agentFlow(6, 25565, "192.168.1.22:80"), agentForeign, nil},
		{"other table's DNAT on a host-name port, other target port", []nft.AgentPublication{base}, nft.AgentPublication{},
			agentFlow(6, 8443, "192.168.1.30:80"), agentForeign, nil},
		{"range port with the wrong offset", []nft.AgentPublication{base}, nft.AgentPublication{},
			agentFlow(17, 2457, "192.168.1.20:2456"), agentForeign, nil},
		{"TCP on a port only UDP declared", []nft.AgentPublication{base}, nft.AgentPublication{},
			agentFlow(6, 2456, "192.168.1.20:2456"), agentForeign, nil},
		{"ICMP", []nft.AgentPublication{base}, nft.AgentPublication{},
			agentFlow(1, 0, "192.168.1.22:0"), agentForeign, nil},
		{"unusable target port never matches", []nft.AgentPublication{publish(nil, nil, mcZero)}, nft.AgentPublication{},
			agentFlow(6, 25565, "192.168.1.22:0"), agentForeign, nil},
		{"host-name retarget in an unconverged publication", []nft.AgentPublication{
			publish(resolves("nas.lan", "192.168.1.30"), nil, webTo80), publish(resolves("nas2.lan", "192.168.1.31"), nil, web2To80)},
			publish(resolves("nas2.lan", "192.168.1.31"), nil, web2To80), agentFlow(6, 8443, "192.168.1.30:80"), agentRetargeted, nil},
		{"host-name retarget in an unconverged publication that failed to resolve", []nft.AgentPublication{
			publish(resolves("nas.lan", "192.168.1.30"), nil, webTo80), publish(nil, nil, web2To80)},
			publish(nil, nil, web2To80), agentFlow(6, 8443, "192.168.1.30:80"), agentRetargeted, nil},
		{"IP literal to host name in an unconverged publication", []nft.AgentPublication{
			publish(nil, nil, litTo80), publish(resolves("nas2.lan", "192.168.1.31"), nil, web2To80)},
			publish(resolves("nas2.lan", "192.168.1.31"), nil, web2To80), agentFlow(6, 8443, "192.168.1.22:80"), agentRetargeted, nil},
		{"IP-literal origin without a published target is closed by the allow list", []nft.AgentPublication{publish(nil, allowOnly("192.168.1.30/32"), mc)},
			publish(nil, allowOnly("192.168.1.30/32"), mc), agentFlow(6, 25565, "192.168.1.22:25565"), agentNotAllowed, allowOnly("192.168.1.30/32")},
		{"port-only match is not closed by the allow list", []nft.AgentPublication{base},
			publish(resolves("nas.lan", "192.168.1.30"), allowOnly("192.168.1.0/24"), mc, vh, web), agentFlow(6, 8443, "172.17.0.2:443"), agentKeep, allowOnly("192.168.1.0/24")},
		{"created under an older publication than the list", []nft.AgentPublication{
			publish(nil, nil, mcAddr)}, publish(nil, nil, mcPort), agentFlow(6, 25565, "192.168.1.22:25565"), agentForeign, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prev := make([]agentIndex, len(tt.prev))
			for i, p := range tt.prev {
				prev[i] = indexAgent(p)
			}
			scope := agentScope
			scope.AllowTarget = tt.allow
			if got := classifyAgentFlow(tt.flow, prev, indexAgent(tt.cur), scope); got != tt.want {
				t.Errorf("verdict = %v, want %v", got, tt.want)
			}
		})
	}
}

// 許可一覧の判定は、宣言が変わらず残すフローにだけ掛かる。今の宛先に合うフローと、見分けられないフローには
// 呼ばない。
func TestClassifyAgentFlowAllowListScope(t *testing.T) {
	mc := rule("r_mc", proto.TCP, 25565, 25565, "192.168.1.22:25565")
	pub := publish(nil, nil, mc)
	idx := []agentIndex{indexAgent(pub)}
	deny := AgentScope{Local: agentLocal, Peer: agentPeer, AllowTarget: func(netip.AddrPort) bool { return false }}
	if got := classifyAgentFlow(agentFlow(6, 25565, "192.168.1.22:25565"), idx, indexAgent(pub), deny); got != agentKeep {
		t.Errorf("flow on the current target = %v, want keep: the current target passed the allow list when it was published", got)
	}
	if got := classifyAgentFlow(agentFlow(6, 8080, "172.17.0.2:80"), idx, indexAgent(pub), deny); got != agentForeign {
		t.Errorf("foreign flow = %v, want untouched", got)
	}
}

// fakeAgentConn は DumpFilter で固定のフローを返し、Delete の誤りを差し替えられる。
type fakeAgentConn struct {
	flows   []conntrack.Flow
	dumpErr error
	delErr  func(conntrack.Flow) error
	deleted []conntrack.Flow
}

func (c *fakeAgentConn) DumpFilter(conntrack.Filter, *conntrack.DumpOptions) ([]conntrack.Flow, error) {
	return c.flows, c.dumpErr
}
func (c *fakeAgentConn) Delete(f conntrack.Flow) error {
	if c.delErr != nil {
		if err := c.delErr(f); err != nil {
			return err
		}
	}
	c.deleted = append(c.deleted, f)
	return nil
}

func TestConvergeAgent(t *testing.T) {
	mc := rule("r_mc", proto.TCP, 25565, 25565, "192.168.1.22:25565")
	vh := rule("r_vh", proto.UDP, 2456, 2457, "192.168.1.20:2456")
	gone := rule("r_gone", proto.TCP, 7000, 7000, "192.168.1.40:7000")
	prev := publish(nil, nil, mc, vh, gone)
	mcAddr := mc
	mcAddr.Target = "192.168.1.23:25565"
	cur := publish(nil, nil, mcAddr, vh)
	flows := []conntrack.Flow{
		agentFlow(6, 25565, "192.168.1.22:25565"), // 宛先が変わった
		agentFlow(6, 25565, "192.168.1.23:25565"), // 新しい宛先へのフロー
		agentFlow(17, 2456, "192.168.1.20:2456"),  // 変わらない
		agentFlow(6, 7000, "192.168.1.40:7000"),   // 削除した
		agentFlow(6, 7000, "172.17.0.2:80"),       // 他のテーブルの DNAT
		rawFlow(6, "192.168.1.50", "192.168.1.2", 8080, "172.17.0.2:80", true),
	}
	c := &fakeAgentConn{flows: flows}
	res, err := convergeAgent(c, []nft.AgentPublication{prev}, cur, agentScope)
	if err != nil {
		t.Fatal(err)
	}
	want := AgentResult{Kept: 2, Removed: 1, Retargeted: 1}
	if res != want {
		t.Errorf("result = %+v, want %+v", res, want)
	}
	if len(c.deleted) != 2 || c.deleted[0].TupleOrig.Proto.DestinationPort != 25565 || c.deleted[1].TupleOrig.Proto.DestinationPort != 7000 {
		t.Errorf("deleted = %v, want the retargeted and the removed flow", c.deleted)
	}
	if got := res.String(); got != "closed 2 flows: 1 removed, 1 retargeted, 0 not allowed; kept 2" {
		t.Errorf("String = %q", got)
	}
}

// 既に消えていたエントリは消したものと数える。他の削除の失敗は数えて誤りにし、残りの削除は続ける。
func TestConvergeAgentDeleteErrors(t *testing.T) {
	mc := rule("r_mc", proto.TCP, 25565, 25565, "192.168.1.22:25565")
	gone := rule("r_gone", proto.TCP, 7000, 7002, "192.168.1.40:7000")
	prev := publish(nil, nil, mc, gone)
	cur := publish(nil, nil, mc)
	boom := errors.New("boom")
	c := &fakeAgentConn{
		flows: []conntrack.Flow{
			agentFlow(6, 7000, "192.168.1.40:7000"),
			agentFlow(6, 7001, "192.168.1.41:7001"), // 他のテーブル
			agentFlow(6, 7001, "192.168.1.40:7001"),
			agentFlow(6, 7002, "192.168.1.40:7002"),
		},
		delErr: func(f conntrack.Flow) error {
			switch f.TupleOrig.Proto.DestinationPort {
			case 7000:
				return unix.ENOENT
			case 7001:
				return boom
			}
			return nil
		},
	}
	res, err := convergeAgent(c, []nft.AgentPublication{prev}, cur, agentScope)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the delete failure", err)
	}
	if want := (AgentResult{Removed: 2, Failed: 1}); res != want {
		t.Errorf("result = %+v, want %+v", res, want)
	}
	if len(c.deleted) != 1 || c.deleted[0].TupleOrig.Proto.DestinationPort != 7002 {
		t.Errorf("deleted = %v, want the delete to go on past the failure", c.deleted)
	}
	if got := res.String(); got != "closed 2 flows: 2 removed, 0 retargeted, 0 not allowed; kept 0; failed to close 1" {
		t.Errorf("String = %q", got)
	}
}

func TestConvergeAgentDumpError(t *testing.T) {
	boom := errors.New("boom")
	c := &fakeAgentConn{dumpErr: boom}
	if _, err := convergeAgent(c, nil, nft.AgentPublication{}, agentScope); !errors.Is(err, boom) {
		t.Errorf("err = %v, want the dump failure", err)
	}
}

func TestConvergeAgentScope(t *testing.T) {
	for _, s := range []AgentScope{
		{Peer: agentPeer},
		{Local: agentLocal},
		{Local: netip.MustParseAddr("fd00::2"), Peer: agentPeer},
	} {
		c := &fakeAgentConn{flows: []conntrack.Flow{agentFlow(6, 25565, "192.168.1.22:25565")}}
		if _, err := convergeAgent(c, nil, nft.AgentPublication{}, s); err == nil {
			t.Errorf("scope %+v: want an error", s)
		}
	}
}
