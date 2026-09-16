package check

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/proto"
)

// 実機で見た /proc/net/tcp の形
const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:08AE 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0D05 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 0000000000000000 100 0 0 10 0
   2: 0164A8C0:1F90 0264A8C0:C350 01 00000000:00000000 00:00000000 00000000     0        0 1 0000000000000000 20 4 30 10 -1
`
const procUDP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000000000000000000000000000:CA6C 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1 0000000000000000 0
  101: 00000000000000000000000001000000:0D05 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1 0000000000000000 0
`

func TestParseProcNet(t *testing.T) {
	var got []string
	if err := parseProcNet(strings.NewReader(procTCP), true, func(a netip.Addr, p uint16) {
		got = append(got, a.String()+":"+itoa(p))
	}); err != nil {
		t.Fatal(err)
	}
	// 2222 は 0.0.0.0 で LISTEN → 含む。3333 は 127.0.0.1 → 除外。8080 は ESTABLISHED → 除外
	if len(got) != 1 || got[0] != "0.0.0.0:2222" {
		t.Errorf("tcp = %v, want [0.0.0.0:2222]", got)
	}
	got = nil
	if err := parseProcNet(strings.NewReader(procUDP6), false, func(a netip.Addr, p uint16) {
		got = append(got, a.String()+":"+itoa(p))
	}); err != nil {
		t.Fatal(err)
	}
	// [::]:51820 は含む、[::1]:3333 は除外
	if len(got) != 1 || got[0] != ":::51820" {
		t.Errorf("udp6 = %v, want [:::51820]", got)
	}
}

func itoa(p uint16) string { return strconv.Itoa(int(p)) }

func TestBoundConflicts(t *testing.T) {
	b := Bound{proto.TCP: {22: {netip.IPv4Unspecified()}, 8443: {netip.MustParseAddr("198.51.100.1")}}, proto.UDP: {}}
	if c := b.Conflicts(proto.TCP, proto.PortRange{Lo: 20, Hi: 30}); len(c) != 1 || c[22] == nil {
		t.Errorf("conflicts = %v", c)
	}
	if c := b.Conflicts(proto.UDP, proto.PortRange{Lo: 22, Hi: 22}); len(c) != 0 {
		t.Errorf("udp conflicts = %v, want none", c)
	}
}

func ifname(key expr.MetaKey, name string) []expr.Any {
	b := make([]byte, 16)
	copy(b, name)
	return []expr.Any{&expr.Meta{Key: key, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: b}}
}

func TestUnconditionalTerminalAndJump(t *testing.T) {
	drop := []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}
	reject := []expr.Any{&expr.Reject{Type: 2, Code: 3}}
	condDrop := append(ifname(expr.MetaKeyIIFNAME, "eth0"), &expr.Verdict{Kind: expr.VerdictDrop})
	acceptAll := []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
	if ok, how := unconditionalTerminal(drop); !ok || how != "drop" {
		t.Errorf("drop: %v %q", ok, how)
	}
	if ok, how := unconditionalTerminal(reject); !ok || how != "reject" {
		t.Errorf("reject: %v %q", ok, how)
	}
	if ok, _ := unconditionalTerminal(condDrop); ok {
		t.Error("conditional drop must not count")
	}
	if ok, _ := unconditionalTerminal(acceptAll); ok {
		t.Error("accept must not count")
	}
	if got := jumpOnly([]expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictJump, Chain: "DOCKER-USER"}}); got != "DOCKER-USER" {
		t.Errorf("jumpOnly = %q", got)
	}
	if got := jumpOnly(append(ifname(expr.MetaKeyIIFNAME, "eth0"), &expr.Verdict{Kind: expr.VerdictJump, Chain: "X"})); got != "" {
		t.Errorf("conditional jump must not count, got %q", got)
	}
}

func TestAcceptsEstablished(t *testing.T) {
	native := []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(0x6), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
	newOnly := []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(0x8), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
	anonSet := []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeySTATE}, &expr.Lookup{SourceRegister: 1, SetName: "__set0"}, &expr.Verdict{Kind: expr.VerdictAccept}}
	xtMatch := []expr.Any{&expr.Match{Name: "conntrack", Rev: 3, Info: &xt.ConntrackMtinfo3{ConntrackMtinfo2: xt.ConntrackMtinfo2{StateMask: 0x6}}}, &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept}}
	nativeDrop := append(native[:3:3], &expr.Verdict{Kind: expr.VerdictDrop})
	for name, tt := range map[string]struct {
		exprs []expr.Any
		want  bool
	}{"native": {native, true}, "new only": {newOnly, false}, "anon set": {anonSet, true}, "xt conntrack": {xtMatch, true}, "native drop": {nativeDrop, false}} {
		if got := acceptsEstablished(tt.exprs); got != tt.want {
			t.Errorf("%s: %v, want %v", name, got, tt.want)
		}
	}
}

func dport() *expr.Payload {
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}
}
func l4(p byte) []expr.Any {
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{p}}}
}

func TestMatchPortsAndDNAT(t *testing.T) {
	nat := &expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1}
	xtDNAT := &expr.Target{Name: "DNAT", Rev: 2, Info: &xt.NatRange2{}}
	eq := append(append(l4(unix.IPPROTO_UDP), dport(), &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(7777)}), &expr.Counter{}, xtDNAT)
	rng := append(append(l4(unix.IPPROTO_TCP), dport(), &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: binaryutil.BigEndian.PutUint16(8000), ToData: binaryutil.BigEndian.PutUint16(8010)}), xtDNAT)
	gteLte := append(append(l4(unix.IPPROTO_UDP), dport(), &expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.BigEndian.PutUint16(2456)}, &expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: binaryutil.BigEndian.PutUint16(2457)}), &expr.Immediate{Register: 1, Data: []byte{1, 2, 3, 4}}, nat)
	noPort := append(l4(unix.IPPROTO_TCP), nat)
	masq := []expr.Any{&expr.Masq{}}

	if !isDNAT(eq) || !isDNAT(gteLte) || isDNAT(masq) {
		t.Error("isDNAT")
	}
	for name, tt := range map[string]struct {
		exprs   []expr.Any
		p       proto.Proto
		lo, hi  uint16
		unknown bool
	}{
		"xt eq":      {eq, proto.UDP, 7777, 7777, false},
		"xt range":   {rng, proto.TCP, 8000, 8010, false},
		"native rng": {gteLte, proto.UDP, 2456, 2457, false},
		"no port":    {noPort, proto.TCP, 0, 0, true},
	} {
		p, ports, unknown := matchPorts(nil, nil, tt.exprs)
		if p != tt.p || unknown != tt.unknown || (!unknown && (ports.Lo != tt.lo || ports.Hi != tt.hi)) {
			t.Errorf("%s: proto=%s ports=%v unknown=%v", name, p, ports, unknown)
		}
	}
	rep := &Report{DNATs: []DNAT{{Where: "ip nat PREROUTING", Proto: proto.UDP, Ports: proto.PortRange{Lo: 7777, Hi: 7777}},
		{Where: "x", Proto: proto.TCP, Unknown: true}}}
	if c := rep.DNATConflicts(proto.UDP, proto.PortRange{Lo: 7770, Hi: 7780}); len(c) != 1 {
		t.Errorf("conflicts = %v", c)
	}
	if c := rep.DNATConflicts(proto.TCP, proto.PortRange{Lo: 1, Hi: 65535}); len(c) != 0 {
		t.Errorf("unknown must not conflict: %v", c)
	}
}

func TestSuggestionsForms(t *testing.T) {
	drop := nftables.ChainPolicyDrop
	ipt := &nftables.Chain{Name: "FORWARD", Table: &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "filter"}, Policy: &drop}
	rep := &Report{}
	rep.inspectForward(ipt, []*nftables.Rule{{Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictJump, Chain: "DOCKER-USER"}}}}, "wg0")
	if len(rep.Findings) != 1 || !strings.Contains(rep.Findings[0].Suggest[0], "iptables -I DOCKER-USER -o wg0 -j ACCEPT") {
		t.Errorf("docker form: %+v", rep.Findings)
	}
	accept := nftables.ChainPolicyAccept
	fw := &nftables.Chain{Name: "filter_FORWARD", Table: &nftables.Table{Family: nftables.TableFamilyINet, Name: "firewalld"}, Policy: &accept}
	rep = &Report{}
	rep.inspectForward(fw, []*nftables.Rule{{Exprs: []expr.Any{&expr.Reject{}}}}, "wg0")
	if len(rep.Findings) != 1 || !strings.Contains(rep.Findings[0].Problem, "reject") || !strings.Contains(rep.Findings[0].Suggest[0], `nft insert rule inet firewalld filter_FORWARD oifname "wg0" accept`) {
		t.Errorf("firewalld form: %+v", rep.Findings)
	}
	rep = &Report{}
	rep.inspectForward(fw, []*nftables.Rule{{Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}}}, "wg0")
	if len(rep.Findings) != 0 {
		t.Errorf("accept-by-default chain must not warn: %+v", rep.Findings)
	}
}
