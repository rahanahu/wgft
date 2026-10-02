//go:build linux

package agent

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/controlapi"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/proto"
)

func kernelDoctorCreds(t *testing.T, rules ...proto.AgentRule) *credentials.Credentials {
	t.Helper()
	serverKey := testKey(t)
	st := &proto.State{Generation: 5, WG: proto.WGConfig{ServerPubkey: serverKey.PublicKey().String(), Endpoint: "203.0.113.1:51820",
		Address: "10.200.0.2/24", MTU: 1420, Keepalive: 25}, Rules: rules}
	return &credentials.Credentials{Mode: credentials.ModeKernel, WGPrivateKey: testKey(t).String(), LastState: st}
}

// 宣言どおりのインタフェースは、所有、ピア、経路が揃い、違う点を持たない。停止中の読み方と 30 秒ごとの
// 見直しは同じ linkDiffs を使う(設計文書 10.2c 節)。
func TestReadKernelHealthyInterface(t *testing.T) {
	f := kernelDoctorCreds(t)
	k := healthyKernel(t, f)
	withKernelDoctor(t, k)
	got := ReadKernel(f, "wgft0").Interface
	if got.Ownership != controlapi.KernelOwnershipCurrent || !got.PeerOK || len(got.Differs) != 0 || !got.Declared ||
		got.RouteInterface != "wgft0" || got.ServerAddress != "10.200.0.1" || got.NeedsNetAdmin {
		t.Errorf("interface = %+v", got)
	}
}

// 鍵とピアが食い違うインタフェースは、それぞれ別の事実として読める。
func TestReadKernelInterfaceDifferences(t *testing.T) {
	f := kernelDoctorCreds(t)
	for _, tc := range []struct {
		name   string
		edit   func(s *wg.AgentState)
		own    string
		peerOK bool
		differ []string
	}{
		{"previous key", func(s *wg.AgentState) { s.Ownership = wg.OwnedByPreviousKey }, controlapi.KernelOwnershipPrevious, true, []string{"the key"}},
		{"foreign key", func(s *wg.AgentState) { s.Ownership = wg.ForeignKey }, controlapi.KernelOwnershipForeign, false, nil},
		{"keyless", func(s *wg.AgentState) { s.Ownership, s.PublicKey = wg.ForeignKey, wgtypes.Key{} }, controlapi.KernelOwnershipKeyless, false, nil},
		{"no peer", func(s *wg.AgentState) { s.Peers = nil }, controlapi.KernelOwnershipCurrent, false, []string{"the peer"}},
		{"peer without the server address", func(s *wg.AgentState) {
			s.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.200.0.9/32")}
		}, controlapi.KernelOwnershipCurrent, false, []string{"the peer"}},
		{"keepalive", func(s *wg.AgentState) { s.Peers[0].Keepalive = 0 }, controlapi.KernelOwnershipCurrent, true, []string{"the peer"}},
		{"mtu", func(s *wg.AgentState) { s.MTU = 1280 }, controlapi.KernelOwnershipCurrent, true, []string{"the MTU"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := healthyKernel(t, f)
			tc.edit(&k.state)
			withKernelDoctor(t, k)
			got := ReadKernel(f, "wgft0").Interface
			if got.Ownership != tc.own || got.PeerOK != tc.peerOK || !reflect.DeepEqual(got.Differs, tc.differ) {
				t.Errorf("ownership %q peerOK %v differs %v; want %q %v %v", got.Ownership, got.PeerOK, got.Differs, tc.own, tc.peerOK, tc.differ)
			}
		})
	}
}

// CAP_NET_ADMIN の無い呼び出し元は、鍵とピア、テーブル、他のテーブルを読めない。リンクの属性と経路と
// sysctl は読める(ラボで確かめた読み分け。設計文書 10.2c 節)。
func TestReadKernelWithoutNetAdmin(t *testing.T) {
	f := kernelDoctorCreds(t)
	f.KernelPublication = []byte(`{"generation":5,"rules":[]}`)
	k := healthyKernel(t, f)
	k.eperm, k.up, k.route = true, true, "tailscale0"
	withKernelDoctor(t, k)
	got := ReadKernel(f, "wgft0")
	if !got.Interface.NeedsNetAdmin || !got.Interface.Exists || !got.Interface.Up || got.Interface.Ownership != "" || got.Interface.RouteInterface != "tailscale0" {
		t.Errorf("interface = %+v", got.Interface)
	}
	if !got.Table.NeedsNetAdmin || got.Table.ReadError == "" {
		t.Errorf("table = %+v", got.Table)
	}
	if !got.Forwarding.PolicyNeedsNetAdmin || got.Forwarding.IPForward != "1" {
		t.Errorf("forwarding = %+v", got.Forwarding)
	}
}

// リンクが無い、WireGuard でない、は権限なしで分かるので、鍵を読みに行かない。
func TestReadKernelLinkLevelFacts(t *testing.T) {
	f := kernelDoctorCreds(t)
	k := &fakeKernelDoctor{eperm: true}
	withKernelDoctor(t, k)
	if got := ReadKernel(f, "wgft0").Interface; got.Exists || got.Ownership != controlapi.KernelOwnershipAbsent || got.NeedsNetAdmin {
		t.Errorf("absent = %+v", got)
	}
	k.exists, k.kind, k.up = true, "dummy", true
	if got := ReadKernel(f, "wgft0").Interface; got.Ownership != controlapi.KernelOwnershipNotWireGuard || got.NeedsNetAdmin || got.Kind != "dummy" {
		t.Errorf("not wireguard = %+v", got)
	}
}

// 記録があれば、記録そのものと比べ、欠けた行と DNAT、加わった行を分けて返す。ルールの状態は記録の理由から来る。
func TestReadKernelTableAgainstTheRecord(t *testing.T) {
	pub := nft.AgentPublication{Generation: 9, Rules: []nft.AgentRuleResult{
		{RuleID: "r1", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 100, Hi: 101}, Target: "192.168.1.2:100",
			Ranges: []nft.AgentRange{{Ports: proto.PortRange{Lo: 100, Hi: 101}, Dest: netip.MustParseAddrPort("192.168.1.2:100")}}},
		{RuleID: "r2", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 200, Hi: 200}, Target: "127.0.0.1:22",
			Reason: "target 127.0.0.1 is a loopback address; kernel mode does not forward to loopback targets, use this host's LAN address"},
	}}
	raw, _ := json.Marshal(pub)
	f := kernelDoctorCreds(t)
	f.KernelPublication = raw
	k := healthyKernel(t, f)
	k.table = nft.AgentInspection{
		Missing:      []string{"postrouting: masquerade"},
		MissingDNATs: []nft.AgentDNAT{{RuleID: "r1", Proto: proto.TCP, Ports: proto.PortRange{Lo: 101, Hi: 101}, Dest: netip.MustParseAddrPort("192.168.1.2:101")}},
		Unexpected:   []string{"chain nat_pre: row 3 is not one wgft writes"},
		Unrecognized: 1,
		Moved:        []string{"forward: drop the rest from wgft0, now at row 1"},
		MissingItems: []nft.MissingItem{{Desc: "postrouting: masquerade", Role: nft.RoleCarryLAN},
			{Desc: "DNAT tcp 101 of rule r1 to 192.168.1.2:101", Role: nft.RoleCarry},
			{Desc: "filter_pre: drop the rest from wgft0", Role: nft.RoleGuard, Guard: nft.GuardPreDrop},
			{Desc: "forward: clamp the MSS of SYNs from wgft0", Role: nft.RoleGuard, Guard: nft.GuardMSS},
			{Desc: "forward: clamp the MSS of SYNs to wgft0", Role: nft.RoleGuard, Guard: nft.GuardMSS}},
	}
	withKernelDoctor(t, k)
	got := ReadKernel(f, "wgft0").Table
	if got.Source != controlapi.KernelTableFromRecord || got.Generation != 9 || !reflect.DeepEqual(k.wantSeen, pub) {
		t.Errorf("compared with %+v from %q gen %d; want the record", k.wantSeen, got.Source, got.Generation)
	}
	if got.MissingCount != 2 || !strings.Contains(strings.Join(got.Missing, "|"), "DNAT tcp 101 of rule r1 to 192.168.1.2:101") {
		t.Errorf("missing = %d %v", got.MissingCount, got.Missing)
	}
	if got.GuardMissingCount != 3 || got.GuardMissing[0] != "filter_pre: drop the rest from wgft0" ||
		!reflect.DeepEqual(got.GuardEffects, []string{controlapi.KernelEffectOtherDNAT, controlapi.KernelEffectMSS}) ||
		!reflect.DeepEqual(got.GuardClosed, []string{controlapi.KernelClosedHostByInput, controlapi.KernelClosedLANByForward}) {
		t.Errorf("guard missing = %d %v, effects %v, closed %v", got.GuardMissingCount, got.GuardMissing, got.GuardEffects, got.GuardClosed)
	}
	if got.MovedCount != 1 || got.Moved[0] != "forward: drop the rest from wgft0, now at row 1" {
		t.Errorf("moved = %d %v", got.MovedCount, got.Moved)
	}
	if got.UnexpectedCount != 1 {
		t.Errorf("unexpected = %d %v, want the added row once", got.UnexpectedCount, got.Unexpected)
	}
	want := []controlapi.DoctorRule{
		{ID: "r1", State: proto.StatusOK, Proto: proto.TCP, Ports: 2, DNATPorts: 2},
		{ID: "r2", State: proto.StatusError, Reason: pub.Rules[1].Reason, Proto: proto.TCP, Ports: 1},
	}
	if !reflect.DeepEqual(got.Rules, want) {
		t.Errorf("rules = %+v\nwant %+v", got.Rules, want)
	}
}

// 記録の無い実行では、宣言から導ける範囲だけを比べる。IP リテラルは宛先まで、ホスト名はポートだけを見て、
// ループバックの宛先は理由を持つ。許可一覧は当てはめない(設計文書 10.2c 節の「記録が無い場合」)。
func TestReadKernelTableFromTheDeclaration(t *testing.T) {
	f := kernelDoctorCreds(t,
		tcpRule("lit", "192.168.1.2:80", 8080, 8081),
		tcpRule("name", "game.lan:25565", 25565, 25566),
		tcpRule("lo", "127.0.0.1:22", 2222, 2222),
	)
	k := healthyKernel(t, f)
	k.table = nft.AgentInspection{DNATs: []nft.AgentDNAT{
		{RuleID: "lit", Proto: proto.TCP, Ports: proto.PortRange{Lo: 8080, Hi: 8080}, Dest: netip.MustParseAddrPort("192.168.1.2:80")},
		{RuleID: "lit", Proto: proto.TCP, Ports: proto.PortRange{Lo: 8081, Hi: 8081}, Dest: netip.MustParseAddrPort("192.168.1.9:81")},
		{RuleID: "name", Proto: proto.TCP, Ports: proto.PortRange{Lo: 25565, Hi: 25566}, Dest: netip.MustParseAddrPort("192.168.1.7:25565")},
	}}
	withKernelDoctor(t, k)
	got := ReadKernel(f, "wgft0").Table
	if got.Source != controlapi.KernelTableFromDeclaration || got.Generation != 5 {
		t.Fatalf("source %q gen %d", got.Source, got.Generation)
	}
	if got.MissingCount != 1 || !strings.Contains(got.Missing[0], "rule lit") || !strings.Contains(got.Missing[0], "1 of 2 ports") {
		t.Errorf("missing = %v", got.Missing)
	}
	byID := map[string]controlapi.DoctorRule{}
	for _, r := range got.Rules {
		byID[r.ID] = r
	}
	if r := byID["name"]; r.State != proto.StatusOK || r.DNATPorts != 2 || r.Reason != "" {
		t.Errorf("host-name rule = %+v, want its two ports covered and no invented reason", r)
	}
	if r := byID["lo"]; r.State != proto.StatusError || !strings.Contains(r.Reason, "loopback") {
		t.Errorf("loopback rule = %+v", r)
	}
	if r := byID["lit"]; r.DNATPorts != 1 {
		t.Errorf("literal rule = %+v, want 1 port in place", r)
	}

	// ホスト名のルールのポートが欠ければ、それも欠けとして数える
	k.table.DNATs = k.table.DNATs[:2]
	got = ReadKernel(f, "wgft0").Table
	if got.MissingCount != 2 {
		t.Errorf("missing = %v, want the host-name rule's ports as well", got.Missing)
	}
}

// ホストの転送の設定は、ip_forward、strict の rp_filter、他のテーブルの既定の落としを分けて返す。
func TestReadKernelForwarding(t *testing.T) {
	f := kernelDoctorCreds(t)
	k := healthyKernel(t, f)
	k.sysctl["ip_forward"] = "0"
	k.sysctl["conf/all/rp_filter"] = "1"
	k.drops = []string{"inet otherfw fwd"}
	withKernelDoctor(t, k)
	got := ReadKernel(f, "wgft0").Forwarding
	if got.IPForward != "0" || !reflect.DeepEqual(got.RPFilterStrict, []string{"all"}) || !reflect.DeepEqual(got.PolicyDrops, []string{"inet otherfw fwd"}) {
		t.Errorf("forwarding = %+v", got)
	}
	delete(k.sysctl, "ip_forward")
	if got := ReadKernel(f, "wgft0").Forwarding; got.IPForwardError == "" {
		t.Errorf("an unreadable ip_forward = %+v, want its error", got)
	}
}

// CapEff の 12 番目のビットが CAP_NET_ADMIN である。
func TestCapEffHasNetAdmin(t *testing.T) {
	for _, tc := range []struct {
		status string
		want   *bool
	}{
		{"Name:\twgft\nCapEff:\t0000000000001000\n", ptr(true)},
		{"CapEff:\t000001ffffffffff\n", ptr(true)},
		{"CapEff:\t0000000000000000\n", ptr(false)},
		{"CapEff:\tzz\n", nil},
		{"Name:\twgft\n", nil},
	} {
		got := capEffHasNetAdmin(tc.status)
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("%q: got %v, want %v", tc.status, deref(got), deref(tc.want))
		}
	}
}

func ptr(b bool) *bool { return &b }
func deref(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

// nat_pre に加わった 1 行は、行の形の比較と DNAT の読みの両方に表れるが、1 件に数える。既にある行の map に
// 加わった要素は行の比較に表れないので、DNAT として 1 件に数える。
func TestReadKernelCountsAnAddedRowOnce(t *testing.T) {
	raw, _ := json.Marshal(nft.AgentPublication{Generation: 9})
	f := kernelDoctorCreds(t)
	f.KernelPublication = raw
	extra := nft.AgentDNAT{RuleID: "r9", Proto: proto.TCP, Ports: proto.PortRange{Lo: 9, Hi: 9}, Dest: netip.MustParseAddrPort("192.168.1.9:9")}
	for _, tc := range []struct {
		name string
		ins  nft.AgentInspection
		want int
	}{
		{"an unreadable row", nft.AgentInspection{Unexpected: []string{"chain nat_pre: row 3 is not one wgft writes"}, Unrecognized: 1}, 1},
		{"a DNAT row", nft.AgentInspection{Unexpected: []string{"chain nat_pre: row 3 is not one wgft writes"}, ExtraDNATs: []nft.AgentDNAT{extra}}, 1},
		{"a map element", nft.AgentInspection{ExtraDNATs: []nft.AgentDNAT{extra}, ExtraDNATsInPlace: []nft.AgentDNAT{extra}}, 1},
		// DNAT でない行が nat_pre に加わり、同時に既存の map に要素が加わっても、要素は消えない
		{"a nat_pre row and a map element", nft.AgentInspection{Unexpected: []string{"chain nat_pre: row 3 is not one wgft writes"}, Unrecognized: 1,
			ExtraDNATs: []nft.AgentDNAT{extra}, ExtraDNATsInPlace: []nft.AgentDNAT{extra}}, 2},
		{"a row elsewhere and a map element", nft.AgentInspection{Unexpected: []string{"chain forward: row 1 is not one wgft writes"}, ExtraDNATs: []nft.AgentDNAT{extra},
			ExtraDNATsInPlace: []nft.AgentDNAT{extra}}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := healthyKernel(t, f)
			k.table = tc.ins
			withKernelDoctor(t, k)
			if got := ReadKernel(f, "wgft0").Table; got.UnexpectedCount != tc.want {
				t.Errorf("unexpected = %d %v, want %d", got.UnexpectedCount, got.Unexpected, tc.want)
			}
		})
	}
}

// 宛先がホスト自身でないルールだけが通る行と、ホスト自身のルールだけが通る行は、記録にその宛先のルールが
// あるときだけ転送を止める側に数える。ホスト自身のアドレスを読めなければ、どちらも止める側に数える。
func TestSplitMissingByTarget(t *testing.T) {
	items := []nft.MissingItem{
		{Desc: "carry", Role: nft.RoleCarry},
		{Desc: "lan", Role: nft.RoleCarryLAN},
		{Desc: "self", Role: nft.RoleCarrySelf},
		{Desc: "guard", Role: nft.RoleGuard},
	}
	pub := func(dests ...string) nft.AgentPublication {
		var p nft.AgentPublication
		for i, d := range dests {
			p.Rules = append(p.Rules, nft.AgentRuleResult{RuleID: fmt.Sprintf("r%d", i), Proto: proto.TCP,
				Ranges: []nft.AgentRange{{Ports: proto.PortRange{Lo: uint16(100 + i), Hi: uint16(100 + i)}, Dest: netip.MustParseAddrPort(d)}}})
		}
		return p
	}
	local := func() (map[netip.Addr]bool, error) {
		return map[netip.Addr]bool{netip.MustParseAddr("192.168.1.2"): true}, nil
	}
	for _, tc := range []struct {
		name         string
		pub          nft.AgentPublication
		local        func() (map[netip.Addr]bool, error)
		carry, guard []string
	}{
		{"LAN targets only", pub("192.168.1.9:80"), local, []string{"carry", "lan"}, []string{"self", "guard"}},
		{"this host only", pub("192.168.1.2:80"), local, []string{"carry", "self"}, []string{"lan", "guard"}},
		{"both", pub("192.168.1.9:80", "192.168.1.2:80"), local, []string{"carry", "lan", "self"}, []string{"guard"}},
		{"addresses unreadable", pub("192.168.1.9:80"), func() (map[netip.Addr]bool, error) { return nil, os.ErrPermission },
			[]string{"carry", "lan", "self"}, []string{"guard"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			carry, guard, _ := splitMissing(items, tc.pub, tc.local)
			if !reflect.DeepEqual(carry, tc.carry) || !reflect.DeepEqual(guard, tc.guard) {
				t.Errorf("carry %v guard %v; want %v %v", carry, guard, tc.carry, tc.guard)
			}
		})
	}
}

// drop の行は層になっている。開く面は欠けた行の組み合わせで決まり、1 行だけの欠けで面が開かないときは、
// 残っている行が閉じていることを返す(設計文書 10.2c 節)。組み合わせはラボで確かめた。
func TestGuardEffectsFollowTheLayers(t *testing.T) {
	for _, tc := range []struct {
		name            string
		missing         []string
		effects, closed []string
	}{
		{"input drop only", []string{nft.GuardInputDrop}, nil, []string{controlapi.KernelClosedHostByFilterPre}},
		{"filter_pre drop only", []string{nft.GuardPreDrop}, []string{controlapi.KernelEffectOtherDNAT},
			[]string{controlapi.KernelClosedHostByInput, controlapi.KernelClosedLANByForward}},
		{"filter_pre and input drops", []string{nft.GuardPreDrop, nft.GuardInputDrop}, []string{controlapi.KernelEffectHost, controlapi.KernelEffectOtherDNAT},
			[]string{controlapi.KernelClosedLANByForward}},
		{"forward drop from wgft0 only", []string{nft.GuardForwardFromDrop}, nil, []string{controlapi.KernelClosedLANByFilterPre}},
		{"filter_pre and forward drops", []string{nft.GuardPreDrop, nft.GuardForwardFromDrop}, []string{controlapi.KernelEffectOtherDNAT, controlapi.KernelEffectLAN},
			[]string{controlapi.KernelClosedHostByInput}},
		{"hairpin drop", []string{nft.GuardHairpinDrop}, []string{controlapi.KernelEffectHairpin}, nil},
		{"drop to wgft0", []string{nft.GuardForwardToDrop}, []string{controlapi.KernelEffectToTunnel}, nil},
		{"MSS rows", []string{nft.GuardMSS}, []string{controlapi.KernelEffectMSS}, nil},
		{"every drop", []string{nft.GuardPreDrop, nft.GuardInputDrop, nft.GuardForwardFromDrop, nft.GuardForwardToDrop, nft.GuardHairpinDrop},
			[]string{controlapi.KernelEffectHost, controlapi.KernelEffectOtherDNAT, controlapi.KernelEffectLAN, controlapi.KernelEffectHairpin, controlapi.KernelEffectToTunnel}, nil},
		{"an established accept only", nil, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			effects, closed := guardEffects(tc.missing)
			if !reflect.DeepEqual(effects, tc.effects) || !reflect.DeepEqual(closed, tc.closed) {
				t.Errorf("effects %v closed %v; want %v %v", effects, closed, tc.effects, tc.closed)
			}
		})
	}
}

// Same overflow shape as secondsToDuration guards against (dataplane_userspace.go): if
// agent.json is corrupted or tampered with, st.WG.Keepalive could sit outside the 0-65535
// range that kernel mode's CheckWG (dataplane_kernel.go) normally enforces before this value
// is ever recorded. declaredAgentLink rejects it rather than let `agent doctor` display an
// out-of-range or overflowed Keepalive.
func TestDeclaredAgentLinkRejectsOutOfRangeKeepalive(t *testing.T) {
	serverPriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cur, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	base := proto.WGConfig{
		ServerPubkey: serverPriv.PublicKey().String(),
		Address:      "10.200.0.2/24",
		MTU:          1420,
	}

	tests := []struct {
		name      string
		keepalive int64
		wantOK    bool
	}{
		{"typical value in range", 25, true},
		{"at the upper bound", 65535, true},
		{"overflow value that wraps to 512ns is rejected", 20211507185753197, false},
		{"one past the upper bound is rejected", 65536, false},
		{"negative is rejected", -1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !fitsInt(tt.keepalive) {
				t.Skip("the keepalive value does not fit in int on this platform")
			}
			w := base
			w.Keepalive = int(tt.keepalive)
			_, ok := declaredAgentLink("wgft0", cur, wgtypes.Key{}, w)
			if ok != tt.wantOK {
				t.Errorf("declaredAgentLink ok = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}
