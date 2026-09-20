package model

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

func pr(lo, hi uint16) proto.PortRange { return proto.PortRange{Lo: lo, Hi: hi} }

func rate(s string) *proto.Rate {
	r, err := proto.ParseRate(s)
	if err != nil {
		panic(err)
	}
	return &r
}

func cidr(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// fixtureRules is a broad set of valid proto.Rule values covering the combinations the
// FromProto/ToProto adapter must round-trip losslessly (Phase 1 completion criterion,
// design.md 7a.8): single ports, ranges, both vps_mode values, proxy_protocol on and off,
// allow/deny lists (including both on the same rule, and neither), all three rate kinds set and
// unset, disabled rules, and rules produced by proto.Rule.Split/Merge.
func fixtureRules() []proto.Rule {
	rules := []proto.Rule{
		{
			ID: "r_kernel_basic", Agent: "home", Proto: proto.UDP,
			ListenPort: pr(2456, 2456), Target: "192.168.1.20:2456",
			VPSMode: proto.ModeKernel, Enabled: true,
		},
		{
			ID: "r_kernel_range", Agent: "home", Group: "valheim", Note: "weekend server, friends only",
			Proto: proto.UDP, ListenPort: pr(2500, 2503), Target: "192.168.1.20:2500",
			VPSMode: proto.ModeKernel, Enabled: true,
			SourceDeny: []netip.Prefix{cidr("203.0.113.0/24")},
		},
		{
			ID: "r_kernel_allow_deny", Agent: "home", Proto: proto.TCP,
			ListenPort: pr(8080, 8080), Target: "192.168.1.21:80",
			VPSMode: proto.ModeKernel, Enabled: true,
			SourceAllow: []netip.Prefix{cidr("198.51.100.0/24"), cidr("192.0.2.0/24")},
			SourceDeny:  []netip.Prefix{cidr("192.0.2.128/25")},
		},
		{
			ID: "r_kernel_rates", Agent: "home", Proto: proto.UDP,
			ListenPort: pr(3478, 3478), Target: "192.168.1.22:3478",
			VPSMode: proto.ModeKernel, Enabled: true,
			NewFlowRate: rate("100/second"), PacketRate: rate("5000/second"), PerSourceRate: rate("10/second"),
		},
		{
			ID: "r_kernel_disabled", Agent: "home", Proto: proto.TCP,
			ListenPort: pr(9000, 9000), Target: "192.168.1.23:9000",
			VPSMode: proto.ModeKernel, Enabled: false,
			SourceDeny: []netip.Prefix{cidr("203.0.113.0/24")},
		},
		{
			ID: "r_proxy_plain", Agent: "home", Proto: proto.TCP,
			ListenPort: pr(443, 443), Target: "192.168.1.30:443",
			VPSMode: proto.ModeProxy, ProxyProtocol: false, Enabled: true,
			SourceAllow: []netip.Prefix{cidr("198.51.100.0/24")},
		},
		{
			ID: "r_proxy_proxyproto", Agent: "home", Proto: proto.TCP,
			ListenPort: pr(8443, 8443), Target: "192.168.1.31:8443",
			VPSMode: proto.ModeProxy, ProxyProtocol: true, Enabled: true,
		},
		{
			ID: "r_proxy_disabled", Agent: "office", Proto: proto.TCP,
			ListenPort: pr(9443, 9443), Target: "192.168.2.10:9443",
			VPSMode: proto.ModeProxy, ProxyProtocol: true, Enabled: false,
		},
		{
			ID: "r_no_group_note", Agent: "office", Proto: proto.UDP,
			ListenPort: pr(51820, 51820), Target: "192.168.2.11:51820",
			VPSMode: proto.ModeKernel, Enabled: true,
		},
	}

	// Rules produced by Split (design.md 5.4, 10.1/10.2 節): head keeps the original ID, tail gets a
	// new one, both keep the effective target unchanged.
	wide := proto.Rule{
		ID: "r_split_src", Agent: "home", Proto: proto.UDP,
		ListenPort: pr(2600, 2604), Target: "192.168.1.20:2600",
		VPSMode: proto.ModeKernel, Enabled: true,
	}
	head, tail, err := wide.Split(pr(2602, 2602), "r_split_tail")
	if err != nil {
		panic(err)
	}
	rules = append(rules, head, tail)

	// A rule produced by Merge (design.md 5.4 節): two adjacent single-port rules combined into one.
	a := proto.Rule{
		ID: "r_merge_a", Agent: "home", Proto: proto.TCP,
		ListenPort: pr(7000, 7000), Target: "192.168.1.40:7000",
		VPSMode: proto.ModeKernel, Enabled: true,
		SourceAllow: []netip.Prefix{cidr("198.51.100.0/24")}, NewFlowRate: rate("50/second"),
	}
	b := proto.Rule{
		ID: "r_merge_b", Agent: "home", Proto: proto.TCP,
		ListenPort: pr(7001, 7001), Target: "192.168.1.40:7001",
		VPSMode: proto.ModeKernel, Enabled: true,
		SourceAllow: []netip.Prefix{cidr("198.51.100.0/24")}, NewFlowRate: rate("50/second"),
	}
	merged, err := proto.Merge(a, b)
	if err != nil {
		panic(err)
	}
	rules = append(rules, merged)

	return rules
}

// TestRoundTripLossless は、fixtureRules の各ルールについて FromProto -> ToProto が元の値と
// 完全に一致することを確かめる(設計文書 7a.8 節 Phase 1 の完了条件)。
func TestRoundTripLossless(t *testing.T) {
	for _, r := range fixtureRules() {
		t.Run(r.ID, func(t *testing.T) {
			m, err := FromProto(r)
			if err != nil {
				t.Fatalf("FromProto: %v", err)
			}
			got := m.ToProto()
			if !reflect.DeepEqual(got, r) {
				t.Fatalf("round trip mismatch:\n  got  %+v\n  want %+v", got, r)
			}
		})
	}
}

// TestForwardingMapping locks the exact mapping table in design.md 7a.2.
func TestForwardingMapping(t *testing.T) {
	tests := []struct {
		name          string
		mode          proto.VPSMode
		proxyProtocol bool
		wantForward   Forwarding
		wantMeta      SourceMetadata
	}{
		{"kernel/no-header", proto.ModeKernel, false, Transparent, NoSourceMetadata},
		{"proxy/no-header", proto.ModeProxy, false, Relay, NoSourceMetadata},
		{"proxy/proxy-v2", proto.ModeProxy, true, Relay, ProxyV2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, m, err := forwardingFromProto(tt.mode, tt.proxyProtocol)
			if err != nil {
				t.Fatalf("forwardingFromProto: %v", err)
			}
			if f != tt.wantForward || m != tt.wantMeta {
				t.Fatalf("forwardingFromProto(%v, %v) = (%v, %v), want (%v, %v)",
					tt.mode, tt.proxyProtocol, f, m, tt.wantForward, tt.wantMeta)
			}
			gotMode, gotProxyProtocol := protoForwarding(f, m)
			if gotMode != tt.mode || gotProxyProtocol != tt.proxyProtocol {
				t.Fatalf("protoForwarding(%v, %v) = (%v, %v), want (%v, %v)",
					f, m, gotMode, gotProxyProtocol, tt.mode, tt.proxyProtocol)
			}
		})
	}
}

// TestTransparentProxyV2Rejected は、Transparent + ProxyV2(vps_mode=kernel かつ
// proxy_protocol=true)が無効な組み合わせとして拒否されることを確かめる。proto.Rule.Validate が
// 同じ組み合わせを "proxy_protocol can only be enabled when vps_mode=proxy" で拒否しており、
// FromProto はこの制約をモデルの語彙で言い直しているだけである(重複した新しい規則ではない)。
func TestTransparentProxyV2Rejected(t *testing.T) {
	r := proto.Rule{
		ID: "r_bad", Agent: "home", Proto: proto.TCP,
		ListenPort: pr(443, 443), Target: "192.168.1.1:443",
		VPSMode: proto.ModeKernel, ProxyProtocol: true, Enabled: true,
	}
	if _, err := FromProto(r); err == nil {
		t.Fatal("FromProto: want error for vps_mode=kernel + proxy_protocol=true, got nil")
	}
	if err := r.Validate(); err == nil {
		t.Fatal("proto.Rule.Validate: want error for the same combination, got nil (fixture is stale)")
	}
}

// TestNormalizeRulesUsesProtoValidation は NormalizeRules が proto.ValidateRules をそのまま
// 呼んでいることを、同じ入力で同じ誤りが返ることによって確かめる(重複実装しない、という
// 設計文書 7a.2 節の指示)。
func TestNormalizeRulesUsesProtoValidation(t *testing.T) {
	overlapping := []proto.Rule{
		{ID: "r1", Agent: "home", Proto: proto.UDP, ListenPort: pr(2456, 2458), Target: "192.168.1.1:1", VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r2", Agent: "home", Proto: proto.UDP, ListenPort: pr(2458, 2460), Target: "192.168.1.2:1", VPSMode: proto.ModeKernel, Enabled: true},
	}
	wantErr := proto.ValidateRules(overlapping, nil)
	if wantErr == nil {
		t.Fatal("proto.ValidateRules: want error for overlapping ranges, got nil (fixture is stale)")
	}
	_, gotErr := NormalizeRules(overlapping, nil)
	if gotErr == nil || gotErr.Error() != wantErr.Error() {
		t.Fatalf("NormalizeRules error = %v, want %v", gotErr, wantErr)
	}
}
