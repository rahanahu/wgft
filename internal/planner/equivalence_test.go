package planner

import (
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/vpsd/proxyrelay"
	"github.com/rahanahu/wgft/proto"
)

// This file proves the Phase 1 "no behaviour change" completion criterion (design.md 7a.8 節):
// the set of ports/rules Planner.Build classifies as kernel DNAT, vpsd-terminated relay, or
// userspace relay equals what today's code, unmodified, derives from the same proto.Rule set.
//
//   - kernel DNAT: compared against the same rule-level filter internal/vpsd/nft.emit applies
//     before it emits a DNAT row (r.Enabled && r.VPSMode == proto.ModeKernel && agent known;
//     internal/vpsd/nft/build.go's main loop). nft.emit itself is not called (it needs a real or
//     recorded nftables.Conn); the filter is the "current behaviour" this test locks down.
//   - vpsd-terminated relay: compared directly against proxyrelay.FromRules, the exported function
//     internal/vpsd/apply.go actually calls to build the proxy relay's declaration, in both kernel
//     and userspace dataplane modes (internal/vpsd/vpsd.go wires the same proxyrelay.Manager either
//     way; only its Dial func differs).
//   - userspace relay: compared against a reproduction of internal/vpsd/dataplane_userspace.go's
//     ApplyNFT loop (unexported method on an unexported type, so it cannot be called directly);
//     the reproduction is transcribed verbatim from that loop and cited by name so a future change
//     to ApplyNFT's filter is visible as a diff here too.
func equivalenceFixture() (rules []proto.Rule, agentAddr map[string]netip.Addr) {
	rate := func(s string) *proto.Rate {
		r, err := proto.ParseRate(s)
		if err != nil {
			panic(err)
		}
		return &r
	}
	cidr := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }

	rules = []proto.Rule{
		{ID: "r_kernel_single", Agent: "home", Proto: proto.UDP, ListenPort: pr(2456, 2456),
			Target: "192.168.1.20:2456", VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_kernel_range_udp", Agent: "home", Proto: proto.UDP, ListenPort: pr(2500, 2503),
			Target: "192.168.1.20:2500", VPSMode: proto.ModeKernel, Enabled: true,
			SourceDeny: []netip.Prefix{cidr("203.0.113.0/24")}},
		{ID: "r_kernel_range_tcp", Agent: "office", Proto: proto.TCP, ListenPort: pr(9000, 9002),
			Target: "192.168.2.10:9000", VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_kernel_rates", Agent: "home", Proto: proto.UDP, ListenPort: pr(7777, 7777),
			Target: "192.168.1.25:7777", VPSMode: proto.ModeKernel, Enabled: true,
			NewFlowRate: rate("100/second"), PacketRate: rate("5000/second"), PerSourceRate: rate("10/second")},
		{ID: "r_kernel_disabled", Agent: "home", Proto: proto.UDP, ListenPort: pr(3000, 3000),
			Target: "192.168.1.26:3000", VPSMode: proto.ModeKernel, Enabled: false},
		{ID: "r_kernel_unknown_agent", Agent: "ghost", Proto: proto.UDP, ListenPort: pr(4000, 4000),
			Target: "192.168.1.27:4000", VPSMode: proto.ModeKernel, Enabled: true},

		{ID: "r_proxy_plain", Agent: "home", Proto: proto.TCP, ListenPort: pr(443, 443),
			Target: "192.168.1.30:443", VPSMode: proto.ModeProxy, ProxyProtocol: false, Enabled: true,
			SourceAllow: []netip.Prefix{cidr("198.51.100.0/24")}},
		{ID: "r_proxy_proxyproto", Agent: "office", Proto: proto.TCP, ListenPort: pr(8443, 8443),
			Target: "192.168.2.11:8443", VPSMode: proto.ModeProxy, ProxyProtocol: true, Enabled: true},
		{ID: "r_proxy_disabled", Agent: "home", Proto: proto.TCP, ListenPort: pr(9443, 9443),
			Target: "192.168.1.31:9443", VPSMode: proto.ModeProxy, ProxyProtocol: true, Enabled: false},
		{ID: "r_proxy_unknown_agent", Agent: "ghost", Proto: proto.TCP, ListenPort: pr(1443, 1443),
			Target: "192.168.1.32:1443", VPSMode: proto.ModeProxy, Enabled: true},
	}
	agentAddr = map[string]netip.Addr{"home": addr("10.200.0.2"), "office": addr("10.200.0.3")}
	return rules, agentAddr
}

func buildPlan(t *testing.T, rules []proto.Rule, agentAddr map[string]netip.Addr) Plan {
	t.Helper()
	normalized, err := model.NormalizeRules(rules, nil)
	if err != nil {
		t.Fatalf("model.NormalizeRules: %v", err)
	}
	var agents []Agent
	for name, a := range agentAddr {
		agents = append(agents, Agent{Name: name, Addr: a})
	}
	return Build(Input{Generation: 1, Rules: normalized, Agents: agents})
}

// TestEquivalenceKernelDNAT locks down that Plan.Transparent() names exactly the rules that
// internal/vpsd/nft.emit's main loop would give a DNAT row (design.md 6.1 節), for the
// DataplaneMode=Kernel case: r.Enabled && r.VPSMode == proto.ModeKernel && the agent is known.
func TestEquivalenceKernelDNAT(t *testing.T) {
	rules, agentAddr := equivalenceFixture()
	plan := buildPlan(t, rules, agentAddr)

	type route struct {
		proto  proto.Proto
		port   proto.PortRange
		target netip.Addr
	}
	want := map[string]route{}
	for _, r := range rules {
		if !r.Enabled || r.VPSMode != proto.ModeKernel {
			continue
		}
		a, ok := agentAddr[r.Agent]
		if !ok {
			continue
		}
		want[r.ID] = route{r.Proto, r.ListenPort, a}
	}

	got := map[string]route{}
	for _, pp := range plan.Transparent() {
		got[pp.RuleID] = route{pp.Proto, pp.ListenPort, pp.AgentAddr}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Plan.Transparent() ports = %+v, want %+v", got, want)
	}
	// Cross-check: every enabled, known-agent rule is exactly one of Transparent or Relay, never both.
	if got, want := len(plan.Transparent())+len(plan.Relay()), len(plan.Ports); got != want {
		t.Fatalf("Transparent+Relay = %d ports, want %d (Plan.Ports total)", got, want)
	}
}

// TestEquivalenceVPSDRelay locks down that Plan.Relay() equals proxyrelay.FromRules on the same
// input, field for field (design.md 6.2 節). proxyrelay.FromRules is the function
// internal/vpsd/apply.go actually calls before every nftables apply, in both kernel and userspace
// dataplane modes (internal/vpsd/vpsd.go builds one proxyrelay.Manager for both; only Dial differs).
func TestEquivalenceVPSDRelay(t *testing.T) {
	rules, agentAddr := equivalenceFixture()
	plan := buildPlan(t, rules, agentAddr)

	want := proxyrelay.FromRules(rules, agentAddr)
	sort.Slice(want, func(i, j int) bool { return want[i].ID < want[j].ID })

	var got []proxyrelay.Rule
	for _, pp := range plan.Relay() {
		got = append(got, proxyrelay.Rule{
			ID: pp.RuleID, ListenPort: pp.ListenPort.Lo, AgentAddr: pp.AgentAddr, AgentPort: pp.ListenPort.Lo,
			ProxyProtocol: pp.SourceMetadata == model.ProxyV2,
			SourceDeny:    pp.Policy.SourceDeny, SourceAllow: pp.Policy.SourceAllow, Agent: pp.Agent,
		})
	}
	sort.Slice(got, func(i, j int) bool { return got[i].ID < got[j].ID })

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Plan.Relay() converted to []proxyrelay.Rule = %+v, want proxyrelay.FromRules(...) = %+v", got, want)
	}
}

// referenceUserspacePorts reproduces internal/vpsd/dataplane_userspace.go's ApplyNFT loop
// (design.md 6.3 節): for every enabled, non-proxy rule whose agent is known, one relay.Desired
// entry per individual port in the range, target = agent address at that same port. Transcribed
// verbatim (down to the JoinHostPort/Itoa calls) rather than imported, because ApplyNFT is an
// unexported method on an unexported type; a change to that loop's filter should show up as a
// failing assertion here, prompting the same change to be made to this reference.
func referenceUserspacePorts(rules []proto.Rule, agentAddr map[string]netip.Addr) map[string]string {
	desired := map[string]string{}
	for i := range rules {
		r := &rules[i]
		if !r.Enabled || r.VPSMode == proto.ModeProxy {
			continue
		}
		a, ok := agentAddr[r.Agent]
		if !ok {
			continue
		}
		for p := int(r.ListenPort.Lo); p <= int(r.ListenPort.Hi); p++ {
			desired[string(r.Proto)+"/"+strconv.Itoa(p)] = net.JoinHostPort(a.String(), strconv.Itoa(p))
		}
	}
	return desired
}

// TestEquivalenceUserspaceRelay locks down that Plan.Transparent(), expanded one port at a time,
// equals referenceUserspacePorts on the same input (design.md 6.3 節, DataplaneMode=Userspace case).
func TestEquivalenceUserspaceRelay(t *testing.T) {
	rules, agentAddr := equivalenceFixture()
	plan := buildPlan(t, rules, agentAddr)

	want := referenceUserspacePorts(rules, agentAddr)

	got := map[string]string{}
	for _, pp := range plan.Transparent() {
		for p := int(pp.ListenPort.Lo); p <= int(pp.ListenPort.Hi); p++ {
			got[string(pp.Proto)+"/"+strconv.Itoa(p)] = net.JoinHostPort(pp.AgentAddr.String(), strconv.Itoa(p))
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Plan.Transparent() expanded per-port = %+v, want %+v", got, want)
	}
}
