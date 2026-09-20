// Package planner turns a normalized rule set and admission policy inputs into a Plan: the
// backend-independent description of what wgft should forward (design.md 7a.2 節).
//
// Planner "は、normalize したルール集合と AdmissionPolicy から Plan を組み立てる。OS、nftables、
// gVisor の実装詳細を知らない。" This package holds no Backend, Runtime, or reconcile logic (those
// come later; design.md 7a.7 節 assigns them to internal/dataplane, internal/frontend and
// internal/reconcile). It only computes what should exist, never applies anything.
//
// This package is pure: it imports internal/model, internal/policy (OS-free types, admission
// limits included) and proto (the external contract), and nothing from
// dataplane/frontend/platform/vpsd/agent or OS-specific packages (design.md 7a.7 節).
package planner

import (
	"net/netip"
	"sort"

	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

// Agent is a registered agent as the Planner sees it: its name and its address on wg0. This is the
// only agent-derived Planner input in Phase 1 (design.md 7a.8 節: "normalize したルール集合と
// AdmissionPolicy から Plan を組み立てる"); see Peer's doc comment for what is deliberately left out.
type Agent struct {
	Name string
	Addr netip.Addr
}

// Input is everything Build needs to produce a Plan. Limits is the per-source concurrent flow cap
// setting (WGFT_MAX_*_FLOWS_PER_SOURCE; design.md 7a.5, 7a.10 節); Build passes it straight to
// policy.Build, so a zero-value AdmissionLimits{} means "use the default caps" (see
// PerSourceFlowCaps's doc comment in internal/policy), never "no cap". The process-wide flow
// budget belongs to Resource Guard (internal/resource) and is no Planner input.
type Input struct {
	Generation uint64
	Rules      []model.Rule
	Limits     policy.AdmissionLimits
	Agents     []Agent
}

// PortPlan is the route, ingress admission plan, and forwarding kind for one owned port (one
// enabled rule whose agent is known; design.md 7a.2 節: Plan holds "送信元制限を含む ingress の
// 計画" and "宛先までの経路の集合" per owned port).
//
// A port range (proto.PortRange with Lo != Hi) stays one entry here, at the same granularity a
// kernel-mode DNAT dispatch rule uses (design.md 6.1 節: one rule with a gte/lte port comparison,
// not one row per port). A Backend that needs one entry per individual port (design.md 6.3 節: the
// userspace relay opens one listener per port) expands the range itself; that expansion is a
// Backend concern, not something this backend-independent Plan does (design.md 7a.7 節).
type PortPlan struct {
	RuleID         string
	Agent          string
	Proto          proto.Proto
	ListenPort     proto.PortRange
	Forwarding     model.Forwarding
	SourceMetadata model.SourceMetadata
	// Target is the rule's declared LAN destination (host:port, unshifted). The agent, not the VPS
	// side, maps a range's individual ports onto it (design.md 5.3, 7 節 "実効宛先"); it is carried
	// through here only as the informational tail end of the route, for a future Backend/agent-wire
	// layer to consume (Phase 2+), not because the VPS side computes anything from it.
	Target string
	// AgentAddr is the agent's wg0 address wgft routes to. The VPS side never rewrites the port
	// (design.md 6.1 節: "DNAT では宛先アドレスだけを書き換え...ポートは書き換えない"; the relay in
	// 6.2/6.3 節 dials the agent at the same listen port too), so ListenPort doubles as the
	// agent-side port; there is no separate "route port" field.
	AgentAddr netip.Addr
	// Policy is this rule's AdmissionPolicy entry (source allow/deny and the three rate limits). It
	// is a copy of the matching entry in Plan.Admission.Rules (same RuleID), kept here too as a
	// convenience view for callers that already have a PortPlan and want its policy without
	// searching Plan.Admission.Rules; Plan.Admission is the single source of truth both are built
	// from (see Build). The zero value means the rule declared none of them, matching
	// policy.Build's convention.
	Policy policy.RulePolicy
}

// Peer is one WireGuard peer the Plan expects to exist on wg0, identified by the agent's wg0
// address. Phase 1 takes no key material as Planner input (design.md 7a.8 節 scopes this phase to
// "normalize したルール集合と AdmissionPolicy"); the full peer configuration (public key, allowed
// IPs, keepalive) is assembled by the dataplane Backend from Phase 2 onward, once Runtime exists.
type Peer struct {
	Agent string
	Addr  netip.Addr
}

// Plan is the desired generation, ingress/admission plan per owned port, routes to targets, and
// WireGuard peer set (design.md 7a.2 節): backend-independent data a Backend (design.md 7a.7 節,
// Phase 2/3) reads to converge. internal/planner never calls into a Backend; the dependency is
// one-directional.
//
// Admission is the AdmissionPolicy IR (internal/policy) for what this Plan forwards: its Rules hold
// only the rules that have an entry in Ports (disabled rules and rules of unregistered agents are
// left out), and PerSourceFlowCaps holds the global caps. It is not just the rule-level entries: a
// Backend given only a Plan must be able to compile admission policy end to end, including the
// per-source concurrent flow caps (design.md 7a.5 節), without reaching back into whatever built
// the Plan. This is also what the future nftables/Go-evaluator compilers (Phase 5, design.md 7a.8
// 節) will compile from. PortPlan.Policy is a per-port copy of the matching Admission.Rules entry,
// not a second, independently-computed value; see PortPlan.Policy's doc comment.
type Plan struct {
	Generation uint64
	Ports      []PortPlan
	Peers      []Peer
	Admission  policy.Policy
}

// Build derives a Plan from normalized rules, admission policy settings, and agent addresses
// (design.md 7a.2 節). It is pure (no OS, nftables, or gVisor calls) and deterministic: for the
// same Input, Plan.Ports is always sorted by (Proto, ListenPort.Lo, RuleID) and Plan.Peers by
// Agent, regardless of the input rule or agent order.
//
// A rule is left out of Plan.Ports when it is disabled, or when its agent is not in Input.Agents.
// This matches what every dataplane already needs before it can forward anything: before this Plan
// existed, internal/vpsd/nft.emit skipped a rule when cfg.AgentAddr[r.Agent] was not found (and
// always skipped !r.Enabled), internal/vpsd/proxyrelay.FromRules did the same for the Relay
// declaration, and so did the userspace relay's rule-based listener set. Since Phase 2/3 (design.md
// 7a.8 節) all three read this Plan instead (the kernel nft package's emit(), the vpsd-side
// relayRules(), and the userspace Backend), so FromRules and the rules-based emit() no longer exist
// to duplicate the filter. A rule cannot be forwarded to an agent wgft does not know the address of.
func Build(in Input) Plan {
	addrByAgent := make(map[string]netip.Addr, len(in.Agents))
	for _, a := range in.Agents {
		addrByAgent[a.Name] = a.Addr
	}

	pol := policy.Build(in.Rules, in.Limits)
	polByRuleID := make(map[string]policy.RulePolicy, len(pol.Rules))
	for _, rp := range pol.Rules {
		polByRuleID[rp.RuleID] = rp
	}

	plan := Plan{Generation: in.Generation, Admission: policy.Policy{PerSourceFlowCaps: pol.PerSourceFlowCaps}}
	for _, r := range in.Rules {
		if !r.Enabled {
			continue
		}
		addr, ok := addrByAgent[r.Agent]
		if !ok {
			continue
		}
		plan.Ports = append(plan.Ports, PortPlan{
			RuleID: r.ID, Agent: r.Agent, Proto: r.Proto, ListenPort: r.ListenPort,
			Forwarding: r.Forwarding, SourceMetadata: r.SourceMetadata,
			Target: r.Target, AgentAddr: addr, Policy: polByRuleID[r.ID],
		})
	}
	// Admission.Rules keeps only the rules that got a port above (enabled, agent registered), in
	// policy.Build's order. A rule that wgft does not forward must not carry admission policy: a
	// Backend compiling Plan.Admission would otherwise put policy on a port nothing forwards
	// (design.md 7a.4 節). PerSourceFlowCaps stays the global value.
	owned := make(map[string]bool, len(plan.Ports))
	for _, p := range plan.Ports {
		owned[p.RuleID] = true
	}
	for _, rp := range pol.Rules {
		if owned[rp.RuleID] {
			plan.Admission.Rules = append(plan.Admission.Rules, rp)
		}
	}

	sort.Slice(plan.Ports, func(i, j int) bool {
		a, b := plan.Ports[i], plan.Ports[j]
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.ListenPort.Lo != b.ListenPort.Lo {
			return a.ListenPort.Lo < b.ListenPort.Lo
		}
		return a.RuleID < b.RuleID
	})

	for _, a := range in.Agents {
		plan.Peers = append(plan.Peers, Peer{Agent: a.Name, Addr: a.Addr})
	}
	sort.Slice(plan.Peers, func(i, j int) bool { return plan.Peers[i].Agent < plan.Peers[j].Agent })

	return plan
}

// Transparent returns the ports in kernel-DNAT/userspace-relay territory: Forwarding=Transparent.
// design.md 7a.2 節: "kernel backend では Transparent は nftables の DNAT で完結し...userspace
// backend では両者は同じ中継コードを使う." Which Backend a given Plan feeds decides the treatment;
// this helper just partitions Plan.Ports by Forwarding for callers (and tests) that need one kind
// at a time.
func (p Plan) Transparent() []PortPlan { return p.byForwarding(model.Transparent) }

// Relay returns the ports vpsd itself terminates and relays (Forwarding=Relay, today's
// vps_mode=proxy), regardless of DataplaneMode (design.md 6.2, 6.3 節: the relay is the same
// TCP-terminating code in both kernel and userspace dataplane modes).
func (p Plan) Relay() []PortPlan { return p.byForwarding(model.Relay) }

func (p Plan) byForwarding(f model.Forwarding) []PortPlan {
	var out []PortPlan
	for _, pp := range p.Ports {
		if pp.Forwarding == f {
			out = append(out, pp)
		}
	}
	return out
}

// Without returns a copy of p that forwards none of the rules in ids: their ports and their
// Admission entries are left out, everything else (generation, peers, per-source caps) is kept.
// The Runtime uses it to publish a fail-closed Plan, one where the rules whose Prepare failed
// have no dispatch at all (design.md 7a.3 節). p itself is not modified.
func (p Plan) Without(ids map[string]bool) Plan {
	if len(ids) == 0 {
		return p
	}
	out := Plan{Generation: p.Generation, Peers: p.Peers,
		Admission: policy.Policy{PerSourceFlowCaps: p.Admission.PerSourceFlowCaps}}
	for _, pp := range p.Ports {
		if !ids[pp.RuleID] {
			out.Ports = append(out.Ports, pp)
		}
	}
	for _, rp := range p.Admission.Rules {
		if !ids[rp.RuleID] {
			out.Admission.Rules = append(out.Admission.Rules, rp)
		}
	}
	return out
}

// Port returns the PortPlan of ruleID, if the Plan forwards it.
func (p Plan) Port(ruleID string) (PortPlan, bool) {
	for _, pp := range p.Ports {
		if pp.RuleID == ruleID {
			return pp, true
		}
	}
	return PortPlan{}, false
}
