// Package policy は AdmissionPolicy の中間表現(IR)を持つ(設計文書 7a.2、7a.4 節)。
//
// AdmissionPolicy は、送信元の許可拒否、送信元ごとの新規フローレート、送信元ごとの同時フロー数の
// 上限、ルール全体の新規フローレートとパケットレートをまとめた、backend に依存しないデータである。
// kernel の nftables コンパイラと userspace の Go 評価器(どちらも Phase 5、設計文書 7a.8 節)は、
// この 1 つの IR から作る。このパッケージ自身はコンパイラも評価器も持たない、データと評価順だけの
// 表現である。
//
// このパッケージは純粋で、proto(外部契約)、internal/model、internal/flowcap(OS を知らない
// カウンタと上限の計算だけを持つ)だけを import する。dataplane、frontend、platform、vpsd、agent
// のどの package も import しない(設計文書 7a.7 節)。
package policy

import (
	"fmt"
	"net/netip"

	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/proto"
)

// Step は入口の判定 1 つを表す。評価順は設計文書 6.1 節(deny、allow、接続元ごとの meter、
// 接続元ごとの同時フロー数の上限、新規フローの集約上限、パケットの集約上限)のとおりで、
// 7a.2 節はこれを IR の一部として 1 か所にだけ書くことを求める。kernel の nftables コンパイラと
// userspace の Go 評価器(どちらも Phase 5)は、どちらもこの Order の順で判定を並べる。
type Step int

const (
	StepSourceDeny Step = iota
	StepSourceAllow
	StepPerSourceRate
	StepPerSourceConcurrentFlows
	StepAggregateNewFlowRate
	StepAggregatePacketRate
)

func (s Step) String() string {
	switch s {
	case StepSourceDeny:
		return "source_deny"
	case StepSourceAllow:
		return "source_allow"
	case StepPerSourceRate:
		return "per_source_rate"
	case StepPerSourceConcurrentFlows:
		return "per_source_concurrent_flows"
	case StepAggregateNewFlowRate:
		return "aggregate_new_flow_rate"
	case StepAggregatePacketRate:
		return "aggregate_packet_rate"
	default:
		return fmt.Sprintf("Step(%d)", int(s))
	}
}

// Order is the fixed evaluation order (design.md 6.1, 7a.2 節). It is recorded once, here; both
// future compilers (Phase 5) apply it in this order instead of each hard-coding their own copy.
var Order = []Step{
	StepSourceDeny,
	StepSourceAllow,
	StepPerSourceRate,
	StepPerSourceConcurrentFlows,
	StepAggregateNewFlowRate,
	StepAggregatePacketRate,
}

// PerSourceFlowCaps is the admission-policy input that comes from server configuration rather than
// from rules: the per-source concurrent flow cap (WGFT_MAX_*_FLOWS_PER_SOURCE), one value per
// protocol because flows_udp/flows_tcp (design.md 6.1 節) are each one set shared by every rule of
// that protocol, not a per-rule value. design.md 7a.5 節 places this cap in AdmissionPolicy, not
// Resource Guard, because it is a policy for how one source may use the published services, not a
// protection of wgft's own resources.
//
// UDP and TCP are already-resolved effective values (0 disables the cap for that protocol). Build
// takes a flowcap.Limits and resolves these through Limits.UDPPerSourceCap()/TCPPerSourceCap()
// instead of taking raw ints here, precisely so that a zero-value input means "use the default"
// (256/128) rather than "no cap": internal/flowcap fixed exactly this zero-value footgun for
// Limits itself, and duplicating a second, independently-zero-value-sensitive type in this package
// would reintroduce it. Importing internal/flowcap does not violate design.md 7a.7 節's "no OS,
// nftables, or gVisor" rule for this package; flowcap is pure Go (counters and derived limits).
type PerSourceFlowCaps struct {
	UDP int
	TCP int
}

// RulePolicy is the admission policy declared by one rule (design.md 6.1, 7a.2 節): source
// allow/deny and the three rate limits. The per-source concurrent flow cap is not repeated here
// because every rule of a protocol shares the same counter (Policy.PerSourceFlowCaps), it is not a
// per-rule value.
type RulePolicy struct {
	RuleID        string
	Proto         proto.Proto
	SourceAllow   []netip.Prefix
	SourceDeny    []netip.Prefix
	PerSourceRate *proto.Rate
	NewFlowRate   *proto.Rate
	PacketRate    *proto.Rate
}

// Policy is the AdmissionPolicy IR for one rule set: one RulePolicy per rule that declares
// admission-relevant fields, plus the settings-derived per-source concurrent flow caps.
type Policy struct {
	Rules             []RulePolicy
	PerSourceFlowCaps PerSourceFlowCaps
}

// Build derives the AdmissionPolicy IR from a normalized rule set and the per-source concurrent
// flow cap settings (design.md 7a.2 節). Only enabled rules participate, matching the rule-level
// condition every current implementation applies (internal/vpsd/nft.emit,
// internal/vpsd/srcpolicy.Policy.Update).
//
// limits is resolved through flowcap.Limits.UDPPerSourceCap()/TCPPerSourceCap(), so a zero-value
// flowcap.Limits{} yields the default caps (256/128), and flowcap.PerSourceOff explicitly disables
// one protocol's cap, exactly like every other consumer of flowcap.Limits (see PerSourceFlowCaps's
// doc comment). Only the two per-source fields of limits matter here; its process-wide totals
// belong to Resource Guard (design.md 7a.5 節), not AdmissionPolicy.
//
// design.md 7a.4 節 further restricts the kernel ingress layer to ports wgft has actually bound or
// DNATed ("wgft が実際に待ち受けを開けている、または DNAT を持つポートだけ"), which is a Runtime
// property (whether an agent is known, whether a listener bound). Phase 1 has no Runtime, so Build
// applies only the rule-level condition; joining rules to actually-owned ports is
// internal/planner's job (and, from Phase 4 onward, Prepare/Commit's).
func Build(rules []model.Rule, limits flowcap.Limits) Policy {
	p := Policy{PerSourceFlowCaps: PerSourceFlowCaps{UDP: limits.UDPPerSourceCap(), TCP: limits.TCPPerSourceCap()}}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		p.Rules = append(p.Rules, RulePolicy{
			RuleID: r.ID, Proto: r.Proto,
			SourceAllow: r.SourceAllow, SourceDeny: r.SourceDeny,
			PerSourceRate: r.PerSourceRate, NewFlowRate: r.NewFlowRate, PacketRate: r.PacketRate,
		})
	}
	return p
}
