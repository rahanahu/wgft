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
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
	"sort"
	"time"

	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/proto"
)

// 評価の定数(設計文書 7a.9 節「IR の形」)。トークンバケットの burst、接続元ごとの表の期限と
// 大きさ、同時フロー数の set の大きさは、どの実装でも変えない仕様値なので、この 1 か所だけに書く。
// 以前は internal/dataplane/linuxkernel/nft と internal/dataplane/userspace/srcpolicy(Phase 5 の
// 移行の手順 5 で削除)がそれぞれ同じ値を書いていたので、両方をこの定数を使う形に直した
// (Phase 5 移行の手順 1)。
const (
	// TokenBucketBurst is nftables' `limit rate over` burst (nft の既定値)。userspace の
	// トークンバケットは、ラボでカーネルモードと通過数・drop 数の累計が一致することを確かめた
	// 固定 burst 5 で、この値を模している(design.md 7a.4 節「トークンバケットの粒度」)。
	TokenBucketBurst = 5

	// PerSourceTableTTL is how long an idle entry stays in a per-source rate-limit table: the
	// nftables meter's timeout, and the Go evaluator's per-source table (design.md 6.1, 7a.4 節)。
	PerSourceTableTTL = time.Minute

	// PerSourceTableSize is the maximum number of distinct sources a per-source rate-limit table
	// holds at once: the nftables meter's set size, and the Go evaluator's per-source table cap
	// (design.md 6.1, 7a.4 節)。
	PerSourceTableSize = 65535

	// FlowSetSize is the size of the set that counts per-source concurrent flows: nftables'
	// flows_tcp/flows_udp, and the Go evaluator's equivalent (design.md 6.1 節)。
	FlowSetSize = 65535
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

// DropKind is the drop-counter kind persisted for this step's rejections (design.md 7a.9 節「段と
// drop の種類の対応」): the exact strings nft and goengine write to their drop counters,
// which vpsd accumulates into SQLite (7 節 "各 drop のカウンタは...SQLite に累積する")。This
// method only names the mapping in one place; it does not change any of the strings themselves.
func (s Step) DropKind() string {
	switch s {
	case StepSourceDeny:
		return "deny"
	case StepSourceAllow:
		return "allow"
	case StepPerSourceRate:
		return "per_source"
	case StepPerSourceConcurrentFlows:
		return "src_flow"
	case StepAggregateNewFlowRate:
		return "new_flow"
	case StepAggregatePacketRate:
		return "packet"
	default:
		return ""
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

// ForProto returns the cap for p (UDP or TCP). Callers that need "the per-source cap for this
// rule's protocol" (e.g. a compiler, or a test deriving the src_flow set from a Policy) should use
// this instead of switching on proto.Proto themselves.
func (c PerSourceFlowCaps) ForProto(p proto.Proto) int {
	if p == proto.TCP {
		return c.TCP
	}
	return c.UDP
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
// condition internal/dataplane/linuxkernel/nft.emit applies to the ports it draws from this Policy
// (via Plan.Admission); internal/policy/goengine.Engine.Update takes this Policy directly.
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
//
// Build is deterministic: Policy.Rules is always sorted by RuleID, regardless of the input rules'
// order, so a Policy embedded in a larger deterministic structure (internal/planner.Plan.Admission)
// does not reintroduce input-order dependence.
func Build(rules []model.Rule, limits flowcap.Limits) Policy {
	p := Policy{PerSourceFlowCaps: PerSourceFlowCaps{UDP: limits.UDPPerSourceCap(), TCP: limits.TCPPerSourceCap()}}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		p.Rules = append(p.Rules, RulePolicy{
			RuleID: r.ID, Proto: r.Proto,
			SourceAllow: NormalizePrefixes(r.SourceAllow), SourceDeny: NormalizePrefixes(r.SourceDeny),
			PerSourceRate: r.PerSourceRate, NewFlowRate: r.NewFlowRate, PacketRate: r.PacketRate,
		})
	}
	sort.Slice(p.Rules, func(i, j int) bool { return p.Rules[i].RuleID < p.Rules[j].RuleID })
	return p
}

// NormalizePrefixes masks each prefix, merges overlapping and adjacent ranges, and returns the
// result sorted ascending by address (design.md 7a.9 節「CIDR の正規化」). Build calls this for
// source_allow and source_deny so the IR itself carries the normalized form; previously only the
// nftables set construction merged (intervalElements in internal/dataplane/linuxkernel/nft), while
// the Go evaluator walked the un-merged list. Merging never changes which sources match (it only
// removes redundant/adjacent boundaries), so this is behavior-preserving for both compilers: the
// nftables compiler's own interval merge is idempotent on an already-normalized input, and
// SourceAllowed/matchesAny-style scans give the same verdict either way.
//
// v1 is IPv4-only (design.md 4, 7a.9 節). proto.Rule's validation rejects non-IPv4 source_allow/
// source_deny entries, so only IPv4 prefixes are expected here; any other prefix is kept, masked but
// not merged, after the IPv4 ones instead of being dropped or crashing the merge.
func NormalizePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	type span struct{ lo, hi uint64 } // hi は排他的(nft/build.go の intervalElements と同じ形)
	spans := make([]span, 0, len(prefixes))
	var other []netip.Prefix // IPv4 でないもの。検証で弾かれるはずだが、来ても panic せず併合せずに残す
	for _, p := range prefixes {
		p = p.Masked()
		if !p.Addr().Is4() {
			other = append(other, p)
			continue
		}
		lo := uint64(binary.BigEndian.Uint32(p.Addr().AsSlice()))
		spans = append(spans, span{lo, lo + 1<<(32-p.Bits())})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })
	merged := spans[:0]
	for _, s := range spans {
		if n := len(merged); n > 0 && s.lo <= merged[n-1].hi {
			if s.hi > merged[n-1].hi {
				merged[n-1].hi = s.hi
			}
			continue
		}
		merged = append(merged, s)
	}

	var out []netip.Prefix
	for _, s := range merged {
		out = append(out, spanToPrefixes(s.lo, s.hi)...)
	}
	return append(out, other...)
}

// spanToPrefixes decomposes the IPv4 address range [lo, hi) into the minimal list of CIDR blocks
// that cover exactly that range (the standard range-to-CIDR algorithm): repeatedly take, at the
// current lo, the largest power-of-two block that both starts at lo (its trailing zero bits) and
// fits within what remains of the range.
func spanToPrefixes(lo, hi uint64) []netip.Prefix {
	var out []netip.Prefix
	for lo < hi {
		block := bits.TrailingZeros64(lo)
		if block > 32 {
			block = 32 // lo == 0 の場合、TrailingZeros64 は 64 を返す
		}
		for block > 0 && uint64(1)<<uint(block) > hi-lo {
			block--
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(lo))
		out = append(out, netip.PrefixFrom(netip.AddrFrom4(b), 32-block))
		lo += uint64(1) << uint(block)
	}
	return out
}

// SourceAllowed reports whether src passes the rule's source deny and allow lists (deny first; an
// empty allow list admits every source). Rate limits are left out: they only concern new flows,
// while this answers whether an established flow is still admitted, for example when a
// fail-closed rule decides which of its established flows to keep (design.md 7a.3 節).
func (r RulePolicy) SourceAllowed(src netip.Addr) bool {
	for _, p := range r.SourceDeny {
		if p.Contains(src) {
			return false
		}
	}
	if len(r.SourceAllow) == 0 {
		return true
	}
	for _, p := range r.SourceAllow {
		if p.Contains(src) {
			return true
		}
	}
	return false
}
