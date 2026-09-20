package admin

import "github.com/rahanahu/wgft/proto"

// このファイルは、Resource Guard の予算と拒否数(設計文書 7a.10 節「拒否の報告」)を管理用 API v1 に
// 加算的に載せる型を持つ。既存のフィールドの意味は変えない(7a.6 節)。

// FlowBudget is Resource Guard's process-wide flow budget for one protocol (design.md 7a.10 節
// 「共有プールと隔離予約」).
type FlowBudget struct {
	// InUse is u, the number of flows the process currently holds for this protocol, across every
	// rule.
	InUse int `json:"in_use"`
	// Limit is T, the configured process-wide budget (WGFT_MAX_UDP_FLOWS / WGFT_MAX_TCP_FLOWS).
	Limit int `json:"limit"`
}

// ResourceStatus is Resource Guard's report (design.md 7a.10 節「拒否の報告」): the process-wide
// flow budget by protocol, and the admission refusals accumulated since the process started, by
// rule ID and reason. Reasons are "budget", "rule_cap" and "reserve" (internal/resource.Reason); a
// rule or reason that never triggered a refusal is simply absent from the map, not present with a
// zero count, matching internal/resource.Pool.Refusals. Not persisted across restarts.
type ResourceStatus struct {
	// FlowBudget is keyed by protocol ("udp", "tcp"). Kernel mode server has no entry for "udp":
	// kernel mode counts UDP through nftables/conntrack, not through a resource.Pool.
	FlowBudget map[proto.Proto]FlowBudget
	// Refusals is keyed by rule ID, then by reason. A rule of a protocol/forwarding combination that
	// Go never judges (a Transparent rule in kernel mode) never appears here, since no resource.Pool
	// ever sees it (design.md 7a.10 節「kernel 側の保護」).
	Refusals map[string]map[string]uint64
}

// ResourceStatusBackend is implemented by a Backend that can report Resource Guard's status. It is
// a separate interface, like ApplyStatusBackend, so the report stays optional: a Backend without it
// (a fake or demo Backend, e.g.) serves the rules without the added fields.
type ResourceStatusBackend interface {
	ResourceStatus() ResourceStatus
}

// resourceStatus returns the Backend's report, if it has one.
func (s *Server) resourceStatus() (ResourceStatus, bool) {
	b, ok := s.backend.(ResourceStatusBackend)
	if !ok {
		return ResourceStatus{}, false
	}
	return b.ResourceStatus(), true
}

// withResourceStatus adds flow_budget and resource_refusals to a rules response, when the Backend
// reports them (design.md 7a.10 節; additive to API v1).
func (s *Server) withResourceStatus(resp *BatchResponse) {
	st, ok := s.resourceStatus()
	if !ok {
		return
	}
	resp.FlowBudget = st.FlowBudget
	resp.ResourceRefusals = st.Refusals
}
