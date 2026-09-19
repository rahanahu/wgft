package admin

import "github.com/rahanahu/wgft/proto"

// このファイルは、server 側のデータプレーンへの適用状態(設計文書 7a.3 節の Desired と Active)を
// 管理用 API v1 に加算的に載せる型を持つ。既存のフィールドの意味は変えない(7a.6 節)。

// Apply states of a rule on the server (RuleApply.ApplyState).
const (
	ApplyActive    = "active"
	ApplyPending   = "pending"
	ApplyNotActive = "not_active"
)

// RuleApply is one rule's apply state on the server's data plane (design.md 7a.3 節).
type RuleApply struct {
	// ApplyState is active, pending (the last transaction failed as a whole; what was Active
	// before still forwards) or not_active (see Reason).
	ApplyState string `json:"apply_state"`
	// Reason explains pending and not_active, e.g. "bind failed: ...", "disabled".
	Reason string `json:"reason,omitempty"`
	// ActiveGeneration is the generation at which the rule's forwarding value was last published;
	// 0 when it never was.
	ActiveGeneration uint64 `json:"active_generation"`
}

// DriftResource is one forwarding resource that differs from the declaration.
type DriftResource struct {
	RuleID     string          `json:"rule_id"`
	Proto      proto.Proto     `json:"proto"`
	ListenPort proto.PortRange `json:"listen_port"`
	Forwarding string          `json:"forwarding"` // transparent | relay
}

// Drift lists what is forwarded although the declaration no longer asks for it.
type Drift struct {
	// ActiveOnly is still forwarding although deleted, disabled or of an unregistered agent: its
	// removal was kept from being published by a failed transaction.
	ActiveOnly []DriftResource `json:"active_only"`
	// Retiring is the previous value of rules made fail-closed: it accepts no new flows, and the
	// established flows it still admits are kept until they end.
	Retiring []DriftResource `json:"retiring"`
}

// ApplyStatus is the server's Desired against Active report.
type ApplyStatus struct {
	DesiredGeneration uint64
	ActiveGeneration  uint64
	Rules             map[string]RuleApply
	Drift             Drift
	// LastError is the failure of the last transaction that failed as a whole, or, when it
	// published but a repair after the publication failed, that failure (design.md 7a.3 節: 戻れない
	// 地点の後の修復). Empty once everything succeeded.
	LastError string
}

// ApplyStatusBackend is implemented by a Backend that can report the apply state. It is a
// separate interface so the report stays optional: a Backend without it serves the rules without
// the added fields.
type ApplyStatusBackend interface {
	// ApplyStatus returns the report, and false until the first transaction was attempted.
	ApplyStatus() (ApplyStatus, bool)
}

// applyStatus returns the Backend's report, if it has one.
func (s *Server) applyStatus() (ApplyStatus, bool) {
	b, ok := s.backend.(ApplyStatusBackend)
	if !ok {
		return ApplyStatus{}, false
	}
	return b.ApplyStatus()
}

// withApply adds the apply state to a rules response (design.md 7a.3 節; additive to API v1).
func (s *Server) withApply(resp *BatchResponse) {
	st, ok := s.applyStatus()
	if !ok {
		return
	}
	desired, active := st.DesiredGeneration, st.ActiveGeneration
	resp.DesiredGeneration, resp.ActiveGeneration = &desired, &active
	resp.RuleStates = st.Rules
	drift := st.Drift
	if drift.ActiveOnly == nil {
		drift.ActiveOnly = []DriftResource{}
	}
	if drift.Retiring == nil {
		drift.Retiring = []DriftResource{}
	}
	resp.Drift = &drift
	resp.ApplyError = st.LastError
}
