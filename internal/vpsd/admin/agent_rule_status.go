package admin

// このファイルは、ルールごとの agent 側の状態(設計文書 5.2、7a.11 節)を管理用 API v1 に
// 加算的に載せる型を持つ。既存のフィールドの意味は変えない(7a.6 節)。
//
// rule_states(apply.go)は server がそのルールをデータプレーンへ公開できたかどうかを、
// resource_refusals(resource_status.go)は Resource Guard がそのルールの新しいフローを
// 拒んだ回数を、それぞれ持つ。どちらも agent 側の理由(WGFT_AGENT_ALLOW_TARGETS による宛先拒否、
// リスナーの開放失敗、TCP の target への接続確認の失敗)を持たず、これまで `agent ls` の RULES 列
// (id:reason の形)と Web UI にしか出ていなかった(v0.5.0・v0.5.1 の Known issues)。
// AgentRuleStates はこれを rule_id をキーに引けるようにする。

// AgentRuleStatus is one rule's agent-side status (design.md 5.2, 7a.11 節), sourced from the
// proto.RuleStatus entries the rule's agent sends in its heartbeat. It complements RuleStates (the
// server's own apply state, apply.go) and ResourceRefusals (Resource Guard, resource_status.go) with
// what only `agent ls` and the Web UI showed until now.
type AgentRuleStatus struct {
	// Agent is the name of the rule's agent (proto.Rule.Agent), the one that reported this status.
	Agent string `json:"agent"`
	// State is "ok" or "error" (proto.StatusOK/StatusError); an open set, like every other state
	// field in this API (7a.11 節).
	State string `json:"state"`
	// Reason explains an error state: the agent's own refusal of the target
	// (WGFT_AGENT_ALLOW_TARGETS), a listener bind failure, or a failed TCP connectivity check.
	Reason string `json:"reason,omitempty"`
	// At is the reporting agent's last heartbeat (RFC3339), matching AgentInfo.LastHeartbeat.
	At string `json:"at,omitempty"`
	// Connected is whether the reporting agent's stream is connected right now. When false,
	// State/Reason/At are that agent's last report before the stream dropped, not a current value
	// (design.md 5.2 節); a consumer must not draw them as current.
	Connected bool `json:"connected"`
}

// AgentRuleStatusBackend is implemented by a Backend that can report every rule's agent-side status.
// It is a separate interface, like ApplyStatusBackend and ResourceStatusBackend, so the report stays
// optional: a Backend without it (a fake or demo Backend, e.g.) serves the rules without the added
// field.
type AgentRuleStatusBackend interface {
	// AgentRuleStatuses returns the status of every rule its agent has reported at least once, by
	// rule ID. A rule its agent never reported (the agent never connected, or has not processed that
	// rule yet) is simply absent, not present with a zero value, matching ResourceStatus.Refusals.
	AgentRuleStatuses() (map[string]AgentRuleStatus, error)
}

// withAgentRuleStatus adds agent_rule_states to a rules response, when the Backend reports it
// (design.md 5.2, 7a.11 節; additive to API v1). It returns the Backend's error, if any: the
// underlying read (the registered-agent list) is the same one GET /api/v1/agents fails the whole
// response over, so a failure here fails this response too rather than silently omitting a status
// report an operator would otherwise read as "all clear" (design.md 10.5 節、フェイルクローズ).
func (s *Server) withAgentRuleStatus(resp *BatchResponse) error {
	b, ok := s.backend.(AgentRuleStatusBackend)
	if !ok {
		return nil
	}
	st, err := b.AgentRuleStatuses()
	if err != nil {
		return err
	}
	resp.AgentRuleStates = st
	return nil
}
