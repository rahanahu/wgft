package admin

import "github.com/rahanahu/wgft/proto"

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
// proto.RuleStatus entries the rule's own agent (proto.Rule.Agent) sends in its heartbeat. It
// complements RuleStates (the server's own apply state, apply.go) and ResourceRefusals (Resource
// Guard, resource_status.go) with what only `agent ls` and the Web UI showed until now.
//
// Every current rule gets an entry (2026-09-21, owner's decision): a rule id absent from
// agent_rule_states as a whole means the Backend does not implement AgentRuleStatusBackend at all,
// not "this particular rule was never reported" - if entries were only added once a report arrived,
// the two would be indistinguishable from the JSON alone. State/Reason/At are therefore omitted
// (via omitempty), not defaulted to a fabricated value, when the agent has not reported this rule
// yet: State only ever holds the agent's own vocabulary ("ok"/"error"), so a server-invented value
// such as "unknown" or "pending" in the same field would blur who said what, and an absent key
// already means "not observed" throughout this API (design.md 7a.11 節). Agent/Connected are always
// present regardless, since Connected alone already answers "should I expect a report soon" (an
// offline agent will not report; a connected one may not have gotten to this rule yet).
type AgentRuleStatus struct {
	// Agent is the name of the rule's current agent (proto.Rule.Agent). Always present, even when
	// that name is no longer a registered agent (e.g. revoked): the rule still names it, and looking
	// it up simply finds no connection.
	Agent string `json:"agent"`
	// State is "ok" or "error" (proto.StatusOK/StatusError); an open set, like every other state
	// field in this API (7a.11 節). Omitted when the agent has not reported this rule yet, whether or
	// not it is connected: read State's absence together with Connected (below).
	State string `json:"state,omitempty"`
	// Reason explains an error state: the agent's own refusal of the target
	// (WGFT_AGENT_ALLOW_TARGETS), a listener bind failure, or a failed TCP connectivity check.
	Reason string `json:"reason,omitempty"`
	// At is the reporting agent's last heartbeat (RFC3339), matching AgentInfo.LastHeartbeat. Omitted
	// along with State when nothing was reported.
	At string `json:"at,omitempty"`
	// Connected is whether the rule's current agent's stream is connected right now, always present.
	// The three readings (design.md 5.2, 7a.11 節):
	//   - State present, Connected true: a live report from the agent that owns this rule now.
	//   - State present, Connected false: that agent's last report before its stream dropped; history,
	//     not a current value (design.md 5.2 節) - a consumer must not draw it as current.
	//   - State absent: the agent has not reported this rule yet. Connected true means it is online
	//     and may still get to it; Connected false means it is offline (or has never connected at
	//     all, e.g. a revoked agent's name, or one never registered) and nothing will arrive soon.
	Connected bool `json:"connected"`
}

// AgentRuleStatusBackend is implemented by a Backend that can report every rule's agent-side status.
// It is a separate interface, like ApplyStatusBackend and ResourceStatusBackend, so the report stays
// optional: a Backend without it (a fake or demo Backend, e.g.) serves the rules without the added
// field at all - the only way a consumer can tell "this Backend does not report agent status" apart
// from "every rule was reported and fine", now that every current rule gets an entry.
type AgentRuleStatusBackend interface {
	// AgentRuleStatuses returns an entry for every one of rules, by rule ID - never fewer, since an
	// absent id would be indistinguishable from omitting the whole field (see AgentRuleStatus). rules
	// is the rule set already read for this response (getRules/postBatch pass resp.Rules), so this
	// needs no store read of its own.
	//
	// A rule's status comes only from its OWN agent (r.Agent), never from a different agent that
	// happens to also list the same rule ID in a stale cached heartbeat. This matters because a
	// disconnected agent keeps its last heartbeat's content (design.md 5.2 節): if a rule moves from
	// agent A to agent B while A is offline, or is deleted while its agent is offline, A's old
	// heartbeat can still list that rule ID. Looking it up by the rule's current agent, rather than
	// scanning every agent that ever mentioned the ID, is what keeps a moved rule showing B's live
	// status (not A's stale one) and keeps a deleted rule's ID from appearing at all (it is no longer
	// in rules, so it is never looked up).
	AgentRuleStatuses(rules []proto.Rule) map[string]AgentRuleStatus
}

// withAgentRuleStatus adds agent_rule_states to a rules response, when the Backend reports it
// (design.md 5.2, 7a.11 節; additive to API v1). It passes resp.Rules, the rule set already read for
// this response, so the Backend can look each rule's status up by that rule's own current agent
// rather than needing a read of its own.
func (s *Server) withAgentRuleStatus(resp *BatchResponse) {
	b, ok := s.backend.(AgentRuleStatusBackend)
	if !ok {
		return
	}
	resp.AgentRuleStates = b.AgentRuleStatuses(resp.Rules)
}
