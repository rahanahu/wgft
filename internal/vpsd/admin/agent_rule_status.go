package admin

import (
	"github.com/rahanahu/wgft/internal/vpsd/adminapi"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、ルールごとの agent 側の状態(設計文書 5.2、7a.11 節)を管理用 API v1 に
// 加算的に載せる型を持つ。既存のフィールドの意味は変えない(7a.6 節)。
//
// rule_states(apply.go)は server がそのルールをデータプレーンへ公開できたかどうかを、
// resource_refusals(resource_status.go)は Resource Guard がそのルールの新しいフローを
// 拒んだ回数を、それぞれ持つ。どちらも agent 側の理由(WGFT_AGENT_ALLOW_TARGETS による宛先拒否、
// リスナーの開放失敗、TCP の target への接続確認の失敗)を持たず、これまで `agent ls` の RULES 列
// (id:reason の形)と Web UI にしか出ていなかった(v0.5.0・v0.5.1 の Known issues)。
// AgentRuleStates はこれを rule_id をキーに引けるようにする。

// AgentRuleStatus is one rule's agent-side status (design.md 5.2, 7a.11 節). 宣言は
// internal/vpsd/adminapi にあり、その型の説明もそこにある。ここは別名である
// (design.md 10.2d 節。admin.go の別名と同じ理由である)。
type AgentRuleStatus = adminapi.AgentRuleStatus

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

// UDPReply is what the server has seen of one UDP rule's replies (design.md 10.2a 節「UDP の応答の
// 観測」、7a.11 節). 宣言は internal/vpsd/adminapi にある。
type UDPReply = adminapi.UDPReply

// UDPReplyBackend is implemented by a Backend that observes its UDP rules' replies. It is optional
// like AgentRuleStatusBackend: a Backend without it (fakeBackend, tools/uidemo) serves the rules
// without udp_replies.
type UDPReplyBackend interface {
	// UDPReplies returns an entry for each of rules that is an enabled UDP rule the server
	// publishes now, by rule ID. ok is false when the server does not observe replies at all.
	UDPReplies(rules []proto.Rule) (replies map[string]UDPReply, ok bool)
}

// IPForwardStatus is net.ipv4.ip_forward as the server read it (design.md 6.1、10.2a 節). 宣言は
// internal/vpsd/adminapi にある。
type IPForwardStatus = adminapi.IPForwardStatus

// IPForwardBackend is implemented by a Backend that forwards through the kernel and so depends on
// net.ipv4.ip_forward (design.md 6.1、10.2a 節). It is optional like UDPReplyBackend: a Backend without
// it, and a userspace-mode server, serve the rules without ip_forward.
type IPForwardBackend interface {
	// IPForward reads the sysctl now. ok is false when this server does not forward through the
	// kernel, so the value would say nothing about its rules.
	IPForward() (status IPForwardStatus, ok bool)
}

// withIPForward adds ip_forward to a rules response, when the Backend reports it (design.md 10.2a、
// 7a.11 節; additive to API v1).
func (s *Server) withIPForward(resp *BatchResponse) {
	b, ok := s.backend.(IPForwardBackend)
	if !ok {
		return
	}
	if st, ok := b.IPForward(); ok {
		resp.IPForward = &st
	}
}

// withUDPReplies adds udp_replies to a rules response, when the Backend observes them (design.md
// 10.2a、7a.11 節; additive to API v1).
func (s *Server) withUDPReplies(resp *BatchResponse) {
	b, ok := s.backend.(UDPReplyBackend)
	if !ok {
		return
	}
	if replies, ok := b.UDPReplies(resp.Rules); ok {
		resp.UDPReplies = replies
	}
}
