// Package adminapi holds the read model of the admin API (design.md 7a.11 節): the shapes
// `GET /api/v1/rules`, `GET /api/v1/agents` and `POST /api/v1/rules/{id}/check` answer with.
//
// internal/vpsd/admin owns this API and serves it; it re-exports every type here under its own
// name, so `admin.AgentInfo` and the rest keep working unchanged. The declarations live in this
// separate package for one reason: the diagnosis (internal/vpsd/doctor, design.md 10.2a、10.2d 節)
// reads exactly these values as its evidence and is imported BY internal/vpsd/admin, so it cannot
// import internal/vpsd/admin back (design.md 10.2d 節「診断のロジックの置き場所」). A package that
// both can import keeps one declaration of each type, and with it one set of JSON tags, instead of
// a second copy that the diagnosis would have to be converted into.
//
// Nothing here talks to a Backend or to the kernel: these are plain wire shapes over proto's
// types. The functions that build them stay in internal/vpsd/admin (withApply,
// withResourceStatus, withAgentRuleStatus, TunnelStatusView).
package adminapi

import "github.com/rahanahu/wgft/proto"

// ConnCheck は疎通確認の結果。Reach は "target" / "agent" / "none"。
type ConnCheck struct {
	OK     bool   `json:"ok"`
	Reach  string `json:"reach"`
	Detail string `json:"detail"`
}

// Warning は窃取検知の警告 1 件。
type Warning struct {
	Agent  string `json:"agent"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	At     string `json:"at"`
}

// AgentInfo はエージェント一覧の 1 行(仕様 10.1 節)。
type AgentInfo struct {
	Name           string `json:"name"`
	Address        string `json:"address"`
	PublicKey      string `json:"public_key,omitempty"`
	RegisteredFrom string `json:"registered_from"`
	CreatedAt      string `json:"created_at"`
	// Disabled はエージェントが無効か(設計文書 5.1、7a.11 節)。常に持つ。旧い版の server は返さない
	// ので、読み手は不在を false と読む。旧い版の server は無効化を持たないので、その読みは正しい
	Disabled bool `json:"disabled"`
	// DisabledAt は無効にした時刻(RFC3339)。有効なエージェントでは省く
	DisabledAt string `json:"disabled_at,omitempty"`
	// stream
	Connected     bool   `json:"connected"`
	StreamFrom    string `json:"stream_from,omitempty"`
	LastHeartbeat string `json:"last_heartbeat,omitempty"`
	Generation    uint64 `json:"generation"` // 処理済み世代
	// GenerationBehindSince は、このエージェントが server の今のルール集合の世代に追いついて
	// いない状態の始まり(RFC3339)。遅れていなければ省く。server がメモリに持つ値で、再起動の
	// 後は、起動の後に初めて遅れを観測した時刻から数え直す(設計文書 10.2a 節)。v1 への加算
	GenerationBehindSince string             `json:"generation_behind_since,omitempty"`
	Tunnel                TunnelStatus       `json:"tunnel"` // wire の proto.TunnelStatus とは別の見せ方(7a.11 節)
	Rules                 []proto.RuleStatus `json:"rules,omitempty"`
	// 版の交渉(仕様 7a.6 節)。未接続、または接続が legacy v0 なら ProtocolVersion は 0 で、
	// AgentProtocolLegacy が true な場合だけ「legacy v0 と判定した」ことを示す(未接続との違いは
	// Connected を見る)
	ProtocolVersion     int  `json:"protocol_version,omitempty"`
	AgentProtocolLegacy bool `json:"agent_protocol_legacy,omitempty"`
	AgentProtocolMin    int  `json:"agent_protocol_min,omitempty"`
	AgentProtocolMax    int  `json:"agent_protocol_max,omitempty"`
	// wg
	WGEndpoint    string `json:"wg_endpoint,omitempty"`
	LastHandshake string `json:"last_handshake,omitempty"`
	// 窃取検知
	Warnings []Warning `json:"warnings,omitempty"`
}

// TunnelStatus is the tunnel status as `agent ls`/the admin API show it (design.md 5.2、7a.11 節):
// the wire's proto.TunnelStatus, with LastHandshake formatted like every sibling timestamp in this
// API (RFC3339, omitted when never observed) instead of a bare time.Time. The conversion itself is
// admin.TunnelStatusView, which is where the reasoning for the separate type lives.
type TunnelStatus struct {
	State         string `json:"state"` // ok | error; an open set (7a.11 節)
	Reason        string `json:"reason,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"` // 解決したエンドポイント(ip:port)
	LastHandshake string `json:"last_handshake,omitempty"`
}

// BatchResponse はバッチの結果。
type BatchResponse struct {
	Generation uint64            `json:"generation"`
	Changed    bool              `json:"changed"`
	Rules      []proto.Rule      `json:"rules"`
	Drops      map[string]uint64 `json:"drops,omitempty"` // rule_id → 累積 drop パケット数
	// 以下は server のデータプレーンへの適用状態(設計文書 7a.3 節)。v1 への加算で、報告を持たない
	// Backend では省く。DesiredGeneration は最後に適用を試みた宣言の世代、ActiveGeneration は
	// 最後に成功した適用の世代(backend 全体の失敗では進まない)。
	DesiredGeneration *uint64              `json:"desired_generation,omitempty"`
	ActiveGeneration  *uint64              `json:"active_generation,omitempty"`
	RuleStates        map[string]RuleApply `json:"rule_states,omitempty"` // rule_id → 適用状態
	Drift             *Drift               `json:"drift,omitempty"`
	ApplyError        string               `json:"apply_error,omitempty"` // 最後の適用の backend 全体の失敗か、公開の後の修復の失敗
	// FlowBudget と ResourceRefusals は Resource Guard の状態(設計文書 7a.10 節「拒否の報告」)。
	// v1 への加算で、報告を持たない Backend では省く(admin の withResourceStatus)。
	FlowBudget       map[proto.Proto]FlowBudget   `json:"flow_budget,omitempty"`
	ResourceRefusals map[string]map[string]uint64 `json:"resource_refusals,omitempty"`
	// AgentRuleStates is each rule's agent-side status (design.md 5.2、7a.11 節). v1 への加算で、
	// 報告を持たない Backend では省く(admin の withAgentRuleStatus)。
	AgentRuleStates map[string]AgentRuleStatus `json:"agent_rule_states,omitempty"`
	// UDPReplies is what this server has seen of each UDP rule's replies (design.md 10.2a 節「UDP の
	// 応答の観測」、7a.11 節). v1 への加算で、報告を持たない Backend では省く(admin の
	// withUDPReplies)。キーは、server が今公開している有効な UDP のルールの ID だけである。
	UDPReplies map[string]UDPReply `json:"udp_replies,omitempty"`
}

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
	// nil (the key absent on the wire) when it never was. Generation 0 is a real, reachable value
	// (design.md 9 節: the generation is 0 while there are no rules at all), so it cannot double as
	// "never published"; this follows the same *uint64 convention as the sibling
	// BatchResponse.DesiredGeneration/ActiveGeneration (design.md 7a.11 節).
	ActiveGeneration *uint64 `json:"active_generation,omitempty"`
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

// FlowBudget is Resource Guard's process-wide flow budget for one protocol (design.md 7a.10 節
// 「共有プールと隔離予約」).
type FlowBudget struct {
	// InUse is u, the number of flows the process currently holds for this protocol, across every
	// rule.
	InUse int `json:"in_use"`
	// Limit is T, the configured process-wide budget (WGFT_MAX_UDP_FLOWS / WGFT_MAX_TCP_FLOWS).
	Limit int `json:"limit"`
}

// AgentRuleStatus is one rule's agent-side status (design.md 5.2, 7a.11 節), sourced from the
// proto.RuleStatus entries the rule's own agent (proto.Rule.Agent) sends in its heartbeat. It
// complements RuleApply (the server's own apply state) and BatchResponse.ResourceRefusals
// (Resource Guard) with what only `agent ls` and the Web UI showed until it was added.
//
// Every current rule gets an entry (2026-09-21, owner's decision): a rule id absent from
// agent_rule_states as a whole means the Backend does not implement admin.AgentRuleStatusBackend at
// all, not "this particular rule was never reported" - if entries were only added once a report
// arrived, the two would be indistinguishable from the JSON alone. State/Reason/At are therefore
// omitted (via omitempty), not defaulted to a fabricated value, when the agent has not reported this
// rule yet: State only ever holds the agent's own vocabulary ("ok"/"error"), so a server-invented
// value such as "unknown" or "pending" in the same field would blur who said what, and an absent key
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

// UDPReply is what the server itself has seen of one UDP rule's replies: the datagrams the rule's
// target sent back through the tunnel to this server (design.md 10.2a 節「UDP の応答の観測」). It is
// kept in memory only, so a restarted server starts watching over. It is an observation, not a
// verdict: no reply seen is not a failure, since an idle rule and a silent service look the same.
type UDPReply struct {
	// Since is when the server began watching this rule without a gap (RFC3339): its start, the
	// publication after the rule's ID, agent, target or ports changed, or the first reading after
	// the watch was interrupted. Omitted when NotObserved is set.
	Since string `json:"since,omitempty"`
	// LastReplyAt is the last reply seen since Since (RFC3339). Omitted when none was seen. In
	// kernel mode it is the time of the counter reading that saw the reply, up to about 10 seconds
	// after it.
	LastReplyAt string `json:"last_reply_at,omitempty"`
	// NotObserved is set, with the reason, when the server cannot observe the rule's replies now
	// (it could not read its reply counters, for example). It is not "no reply".
	NotObserved string `json:"not_observed,omitempty"`
}
