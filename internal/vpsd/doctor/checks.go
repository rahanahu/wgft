package doctor

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/vpsd/adminapi"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは検査 1 つずつの判定を持つ。経路の順は doctor.go の checkOrder が、検査どうしの
// 優先順位は design.md 10.2a 節が定める。

// publicPortCheck は、server がこのルールの公開ポートを扱えているかを見る。扱えていても、
// 外から届くかどうかは試していないので ok にはしない(設計文書 10.2a 節の状態の定義)。
func publicPortCheck(r proto.Rule, in Input) Check {
	c := Check{ID: CheckPublicPort, RuleID: r.ID, Group: GroupServer, Label: "public port"}
	res := in.Rules
	if res.RuleStates == nil {
		c.Status, c.Reason = StatusUnknown, ReasonNotReportedByServer
		c.Detail = "this server does not report whether it serves this port"
		c.Next = "read the server log for this rule, or upgrade the server to one that reports it"
		return c
	}
	st, ok := res.RuleStates[r.ID]
	if !ok {
		c.Status, c.Reason = StatusUnknown, ReasonNotReported
		c.Detail = "this server reports nothing about this port"
		c.Next = "re-run after the server's next change; if it stays silent, read the server log"
		return c
	}
	c.Internal = append(c.Internal, "apply_state "+st.ApplyState)
	if st.ActiveGeneration != nil {
		c.Internal = append(c.Internal, fmt.Sprintf("published at generation %d", *st.ActiveGeneration))
	}
	c.ObservedAt = in.Now.UTC().Format(time.RFC3339)
	switch st.ApplyState {
	case adminapi.ApplyActive:
		c.Status, c.Reason = StatusNotTested, ReasonExternalNotTested
		c.Detail = fmt.Sprintf("serving %s %s; reachability from outside was not tested", r.Proto, r.ListenPort)
		if d := driftNote(r.ID, res.Drift); d != "" {
			c.Detail += "; " + d
			c.Internal = append(c.Internal, "drift: "+d)
		}
		c.Next = "test it from another host: nc -vz <this vps> " + strings.Split(r.ListenPort.String(), "-")[0]
		return c
	case adminapi.ApplyNotActive:
		c.Status = StatusFailed
		c.Reason = ReasonNotPublished
		if strings.Contains(st.Reason, "bind failed") {
			c.Reason = ReasonBindFailed
		}
		c.Detail = "the server does not handle this port: " + ReasonOr(st.Reason, "no reason reported")
		c.Next = applyNextStep(st.Reason)
		return c
	case adminapi.ApplyPending:
		c.Status, c.Reason = StatusFailed, ReasonNotPublished
		c.Detail = "the server has not yet published this port: " + ReasonOr(firstNonEmpty(st.Reason, res.ApplyError), "the last change failed as a whole")
		c.Next = "free whatever the reason names; the server retries every 30s. Which declaration the kernel is forwarding depends on where the apply failed; check it with wgft server nft."
		return c
	}
	c.Status, c.Reason = StatusUnknown, ReasonUnknownValue
	c.Detail = fmt.Sprintf("the server reports a state this build does not know: %q", st.ApplyState)
	c.Next = "upgrade this CLI to the server's version"
	return c
}

// DataplaneCheck は server 全体の公開の状態を見る(設計文書 7a.3 節)。ルールに属さない唯一の
// 検査であり、どのルールの経路にも入る。
func DataplaneCheck(in Input) Check {
	c := Check{ID: CheckDataplane, Group: GroupServer, Label: "dataplane", ObservedAt: in.Now.UTC().Format(time.RFC3339)}
	res := in.Rules
	if res.DesiredGeneration == nil && res.ApplyError == "" && res.RuleStates == nil {
		c.Status, c.Reason = StatusUnknown, ReasonNotReportedByServer
		c.Detail = "this server does not report its forwarding state"
		c.Next = "read the server log; an older server reports this only there"
		return c
	}
	c.Internal = append(c.Internal, fmt.Sprintf("generation %d", res.Generation))
	if res.DesiredGeneration != nil && res.ActiveGeneration != nil {
		c.Internal = append(c.Internal, fmt.Sprintf("desired %d, active %d", *res.DesiredGeneration, *res.ActiveGeneration))
	}
	if b := FlowBudgetLine(res.FlowBudget); b != "" {
		c.Internal = append(c.Internal, b)
	}
	if gap := GenerationGap(res); gap != "" {
		c.Status, c.Reason = StatusFailed, ReasonNotPublished
		c.Detail = "the last change has not reached the forwarding path: " + gap
		if res.ApplyError != "" {
			c.Detail += "; apply error: " + res.ApplyError
		}
		c.Next = "free whatever the reason names; the server retries every 30s and publishes the change when it succeeds"
		return c
	}
	if res.ApplyError != "" {
		c.Status, c.Reason = StatusUnknown, ReasonRepairFailed
		c.Detail = "the rules are published, but a repair after that failed: " + res.ApplyError
		c.Next = "new traffic follows the current rules; connections that should have been cut may still run. The server retries every 30s."
		return c
	}
	c.Status = StatusOK
	c.Detail = fmt.Sprintf("the server's forwarding matches the current rules, generation %d, read just now", res.Generation)
	return c
}

// GenerationGap は desired と active の世代の食い違いを 1 文で返す。差が無ければ空文字を返す。
// `wgft status`(design.md 10.2b 節)の server の行も、同じ食い違いを同じ文で出すために呼ぶ。
func GenerationGap(res *adminapi.BatchResponse) string {
	if res.DesiredGeneration == nil || res.ActiveGeneration == nil || *res.ActiveGeneration >= *res.DesiredGeneration {
		return ""
	}
	return fmt.Sprintf("it forwards generation %d while the rules are at %d", *res.ActiveGeneration, *res.DesiredGeneration)
}

// driftNote は、このルールが宣言に無いまま転送に残っているかどうかを 1 文で返す。
func driftNote(id string, d *adminapi.Drift) string {
	if d == nil {
		return ""
	}
	for _, x := range d.ActiveOnly {
		if x.RuleID == id {
			return "it is also still forwarding although the rules no longer ask for it"
		}
	}
	for _, x := range d.Retiring {
		if x.RuleID == id {
			return "its previous value is retiring: it takes no new connections and keeps open ones until they end"
		}
	}
	return ""
}

// applyNextStep は、server が公開できない理由に応じた次の手である。bind の失敗はユーザー空間
// モードでエフェメラルポートと衝突する形が多いので、その可能性を名指しする(docs/setup.md)。
func applyNextStep(reason string) string {
	switch {
	case strings.Contains(reason, "bind failed"):
		return "another process on this VPS holds that port. In userspace mode the server binds every listen port, and a port inside " +
			"net.ipv4.ip_local_port_range, 32768-60999 by default, can be taken by any outbound connection or its TIME_WAIT. Move the " +
			"listen port outside that range, or reserve it with net.ipv4.ip_local_reserved_ports. The server retries every 30s."
	case strings.HasPrefix(reason, "agent ") && strings.HasSuffix(reason, " is disabled"):
		// 無効なエージェントのルールは、Diagnose が agent.enabled の agent_disabled として先に
		// 扱うので、普段はここに来ない。来るのは、ルールの読み取りとエージェントの読み取りの間に
		// エージェントが有効化された場合だけである。エージェントは既に有効なので agent enable は
		// 案内せず、読み直しを勧める。rule enable も何も変えないので、下のルール自身の
		// "disabled" より先に判定する(設計文書 5.1、10.2a 節)。
		return "the agent may have just been enabled while this command read the evidence; run it again"
	case strings.Contains(reason, "disabled"):
		return "enable it: wgft rule enable <rule>"
	case strings.Contains(reason, "not registered") || strings.Contains(reason, "unregistered"):
		return "register an agent under that name: wgft agent join-string --name <agent>"
	}
	return "fix what the reason names; the server retries every 30s on its own"
}

// sourceFilterCheck は、--from で示された接続元がこのルールの拒否・許可リストを通るかを見る
// (設計文書 5.3 節。拒否を先に評価する)。--from が無ければ試さない。
func sourceFilterCheck(r proto.Rule, in Input) Check {
	c := Check{ID: CheckSourceFilter, RuleID: r.ID, Group: GroupServer, Label: "source filter", hideWhenUntested: true}
	c.Internal = append(c.Internal, fmt.Sprintf("%d deny %s, %d allow %s", len(r.SourceDeny), entryNoun(len(r.SourceDeny)), len(r.SourceAllow), entryNoun(len(r.SourceAllow))))
	if !in.HasFrom {
		c.Status, c.Reason = StatusNotTested, ReasonNoFrom
		c.Detail = fmt.Sprintf("not tested: this rule has %d deny %s and %d allow %s, and no client address was given",
			len(r.SourceDeny), entryNoun(len(r.SourceDeny)), len(r.SourceAllow), entryNoun(len(r.SourceAllow)))
		c.Next = "add --from <client address> to see whether one client would be let in"
		return c
	}
	c.ObservedAt = in.Now.UTC().Format(time.RFC3339)
	if !in.From.Is4() {
		c.Status, c.Reason = StatusUnknown, ReasonNotIPv4
		c.Detail = in.From.String() + " is not IPv4; this version forwards IPv4 only and drops other sources before these lists"
		c.Next = "test with the IPv4 address the client actually reaches this VPS from"
		return c
	}
	for _, p := range r.SourceDeny {
		if p.Contains(in.From) {
			c.Status, c.Reason = StatusFailed, ReasonDeniedByDenyList
			c.Detail = "the deny list drops " + in.From.String() + ": it is inside " + p.String()
			c.Next = fmt.Sprintf("if that is wrong: wgft rule deny rm %s %s", ShortID(r.ID), p)
			return c
		}
	}
	if len(r.SourceAllow) > 0 {
		for _, p := range r.SourceAllow {
			if p.Contains(in.From) {
				c.Status = StatusOK
				c.Detail = in.From.String() + " is let in by " + p.String() + ", evaluated just now"
				return c
			}
		}
		c.Status, c.Reason = StatusFailed, ReasonNotInAllowList
		c.Detail = fmt.Sprintf("the allow list holds %d %s and none covers %s, so every other client is dropped", len(r.SourceAllow), entryNoun(len(r.SourceAllow)), in.From)
		c.Next = fmt.Sprintf("if that is wrong: wgft rule allow add %s %s/32", ShortID(r.ID), in.From)
		return c
	}
	c.Status = StatusOK
	c.Detail = in.From.String() + " is let in: no deny entry covers it and the allow list is empty, evaluated just now"
	return c
}

// TunnelHealth is doctor's `tunnel.handshake` judgment (design.md 10.2a 節), factored out of
// handshakeCheck below so `wgft status`(cmd/wgft/status.go の agentHealthOf、design.md 10.2b 節)can share
// the exact same freshness rule (HandshakeStale、3 分)for its Agents row instead of reimplementing
// it. handshakeCheck stays the only caller that turns this into a Check, so this extraction
// changes nothing about doctor's own output; cmd/wgft/doctor_test.go's existing coverage of
// CheckHandshake still exercises this function through handshakeCheck.
func TunnelHealth(ai *adminapi.AgentInfo, now time.Time) (status, reason, detail, observedAt string) {
	hs, ok := ParseWhen(ai.LastHandshake)
	if ok {
		observedAt = ai.LastHandshake
	}
	if !ok || now.Sub(hs) > HandshakeStale {
		detail = "no WireGuard handshake with this agent has ever been observed"
		if ok {
			detail = "handshake " + Since(now, hs).String() + " ago; a live tunnel renews it within 145s"
		}
		return StatusFailed, ReasonNoRecentHandshake, detail, observedAt
	}
	age := "handshake " + Since(now, hs).String() + " ago"
	if !ai.Connected {
		return StatusOK, "", age + "; the agent's own tunnel report is last:" + tunnelStateText(ai.Tunnel) + ", not a current value", observedAt
	}
	if ai.Tunnel.State == proto.StatusError {
		return StatusFailed, ReasonTunnelError,
			"the agent reports its tunnel in error: " + ReasonOr(ai.Tunnel.Reason, "no reason reported") + "; this VPS still saw a " + age,
			observedAt
	}
	if ai.Tunnel.State != "" && ai.Tunnel.State != proto.StatusOK {
		return StatusUnknown, ReasonUnknownValue, age + fmt.Sprintf("; the agent reports a tunnel state this build does not know: %q", ai.Tunnel.State), observedAt
	}
	return StatusOK, "", age, observedAt
}

// handshakeCheck はトンネルを見る。最終ハンドシェイクは server が WireGuard から直接読む今の
// 値なので、stream が切れていても使える。エージェント自身のトンネルの報告はハートビート由来
// なので、切れている間は今の値として扱わない(設計文書 5.2 節)。判定そのものは TunnelHealth に
// 持つ。
func handshakeCheck(r proto.Rule, ai *adminapi.AgentInfo, in Input) Check {
	c := Check{ID: CheckHandshake, RuleID: r.ID, Agent: r.Agent, Group: GroupTunnel, Label: "WireGuard"}
	if ai == nil {
		c.Status, c.Reason = StatusSkipped, ReasonAgentNotRegistered
		c.Detail = "not tested: no agent is registered under that name, so there is no tunnel yet"
		c.Next = "register one: wgft agent join-string --name " + r.Agent
		return c
	}
	if ai.WGEndpoint != "" {
		c.Internal = append(c.Internal, "peer endpoint "+ai.WGEndpoint)
	}
	c.Internal = append(c.Internal, "agent tunnel report is "+tunnelStateText(ai.Tunnel))
	c.Status, c.Reason, c.Detail, c.ObservedAt = TunnelHealth(ai, in.Now)
	switch c.Reason {
	case ReasonNoRecentHandshake:
		c.Causes = handshakeCauses()
		c.Next = handshakeNext()
	case ReasonTunnelError:
		c.Next = "read that reason on the agent host; the agent retries every 30s and rebuilds the tunnel after 300s without a handshake"
	case ReasonUnknownValue:
		c.Next = "upgrade this CLI to the agent's version"
	}
	return c
}

// handshakeCauses は、ハンドシェイクが無いことから切り分けられない原因である。VPS の側からは
// どれか 1 つに決められない(設計文書 10.2a 節)。
func handshakeCauses() []string {
	return []string{
		"this VPS's WireGuard UDP port does not reach the agent's network",
		"the home firewall or the ISP drops the tunnel's UDP",
		"the agent is not running, or holds a different key",
		"something between the two drops it",
	}
}

func handshakeNext() string {
	return "settle it on the agent host: check that the agent runs, that its public key matches `wgft agent ls`, and that UDP to this VPS's WireGuard port leaves the home line"
}

func tunnelStateText(t adminapi.TunnelStatus) string {
	if t.State == "" {
		return "nothing reported"
	}
	if t.Reason == "" {
		return t.State
	}
	return t.State + ": " + t.Reason
}

// connectionCheck はエージェントの stream を見る。stream が切れているのにハンドシェイクが
// 新しい場合は、転送は続いているが新しいルールが届かない状態として名指しする。
func connectionCheck(r proto.Rule, ai *adminapi.AgentInfo, in Input) Check {
	c := Check{ID: CheckConnection, RuleID: r.ID, Agent: r.Agent, Group: GroupAgent, Label: "control connection"}
	if ai == nil {
		c.Status, c.Reason = StatusFailed, ReasonAgentNotRegistered
		c.Detail = fmt.Sprintf("no agent named %q is registered, so this rule has nowhere to forward to", r.Agent)
		c.Causes = []string{"its credentials were revoked", "it has never registered", "the rule names an agent that does not exist"}
		c.Next = "register one under that name: wgft agent join-string --name " + r.Agent
		return c
	}
	if ai.StreamFrom != "" {
		c.Internal = append(c.Internal, "stream from "+ai.StreamFrom)
	}
	c.Internal = append(c.Internal, "last heartbeat "+orDash(ai.LastHeartbeat))
	hb, hbOK := ParseWhen(ai.LastHeartbeat)
	if hbOK {
		c.ObservedAt = ai.LastHeartbeat
	}
	if !ai.Connected {
		c.Reason = ReasonAgentDisconnected
		seen := ""
		if hbOK {
			seen = ", last seen " + Since(in.Now, hb).String() + " ago"
		}
		if hs, ok := ParseWhen(ai.LastHandshake); ok && in.Now.Sub(hs) < HandshakeStale {
			// 制御の経路だけが切れていて、トンネルは生きている状態である。この検査が測るのは
			// 制御の経路の健全さであって、転送が止まった位置ではない(設計文書 10.2a 節)。
			// stream が切れていることは確かだが、このルールが今も転送しているかどうかは、この
			// 証拠からは決まらない。failed にすると、疎通確認が実際に target まで届いた場合でも
			// 「転送はここで止まった」と報告してしまう。
			c.Status = StatusUnknown
			c.Detail = "the control connection is down" + seen + "; existing traffic can still flow, but rule changes will " +
				"not arrive. The tunnel handshook " + Since(in.Now, hs).String() + " ago, so the rules the agent already holds may still be forwarding"
			c.Causes = []string{
				"the control connection dropped and the agent has not reconnected yet; it backs off up to 5 minutes",
				"the agent reached this server but was rejected; see the server log",
				"this server has not yet noticed a connection that is in fact alive",
			}
			c.Next = "read this server's log for this agent's control connection, and run wgft agent doctor on the agent host."
			switch {
			case r.Proto == proto.UDP:
				// UDP のルールには --probe を勧めない。管理用 API が UDP のルールの確認その
				// ものを拒むためである。代わりに、`rule.probe` の判定が同じ状況で返す案内
				// (udpProbeNext)をそのまま繰り返す(設計文書 10.2a 節の改訂の記録、
				// 2026-09-23)。
				c.Next += " " + strings.ToUpper(udpProbeNext[:1]) + udpProbeNext[1:] + "."
			case !in.Probed:
				// 既に疎通確認を行った実行に「--probe を付けよ」と言わない。今やったことを
				// 勧める行は読み手にとって雑音である。
				c.Next += " To see whether this rule still carries traffic, add --probe."
			}
			return c
		}
		// ハンドシェイクも新しくない。転送が止まったことは `tunnel.handshake` が failed として
		// 報告し、経路の順でそちらが先に来るので、ルールはトンネルで止まる。
		c.Status = StatusFailed
		c.Detail = "the agent is not connected to this server"
		if hbOK {
			c.Detail = "last seen " + Since(in.Now, hb).String() + " ago"
		}
		c.Causes = []string{"the agent is not running", "it cannot reach this VPS's agent API port", "the home line or the ISP is down"}
		c.Next = "run wgft agent doctor on the agent host; it answers whether the agent runs there and what its own state is, " +
			"then check that it can reach this VPS's agent API port"
		return c
	}
	if !hbOK {
		c.Status, c.Reason = StatusUnknown, ReasonNotReported
		c.Detail = "the agent is connected but has not sent a heartbeat yet"
		c.Next = "re-run in about 30 seconds; the agent reports every 30s"
		return c
	}
	age := Since(in.Now, hb)
	if age > HeartbeatStale {
		c.Status, c.Reason = StatusUnknown, ReasonStaleReport
		c.Detail = "heartbeat " + age.String() + " ago, past the 90s at which this server stops treating it as current; the agent sends one every 30s"
		c.Next = "re-run this command; if the heartbeat stays old, read the agent's log"
		return c
	}
	c.Status = StatusOK
	c.Detail = "heartbeat " + age.String() + " ago"
	return c
}

// rulesReceivedCheck は、そのエージェントが今のルール集合を持っているかを見る。ルールを別の
// エージェントへ移した直後は、移った先がまだ受け取っていない状態として出る。
func rulesReceivedCheck(r proto.Rule, ai *adminapi.AgentInfo, in Input) Check {
	c := Check{ID: CheckRulesReceived, RuleID: r.ID, Agent: r.Agent, Group: GroupAgent, Label: "rules received"}
	if ai == nil {
		c.Status, c.Reason = StatusSkipped, ReasonAgentNotRegistered
		c.Detail = "not tested: no agent is registered under that name"
		c.Next = "register one: wgft agent join-string --name " + r.Agent
		return c
	}
	cur := in.Rules.Generation
	c.Internal = append(c.Internal, fmt.Sprintf("agent generation %d, server generation %d", ai.Generation, cur))
	if !ai.Connected {
		c.Status, c.Reason = StatusUnknown, ReasonStaleReport
		c.ObservedAt = ai.LastHeartbeat
		c.Detail = fmt.Sprintf("last: it held rule set %d before it went away; this server now serves %d", ai.Generation, cur)
		c.Next = "the control connection line above says what to do; this value is history"
		return c
	}
	// 接続してからまだハートビートが無い間は、server はこの接続のエージェントの世代を観測して
	// いない。Generation の 0 は報告された世代ではないので比べない。判定の条件は
	// connectionCheck と同じ(LastHeartbeat が読めないこと)にし、2 つの検査が食い違わない
	// ようにする(設計文書 10.2a 節)。遅れの始まりが再接続の前から記録されていても同じである
	if _, ok := ParseWhen(ai.LastHeartbeat); !ok {
		c.Status, c.Reason = StatusUnknown, ReasonNotReported
		c.Detail = fmt.Sprintf("the agent is connected but has not sent a heartbeat yet, so which rule set it holds is not known; this server serves %d", cur)
		c.Next = "re-run in about 30 seconds; the agent reports every 30s"
		return c
	}
	c.ObservedAt = ai.LastHeartbeat
	if ai.Generation == cur {
		c.Status = StatusOK
		c.Detail = fmt.Sprintf("it holds rule set %d, this server's current one%s", cur, heartbeatAgeSuffix(ai, in))
		return c
	}
	// 遅れの始まりは server がメモリに持ち、管理用 API が generation_behind_since で返す
	// (設計文書 10.2a 節)。閾値の内側の遅れは、配り直しの途中でありうるので UNKNOWN にする。
	// 始まりが無い応答(この値を返さない旧い server)は、v1.1 と同じく FAILED のままにする。
	if since, ok := ParseWhen(ai.GenerationBehindSince); ok {
		age := Since(in.Now, since)
		if age < GenerationBehindLimit {
			c.Status, c.Reason = StatusUnknown, ReasonGenerationPending
			c.Detail = fmt.Sprintf("this agent still holds rule set %d while this server serves %d; it has been behind for %s, and an agent normally takes a new rule set within seconds",
				ai.Generation, cur, age)
			c.Next = "re-run in a few seconds; if it is still behind after a minute, this check turns failed"
			return c
		}
		// 閾値を超えた遅れは、10.2a 節の定めで届く途中ではない。「すぐ届く」「数秒後に再実行」を
		// 言わず、止まった遅れの原因だけを挙げる
		c.Status, c.Reason = StatusFailed, ReasonGenerationBehind
		c.Detail = fmt.Sprintf("this agent still holds rule set %d while this server serves %d; it has been behind for %s without taking the latest rule set", ai.Generation, cur, age)
		c.Causes = []string{
			"the agent is connected but has not applied the new rule set; see its log",
			"this server could not deliver the new rule set to the agent; see this server's log for errors about this agent",
		}
		c.Next = "read the agent's log and this server's log. A rule moved to another agent carries no traffic until that agent takes the new rule set."
		return c
	}
	// 始まりを返さない旧い server:v1.1 と同じ判定と文言
	c.Status, c.Reason = StatusFailed, ReasonGenerationBehind
	c.Detail = fmt.Sprintf("this agent still holds rule set %d while this server serves %d; it has not taken the latest rule set yet", ai.Generation, cur)
	c.Causes = []string{
		"the new rules are in flight and will be applied in a moment",
		"the agent is connected but is not applying them; see its log",
	}
	c.Next = "re-run in a few seconds; if it stays behind, read the agent's log. A rule moved to another agent carries no traffic until that agent takes the new rule set."
	return c
}

func heartbeatAgeSuffix(ai *adminapi.AgentInfo, in Input) string {
	if hb, ok := ParseWhen(ai.LastHeartbeat); ok {
		return ", as of its heartbeat " + Since(in.Now, hb).String() + " ago"
	}
	return ""
}

// credentialsCheck は窃取検知の警告である(設計文書 5.2 節)。往復も食い違いも、第三者と
// ローミングを見分けられないので、警告があるときは unknown にする。
func credentialsCheck(r proto.Rule, ai *adminapi.AgentInfo) Check {
	c := Check{ID: CheckCredentials, RuleID: r.ID, Agent: r.Agent, Group: GroupAgent, Label: "credentials", hideWhenOK: true, offPath: true}
	if ai == nil {
		c.Status, c.Reason = StatusSkipped, ReasonAgentNotRegistered
		c.Detail = "not tested: no agent is registered under that name"
		c.Next = "register one: wgft agent join-string --name " + r.Agent
		return c
	}
	if len(ai.Warnings) == 0 {
		c.Status = StatusOK
		c.Detail = "no open warning that these credentials are used from two places"
		return c
	}
	kinds := make([]string, 0, len(ai.Warnings))
	latest := ""
	for _, w := range ai.Warnings {
		kinds = append(kinds, w.Kind)
		if w.At > latest {
			latest = w.At
		}
	}
	sort.Strings(kinds)
	c.Status, c.Reason, c.ObservedAt = StatusUnknown, ReasonCredentialWarning, latest
	c.Detail = fmt.Sprintf("%d open warning%s that these credentials are used from two places: %s. They do not stop traffic",
		len(ai.Warnings), pluralS(len(ai.Warnings)), strings.Join(uniq(kinds), ", "))
	c.Causes = []string{"someone else holds the same credentials", "one agent moves between two lines and came back"}
	c.Next = "wgft agent warnings; dismiss it if the move was yours, revoke the agent if it was not"
	return c
}

// resolveCheck は target のホスト名の解決である。server は解決そのものを観測できず、失敗は
// エージェントの理由の文字列の中にしか現れない(設計文書 10.2a 節)。IP リテラルの target には
// 解決が無いので ok にする。
func resolveCheck(r proto.Rule, ai *adminapi.AgentInfo, in Input) Check {
	c := Check{ID: CheckTargetResolve, RuleID: r.ID, Agent: r.Agent, Group: GroupAgent, Label: "target resolve"}
	host, _, err := net.SplitHostPort(r.Target)
	if err != nil {
		host = r.Target
	}
	if _, perr := netip.ParseAddr(host); perr == nil {
		c.Status = StatusOK
		c.Detail = "the target is a literal address, so there is no name to resolve"
		c.hideWhenOK = true
		return c
	}
	if ai == nil {
		c.Status, c.Reason = StatusSkipped, ReasonAgentNotRegistered
		c.Detail = "not tested: no agent is registered under that name"
		c.Next = "register one: wgft agent join-string --name " + r.Agent
		return c
	}
	st, fresh := freshAgentRuleReport(r, in)
	switch {
	case fresh && st.State == proto.StatusError && looksLikeResolveFailure(st.Reason):
		c.Status, c.Reason, c.ObservedAt = StatusFailed, ReasonResolveFailed, st.At
		c.Detail = "the agent could not resolve " + host + ": " + st.Reason
		c.Next = "fix name resolution on the agent host, or point the rule at a literal address"
	case fresh && st.State == proto.StatusOK && r.Proto == proto.TCP:
		// TCP のルールが ok であることは、エージェントが target への接続を開けたことを意味する
		// (5.2 節)。名前への接続は解決を経るので、その時点で解決が成功したことを観測している。
		// UDP には同じことが言えない。UDP の ok はリスナーを開けたことしか意味せず、解決を伴わない。
		c.Status, c.ObservedAt = StatusOK, st.At
		age, ok := reportAge(st.At, in.Now)
		c.Detail = "the agent resolved " + host + " and connected to it at its last check"
		if ok {
			c.Detail += " " + age.String() + " ago"
		}
		c.hideWhenOK = true
	default:
		// 証拠がまったく無い。server はエージェントの名前解決を観測しないので、判定に足りない
		// 古い証拠ではなく、そもそも試していない条件として扱う(10.2a 節の状態の定義)。
		c.Status, c.Reason = StatusNotTested, ReasonResolvedByAgent
		c.Detail = "not tested: the agent resolves " + host + " itself and this server never observes the result; only a failure reaches it, inside the reason on the target line below"
		c.Next = "to see resolution itself, run wgft agent doctor on the agent host and resolve " + host + " there"
	}
	return c
}

// freshAgentRuleReport は、このルールについてエージェントが今報告している内容である。接続中で、
// かつ TargetReportStale より新しい報告だけを今の値として返す(設計文書 5.2、10.2a 節)。
// 鮮度の規則そのものは FreshAgentRuleStatus に切り出してあり、`wgft status`(cmd/wgft/status.go の
// rulesStatusOf)もこの版から同じ規則を共有する(design.md 10.2b 節)。
func freshAgentRuleReport(r proto.Rule, in Input) (adminapi.AgentRuleStatus, bool) {
	return FreshAgentRuleStatus(in.Rules.AgentRuleStates[r.ID], in.Now)
}

// FreshAgentRuleStatus は、1 件の agent_rule_states の項目が「今の値」として使えるかどうかを
// 判定する(設計文書 5.2、10.2a、10.2b 節)。接続中(Connected)であること、State が空でない
// こと(まだ 1 度も報告していない項目と区別する)、報告の時刻が TargetReportStale より新しい
// ことの 3 つをすべて満たす場合だけ、その値をそのまま返す。1 つでも欠ければ、ゼロ値と false を
// 返す。ゼロ値の st(agent_rule_states にその行が無い呼び出し元も渡せる)を渡しても、Connected
// が false かつ State が空なので、この関数はそのまま false を返す。
func FreshAgentRuleStatus(st adminapi.AgentRuleStatus, now time.Time) (adminapi.AgentRuleStatus, bool) {
	if !st.Connected || st.State == "" {
		return adminapi.AgentRuleStatus{}, false
	}
	age, ok := reportAge(st.At, now)
	if !ok || age > TargetReportStale {
		return adminapi.AgentRuleStatus{}, false
	}
	return st, true
}

// looksLikeResolveFailure は、エージェントの理由が名前解決の失敗かどうかを見る。Go の net が
// 返す文言に依る判定なので確実ではない。外したときは決めつけず、target の誤りとして扱う。
func looksLikeResolveFailure(reason string) bool {
	for _, m := range []string{"no such host", "lookup ", "server misbehaving", "name resolution"} {
		if strings.Contains(reason, m) {
			return true
		}
	}
	return false
}

// targetCheck は、そのルールの持ち主のエージェント自身の報告である(設計文書 5.2、7a.11 節の
// agent_rule_states)。stream が切れている間の報告は履歴であり、今の原因として示してはならない
// ので unknown と "last:" にする。報告が 90 秒より古い場合も今の値として扱わない。この鮮度の
// 判定そのものは FreshAgentRuleStatus と共有する。state・Connected・報告の有無で文言を出し
// 分ける場合分けは、この関数に残す(2026-09-22 の改訂まではここに同じ鮮度の条件を別のインライン
// のコードとして持っており、FreshAgentRuleStatus を直しても追随しなかった。レビューの指摘)。
func targetCheck(r proto.Rule, ai *adminapi.AgentInfo, in Input) Check {
	c := Check{ID: CheckTarget, RuleID: r.ID, Agent: r.Agent, Group: GroupAgent, Label: "target"}
	states := in.Rules.AgentRuleStates
	if states == nil {
		c.Status, c.Reason = StatusUnknown, ReasonNotReportedByServer
		c.Detail = "this server does not report what the agent says about each rule"
		c.Next = "wgft agent ls shows the same information for an older server"
		return c
	}
	st, ok := states[r.ID]
	if !ok {
		c.Status, c.Reason = StatusUnknown, ReasonNotReported
		c.Detail = "this server reports nothing the agent said about this rule"
		c.Next = "wgft agent ls shows what that agent last reported"
		return c
	}
	c.Internal = append(c.Internal, "agent_rule_states: state "+orDash(st.State)+", connected "+fmt.Sprint(st.Connected)+", at "+orDash(st.At))
	c.ObservedAt = st.At
	if !st.Connected {
		c.Status, c.Reason = StatusUnknown, ReasonStaleReport
		if st.State == "" {
			c.Detail = "last: the agent never reported this rule before it went away, so there is nothing to read"
		} else {
			c.Detail = "last: the agent reported " + agentStateText(st) + " before it went away; that is history, not the current cause"
		}
		c.Next = "the control connection line above says what to do; this value is not current"
		return c
	}
	if st.State == "" {
		c.Status, c.Reason = StatusUnknown, ReasonNotReported
		c.Detail = "the agent is connected but has not reported this rule yet"
		c.Next = "re-run in about 30 seconds; the agent reports every 30s, and at once after taking new rules"
		return c
	}
	reportAge, ageOK := reportAge(st.At, in.Now)
	// fresh は、この st がすでに Connected と State を満たしていることを前提に、報告の時刻だけを
	// FreshAgentRuleStatus と同じ規則で判定する。呼び出す前に Connected・State を確かめ済みなので、
	// FreshAgentRuleStatus の最初の条件は必ず通り、結果は下の ageOK・reportAge の計算と揃う。
	_, fresh := FreshAgentRuleStatus(st, in.Now)
	switch st.State {
	case proto.StatusOK:
		if !fresh {
			c.Status, c.Reason = StatusUnknown, ReasonStaleReport
			c.Detail = "the agent last reported this rule ok, but that was " + staleAgeText(reportAge, ageOK) + ", so it is not a current observation"
			c.Next = "re-run this command; if the report stays old, read the control connection line above and the agent's log"
			return c
		}
		if r.Proto != proto.TCP {
			// UDP のルールの ok は、エージェントがリスナーを開けたことしか意味しない(設計文書
			// 5.2 節)。宛先がデータグラムを受け取ったことも応えたことも示さないので、OK の定義
			// (実際に成功を観測した)に当たらない。報告そのものは新しいので、観測の時刻は残す
			// (設計文書 10.2a 節、2026-09-24 の改訂の記録)。
			c.Status, c.Reason = StatusNotTested, ReasonUDPListenerOnly
			c.Detail = "not tested: the agent has its listener open, last report " + reportAge.String() + " ago, but a UDP send cannot tell whether the target received it or answered"
			c.Next = "confirm the service from a real client"
			return c
		}
		c.Status = StatusOK
		c.Detail = "the agent reached " + r.TargetDisplay() + ", last check " + reportAge.String() + " ago, repeated every 30s"
		return c
	case proto.StatusError:
		if !fresh {
			c.Status, c.Reason = StatusUnknown, ReasonStaleReport
			c.Detail = "the agent last reported an error on this rule: " + ReasonOr(st.Reason, "no reason") + ", but that was " + staleAgeText(reportAge, ageOK) + ", so it is not a current observation"
			c.Next = "re-run this command; if the report stays old, read the control connection line above and the agent's log"
			return c
		}
		c.Status, c.Reason = StatusFailed, targetReasonCode(st.Reason)
		c.Detail = "the agent could not use this rule: " + ReasonOr(st.Reason, "no reason reported") + ", last check " + reportAge.String() + " ago"
		c.Next = agentRuleNextStep(st.Reason, r)
		return c
	}
	c.Status, c.Reason = StatusUnknown, ReasonUnknownValue
	c.Detail = fmt.Sprintf("the agent reports a state this build does not know: %q", st.State)
	c.Next = "upgrade this CLI to the agent's version"
	return c
}

// withUDPReply は UDP のルールの rule.target に、server 自身が見た宛先の応答の観測を添える
// (設計文書 10.2a 節「UDP の応答の観測」)。添えるだけで、状態、理由、観測の時刻は変えない。
// 最近の応答があっても NOT TESTED は OK にならず、応答が無いことや古いことも UNKNOWN や FAILED に
// ならない。閾値を持たない。応答が無いことは、使われていないルールと応答しないサービスで同じに
// 見えるためである。
func withUDPReply(c Check, r proto.Rule, in Input) Check {
	if r.Proto != proto.UDP || in.Rules == nil {
		return c
	}
	obs, ok := in.Rules.UDPReplies[r.ID]
	if !ok {
		return c
	}
	if obs.NotObserved != "" {
		c.ReplyNotObserved = obs.NotObserved
		c.ReplyLine = "UDP replies are not observed: " + obs.NotObserved
		return c
	}
	c.LastReplyAt, c.ReplySince = obs.LastReplyAt, obs.Since
	if t, ok := ParseWhen(obs.LastReplyAt); ok {
		c.ReplyLine = "last UDP reply seen by this server " + Since(in.Now, t).String() + " ago"
		return c
	}
	watched, ok := reportAge(obs.Since, in.Now)
	c.ReplyLine = "no UDP reply seen since this server started watching the rule " + staleAgeText(watched, ok) +
		"; an idle rule looks the same"
	return c
}

func staleAgeText(age time.Duration, ok bool) string {
	if !ok {
		return "at an unknown time"
	}
	return age.String() + " ago"
}

func reportAge(at string, now time.Time) (time.Duration, bool) {
	t, ok := ParseWhen(at)
	if !ok {
		return 0, false
	}
	return Since(now, t), true
}

// targetReasonCode は、エージェントの人が読む理由を機械向けの符号に写す。文言に依る判定なので、
// 当てはまらないものは target_error にまとめる。符号は増やせるが、意味は変えない。
func targetReasonCode(reason string) string {
	switch {
	case strings.Contains(reason, allowtargets.Env) || strings.Contains(reason, "is not allowed"):
		return ReasonTargetNotAllowed
	case looksLikeBindFailure(reason):
		return ReasonListenerBindFailed
	case looksLikeResolveFailure(reason):
		return ReasonResolveFailed
	case strings.Contains(reason, "does not forward to loopback targets"):
		// カーネルモードのエージェントの文言(internal/dataplane/linuxkernel/nft の targetAddrs)。名前の
		// 解決に失敗して直前のアドレスも使えない場合は、解決の失敗の側を先に当てる
		return ReasonTargetLoopbackUnsupported
	case strings.Contains(reason, "connection refused"):
		return ReasonConnectionRefused
	case strings.Contains(reason, "timeout") || strings.Contains(reason, "timed out") || strings.Contains(reason, "did not answer"):
		return ReasonTargetTimeout
	case strings.Contains(reason, "no route to host") || strings.Contains(reason, "unreachable"):
		return ReasonTargetUnreachable
	}
	return ReasonTargetError
}

// looksLikeBindFailure は、エージェントの理由がリスナーの bind の失敗かどうかを見る。3 つの文言の
// 形を見る。エージェント自身の文言 "bind failed"、Go の net.Listen がそのまま返す形("listen ...:
// bind: address already in use" のような、"listen" と "bind:" を伴う文言)、そしてユーザー空間
// モードの中継(internal/dataplane/userspace/relay)が実際に組み立てる形である。エージェントの
// 中継は gVisor の netstack(internal/nettun/listen.go の ListenTCP、UDP のリスナーが経由する
// gonet.DialUDP)の上で待ち受けを開き、その bind の失敗は Go の net.OpError をそのまま経由するが、
// Op が "listen" ではなく "bind" になる("bind tcp <トンネルのアドレス>: port is in use" の形。
// net.Listen の "listen ...: bind: ..." とは組み立てが違うので、以前の判定には当たらなかった)。
// この形は、ソースコードから読み取った実際の組み立てと合わせて、試験用の実機(#211 より前の版の
// エージェント。stream が切れてもリレーのポートを空けない不具合があった)で実際に観測されている。
// 意味の分からない target_error に落ちていたのはこの形である。#211 で直した今の版のエージェント
// でも、宛先が先に閉じるセッションの後にルールを閉じ直すと、TIME_WAIT の間ポートを保持する経路
// (設計文書 7 節)から同じ文言に至ることをラボで確かめた(設計文書 改訂の記録)。
func looksLikeBindFailure(reason string) bool {
	if strings.Contains(reason, "bind failed") {
		return true
	}
	if strings.Contains(reason, "listen") && strings.Contains(reason, "bind:") {
		return true
	}
	return strings.Contains(reason, "bind tcp ") || strings.Contains(reason, "bind udp ")
}

func agentStateText(st adminapi.AgentRuleStatus) string {
	if st.State == proto.StatusOK || st.Reason == "" {
		return st.State
	}
	return st.State + ": " + st.Reason
}

// agentRuleNextStep は、エージェントが返した理由に応じた次の手である。
func agentRuleNextStep(reason string, r proto.Rule) string {
	switch targetReasonCode(reason) {
	case ReasonTargetNotAllowed:
		return "the agent refuses this target itself: " + allowtargets.Env + " on the agent host does not list it. Add the target there, or point the rule elsewhere."
	case ReasonListenerBindFailed:
		// ユーザー空間モードの中継の待ち受けはエージェントのプロセス内の netstack にあり、
		// ホストの他のプロセスとポート空間を共有しない。「他のプロセスを探す」という以前の案内は
		// 誤りを誘うため直した。ラボで再現できた経路では、ポートを保持しているのは TIME_WAIT に
		// 残った接続であって待ち受けそのものではないので、待ち受けと接続の両方を挙げる。実機で
		// 観測した pre-#211 の例(stream が切れてもリレーのポートを空けない不具合。#211 で修正済み)
		// は、無効化の直後の有効化でエージェント自身の前の待ち受けがまだそのポートを離していない
		// 場合だった(設計文書 改訂の記録)。
		return "an earlier listener or connection of the agent on this port has not been freed yet; this is internal to the agent process, " +
			"not another process on the agent host. The agent retries every 30s and clears once that hold ends; restarting the agent also frees it at once."
	case ReasonResolveFailed:
		return "fix name resolution on the agent host, or point the rule at a literal address"
	case ReasonTargetLoopbackUnsupported:
		return "the agent runs in kernel mode, which does not forward to a loopback target. Point the rule at the agent host's LAN address instead of " + r.TargetDisplay() + "."
	}
	return "the tunnel and the agent are healthy up to this point. Check that a service is listening on " + r.TargetDisplay() +
		" and accepts connections from the agent host; the agent retries every 30s and clears the error on its own."
}

// flowBudgetCheck は Resource Guard の拒否である(設計文書 7a.10 節)。累積の値なので、拒否が
// あっても今そうであるとは言えず、unknown にする。
func flowBudgetCheck(r proto.Rule, in Input) Check {
	c := Check{ID: CheckFlowBudget, RuleID: r.ID, Group: GroupAgent, Label: "flow budget", hideWhenOK: true, hideWhenUntested: true, offPath: true}
	res := in.Rules
	if res.ResourceRefusals == nil && res.FlowBudget == nil {
		c.Status, c.Reason = StatusUnknown, ReasonNotReportedByServer
		c.Detail = "this server does not report its flow budget"
		c.Next = "wgft rule ls shows the counters an older server does report"
		return c
	}
	refused := ResourceRefusalTotal(res.ResourceRefusals, r.ID)
	if b := FlowBudgetLine(res.FlowBudget); b != "" {
		c.Internal = append(c.Internal, b)
	}
	c.Internal = append(c.Internal, fmt.Sprintf("refused %d, dropped %d since the server started", refused, res.Drops[r.ID]))
	c.ObservedAt = in.Now.UTC().Format(time.RFC3339)
	if refused == 0 {
		c.Status = StatusOK
		c.Detail = "no connection on this rule has been refused for want of wgft's own resources since the server started"
		return c
	}
	c.Status, c.Reason = StatusUnknown, ReasonResourceRefusals
	c.Detail = fmt.Sprintf("%d connection%s on this rule %s refused for want of wgft's own resources since the server started; that is a total, and this command cannot tell whether it is happening now", refused, pluralS(int(refused)), wasWere(int(refused)))
	c.Next = "if that is recent, raise WGFT_MAX_TCP_FLOWS / WGFT_MAX_UDP_FLOWS on this server, or look for a flood holding connections open"
	return c
}

// udpProbeNext is what a UDP rule's probe check tells the operator to do next, whether or not
// --probe was given: the admin API refuses to dial a UDP rule end to end either way, because a
// UDP send cannot tell success. Both branches below share this one phrasing of that fact.
const udpProbeNext = "judge a UDP rule from the target line above, and confirm the service from a real client"

// probeCheck は能動的な疎通確認の結果である(設計文書 10.1 節の疎通確認)。--probe が無ければ
// 何も試していないことをそのまま出す。
func probeCheck(r proto.Rule, in Input) Check {
	c := Check{ID: CheckProbe, RuleID: r.ID, Agent: r.Agent, Group: GroupAgent, Label: "end-to-end probe", hideWhenUntested: true}
	p, ok := in.Probes[r.ID]
	if !ok {
		c.Status, c.Reason = StatusNotTested, ReasonNoProbe
		c.Detail = "nothing was dialled"
		c.Next = "add --probe to open one real TCP connection from this server, through the tunnel and the agent, to the target"
		if r.Proto == proto.UDP {
			// UDP のルールには --probe を付けても意味が無い。管理用 API が UDP のルールの
			// 確認そのものを拒むためである(設計文書 10.2a 節の改訂の記録、2026-09-23)。
			c.Next = udpProbeNext
		}
		return c
	}
	c.ObservedAt = in.Now.UTC().Format(time.RFC3339)
	if p.Err != nil {
		c.Status, c.Reason = StatusUnknown, ReasonNotReported
		c.Detail = "the server declined to dial: " + p.Err.Error()
		c.Next = "read the target line above; it carries what the agent itself found"
		if r.Proto == proto.UDP {
			c.Status, c.Reason = StatusNotTested, ReasonNoProbe
			c.Detail = "a UDP rule cannot be dialled end to end, because a UDP send cannot tell success: " + p.Err.Error()
			c.Next = udpProbeNext
		}
		return c
	}
	if p.Check == nil {
		c.Status, c.Reason = StatusUnknown, ReasonNotReported
		c.Detail = "the server returned no result"
		c.Next = "re-run with --verbose, and read the server log"
		return c
	}
	c.Internal = append(c.Internal, "reach "+p.Check.Reach+": "+p.Check.Detail)
	switch p.Check.Reach {
	case "target":
		c.Status = StatusOK
		c.Detail = "connected to " + r.TargetDisplay() + " through the tunnel and the agent, observed just now. It was closed without speaking the protocol, so it does not prove the service itself is healthy"
		return c
	case "agent":
		c.Status, c.Reason = StatusFailed, ReasonTargetUnreachable
		c.Detail = "the connection reached the agent, but the agent could not reach " + r.TargetDisplay() + ": " + p.Check.Detail
		c.Next = "the tunnel and the agent are healthy. Check that a service is listening on " + r.TargetDisplay() + " and lets the agent host in."
		return c
	case "none":
		c.Status, c.Reason = StatusFailed, ReasonAgentUnreachable
		c.Detail = "the connection did not reach the agent's listener through the tunnel: " + p.Check.Detail
		c.Causes = []string{"the tunnel is down", "the agent has not opened this listener", "the agent is not running"}
		c.Next = "read the WireGuard and connected lines above; they name which of the three it is"
		return c
	}
	c.Status, c.Reason = StatusUnknown, ReasonUnknownValue
	c.Detail = fmt.Sprintf("the server reported a result this build does not know: %q, detail %s", p.Check.Reach, p.Check.Detail)
	c.Next = "upgrade this CLI to the server's version"
	return c
}
