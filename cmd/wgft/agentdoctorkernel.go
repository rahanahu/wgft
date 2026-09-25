package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/rahanahu/wgft/internal/agent"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは `wgft agent doctor` のカーネルモードの検査を持つ(設計文書 10.2c 節の「カーネルモードの
// エージェント」の項)。カーネルモードで転送を担うのは、エージェントのプロセスではなく、カーネルの
// WireGuard インタフェース、table inet wgft_agent、ホストの転送の設定である。その 3 つを見る検査
// dataplane.interface、dataplane.table、host.forwarding を、群 Dataplane として並べる。
//
// 証拠は、稼働中はエージェント自身が制御ソケットの doctor の応答で返し(runtime_state.kernel)、停止中
// だけ、この CLI が internal/agent の ReadKernel で直接読む。読む関数は 1 つで、どちらの実行も同じ形の
// agent.DoctorKernel を受け取り、この CLI が状態を選ぶ。

// カーネルモードの検査の識別子と群。
const (
	agentCheckDPInterface = "dataplane.interface"
	agentCheckDPTable     = "dataplane.table"
	agentCheckForwarding  = "host.forwarding"

	agentGroupDataplane = "Dataplane"
)

// カーネルモードの検査の理由の符号(設計文書 10.2c 節の理由の符号の表)。
const (
	// agentReasonKernelMode は、エージェントがカーネルモードで動き、その検査が見る対象を持たない
	// ことである。リスナー、中継、フロー予算、トンネルの作り直しがこれに当たる。
	agentReasonKernelMode = "kernel_mode"
	// agentReasonUserspaceMode は、エージェントがユーザー空間モードで動き、その検査が見る対象を
	// 持たないことである。
	agentReasonUserspaceMode = "userspace_mode"
	// agentReasonNeedsNetAdmin は、呼び出し元が CAP_NET_ADMIN を持たず、カーネルの状態を直接読めない
	// ことである。停止中のエージェントの診断だけに当たる。
	agentReasonNeedsNetAdmin = "needs_cap_net_admin"
	// agentReasonAgentLacksNetAdmin は、稼働中のカーネルモードのエージェントが実効の CAP_NET_ADMIN を
	// 持たないことである。エージェント自身が答えた事実であり、層 2 には入れない。
	agentReasonAgentLacksNetAdmin = "agent_lacks_cap_net_admin"
	// agentReasonKernelUnreadable は、カーネルの状態を権限以外の理由で読めないことである。
	agentReasonKernelUnreadable = "kernel_unreadable"
	// agentReasonInterfaceMissing は、エージェントの WireGuard インタフェースが無いことである。
	agentReasonInterfaceMissing = "interface_missing"
	// agentReasonInterfaceNotOurs は、同名のリンクが今の鍵か 1 つ前の鍵を持つ WireGuard インタフェース
	// でないことである。
	agentReasonInterfaceNotOurs = "interface_not_ours"
	// agentReasonInterfaceDown は、エージェントの WireGuard インタフェースが down であることである。
	agentReasonInterfaceDown = "interface_down"
	// agentReasonPeerMissing は、server の公開鍵を持ち server のトンネルアドレスを AllowedIPs に含む
	// ピアが無いことである。
	agentReasonPeerMissing = "peer_missing"
	// agentReasonInterfaceDiffers は、インタフェースが宣言とどこかで違うことである。
	agentReasonInterfaceDiffers = "interface_differs"
	// agentReasonRouteNotViaInterface は、server のトンネルアドレスへの経路がエージェントの WireGuard
	// インタフェースを通らないことである。
	agentReasonRouteNotViaInterface = "route_not_via_interface"
	// agentReasonTableMissing は、table inet wgft_agent が無いことである。
	agentReasonTableMissing = "table_missing"
	// agentReasonTableRowsMissing は、テーブルに記録から組む行、チェーン、DNAT のうち、欠けると転送が
	// 止まるもの(転送の行)が無いことである。位置が違うだけの行は欠けに数えない(10.2c 節)。
	agentReasonTableRowsMissing = "table_rows_missing"
	// agentReasonGuardRowsMissing は、テーブルに記録から組む行のうち、欠けても転送が止まらない行
	// (守りの行)だけが欠けていることである。転送は続きうるが、wgft0 から届く面が開きうる。
	agentReasonGuardRowsMissing = "guard_rows_missing"
	// agentReasonTableChanged は、テーブルに記録に無い行かチェーンが加わっているか、記録から組む行が
	// 同じチェーンの別の位置にあることである。どちらも転送への効果が分からない。
	agentReasonTableChanged = "table_changed"
	// agentReasonPublishFailed は、稼働中のエージェントが直近の全体状態を公開できず、旧いテーブルが
	// 残っていることである(7b.3 節の 3 つ目の種類)。
	agentReasonPublishFailed = "publish_failed"
	// agentReasonIPForwardOff は、net.ipv4.ip_forward が 1 でないことである。
	agentReasonIPForwardOff = "ip_forward_off"
	// agentReasonIPForwardUnreadable は、net.ipv4.ip_forward を読めないことである。
	agentReasonIPForwardUnreadable = "ip_forward_unreadable"
	// agentReasonForwardPolicyDrop は、他のテーブルの forward のチェーンが既定で落とすことである。
	agentReasonForwardPolicyDrop = "forward_policy_drop"
	// agentReasonRPFilterStrict は、rp_filter の all か default が 1 であることである。
	agentReasonRPFilterStrict = "rp_filter_strict"
)

// agentKernelSpecs はカーネルモードの 3 つの検査である。どれもカーネルモードでは総合判定を動かす。
var agentKernelSpecs = []agentDoctorCheck{
	{ID: agentCheckDPInterface, Group: agentGroupDataplane, Label: "interface", verdict: true},
	{ID: agentCheckDPTable, Group: agentGroupDataplane, Label: "table", verdict: true},
	{ID: agentCheckForwarding, Group: agentGroupDataplane, Label: "forwarding", verdict: true},
}

// agentModeOf はエージェントのモードである。稼働中のエージェントが答えた mode を先に見て、その答えが
// 無ければ認証情報ファイルの記録を見る。どちらも無ければ空である(10.2c 節)。
func agentModeOf(cred agentCredentialsFile, live agentLive) string {
	if live.Resp != nil && live.Resp.RuntimeState != nil {
		if live.Resp.RuntimeState.Mode == credentials.ModeKernel {
			return credentials.ModeKernel
		}
		return credentials.ModeUserspace
	}
	if cred.State == credOK && cred.Creds != nil {
		return cred.Creds.RecordedMode()
	}
	return ""
}

// agentKernelOnlyNotTested は、カーネルモードに試す対象が無い検査である(10.2c 節)。
func agentKernelOnlyNotTested(id string) bool {
	switch id {
	case agentCheckListeners, agentCheckSessions, agentCheckRefusals, agentCheckWatchdog:
		return true
	}
	return false
}

// agentKernelNotTested は、カーネルモードの実行で、試す対象の無い検査を NOT TESTED にする。
func agentKernelNotTested(c *agentDoctorCheck) {
	c.Status, c.Reason, c.Next = statusNotTested, agentReasonKernelMode, ""
	switch c.ID {
	case agentCheckWatchdog:
		c.Detail = "kernel mode has no tunnel of its own to rebuild; the kernel keeps the WireGuard interface, and the interface line under Dataplane shows it"
	default:
		c.Detail = "kernel mode has no relay, listeners or flow budget; the kernel forwards with DNAT, and the table line under Dataplane shows each rule"
	}
}

// agentKernelEvidence は、カーネルモードの 3 つの検査の材料である。
type agentKernelEvidence struct {
	kernel *agent.DoctorKernel
	// running は、稼働中のエージェントが答えた材料かどうかである
	running bool
	// rules はルールごとの状態である。稼働中はハートビートと同じ読みから、停止中は記録から来る
	rules        []agent.DoctorRule
	publishError string
	checkError   string
}

// agentKernelChecks はカーネルモードの 3 つの検査を組み立てる。実行の状態によって項目は消えない。
func agentKernelChecks(in agentDoctorInput, cred agentCredentialsFile, run agentRunState, live agentLive, mode string) []agentDoctorCheck {
	out := append([]agentDoctorCheck(nil), agentKernelSpecs...)
	set := func(f func(c *agentDoctorCheck)) {
		for i := range out {
			f(&out[i])
		}
	}
	switch mode {
	case "":
		// モードが分からない。手前の agent.credentials の符号を持つ
		st, _ := agentSkipForCredentials(cred, "which mode the agent runs in")
		set(func(c *agentDoctorCheck) { c.Status, c.Reason, c.Detail = st.Status, st.Reason, st.Detail })
		return out
	case credentials.ModeUserspace:
		set(func(c *agentDoctorCheck) {
			c.Status, c.Reason = statusNotTested, agentReasonUserspaceMode
			c.Detail = "the agent runs in userspace mode and relays traffic itself, so there is no kernel dataplane to read; the Relay lines above answer for forwarding"
		})
		return out
	}
	var ev agentKernelEvidence
	switch {
	case run.running():
		switch {
		case live.Kind != liveOK:
			set(func(c *agentDoctorCheck) { agentLiveSkip(c, run, live) })
			return out
		case live.Resp.RuntimeState.Kernel == nil:
			// この変更より前のカーネルモードのエージェントは、カーネルの状態を返さない
			set(func(c *agentDoctorCheck) {
				c.Status, c.Reason = statusSkipped, agentReasonDoctorUnsupported
				c.Detail = "the running agent does not report its kernel state, so this was not read"
				c.Next = agentRestartForDoctorNext
			})
			return out
		}
		rs := live.Resp.RuntimeState
		if rs.AgentDisabled {
			set(func(c *agentDoctorCheck) { agentKernelDisabled(c, agentDisplayName(cred)) })
			return out
		}
		ev = agentKernelEvidence{kernel: rs.Kernel, running: true, rules: rs.Rules,
			publishError: rs.PublishError, checkError: rs.CheckError}
		if ev.rules == nil {
			ev.rules = rs.Kernel.Table.Rules
		}
	case run.undetermined():
		set(func(c *agentDoctorCheck) { agentLiveSkip(c, run, live) })
		return out
	default:
		if ls := cred.Creds.LastState; ls != nil && ls.AgentDisabled {
			set(func(c *agentDoctorCheck) { agentKernelDisabled(c, agentDisplayName(cred)) })
			return out
		}
		k := in.ReadKernel(cred.Creds, in.WGInterface)
		ev = agentKernelEvidence{kernel: k, rules: k.Table.Rules}
	}
	agentInterfaceCheck(&out[0], in, ev)
	agentTableCheck(&out[1], ev)
	agentForwardingCheck(&out[2], ev)
	return out
}

func agentKernelDisabled(c *agentDoctorCheck, agentName string) {
	agentDisabledSkip(c)
	c.Detail = "the server has disabled this agent, so it forwards none of its rules until wgft agent enable " + orDash(agentName) + " is run on the VPS"
}

// agentNeedsNetAdminNext は、CAP_NET_ADMIN の無い呼び出し元に添える次の手である。root での実行を
// 案内するのは、欠けている証拠がファイルではなくカーネルの状態だからである(10.2c 節)。
const agentNeedsNetAdminNext = "start the agent, which holds CAP_NET_ADMIN and reports its kernel state itself, or run this command as root to read that state directly"

// agentKernelStoppedNote は、停止中の実行の所見に添える句である。
func agentKernelStoppedNote(ev agentKernelEvidence) string {
	if ev.running {
		return ""
	}
	return "; read directly from the kernel because the agent is not running"
}

// agentInterfaceCheck は dataplane.interface を組み立てる(10.2c 節)。
func agentInterfaceCheck(c *agentDoctorCheck, in agentDoctorInput, ev agentKernelEvidence) {
	ki := ev.kernel.Interface
	name := ki.Name
	route := ""
	if ki.RouteInterface != "" {
		route = "the route to the server's tunnel address " + ki.ServerAddress + " goes through " + ki.RouteInterface
	}
	switch {
	case ki.ReadError != "":
		c.Status, c.Reason = statusUnknown, agentReasonKernelUnreadable
		c.Detail = name + " could not be read: " + ki.ReadError
		c.Next = "read it with ip -d link show " + name
		return
	case !ki.Exists:
		c.Status, c.Reason = statusFailed, agentReasonInterfaceMissing
		c.Detail = "there is no " + name + " on this host, so nothing receives the tunnel from the VPS" + agentKernelStoppedNote(ev)
		c.Next = agentKernelLinkNext(ev, "the agent creates it on start")
		return
	case ki.Ownership == agent.KernelOwnershipNotWireGuard:
		c.Status, c.Reason = statusFailed, agentReasonInterfaceNotOurs
		c.Detail = name + " is a " + ki.Kind + " link, not WireGuard, so it does not carry the tunnel" + agentKernelStoppedNote(ev)
		c.Next = "delete that link, or set WGFT_WG_INTERFACE to another name and restart the agent"
		return
	// 所有の判定を down より先に見る。他の所有者のインタフェースは、起動しても up にならず、エージェントは
	// 起動を拒むためである(10.2c 節の「dataplane.interface の判定」)。鍵を読めた実行だけが所有を知る
	case ki.Ownership == agent.KernelOwnershipForeign || ki.Ownership == agent.KernelOwnershipKeyless:
		c.Status, c.Reason = statusFailed, agentReasonInterfaceNotOurs
		what := "holds another key than this agent's"
		if ki.Ownership == agent.KernelOwnershipKeyless {
			what = "holds no key"
		}
		c.Detail = name + " is a WireGuard interface that " + what + ", so the VPS's packets for this agent are not accepted on it" + agentKernelStoppedNote(ev)
		c.Next = "the agent refuses to start over an interface that is not its own. If it is left over from an earlier registration on this host, delete it with ip link del " + name +
			"; otherwise set WGFT_WG_INTERFACE to another name"
		return
	case !ki.Up && (ki.NeedsNetAdmin || ki.DeviceError != ""):
		// 鍵を読めないので所有は分からないが、down は鍵を読まずに分かる事実であり、転送を担えないと言える。
		// 読めなかった理由は、権限の不足と読み出しの誤りで分けて示す
		c.Status, c.Reason = statusFailed, agentReasonInterfaceDown
		start := "start the agent; if " + name + " holds its key, it sets the interface up again, and if not, it refuses to start and says why. "
		if ki.NeedsNetAdmin {
			c.Detail = name + " is down, so it carries no traffic; whether it holds this agent's key could not be read without CAP_NET_ADMIN" + agentKernelStoppedNote(ev)
			c.Next = start + "Run this command as root to read the key first"
		} else {
			c.Detail = name + " is down, so it carries no traffic; whether it holds this agent's key could not be read: " + ki.DeviceError + agentKernelStoppedNote(ev)
			c.Next = start + "Read the key first with wg show " + name
		}
		return
	case !ki.Up:
		c.Status, c.Reason = statusFailed, agentReasonInterfaceDown
		c.Detail = name + " is down, so it carries no traffic" + agentKernelStoppedNote(ev)
		c.Next = agentKernelLinkNext(ev, "the agent sets it up again")
		return
	case ki.NeedsNetAdmin:
		c.Status, c.Reason, c.evidenceUnreachable = statusUnknown, agentReasonNeedsNetAdmin, true
		c.Detail = name + " exists and is up, but its key and peer cannot be read without CAP_NET_ADMIN, which this command does not hold"
		if route != "" {
			c.Detail += "; " + route
		}
		c.Next = agentNeedsNetAdminNext
		return
	case ki.DeviceError != "":
		c.Status, c.Reason = statusUnknown, agentReasonKernelUnreadable
		c.Detail = "the key and peer of " + name + " could not be read: " + ki.DeviceError
		c.Next = "read them with wg show " + name
		return
	case !ki.Declared:
		c.Status, c.Reason = statusUnknown, agentReasonNoLastState
		c.Detail = name + " is a WireGuard interface with this agent's key, but agent.json holds no full state to compare it with" + agentKernelStoppedNote(ev)
		c.Next = "start the agent and let it reach the server; the server sends the whole state on every connection"
		return
	case !ki.PeerOK:
		c.Status, c.Reason = statusFailed, agentReasonPeerMissing
		c.Detail = name + " has no peer with the server's key that allows " + ki.ServerAddress + ", so it accepts nothing from the VPS: " + agentPeersText(in.Now, ki) + agentKernelStoppedNote(ev)
		c.Next = agentKernelLinkNext(ev, "the agent puts the peer back")
		return
	}
	facts := agentInterfaceFacts(in.Now, ki)
	if route != "" {
		facts += "; " + route
	} else if ki.RouteError != "" {
		facts += "; the route to " + ki.ServerAddress + " could not be read: " + ki.RouteError
	}
	switch {
	case ki.RouteInterface != "" && ki.RouteInterface != name:
		c.Status, c.Reason = statusUnknown, agentReasonRouteNotViaInterface
		c.Detail = facts + ", not " + name + ". Replies to the VPS may leave through " + ki.RouteInterface + " instead of the tunnel, and then forwarding stops. " +
			"This reads the route of packets this host sends itself; a policy rule that matches on the input interface or a mark can route forwarded replies differently"
		c.Next = "find what claims the address with ip rule and ip route get " + ki.ServerAddress + "; a VPN such as Tailscale that accepts routes for that range is a common cause. " +
			"Exclude the tunnel range from it, or have the server operator move the range with WGFT_WG_ADDRESS"
		return
	}
	var differs []string
	for _, d := range ki.Differs {
		if d == "the up flag" {
			continue
		}
		differs = append(differs, d)
	}
	if len(differs) > 0 {
		c.Status, c.Reason = statusUnknown, agentReasonInterfaceDiffers
		c.Detail = facts + "; it differs from the declaration in " + strings.Join(differs, ", ")
		if ev.running {
			c.Next = "the running agent converges it back on its next 30s check; if this stays, read its log for the check's error"
		} else {
			c.Next = "nothing converges it while the agent is stopped; start the agent, and it converges the interface to the declaration"
		}
		return
	}
	c.Status = statusOK
	c.Detail = facts + agentKernelStoppedNote(ev)
}

// agentKernelLinkNext は、インタフェースが欠けた実行の次の手である。
func agentKernelLinkNext(ev agentKernelEvidence, fix string) string {
	if ev.running {
		return "the running agent repairs this on its next 30s check; if it stays, read its log with journalctl -u wgft-agent, or docker logs for a container"
	}
	return "start the agent; " + fix + ". Until then the kernel does not forward for it"
}

// agentInterfaceFacts はインタフェースの値を 1 句にまとめる。最終ハンドシェイクは値として示し、健全さを
// 判定しない(10.2c 節の「2 つのコマンドの境目」)。
func agentInterfaceFacts(now time.Time, ki agent.DoctorKernelInterface) string {
	key := "the current key"
	if ki.Ownership == agent.KernelOwnershipPrevious {
		key = "the previous key"
	}
	parts := []string{fmt.Sprintf("%s is up with %s, mtu %d, address %s", ki.Name, key, ki.MTU, orDash(strings.Join(ki.Addresses, ", ")))}
	parts = append(parts, agentPeersText(now, ki))
	return strings.Join(parts, "; ")
}

func agentPeersText(now time.Time, ki agent.DoctorKernelInterface) string {
	if len(ki.Peers) == 0 {
		return "no peer"
	}
	var out []string
	for i, p := range ki.Peers {
		if i == 2 {
			out = append(out, agentAndMore(len(ki.Peers)-2))
			break
		}
		s := fmt.Sprintf("peer %s allows %s, endpoint %s", shortHash(p.PublicKey), orDash(strings.Join(p.AllowedIPs, ", ")), orDash(p.Endpoint))
		if p.Keepalive > 0 {
			s += ", keepalive " + p.Keepalive.String()
		}
		s += ", " + agentHandshakeText(now, p.LastHandshake)
		s += fmt.Sprintf(", %d bytes received and %d sent", p.RxBytes, p.TxBytes)
		out = append(out, s)
	}
	return strings.Join(out, "; ")
}

// agentTableCheck は dataplane.table を組み立てる(10.2c 節)。
func agentTableCheck(c *agentDoctorCheck, ev agentKernelEvidence) {
	t := ev.kernel.Table
	switch {
	case t.ReadError != "" && t.NeedsNetAdmin:
		c.Status, c.Reason, c.evidenceUnreachable = statusUnknown, agentReasonNeedsNetAdmin, true
		c.Detail = "table inet wgft_agent cannot be read without CAP_NET_ADMIN, which this command does not hold, so whether the kernel still forwards the rules is not known"
		c.Next = agentNeedsNetAdminNext
		return
	case t.ReadError != "":
		c.Status, c.Reason = statusUnknown, agentReasonKernelUnreadable
		c.Detail = "table inet wgft_agent could not be read: " + t.ReadError
		c.Next = "read it with nft list table inet wgft_agent"
		return
	case t.Source == "":
		c.Status, c.Reason = statusUnknown, agentReasonNoLastState
		c.Detail = "agent.json holds neither a publication record nor a full state, so there is nothing to compare table inet wgft_agent with"
		if t.Present {
			c.Detail += "; the table is there"
		}
		c.Next = "start the agent and let it reach the server; it publishes the table from the full state it receives"
		return
	case !t.Present:
		c.Status, c.Reason = statusFailed, agentReasonTableMissing
		c.Detail = "there is no table inet wgft_agent, so the kernel forwards none of this agent's rules" + agentKernelStoppedNote(ev)
		c.Next = agentKernelTableNext(ev)
		return
	}
	compared := agentTableCompared(t)
	// stale は、名前の解決に失敗して直前の解決の結果で転送を続けているだけのルールである(設計文書
	// 7b.2 節)。DNAT は残っており転送の停止は観測していないので、error でも bad に数えない(10.2c 節、
	// 2026-09-25 の所有者の決定)。理由の後ろに試し接続か ip_forward の誤りが続くルールは bad のままで
	// ある。文言は server doctor と同じ関数で読む。
	var bad, good, stale []agent.DoctorRule
	for _, r := range ev.rules {
		if r.State != proto.StatusError {
			good = append(good, r)
			continue
		}
		if _, rest, ok := doctor.StaleResolution(r.Reason); ok && rest == "" {
			stale = append(stale, r)
			continue
		}
		bad = append(bad, r)
	}
	staleNote := agentStaleText(stale)
	switch {
	case t.MissingCount > 0:
		// 転送を担う行の欠けだけが FAILED である。守りの行の欠けは、同じ所見に添えるだけにする
		// (10.2c 節の「dataplane.table の判定」)
		c.Status, c.Reason = statusFailed, agentReasonTableRowsMissing
		c.Detail = fmt.Sprintf("table inet wgft_agent lacks %d item%s that forwarding needs, among those %s: %s", t.MissingCount, pluralS(t.MissingCount), compared, agentItemsText(t.Missing, t.MissingCount)) +
			agentKernelStoppedNote(ev)
		if t.GuardMissingCount > 0 {
			c.Detail += ". " + agentGuardText(t)
		}
		if ch := agentChangeText(t); ch != "" {
			c.Detail += ". " + ch
		}
		if len(bad) > 0 {
			c.Detail += fmt.Sprintf(". Rules in error besides, %d: %s", len(bad), strings.Join(agentKernelRuleLines(bad), "; "))
		}
		c.Detail += staleNote
		c.Next = agentKernelTableNext(ev)
		return
	case len(bad) > 0:
		c.Status, c.Reason = statusFailed, agentReasonListenerError
		c.Detail = fmt.Sprintf("%d of %d rule%s cannot serve: %s", len(bad), len(ev.rules), pluralS(len(ev.rules)), strings.Join(agentKernelRuleLines(bad), "; "))
		if len(good) > 0 {
			c.Detail += fmt.Sprintf(". Rules without an error: %d", len(good))
		}
		c.Detail += staleNote
		if t.GuardMissingCount > 0 {
			c.Detail += ". " + agentGuardText(t)
		}
		if ch := agentChangeText(t); ch != "" {
			c.Detail += ". " + ch
		}
		c.Detail += agentKernelStoppedNote(ev)
		c.Next = "a rule without DNAT names why: a target outside WGFT_AGENT_ALLOW_TARGETS, a name that does not resolve, or a loopback target, which kernel mode does not forward to; " +
			"use the host's LAN address for a service on this host. A rule with DNAT in place and an error names a target that does not answer, " +
			"including one at the address kept from the last successful resolution, or net.ipv4.ip_forward"
		return
	case t.GuardMissingCount > 0:
		c.Status, c.Reason = statusUnknown, agentReasonGuardRowsMissing
		c.Detail = agentGuardText(t)
		if ch := agentChangeText(t); ch != "" {
			c.Detail += ". " + ch
		}
		c.Detail += staleNote + agentKernelStoppedNote(ev)
		if ev.running {
			c.Next = "the running agent publishes the table again on its next 30s check; if they stay missing, another program on this host removes them"
		} else {
			c.Next = "start the agent; it publishes the whole table again on start. Until then nothing puts these rows back"
		}
		return
	case ev.publishError != "":
		c.Status, c.Reason = statusUnknown, agentReasonPublishFailed
		c.Detail = "the agent could not publish its latest full state, so the table from the previous publication keeps forwarding: " + ev.publishError + staleNote
		c.Next = "the agent retries every 30s; the server shows the lag as agent.rules_received in wgft server doctor. Read the error above and the agent's log"
		return
	case t.UnexpectedCount > 0 || t.MovedCount > 0:
		c.Status, c.Reason = statusUnknown, agentReasonTableChanged
		c.Detail = fmt.Sprintf("table inet wgft_agent holds every row %s. %s", compared, agentChangeText(t)) + staleNote + agentKernelStoppedNote(ev)
		if ev.running {
			c.Next = "the running agent publishes the table again on its next 30s check; if the change keeps coming back, another program on this host writes into the table"
		} else {
			c.Next = "start the agent; it publishes the table again. Whether the added or moved items stop forwarding is not known here"
		}
		return
	}
	if len(stale) > 0 && ev.running {
		c.Status, c.Reason = statusUnknown, agentReasonResolveFailed
		c.Detail = fmt.Sprintf("table inet wgft_agent holds everything %s, but the target name of %d rule%s does not resolve; the kernel keeps forwarding %s to the address from the last successful resolution: %s",
			compared, len(stale), pluralS(len(stale)), itThem(len(stale)), strings.Join(agentKernelRuleLines(stale), "; "))
		// OK の枝と同じく、30 秒ごとの見直しの失敗を添える。表が UNKNOWN のときに消さないためである
		if ev.checkError != "" {
			c.Detail += "; the last 30s check failed: " + ev.checkError
		}
		c.Next = "fix name resolution on this host; until then new connections still go to the address from the last successful resolution, which may no longer be the right one"
		return
	}
	summary := fmt.Sprintf("table inet wgft_agent holds everything %s", compared)
	if len(ev.rules) == 0 {
		summary += "; there are no rules to publish"
	} else {
		summary += fmt.Sprintf("; %d rule%s: %s", len(ev.rules), pluralS(len(ev.rules)), strings.Join(agentKernelRuleLines(ev.rules), "; "))
	}
	if ev.checkError != "" {
		summary += "; the last 30s check failed: " + ev.checkError
	}
	if !ev.running {
		c.Status, c.Reason = statusUnknown, agentReasonNotRunning
		c.Detail = summary + agentKernelStoppedNote(ev) + ". Whether TCP targets answer is tested only by the running agent, so it is not known now"
		c.Next = "the kernel keeps forwarding these rules while the agent is stopped. Start the agent to have its changes, name re-resolution and target checks back"
		return
	}
	c.Status = statusOK
	c.Detail = summary
}

// itThem returns "it" for n == 1 and "them" otherwise, for a pronoun that stands for a count of rules.
func itThem(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

// agentStaleText は、名前の解決に失敗して直前の解決の結果で転送を続けているルールを、他の所見に
// 添える 1 文にする。無ければ空である。
func agentStaleText(stale []agent.DoctorRule) string {
	if len(stale) == 0 {
		return ""
	}
	return fmt.Sprintf(". Rules still forwarding from the last successful resolution while their name does not resolve, %d: %s",
		len(stale), strings.Join(agentKernelRuleLines(stale), "; "))
}

// agentGuardText は守りの行の欠けを述べる。drop の行は層になっているので、開きうる面は欠けた行の組み合わせ
// から来る値(GuardEffects)で言い、1 行だけの欠けでまだ閉じている面は、残っている行が閉じていると言う。表に
// 位置の違う行か加わった行があれば、転送が続きうるとも、残っている行がまだ閉じているとも言わない。加わった
// 行は残っている drop の行より前でパケットを通しうるので、どちらも言い切れないためである(10.2c 節)。
func agentGuardText(t agent.DoctorKernelTable) string {
	s := fmt.Sprintf("guard rows of table inet wgft_agent are missing: %s", agentItemsText(t.GuardMissing, t.GuardMissingCount))
	unchanged := t.UnexpectedCount == 0 && t.MovedCount == 0
	if unchanged {
		s += ". Forwarding may still work without them"
	}
	var effects []string
	for _, e := range t.GuardEffects {
		switch e {
		case agent.KernelEffectHost:
			effects = append(effects, "traffic from the tunnel may reach ports on this host that wgft does not publish")
		case agent.KernelEffectOtherDNAT:
			effects = append(effects, "traffic from the tunnel may reach other tables' DNAT, such as ports a container runtime publishes")
		case agent.KernelEffectLAN:
			effects = append(effects, "packets from the tunnel that no rule DNATs may be forwarded to LAN hosts")
		case agent.KernelEffectHairpin:
			effects = append(effects, "traffic from the tunnel may be forwarded back into it, such as a DNAT whose target lies through the tunnel")
		case agent.KernelEffectToTunnel:
			effects = append(effects, "packets that answer no forwarded flow may be forwarded into the tunnel")
		case agent.KernelEffectMSS:
			effects = append(effects, "large TCP transfers may stall on a path that drops ICMP")
		}
	}
	if len(effects) > 0 {
		s += ". Without them, " + strings.Join(effects, "; ")
	}
	var closed []string
	for _, c := range t.GuardClosed {
		switch c {
		case agent.KernelClosedHostByFilterPre:
			closed = append(closed, "the drop row in filter_pre still keeps the tunnel from ports on this host")
		case agent.KernelClosedHostByInput:
			closed = append(closed, "the drop row in input still keeps the tunnel from ports on this host")
		case agent.KernelClosedLANByFilterPre:
			closed = append(closed, "the drop row in filter_pre still keeps packets that no rule DNATs from the LAN")
		case agent.KernelClosedLANByForward:
			closed = append(closed, "the drop row in forward still keeps packets that no rule DNATs from the LAN")
		}
	}
	if len(closed) > 0 && unchanged {
		s += ". " + upperFirst(strings.Join(closed, "; "))
	}
	return s
}

// agentChangeText は、位置の違う行と加わった行を述べる。どちらも無ければ空である。
func agentChangeText(t agent.DoctorKernelTable) string {
	var parts []string
	if t.MovedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d row%s that wgft writes in another position: %s", t.MovedCount, pluralS(t.MovedCount),
			agentItemsText(t.Moved, t.MovedCount)))
	}
	if t.UnexpectedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d item%s wgft does not write: %s", t.UnexpectedCount, pluralS(t.UnexpectedCount),
			agentItemsText(t.Unexpected, t.UnexpectedCount)))
	}
	if len(parts) == 0 {
		return ""
	}
	return "The table also has " + strings.Join(parts, "; and ") + ". Whether these stop forwarding is not known"
}

// agentTableCompared は、何と比べたかを 1 句で言う。
func agentTableCompared(t agent.DoctorKernelTable) string {
	if t.Source == agent.KernelTableFromDeclaration {
		return fmt.Sprintf("that the full state of generation %d declares; no publication record exists, so only each rule's DNAT was compared", t.Generation)
	}
	return fmt.Sprintf("that the publication of generation %d recorded", t.Generation)
}

func agentKernelTableNext(ev agentKernelEvidence) string {
	if ev.running {
		return "the running agent publishes the table again on its next 30s check; if this stays, read its log with journalctl -u wgft-agent, or docker logs for a container"
	}
	return "start the agent; it publishes the whole table again on start. Until then the kernel does not forward what is missing"
}

func agentItemsText(items []string, total int) string {
	s := strings.Join(items, "; ")
	if total > len(items) {
		s += "; " + agentAndMore(total-len(items))
	}
	return s
}

// agentKernelRuleLines はルールごとの 1 句を組み立てる。DNAT を置いたポートの数を示し、DNAT を置いたまま
// error を報告するルールと、DNAT を持たないルールを見分けられるようにする(10.2c 節)。
func agentKernelRuleLines(rules []agent.DoctorRule) []string {
	out := make([]string, 0, agentMaxRuleLines+1)
	for i, r := range rules {
		if i == agentMaxRuleLines {
			out = append(out, agentAndMore(len(rules)-agentMaxRuleLines))
			break
		}
		line := fmt.Sprintf("%s %s: DNAT on %d of %d port%s", r.ID, orDash(string(r.Proto)), r.DNATPorts, r.Ports, pluralS(r.Ports))
		if r.State == proto.StatusError && r.Reason != "" {
			line += ", " + r.Reason
		}
		out = append(out, line)
	}
	return out
}

// agentForwardingCheck は host.forwarding を組み立てる(10.2c 節)。
func agentForwardingCheck(c *agentDoctorCheck, ev agentKernelEvidence) {
	f := ev.kernel.Forwarding
	var notes []string
	if len(f.RPFilterStrict) > 0 {
		notes = append(notes, "rp_filter is 1, strict, for "+strings.Join(f.RPFilterStrict, " and "))
	}
	switch {
	case f.IPForwardError != "":
		c.Status, c.Reason = statusUnknown, agentReasonIPForwardUnreadable
		c.Detail = "net.ipv4.ip_forward could not be read: " + f.IPForwardError
		c.Next = "read it with sysctl net.ipv4.ip_forward"
		return
	case f.IPForward != "1":
		c.Status, c.Reason = statusFailed, agentReasonIPForwardOff
		c.Detail = "net.ipv4.ip_forward is " + f.IPForward + ", so the kernel forwards nothing from the tunnel to the LAN; only rules whose target is this host itself are reached" +
			agentKernelStoppedNote(ev)
		c.Next = "set it with sysctl -w net.ipv4.ip_forward=1, or restart the agent, which sets it on start. If something on this host keeps setting it to 0, " +
			"find it in /etc/sysctl.d and in the container runtime's settings"
		return
	case f.PolicyNeedsNetAdmin:
		c.Status, c.Reason, c.evidenceUnreachable = statusUnknown, agentReasonNeedsNetAdmin, true
		c.Detail = "net.ipv4.ip_forward is 1, but the other nftables tables cannot be read without CAP_NET_ADMIN, which this command does not hold, so a forward chain that drops by default would not show"
		if len(notes) > 0 {
			c.Detail += "; " + strings.Join(notes, "; ")
		}
		c.Next = agentNeedsNetAdminNext
		return
	case len(f.PolicyDrops) > 0:
		c.Status, c.Reason = statusUnknown, agentReasonForwardPolicyDrop
		verb := " drops"
		if len(f.PolicyDrops) > 1 {
			verb = " drop"
		}
		c.Detail = "net.ipv4.ip_forward is 1, and " + strings.Join(f.PolicyDrops, ", ") + verb + " forwarded packets by default"
		if len(notes) > 0 {
			c.Detail += "; " + strings.Join(notes, "; ")
		}
		c.Next = "forwarding from the tunnel to the LAN stops there unless that table accepts it, for example with an accept for packets in from the tunnel interface " +
			"and for established packets out to it. wgft does not change other tables"
		return
	case len(f.RPFilterStrict) > 0:
		c.Status, c.Reason = statusUnknown, agentReasonRPFilterStrict
		c.Detail = "net.ipv4.ip_forward is 1, and " + strings.Join(notes, "; ")
		c.Next = "on a home with more than one LAN segment, strict rp_filter can drop forwarded replies; wgft does not change it. Set it to 2, loose, if replies go missing"
		return
	}
	c.Status = statusOK
	c.Detail = "net.ipv4.ip_forward is 1, no other table drops forwarded packets by default, and rp_filter is not strict"
	if f.PolicyError != "" {
		c.Detail = "net.ipv4.ip_forward is 1 and rp_filter is not strict; the other tables could not be read: " + f.PolicyError
	}
	c.Detail += agentKernelStoppedNote(ev)
}

// agentPrivilegesWithAgent は host.privileges に、稼働中のエージェントの実行主体と、カーネルモードでは
// その CAP_NET_ADMIN を加える(10.2c 節)。呼び出し元の権限の不足は、この判定より先に効く。
func agentPrivilegesWithAgent(c *agentDoctorCheck, live agentLive, mode string) {
	if live.Resp == nil || live.Resp.Process == nil {
		return
	}
	p := live.Resp.Process
	who := fmt.Sprintf("uid %d", p.UID)
	if p.User != "" {
		who += ", " + p.User
	}
	switch {
	case c.Reason == agentReasonPermissionDenied:
		return
	case c.Reason == agentReasonRunningAsRoot:
		c.Detail += "; the running agent runs as " + who
		if mode == credentials.ModeKernel && p.NetAdmin != nil {
			if *p.NetAdmin {
				c.Detail += " and holds CAP_NET_ADMIN"
			} else {
				c.Detail += " and does not hold CAP_NET_ADMIN"
			}
		}
		return
	}
	if mode != credentials.ModeKernel || p.NetAdmin == nil || c.Status != statusOK {
		return
	}
	if *p.NetAdmin {
		c.Detail += "; the running agent holds CAP_NET_ADMIN, which kernel mode needs"
		return
	}
	c.Status, c.Reason = statusFailed, agentReasonAgentLacksNetAdmin
	c.Detail += "; the running agent, " + who + ", does not hold CAP_NET_ADMIN, which kernel mode needs to keep the interface and the table converged"
	c.Next = "give the agent CAP_NET_ADMIN, for example with AmbientCapabilities=CAP_NET_ADMIN in its systemd unit, and restart it"
}
