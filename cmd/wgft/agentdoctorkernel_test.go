package main

import (
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは `wgft agent doctor` のカーネルモードの検査の表のテストである(設計文書 10.2c 節の
// 「カーネルモードのエージェント」の項)。節が定めた規則をそのまま入力に写し、場面ごとの状態、理由の
// 符号、終了コードを確かめる。カーネルの読み方そのものは internal/agent のテストが確かめる。

// kernelEvidence は、宣言どおりの wgft0、記録どおりのテーブル、転送の設定を持つホストの読みである。
func kernelEvidence() *agent.DoctorKernel {
	return &agent.DoctorKernel{
		Interface: agent.DoctorKernelInterface{
			Name: "wgft0", Exists: true, Kind: "wireguard", Up: true, Ownership: agent.KernelOwnershipCurrent,
			MTU: 1420, Addresses: []string{"10.200.0.2/24"},
			Peers: []agent.DoctorKernelPeer{{PublicKey: "c2VydmVyLWtleQ==", AllowedIPs: []string{"10.200.0.1/32"}, Endpoint: "203.0.113.10:51820",
				Keepalive: 25 * time.Second, LastHandshake: testLiveNow.Add(-40 * time.Second), RxBytes: 100, TxBytes: 200}},
			Declared: true, ServerAddress: "10.200.0.1", PeerOK: true, RouteInterface: "wgft0",
		},
		Table: agent.DoctorKernelTable{Present: true, Source: agent.KernelTableFromRecord, Generation: 12,
			Rules: []agent.DoctorRule{{ID: "r_1", State: proto.StatusOK, Proto: proto.TCP, Ports: 1, DNATPorts: 1}}},
		Forwarding: agent.DoctorKernelForwarding{IPForward: "1"},
	}
}

func kernelCredentials() *credentials.Credentials {
	f := registeredCredentials()
	f.Mode = credentials.ModeKernel
	return f
}

// kernelRuntime は稼働中のカーネルモードのエージェントの応答を組み、渡された手で書き換える。
func kernelRuntime(edit func(st *agent.DoctorRuntimeState)) *agent.DoctorResponse {
	resp := runtimeResponse(func(st *agent.DoctorRuntimeState) {
		st.Mode = credentials.ModeKernel
		st.Budgets, st.RefusalsSince = nil, time.Time{}
		st.Rules = []agent.DoctorRule{{ID: "r_1", State: proto.StatusOK, Proto: proto.TCP, Ports: 1, DNATPorts: 1}}
		st.Kernel = kernelEvidence()
		edit(st)
	})
	netAdmin := true
	resp.Process = &agent.DoctorProcess{UID: 999, User: "wgft", NetAdmin: &netAdmin}
	return resp
}

type kernelScenario struct {
	name string
	// stopped は、止まっているエージェントの場面である。readKernel はその読みを与える
	stopped    bool
	readKernel func(k *agent.DoctorKernel)
	// resp は稼働中のエージェントの応答である
	resp     *agent.DoctorResponse
	creds    func(f *credentials.Credentials)
	root     bool
	dial     func(string) (net.Conn, error)
	want     []wantCheck
	wantExit int
	// wantDetail と wantNext は、所見と次に見るものに必ず含まれる語である
	wantDetail map[string]string
	wantNext   map[string]string
	// wantUnreachable は、層 2 に当たる検査である
	wantUnreachable []string
	// wantAbsent は、所見に含まれてはならない語である
	wantAbsent map[string]string
}

// staleKernelReason は、カーネルモードのエージェントが名前の解決に失敗して直前の解決の結果で転送を
// 続けているルールに付ける理由である(internal/agent の staleReason の形、7b.2 節)。
const staleKernelReason = `name resolution of target host "game.lan" failed: lookup game.lan: no such host; still forwarding to 192.168.1.20 from the last successful resolution`

func TestAgentDoctorKernelScenarios(t *testing.T) {
	scenarios := []kernelScenario{
		{
			name:    "a stopped agent whose interface, table and forwarding are in place",
			stopped: true,
			want: []wantCheck{
				{agentCheckProcess, statusFailed, agentReasonNotRunning},
				{agentCheckDPInterface, statusOK, ""},
				{agentCheckDPTable, statusUnknown, agentReasonNotRunning},
				{agentCheckForwarding, statusOK, ""},
				{agentCheckListeners, statusNotTested, agentReasonKernelMode},
				{agentCheckSessions, statusNotTested, agentReasonKernelMode},
				{agentCheckRefusals, statusNotTested, agentReasonKernelMode},
				{agentCheckWatchdog, statusNotTested, agentReasonKernelMode},
				{agentCheckAllowTargets, statusUnknown, agentReasonNotRunning},
				{agentCheckTunnelLocal, statusSkipped, agentReasonNotRunning},
			},
			wantExit: 0,
			wantDetail: map[string]string{
				agentCheckProcess: "may still be forwarding",
				agentCheckDPTable: "Whether TCP targets answer is tested only by the running agent",
			},
		},
		{
			name:    "a stopped agent whose table lost a DNAT row",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Table.MissingCount, k.Table.Missing = 1, []string{"DNAT tcp 2456 of rule r_1 to 192.168.1.20:2456"}
			},
			want: []wantCheck{
				{agentCheckDPTable, statusFailed, agentReasonTableRowsMissing},
			},
			wantExit:   1,
			wantDetail: map[string]string{agentCheckDPTable: "DNAT tcp 2456 of rule r_1"},
			wantNext:   map[string]string{agentCheckDPTable: "start the agent"},
		},
		{
			// 欠けても転送が止まらない守りの行だけが欠けた表は、転送を担えないとは言えない(10.2c 節)
			name:    "a stopped agent whose table lost only guard rows",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Table.GuardMissingCount, k.Table.GuardMissing = 2, []string{"filter_pre: drop the rest from wgft0", "input: drop the rest from wgft0"}
				k.Table.GuardEffects = []string{agent.KernelEffectHost, agent.KernelEffectOtherDNAT}
			},
			want:       []wantCheck{{agentCheckDPTable, statusUnknown, agentReasonGuardRowsMissing}},
			wantExit:   0,
			wantDetail: map[string]string{agentCheckDPTable: "Forwarding may still work without them. Without them, traffic from the tunnel may reach ports on this host that wgft does not publish"},
			wantNext:   map[string]string{agentCheckDPTable: "start the agent"},
		},
		{
			// 行を消さずに drop を先頭へ移した表は、欠けではなく位置の違いである(10.2c 節)。効果が分からない
			// 変更として table_changed とし、転送が続きうるとは言わない
			name:    "a stopped agent whose drop row moved to the top",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Table.MovedCount, k.Table.Moved = 1, []string{"filter_pre: drop the rest from wgft0, now at row 1"}
			},
			want:       []wantCheck{{agentCheckDPTable, statusUnknown, agentReasonTableChanged}},
			wantExit:   0,
			wantDetail: map[string]string{agentCheckDPTable: "The table also has 1 row that wgft writes in another position: filter_pre: drop the rest from wgft0, now at row 1"},
			wantAbsent: map[string]string{agentCheckDPTable: "Forwarding may still work"},
		},
		{
			name:    "a missing guard row and a moved row",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Table.GuardMissingCount, k.Table.GuardMissing, k.Table.GuardEffects = 1, []string{"input: drop the rest from wgft0"}, []string{agent.KernelEffectHost}
				k.Table.MovedCount, k.Table.Moved = 1, []string{"forward: drop the rest from wgft0, now at row 1"}
			},
			want:       []wantCheck{{agentCheckDPTable, statusUnknown, agentReasonGuardRowsMissing}},
			wantExit:   0,
			wantDetail: map[string]string{agentCheckDPTable: "in another position: forward: drop the rest from wgft0"},
			wantAbsent: map[string]string{agentCheckDPTable: "Forwarding may still work"},
		},
		{
			name:    "a missing guard row and an added row",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Table.GuardMissingCount, k.Table.GuardMissing = 1, []string{"filter_pre: drop the rest from wgft0"}
				k.Table.UnexpectedCount, k.Table.Unexpected = 1, []string{"chain filter_pre: row 1 is not one wgft writes"}
			},
			want:       []wantCheck{{agentCheckDPTable, statusUnknown, agentReasonGuardRowsMissing}},
			wantDetail: map[string]string{agentCheckDPTable: "1 item wgft does not write: chain filter_pre: row 1"},
			wantAbsent: map[string]string{agentCheckDPTable: "Forwarding may still work"},
		},
		{
			// drop の行は層になっている。forward の drop だけの欠けでは、filter_pre の drop が LAN への面を
			// 閉じたままである(10.2c 節)
			name:    "a missing forward drop alone opens nothing",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Table.GuardMissingCount, k.Table.GuardMissing = 1, []string{"forward: drop the rest from wgft0"}
				k.Table.GuardClosed = []string{agent.KernelClosedLANByFilterPre}
			},
			want:       []wantCheck{{agentCheckDPTable, statusUnknown, agentReasonGuardRowsMissing}},
			wantDetail: map[string]string{agentCheckDPTable: "Forwarding may still work without them. The drop row in filter_pre still keeps packets that no rule DNATs from the LAN"},
			wantAbsent: map[string]string{agentCheckDPTable: "Without them"},
		},
		{
			// 加わった行は残っている drop の行より前でパケットを通しうるので、まだ閉じているとは言わない
			// (10.2c 節)。input の drop を消し、filter_pre の先頭に accept を加えた表である
			name:    "a missing input drop and an accept added to filter_pre",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Table.GuardMissingCount, k.Table.GuardMissing = 1, []string{"input: drop the rest from wgft0"}
				k.Table.GuardClosed = []string{agent.KernelClosedHostByFilterPre}
				k.Table.UnexpectedCount, k.Table.Unexpected = 1, []string{"chain filter_pre: row 1 is not one wgft writes"}
			},
			want:       []wantCheck{{agentCheckDPTable, statusUnknown, agentReasonGuardRowsMissing}},
			wantDetail: map[string]string{agentCheckDPTable: "1 item wgft does not write: chain filter_pre: row 1"},
			wantAbsent: map[string]string{agentCheckDPTable: "still keeps"},
		},
		{
			name:    "a missing forward drop and a moved row",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Table.GuardMissingCount, k.Table.GuardMissing = 1, []string{"forward: drop the rest from wgft0"}
				k.Table.GuardClosed = []string{agent.KernelClosedLANByFilterPre}
				k.Table.MovedCount, k.Table.Moved = 1, []string{"filter_pre: accept established and related flows from wgft0, now at row 4"}
			},
			want:       []wantCheck{{agentCheckDPTable, statusUnknown, agentReasonGuardRowsMissing}},
			wantAbsent: map[string]string{agentCheckDPTable: "still keeps"},
		},
		{
			name:    "missing filter_pre and forward drops open the LAN",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Table.GuardMissingCount, k.Table.GuardMissing = 2, []string{"filter_pre: drop the rest from wgft0", "forward: drop the rest from wgft0"}
				k.Table.GuardEffects = []string{agent.KernelEffectOtherDNAT, agent.KernelEffectLAN}
				k.Table.GuardClosed = []string{agent.KernelClosedHostByInput}
			},
			want: []wantCheck{{agentCheckDPTable, statusUnknown, agentReasonGuardRowsMissing}},
			wantDetail: map[string]string{agentCheckDPTable: "Without them, traffic from the tunnel may reach other tables' DNAT, such as ports a container runtime publishes; " +
				"packets from the tunnel that no rule DNATs may be forwarded to LAN hosts. The drop row in input still keeps the tunnel from ports on this host"},
			wantAbsent: map[string]string{agentCheckDPTable: "may reach ports on this host"},
		},
		{
			name:    "a forwarding row missing and a moved row",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Table.MissingCount, k.Table.Missing = 1, []string{"postrouting: masquerade DNATed flows from wgft0 leaving by another interface"}
				k.Table.MovedCount, k.Table.Moved = 1, []string{"filter_pre: drop the rest from wgft0, now at row 1"}
			},
			want:       []wantCheck{{agentCheckDPTable, statusFailed, agentReasonTableRowsMissing}},
			wantExit:   1,
			wantDetail: map[string]string{agentCheckDPTable: "in another position"},
		},
		{
			name: "a running agent whose table lost only guard rows",
			resp: kernelRuntime(func(st *agent.DoctorRuntimeState) {
				st.Kernel.Table.GuardMissingCount, st.Kernel.Table.GuardMissing = 1, []string{"input: drop the rest from wgft0"}
			}),
			want:     []wantCheck{{agentCheckDPTable, statusUnknown, agentReasonGuardRowsMissing}},
			wantExit: 0,
		},
		{
			name:    "a stopped agent whose table lost a forwarding row and a guard row",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Table.MissingCount, k.Table.Missing = 1, []string{"postrouting: masquerade DNATed flows from wgft0 leaving by another interface"}
				k.Table.GuardMissingCount, k.Table.GuardMissing = 1, []string{"filter_pre: drop the rest from wgft0"}
			},
			want:       []wantCheck{{agentCheckDPTable, statusFailed, agentReasonTableRowsMissing}},
			wantExit:   1,
			wantDetail: map[string]string{agentCheckDPTable: "guard rows of table inet wgft_agent are missing: filter_pre: drop the rest from wgft0"},
		},
		{
			name: "a rule error and a missing guard row",
			resp: kernelRuntime(func(st *agent.DoctorRuntimeState) {
				st.Rules[0].State, st.Rules[0].Reason = proto.StatusError, "target 192.168.1.20:2456: connection refused"
				st.Kernel.Table.GuardMissingCount, st.Kernel.Table.GuardMissing = 1, []string{"filter_pre: drop the rest from wgft0"}
			}),
			want:       []wantCheck{{agentCheckDPTable, statusFailed, agentReasonListenerError}},
			wantExit:   1,
			wantDetail: map[string]string{agentCheckDPTable: "guard rows of table inet wgft_agent are missing"},
		},
		{
			name:       "a stopped agent whose table is gone",
			stopped:    true,
			readKernel: func(k *agent.DoctorKernel) { k.Table.Present = false },
			want:       []wantCheck{{agentCheckDPTable, statusFailed, agentReasonTableMissing}},
			wantExit:   1,
		},
		{
			name:    "a stopped agent diagnosed without CAP_NET_ADMIN",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Interface = agent.DoctorKernelInterface{Name: "wgft0", Exists: true, Kind: "wireguard", Up: true, NeedsNetAdmin: true,
					Declared: true, ServerAddress: "10.200.0.1", RouteInterface: "wgft0"}
				k.Table = agent.DoctorKernelTable{ReadError: "listing tables: operation not permitted", NeedsNetAdmin: true, Source: agent.KernelTableFromRecord}
				k.Forwarding = agent.DoctorKernelForwarding{IPForward: "1", PolicyError: "operation not permitted", PolicyNeedsNetAdmin: true}
			},
			want: []wantCheck{
				{agentCheckDPInterface, statusUnknown, agentReasonNeedsNetAdmin},
				{agentCheckDPTable, statusUnknown, agentReasonNeedsNetAdmin},
				{agentCheckForwarding, statusUnknown, agentReasonNeedsNetAdmin},
			},
			wantExit:        2,
			wantUnreachable: []string{agentCheckDPInterface, agentCheckDPTable, agentCheckForwarding},
			wantNext:        map[string]string{agentCheckDPTable: "run this command as root"},
		},
		{
			name:    "a stopped agent without CAP_NET_ADMIN whose interface is missing",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Interface = agent.DoctorKernelInterface{Name: "wgft0", Ownership: agent.KernelOwnershipAbsent, Declared: true}
				k.Table = agent.DoctorKernelTable{ReadError: "operation not permitted", NeedsNetAdmin: true}
			},
			want: []wantCheck{
				{agentCheckDPInterface, statusFailed, agentReasonInterfaceMissing},
				{agentCheckDPTable, statusUnknown, agentReasonNeedsNetAdmin},
			},
			// 層 2 は層 1 に優先する
			wantExit: 2,
		},
		{
			name:       "a down interface",
			stopped:    true,
			readKernel: func(k *agent.DoctorKernel) { k.Interface.Up = false },
			want:       []wantCheck{{agentCheckDPInterface, statusFailed, agentReasonInterfaceDown}},
			wantExit:   1,
		},
		{
			// up の印は権限なしで読めるので、鍵を読めなくても down は FAILED と言える(10.2c 節)
			name:    "a down interface read without CAP_NET_ADMIN",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Interface = agent.DoctorKernelInterface{Name: "wgft0", Exists: true, Kind: "wireguard", NeedsNetAdmin: true, Declared: true}
			},
			want:     []wantCheck{{agentCheckDPInterface, statusFailed, agentReasonInterfaceDown}},
			wantExit: 1,
			// 鍵を読めないので、起動すれば up になるとは言い切らない
			wantDetail: map[string]string{agentCheckDPInterface: "whether it holds this agent's key could not be read"},
			wantNext:   map[string]string{agentCheckDPInterface: "if wgft0 holds its key"},
		},
		{
			// 鍵とピアを権限以外の理由で読めなかった down のインタフェースも、所有は分からない
			name:    "a down interface whose key could not be read",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Interface = agent.DoctorKernelInterface{Name: "wgft0", Exists: true, Kind: "wireguard", Declared: true,
					DeviceError: "read wgft0: no such device"}
			},
			want:       []wantCheck{{agentCheckDPInterface, statusFailed, agentReasonInterfaceDown}},
			wantExit:   1,
			wantDetail: map[string]string{agentCheckDPInterface: "whether it holds this agent's key could not be read: read wgft0: no such device"},
			wantNext:   map[string]string{agentCheckDPInterface: "if wgft0 holds its key"},
		},
		{
			name:    "another program's link under the interface name",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Interface.Kind, k.Interface.Ownership = "dummy", agent.KernelOwnershipNotWireGuard
			},
			want:     []wantCheck{{agentCheckDPInterface, statusFailed, agentReasonInterfaceNotOurs}},
			wantExit: 1,
		},
		{
			// 所有の判定は down より先である。他の所有者の down のインタフェースに「起動すれば up にする」と
			// 案内すると、エージェントは起動を拒んで再起動を繰り返す(10.2c 節)
			name:    "a keyless WireGuard interface that is down",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Interface.Up, k.Interface.Ownership = false, agent.KernelOwnershipKeyless
			},
			want:       []wantCheck{{agentCheckDPInterface, statusFailed, agentReasonInterfaceNotOurs}},
			wantExit:   1,
			wantDetail: map[string]string{agentCheckDPInterface: "holds no key"},
			wantNext:   map[string]string{agentCheckDPInterface: "ip link del wgft0"},
		},
		{
			name:    "another key's WireGuard interface that is down",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Interface.Up, k.Interface.Ownership = false, agent.KernelOwnershipForeign
			},
			want:     []wantCheck{{agentCheckDPInterface, statusFailed, agentReasonInterfaceNotOurs}},
			wantExit: 1,
		},
		{
			name:    "this agent's interface with the previous key, down",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Interface.Up, k.Interface.Ownership = false, agent.KernelOwnershipPrevious
			},
			want:     []wantCheck{{agentCheckDPInterface, statusFailed, agentReasonInterfaceDown}},
			wantExit: 1,
			wantNext: map[string]string{agentCheckDPInterface: "the agent sets it up again"},
		},
		{
			name:       "a WireGuard interface with another key",
			stopped:    true,
			readKernel: func(k *agent.DoctorKernel) { k.Interface.Ownership = agent.KernelOwnershipForeign },
			want:       []wantCheck{{agentCheckDPInterface, statusFailed, agentReasonInterfaceNotOurs}},
			wantExit:   1,
		},
		{
			name:       "no server peer",
			stopped:    true,
			readKernel: func(k *agent.DoctorKernel) { k.Interface.PeerOK, k.Interface.Differs = false, []string{"the peer"} },
			want:       []wantCheck{{agentCheckDPInterface, statusFailed, agentReasonPeerMissing}},
			wantExit:   1,
		},
		{
			name:    "the interface still holds the previous key",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Interface.Ownership, k.Interface.Differs = agent.KernelOwnershipPrevious, []string{"the key"}
			},
			want:       []wantCheck{{agentCheckDPInterface, statusUnknown, agentReasonInterfaceDiffers}},
			wantExit:   0,
			wantDetail: map[string]string{agentCheckDPInterface: "the previous key"},
			wantNext:   map[string]string{agentCheckDPInterface: "nothing converges it while the agent is stopped"},
		},
		{
			name:       "the route to the server leaves through another interface",
			resp:       kernelRuntime(func(st *agent.DoctorRuntimeState) { st.Kernel.Interface.RouteInterface = "tailscale0" }),
			want:       []wantCheck{{agentCheckDPInterface, statusUnknown, agentReasonRouteNotViaInterface}},
			wantExit:   0,
			wantDetail: map[string]string{agentCheckDPInterface: "goes through tailscale0"},
		},
		{
			name:       "ip_forward is 0",
			stopped:    true,
			readKernel: func(k *agent.DoctorKernel) { k.Forwarding.IPForward = "0" },
			want:       []wantCheck{{agentCheckForwarding, statusFailed, agentReasonIPForwardOff}},
			wantExit:   1,
		},
		{
			name:    "another table drops forwarded packets by default",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Forwarding.PolicyDrops = []string{"inet otherfw forward_drop"}
				k.Forwarding.RPFilterStrict = []string{"all"}
			},
			want:       []wantCheck{{agentCheckForwarding, statusUnknown, agentReasonForwardPolicyDrop}},
			wantExit:   0,
			wantDetail: map[string]string{agentCheckForwarding: "inet otherfw forward_drop drops forwarded packets by default"},
		},
		{
			name:       "strict rp_filter",
			stopped:    true,
			readKernel: func(k *agent.DoctorKernel) { k.Forwarding.RPFilterStrict = []string{"default"} },
			want:       []wantCheck{{agentCheckForwarding, statusUnknown, agentReasonRPFilterStrict}},
			wantExit:   0,
		},
		{
			name: "a healthy running agent",
			resp: kernelRuntime(func(*agent.DoctorRuntimeState) {}),
			want: []wantCheck{
				{agentCheckProcess, statusOK, ""},
				{agentCheckDPInterface, statusOK, ""},
				{agentCheckDPTable, statusOK, ""},
				{agentCheckForwarding, statusOK, ""},
				{agentCheckListeners, statusNotTested, agentReasonKernelMode},
				{agentCheckWatchdog, statusNotTested, agentReasonKernelMode},
				{agentCheckTransfer, statusUnknown, agentReasonNoThreshold},
				{agentCheckAllowTargets, statusOK, ""},
				{agentCheckPrivileges, statusOK, ""},
			},
			wantExit: 0,
			wantDetail: map[string]string{
				agentCheckTransfer:   "counted since the kernel created it",
				agentCheckPrivileges: "holds CAP_NET_ADMIN",
				agentCheckDPTable:    "DNAT on 1 of 1 port",
			},
		},
		{
			// 直前の解決の結果で転送を続けているだけのルールは、転送の停止ではない。server doctor と同じく
			// FAILED にせず、名前の解決の失敗として示す(10.2c 節、2026-09-25 の所有者の決定)
			name: "a rule that keeps forwarding to the last resolved address",
			resp: kernelRuntime(func(st *agent.DoctorRuntimeState) {
				st.Rules[0].State = proto.StatusError
				st.Rules[0].Reason = staleKernelReason
			}),
			want:       []wantCheck{{agentCheckDPTable, statusUnknown, agentReasonResolveFailed}},
			wantExit:   0,
			wantDetail: map[string]string{agentCheckDPTable: "does not resolve; the kernel keeps forwarding it to the address from the last successful resolution: r_1 tcp: DNAT on 1 of 1 port, name resolution of target host"},
			wantNext:   map[string]string{agentCheckDPTable: "fix name resolution on this host"},
		},
		{
			// 直前のアドレスの宛先も応えなければ、転送は宛先で止まっている。listener_error のままである
			name: "a rule forwarding to the last resolved address that refuses",
			resp: kernelRuntime(func(st *agent.DoctorRuntimeState) {
				st.Rules[0].State = proto.StatusError
				st.Rules[0].Reason = staleKernelReason + "; target 192.168.1.20:2456: dial tcp 192.168.1.20:2456: connect: connection refused"
			}),
			want:       []wantCheck{{agentCheckDPTable, statusFailed, agentReasonListenerError}},
			wantExit:   1,
			wantDetail: map[string]string{agentCheckDPTable: "connection refused"},
		},
		{
			// 停止中は、記録の理由に直前の解決の結果で転送を続けていることがあっても agent_not_running であり、
			// 所見のルールの一覧に理由を示す
			name:    "a stopped agent whose record holds a rule forwarding from the last resolution",
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Table.Rules[0].State, k.Table.Rules[0].Reason = proto.StatusError, staleKernelReason
			},
			want:       []wantCheck{{agentCheckDPTable, statusUnknown, agentReasonNotRunning}},
			wantExit:   0,
			wantDetail: map[string]string{agentCheckDPTable: "still forwarding to 192.168.1.20 from the last successful resolution"},
		},
		{
			name: "a rule refused by the allowlist",
			resp: kernelRuntime(func(st *agent.DoctorRuntimeState) {
				st.Rules[0] = agent.DoctorRule{ID: "r_1", State: proto.StatusError, Proto: proto.TCP, Ports: 1,
					Reason: "target 192.168.1.30:2456 is not in WGFT_AGENT_ALLOW_TARGETS"}
			}),
			want:       []wantCheck{{agentCheckDPTable, statusFailed, agentReasonListenerError}},
			wantExit:   1,
			wantDetail: map[string]string{agentCheckDPTable: "DNAT on 0 of 1 port"},
		},
		{
			name: "a stopped agent whose record holds a refused rule",
			creds: func(f *credentials.Credentials) {
				f.LastState.Rules[0].Target = "127.0.0.1:2456"
			},
			stopped: true,
			readKernel: func(k *agent.DoctorKernel) {
				k.Table.Rules[0] = agent.DoctorRule{ID: "r_1", State: proto.StatusError, Proto: proto.TCP, Ports: 1,
					Reason: "target 127.0.0.1 is a loopback address; kernel mode does not forward to loopback targets, use this host's LAN address"}
			},
			want:     []wantCheck{{agentCheckDPTable, statusFailed, agentReasonListenerError}},
			wantExit: 1,
		},
		{
			name: "the last full state could not be published",
			resp: kernelRuntime(func(st *agent.DoctorRuntimeState) {
				st.PublishError = "publish table inet wgft_agent: netlink receive: invalid argument"
			}),
			want:       []wantCheck{{agentCheckDPTable, statusUnknown, agentReasonPublishFailed}},
			wantExit:   0,
			wantDetail: map[string]string{agentCheckDPTable: "keeps forwarding"},
		},
		{
			name: "rows another program added",
			resp: kernelRuntime(func(st *agent.DoctorRuntimeState) {
				st.Kernel.Table.UnexpectedCount, st.Kernel.Table.Unexpected = 1, []string{"filter_pre: a row wgft does not write"}
			}),
			want:     []wantCheck{{agentCheckDPTable, statusUnknown, agentReasonTableChanged}},
			wantExit: 0,
		},
		{
			name:     "a running agent the server disabled",
			resp:     kernelRuntime(func(st *agent.DoctorRuntimeState) { st.AgentDisabled = true }),
			want:     []wantCheck{{agentCheckDPInterface, statusSkipped, agentReasonAgentDisabled}, {agentCheckDPTable, statusSkipped, agentReasonAgentDisabled}, {agentCheckForwarding, statusSkipped, agentReasonAgentDisabled}},
			wantExit: 0,
		},
		{
			name:       "a stopped agent the server disabled",
			stopped:    true,
			creds:      func(f *credentials.Credentials) { f.LastState.AgentDisabled = true },
			want:       []wantCheck{{agentCheckDPTable, statusSkipped, agentReasonAgentDisabled}, {agentCheckForwarding, statusSkipped, agentReasonAgentDisabled}},
			wantExit:   0,
			wantDetail: map[string]string{agentCheckDPTable: "until wgft agent enable home is run on the VPS"},
		},
		{
			name:     "a running kernel-mode agent from before the kernel reading",
			resp:     kernelRuntime(func(st *agent.DoctorRuntimeState) { st.Kernel = nil }),
			want:     []wantCheck{{agentCheckDPTable, statusSkipped, agentReasonDoctorUnsupported}},
			wantExit: 0,
		},
		{
			name: "a running agent diagnosed as root",
			resp: kernelRuntime(func(*agent.DoctorRuntimeState) {}),
			root: true,
			want: []wantCheck{{agentCheckPrivileges, statusUnknown, agentReasonRunningAsRoot}},
			wantDetail: map[string]string{
				agentCheckPrivileges: "the running agent runs as uid 999, wgft and holds CAP_NET_ADMIN",
			},
			wantNext: map[string]string{agentCheckPrivileges: "runuser -u wgft -- wgft agent doctor"},
		},
		{
			name: "a running agent without CAP_NET_ADMIN",
			resp: func() *agent.DoctorResponse {
				r := kernelRuntime(func(*agent.DoctorRuntimeState) {})
				no := false
				r.Process.NetAdmin = &no
				return r
			}(),
			want: []wantCheck{{agentCheckPrivileges, statusFailed, agentReasonAgentLacksNetAdmin}},
			// エージェント自身が答えた事実なので層 2 に入れず、host.privileges は総合判定を動かさない
			wantExit: 0,
		},
		{
			name:     "a running agent whose control socket refuses this command",
			resp:     kernelRuntime(func(*agent.DoctorRuntimeState) {}),
			dial:     func(string) (net.Conn, error) { return nil, &net.OpError{Op: "dial", Err: fs.ErrPermission} },
			want:     []wantCheck{{agentCheckDPTable, statusSkipped, agentReasonControlUnreachable}, {agentCheckListeners, statusNotTested, agentReasonKernelMode}},
			wantExit: 2,
		},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			in := testAgentDoctorInput(t, t.TempDir())
			f := kernelCredentials()
			if sc.creds != nil {
				sc.creds(f)
			}
			writeTestCredentials(t, in.CredentialsPath, f)
			in.ReadKernel = func(*credentials.Credentials, string) *agent.DoctorKernel {
				if !sc.stopped {
					t.Error("a running agent's kernel was read directly; only a stopped agent's is")
				}
				k := kernelEvidence()
				if sc.readKernel != nil {
					sc.readKernel(k)
				}
				return k
			}
			if !sc.stopped {
				holdTheLock(t, in.CredentialsPath)
				in.Dial = fakeDoctorSocket(t, liveReply(sc.resp))
				if sc.dial != nil {
					in.Dial = sc.dial
				}
			}
			if sc.root {
				in.Euid = func() int { return 0 }
			}
			rep := agentDiagnose(in)
			for _, w := range sc.want {
				c, ok := findAgentCheck(rep, w.id)
				if !ok {
					t.Fatalf("%s is missing", w.id)
				}
				if c.Status != w.status || c.Reason != w.reason {
					t.Errorf("%s = %s/%s, want %s/%s: %s", w.id, c.Status, c.Reason, w.status, w.reason, c.Detail)
				}
				if c.Status == statusFailed && c.Next == "" {
					t.Errorf("%s is FAILED with nothing to check next", w.id)
				}
			}
			for id, s := range sc.wantDetail {
				if c, _ := findAgentCheck(rep, id); !strings.Contains(c.Detail, s) {
					t.Errorf("%s detail = %q, want it to contain %q", id, c.Detail, s)
				}
			}
			for id, s := range sc.wantNext {
				if c, _ := findAgentCheck(rep, id); !strings.Contains(c.Next, s) {
					t.Errorf("%s next = %q, want it to contain %q", id, c.Next, s)
				}
			}
			for id, str := range sc.wantAbsent {
				if c, _ := findAgentCheck(rep, id); strings.Contains(c.Detail, str) {
					t.Errorf("%s detail = %q, want it without %q", id, c.Detail, str)
				}
			}
			for _, id := range sc.wantUnreachable {
				if c, _ := findAgentCheck(rep, id); !c.evidenceUnreachable {
					t.Errorf("%s does not put the run in layer 2", id)
				}
			}
			if got := agentDoctorExitCode(rep); sc.want != nil && got != sc.wantExit {
				t.Errorf("exit code = %d, want %d", got, sc.wantExit)
			}
		})
	}
}

// ユーザー空間モードのエージェントでは、カーネルモードの検査は NOT TESTED で並び、既存の検査の答えは
// 変わらない(7a.11 節の加算)。
func TestAgentDoctorUserspaceKeepsItsAnswers(t *testing.T) {
	in := testAgentDoctorInput(t, t.TempDir())
	healthyAgentForTest(t, &in)
	in.ReadKernel = func(*credentials.Credentials, string) *agent.DoctorKernel {
		t.Error("a userspace agent's kernel was read")
		return nil
	}
	rep := agentDiagnose(in)
	for _, id := range []string{agentCheckDPInterface, agentCheckDPTable, agentCheckForwarding} {
		if c, _ := findAgentCheck(rep, id); c.Status != statusNotTested || c.Reason != agentReasonUserspaceMode {
			t.Errorf("%s = %s/%s, want not_tested/%s", id, c.Status, c.Reason, agentReasonUserspaceMode)
		}
	}
	if c, _ := findAgentCheck(rep, agentCheckListeners); c.Status != statusOK || !c.verdict {
		t.Errorf("relay.listeners = %+v, want OK and moving the verdict", c)
	}
	if c, _ := findAgentCheck(rep, agentCheckProcess); !c.verdict {
		t.Error("agent.process stopped moving the verdict in userspace mode")
	}
	// 止まったユーザー空間モードのエージェントは、今までどおり終了コード 1 である
	in = testAgentDoctorInput(t, t.TempDir())
	stoppedAgentForTest(t, &in)
	if got := agentDoctorExitCode(agentDiagnose(in)); got != 1 {
		t.Errorf("a stopped userspace agent exits %d, want 1", got)
	}
}

// 稼働中のエージェントの答えのモードは、認証情報ファイルの記録より先に効く。
func TestAgentDoctorModeFromTheRunningAgent(t *testing.T) {
	in := testAgentDoctorInput(t, t.TempDir())
	writeTestCredentials(t, in.CredentialsPath, registeredCredentials()) // 記録はユーザー空間モード
	holdTheLock(t, in.CredentialsPath)
	in.Dial = fakeDoctorSocket(t, liveReply(kernelRuntime(func(*agent.DoctorRuntimeState) {})))
	rep := agentDiagnose(in)
	if c, _ := findAgentCheck(rep, agentCheckDPTable); c.Status != statusOK {
		t.Errorf("dataplane.table = %s/%s, want the running agent's kernel mode to count", c.Status, c.Reason)
	}
	// 認証情報ファイルを読めず、稼働中のエージェントにも繋がらなければ、モードは分からない
	in = testAgentDoctorInput(t, t.TempDir())
	rep = agentDiagnose(in)
	if c, _ := findAgentCheck(rep, agentCheckDPTable); c.Status != statusSkipped || c.Reason != agentReasonCredentialsMissing {
		t.Errorf("dataplane.table without credentials = %s/%s", c.Status, c.Reason)
	}
}

// 層 2 の実行の案内は、欠けた証拠がカーネルの状態なら root での実行も示す(10.2c 節の例外)。
func TestAgentDoctorIncompleteNamesRootForKernelState(t *testing.T) {
	in := testAgentDoctorInput(t, t.TempDir())
	writeTestCredentials(t, in.CredentialsPath, kernelCredentials())
	in.ReadKernel = func(*credentials.Credentials, string) *agent.DoctorKernel {
		k := kernelEvidence()
		k.Table = agent.DoctorKernelTable{ReadError: "operation not permitted", NeedsNetAdmin: true}
		return k
	}
	rep := agentDiagnose(in)
	var buf strings.Builder
	writeAgentDoctorReport(&buf, rep)
	if !strings.Contains(buf.String(), "run this command as root") {
		t.Errorf("the Incomplete section does not name root for the kernel state:\n%s", buf.String())
	}
	err := agentDoctorExit(rep)
	if err == nil || !strings.Contains(err.Error(), "as root") {
		t.Errorf("exit error = %v, want it to name root for the kernel state", err)
	}
}

// dataplane.table の判定は、転送の行の欠け、ルールの error、守りの行の欠け、公開の失敗、加わった行の順に見る(10.2c 節の
// 「dataplane.table の判定」)。ルール単位の失敗は、同じ実行に公開の失敗があっても FAILED のまま示し、
// 公開の失敗は、加わった行より先に示す。
func TestAgentDoctorTableOrder(t *testing.T) {
	ruleError := func(st *agent.DoctorRuntimeState) {
		st.Rules[0].State, st.Rules[0].Reason = proto.StatusError, "target 192.168.1.20:2456: connection refused"
	}
	// stale は、2 本目のルールとして、直前の解決の結果で転送を続けているだけのルールを加える
	stale := func(st *agent.DoctorRuntimeState) {
		st.Rules = append(st.Rules, agent.DoctorRule{ID: "r_2", State: proto.StatusError, Proto: proto.TCP, Ports: 1, DNATPorts: 1,
			Reason: staleKernelReason})
	}
	publishFailed := func(st *agent.DoctorRuntimeState) {
		st.PublishError = "publish table inet wgft_agent: invalid argument"
	}
	added := func(st *agent.DoctorRuntimeState) {
		st.Kernel.Table.UnexpectedCount, st.Kernel.Table.Unexpected = 1, []string{"chain nat_pre: row 3 is not one wgft writes"}
	}
	guard := func(st *agent.DoctorRuntimeState) {
		st.Kernel.Table.GuardMissingCount, st.Kernel.Table.GuardMissing = 1, []string{"filter_pre: drop the rest from wgft0"}
	}
	missing := func(st *agent.DoctorRuntimeState) {
		st.Kernel.Table.MissingCount, st.Kernel.Table.Missing = 1, []string{"postrouting: masquerade"}
	}
	for _, tc := range []struct {
		name  string
		edits []func(*agent.DoctorRuntimeState)
		want  wantCheck
	}{
		{"missing rows before rule errors", []func(*agent.DoctorRuntimeState){missing, ruleError, publishFailed, added},
			wantCheck{agentCheckDPTable, statusFailed, agentReasonTableRowsMissing}},
		{"rule errors before a failed publication", []func(*agent.DoctorRuntimeState){ruleError, publishFailed, added},
			wantCheck{agentCheckDPTable, statusFailed, agentReasonListenerError}},
		{"rule errors before missing guard rows", []func(*agent.DoctorRuntimeState){ruleError, guard, publishFailed},
			wantCheck{agentCheckDPTable, statusFailed, agentReasonListenerError}},
		{"missing guard rows before a failed publication", []func(*agent.DoctorRuntimeState){guard, publishFailed, added},
			wantCheck{agentCheckDPTable, statusUnknown, agentReasonGuardRowsMissing}},
		{"a failed publication before added rows", []func(*agent.DoctorRuntimeState){publishFailed, added},
			wantCheck{agentCheckDPTable, statusUnknown, agentReasonPublishFailed}},
		// 直前の解決の結果で転送を続けるルールは、他のどの所見よりも後ろで、OK の前である。他の所見が
		// あれば、そちらの符号を採り、このルールは所見に併せて示す(10.2c 節)
		{"rule errors before a stale resolution", []func(*agent.DoctorRuntimeState){stale, ruleError},
			wantCheck{agentCheckDPTable, statusFailed, agentReasonListenerError}},
		{"missing guard rows before a stale resolution", []func(*agent.DoctorRuntimeState){stale, guard},
			wantCheck{agentCheckDPTable, statusUnknown, agentReasonGuardRowsMissing}},
		{"a failed publication before a stale resolution", []func(*agent.DoctorRuntimeState){stale, publishFailed},
			wantCheck{agentCheckDPTable, statusUnknown, agentReasonPublishFailed}},
		{"added rows before a stale resolution", []func(*agent.DoctorRuntimeState){stale, added},
			wantCheck{agentCheckDPTable, statusUnknown, agentReasonTableChanged}},
		{"a stale resolution alone", []func(*agent.DoctorRuntimeState){stale},
			wantCheck{agentCheckDPTable, statusUnknown, agentReasonResolveFailed}},
		{"missing rows before a stale resolution", []func(*agent.DoctorRuntimeState){stale, missing},
			wantCheck{agentCheckDPTable, statusFailed, agentReasonTableRowsMissing}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := testAgentDoctorInput(t, t.TempDir())
			writeTestCredentials(t, in.CredentialsPath, kernelCredentials())
			holdTheLock(t, in.CredentialsPath)
			in.Dial = fakeDoctorSocket(t, liveReply(kernelRuntime(func(st *agent.DoctorRuntimeState) {
				for _, e := range tc.edits {
					e(st)
				}
			})))
			c, _ := findAgentCheck(agentDiagnose(in), tc.want.id)
			if c.Status != tc.want.status || c.Reason != tc.want.reason {
				t.Errorf("%s = %s/%s, want %s/%s", c.ID, c.Status, c.Reason, tc.want.status, tc.want.reason)
			}
			// 直前の解決の結果で転送を続けるルールは、どの符号の所見にも示す
			if strings.Contains(tc.name, "stale") && !strings.Contains(c.Detail, "r_2 tcp: DNAT on 1 of 1 port, name resolution") {
				t.Errorf("%s detail = %q, want it to name the rule forwarding from the last resolution", c.ID, c.Detail)
			}
		})
	}
}

// 止まっているエージェントのカーネルは、設定の WGFT_WG_INTERFACE が名指すインタフェースで読む
// (10.2c 節の「カーネルモードの証拠の読み方」)。wgft0 を決め打ちすると、名前を変えた配置で別の
// リンクを読む。
func TestAgentDoctorReadsTheConfiguredInterface(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(config, []byte("WGFT_WG_INTERFACE=wgfthome\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WGFT_WG_INTERFACE", "")
	os.Unsetenv("WGFT_WG_INTERFACE")
	cmd := newAgentDoctorCmd()
	if err := cmd.ParseFlags([]string{"--config", config, "--data-dir", dir}); err != nil {
		t.Fatal(err)
	}
	in, err := agentDoctorInputFrom(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if in.WGInterface != "wgfthome" {
		t.Fatalf("WGInterface = %q, want the configured wgfthome", in.WGInterface)
	}
	in.Now, in.Euid = testLiveNow, func() int { return 1000 }
	writeTestCredentials(t, in.CredentialsPath, kernelCredentials())
	var read string
	in.ReadKernel = func(_ *credentials.Credentials, iface string) *agent.DoctorKernel {
		read = iface
		return kernelEvidence()
	}
	agentDiagnose(in)
	if read != "wgfthome" {
		t.Errorf("the stopped agent's kernel was read for %q, want the configured wgfthome", read)
	}
}

// 直前の解決の結果で転送を続けるルールだけの表の所見は、OK の所見と同じく、30 秒ごとの見直しの失敗を
// 添える(10.2c 節)。表が UNKNOWN のときに、その失敗を消さないためである。
func TestAgentDoctorStaleResolutionKeepsTheCheckError(t *testing.T) {
	in := testAgentDoctorInput(t, t.TempDir())
	writeTestCredentials(t, in.CredentialsPath, kernelCredentials())
	holdTheLock(t, in.CredentialsPath)
	in.Dial = fakeDoctorSocket(t, liveReply(kernelRuntime(func(st *agent.DoctorRuntimeState) {
		st.Rules[0].State, st.Rules[0].Reason = proto.StatusError, staleKernelReason
		st.CheckError = "read table inet wgft_agent: netlink receive: no buffer space available"
	})))
	c, _ := findAgentCheck(agentDiagnose(in), agentCheckDPTable)
	if c.Status != statusUnknown || c.Reason != agentReasonResolveFailed {
		t.Fatalf("%s = %s/%s, want %s/%s", c.ID, c.Status, c.Reason, statusUnknown, agentReasonResolveFailed)
	}
	if !strings.Contains(c.Detail, "the last 30s check failed: read table inet wgft_agent") {
		t.Errorf("detail = %q, want it to carry the failed 30s check", c.Detail)
	}
}
