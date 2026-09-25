package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent"
	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは `wgft agent doctor`(設計文書 10.2c 節)の、稼働中のプロセスの制御ソケットから
// 読む検査の表のテストである。節が定めた規則をそのまま入力に写し、場面ごとの検査の状態と理由の
// 符号と終了コードを確かめる。

// agentLiveScenario は 1 つの場面である。
type agentLiveScenario struct {
	name string
	// dial は制御ソケットに繋ぐ入口である。応答を返す場面では fakeDoctorSocket を使う。
	dial func(path string) (net.Conn, error)
	// want はその場面で節が定める状態と理由の符号である。
	want []wantCheck
	// wantExit は 10.2c 節の終了コードの表のとおりの値である。
	wantExit int
	// wantDetail は所見に必ず含まれる語である。
	wantDetail map[string]string
	// wantNext は次に見るものに必ず含まれる語である。
	wantNext map[string]string
	// longPath は、制御ソケットのパスが sun_path の上限を超える配置に置き換える場面である。
	longPath bool
}

// useLongSocketPath は、制御ソケットのパスが sun_path の上限を超える配置に入力を置き換える。
func useLongSocketPath(t *testing.T, in *agentDoctorInput) {
	t.Helper()
	deep := filepath.Join(in.DataDir, strings.Repeat("d/", 60))
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Skipf("this host cannot hold a path that long: %v", err)
	}
	in.DataDir = deep
	in.CredentialsPath = filepath.Join(deep, "agent.json")
	if len(agent.ControlPath(in.CredentialsPath)) <= agent.ControlPathLimit {
		t.Skipf("the temporary directory is too short to exceed the limit: %s", in.CredentialsPath)
	}
}

func TestAgentDoctorLiveScenarios(t *testing.T) {
	for _, tc := range []agentLiveScenario{
		{
			// 正常な稼働中の配置。稼働中のプロセスからしか取れない検査が、実際の値で埋まる。
			name: "a healthy running agent",
			dial: fakeDoctorSocket(t, liveReply(healthyLiveResponse())),
			want: []wantCheck{
				{agentCheckProcess, statusOK, ""},
				{agentCheckControl, statusOK, ""},
				{agentCheckStreamConn, statusOK, ""},
				{agentCheckStreamBackfl, statusUnknown, agentReasonNoThreshold},
				{agentCheckStreamLive, statusUnknown, agentReasonNoThreshold},
				{agentCheckTunnelLocal, statusOK, ""},
				{agentCheckWatchdog, statusUnknown, agentReasonNoThreshold},
				{agentCheckTransfer, statusUnknown, agentReasonNoThreshold},
				{agentCheckListeners, statusOK, ""},
				{agentCheckSessions, statusUnknown, agentReasonNoThreshold},
				{agentCheckRefusals, statusUnknown, agentReasonNoThreshold},
				{agentCheckAllowTargets, statusOK, ""},
			},
			wantExit: 0,
			wantDetail: map[string]string{
				agentCheckTunnelLocal:  "203.0.113.10:51820",
				agentCheckTransfer:     "1024 bytes received and 2048 bytes sent",
				agentCheckListeners:    "r_1 tcp: 1 of 1 listener open",
				agentCheckSessions:     "tcp budget 1024, 1 in use",
				agentCheckRefusals:     "no flow has been refused",
				agentCheckAllowTargets: allowtargets.Env + "=192.168.1.0/24",
			},
		},
		{
			// 古い常駐プロセスが error: unknown command を返す実行。接続そのものは成功している
			// ので SKIPPED には当たらず、FAILED にすると転送が健全な配置に対しても壊れている
			// 印象を与える(10.2c 節)。終了コードは 0 のままである。
			name: "an older daemon answers error: unknown command",
			dial: fakeDoctorSocket(t, "error: unknown command\n"),
			want: []wantCheck{
				{agentCheckControl, statusUnknown, agentReasonDoctorUnsupported},
				{agentCheckStreamConn, statusSkipped, agentReasonDoctorUnsupported},
				{agentCheckTunnelLocal, statusSkipped, agentReasonDoctorUnsupported},
				{agentCheckListeners, statusSkipped, agentReasonDoctorUnsupported},
				{agentCheckAllowTargets, statusSkipped, agentReasonDoctorUnsupported},
			},
			wantExit: 0,
			wantNext: map[string]string{agentCheckControl: "restart the agent so it runs the installed binary"},
		},
		{
			// 実行時の状態を守る排他を期限内に取れない実行。この実行の agent.control は OK で
			// ある。制御ソケットに繋げて doctor の応答も得ているためである(10.2c 節)。排他を
			// 要らない allow_targets と stream は応答に載るので、実際の値で埋まる。
			name: "the lock that guards the runtime state is not taken in time",
			dial: fakeDoctorSocket(t, liveReply(&agent.DoctorResponse{
				AllowTargets:        &agent.DoctorAllowTargets{Env: allowtargets.Env},
				Stream:              &agent.DoctorStream{Connected: true},
				RuntimeStateTimeout: 2 * time.Second,
			})),
			want: []wantCheck{
				{agentCheckControl, statusOK, ""},
				{agentCheckStreamConn, statusOK, ""},
				{agentCheckStreamBackfl, statusUnknown, agentReasonNoThreshold},
				{agentCheckStreamLive, statusUnknown, agentReasonNoThreshold},
				{agentCheckAllowTargets, statusOK, ""},
				{agentCheckTunnelLocal, statusSkipped, agentReasonRuntimeBusy},
				{agentCheckWatchdog, statusSkipped, agentReasonRuntimeBusy},
				{agentCheckTransfer, statusSkipped, agentReasonRuntimeBusy},
				{agentCheckListeners, statusSkipped, agentReasonRuntimeBusy},
				{agentCheckSessions, statusSkipped, agentReasonRuntimeBusy},
				{agentCheckRefusals, statusSkipped, agentReasonRuntimeBusy},
			},
			// 証拠に権限で到達できなかった実行ではないので、終了コードは 0 のままである。
			wantExit:   0,
			wantDetail: map[string]string{agentCheckTunnelLocal: "within 2s"},
			wantNext:   map[string]string{agentCheckTunnelLocal: "30s round of target checks"},
		},
		{
			// 応答を組む処理が panic した実行。error だけがあり、他の 3 つの項目が無い。
			name: "the agent panicked while collecting its state",
			dial: fakeDoctorSocket(t, liveReply(&agent.DoctorResponse{Error: "the agent panicked while collecting its state: boom"})),
			want: []wantCheck{
				{agentCheckControl, statusUnknown, agentReasonDoctorFailed},
				{agentCheckStreamConn, statusSkipped, agentReasonDoctorFailed},
				{agentCheckTunnelLocal, statusSkipped, agentReasonDoctorFailed},
				{agentCheckListeners, statusSkipped, agentReasonDoctorFailed},
				{agentCheckAllowTargets, statusSkipped, agentReasonDoctorFailed},
			},
			wantExit:   0,
			wantDetail: map[string]string{agentCheckControl: "boom"},
		},
		{
			// トンネルの構築が失敗している実行。総合判定を動かす検査が FAILED になり、終了コード
			// 1 が出る(10.2c 節)。
			name: "building the tunnel failed",
			dial: fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
				st.Tunnel = agent.DoctorTunnel{State: proto.StatusError, Reason: "no tunnel; building it failed and will be retried"}
				st.Rules, st.Budgets = nil, nil
			}))),
			want: []wantCheck{
				{agentCheckTunnelLocal, statusFailed, agentReasonTunnelBuildFailed},
				// 中継はトンネルと一緒に作られるので、トンネルが無い間は中継も無い。
				{agentCheckListeners, statusSkipped, agentReasonNoRelay},
				{agentCheckSessions, statusSkipped, agentReasonNoRelay},
				{agentCheckRefusals, statusSkipped, agentReasonNoRelay},
				{agentCheckTransfer, statusUnknown, agentReasonNoTunnel},
			},
			wantExit: 1,
		},
		{
			// 中継はあるがルールを 1 本も持たない実行。まだ何も公開されていない健全な配置であり、
			// 総合判定を動かす relay.listeners は OK である。中継の有無の見分けは、ルールの並びでは
			// なくフロー予算の項目の有無で行う。ルールの並びは、中継が無い実行でも中継がルールを
			// 持たない実行でも同じく空になるためである。
			name: "the relay is up and holds no rules",
			dial: fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
				st.Rules = nil
			}))),
			want: []wantCheck{
				{agentCheckListeners, statusOK, ""},
				{agentCheckSessions, statusUnknown, agentReasonNoThreshold},
				{agentCheckRefusals, statusUnknown, agentReasonNoThreshold},
				{agentCheckTunnelLocal, statusOK, ""},
			},
			wantExit: 0,
			wantDetail: map[string]string{
				agentCheckListeners: "the relay holds no rules, so it opens no listeners",
				agentCheckSessions:  "the relay holds no rules",
			},
		},
		{
			// server がこのエージェントを無効にしている実行で、中継は生きている場合。無効な
			// ルールは宣言に現れずリスナーを 1 つも開かないので、relay.listeners は SKIPPED とし、
			// 中継が無い場合と区別する(仕様 5.1 節、設計文書 10.2c 節の relay.listeners の粒度)。
			// SKIPPED は総合判定と終了コードを動かさない。
			name: "the server has disabled this agent while the relay is up",
			dial: fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
				st.AgentDisabled = true
				st.Rules = nil
			}))),
			want: []wantCheck{
				{agentCheckListeners, statusSkipped, agentReasonAgentDisabled},
				{agentCheckTunnelLocal, statusOK, ""},
			},
			wantExit: 0,
			wantDetail: map[string]string{
				agentCheckListeners: "the server has disabled this agent; it opens no listeners until wgft agent enable home is run on the VPS",
			},
		},
		{
			// 同じ無効の実行だが、中継そのものも無い場合。agentListenersCheck は st.AgentDisabled を
			// agentNoRelay より先に見るので、理由の符号は agent_disabled のままであり、no_relay には
			// ならない。この判定の順序を入れ替えても両方とも SKIPPED になり状態だけでは区別が付かない
			// ので、理由の符号で固定する。
			name: "the server has disabled this agent while there is no relay",
			dial: fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
				st.AgentDisabled = true
				st.Rules, st.Budgets = nil, nil
			}))),
			want: []wantCheck{
				{agentCheckListeners, statusSkipped, agentReasonAgentDisabled},
			},
			wantExit: 0,
			wantDetail: map[string]string{
				agentCheckListeners: "the server has disabled this agent; it opens no listeners until wgft agent enable home is run on the VPS",
			},
		},
		{
			// ハンドシェイクがまだ成立していない実行。トンネルを作り直した直後に必ず通る状態で
			// あり、UNKNOWN とする。総合判定は動かさない(10.2c 節)。
			name: "no handshake has been established yet",
			dial: fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
				st.Tunnel.State, st.Tunnel.Reason = proto.StatusError, "handshake not established"
				st.Tunnel.LastHandshake = time.Time{}
			}))),
			want:     []wantCheck{{agentCheckTunnelLocal, statusUnknown, agentReasonHandshakePending}},
			wantExit: 0,
		},
		{
			// リスナーの開放に失敗している実行。判定も所見もルール単位であり、FAILED になるのは
			// ルール単位の状態が error の場合だけである(10.2c 節)。
			name: "a listener cannot be opened",
			dial: fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
				st.Rules = []agent.DoctorRule{
					{ID: "r_1", State: proto.StatusError, Proto: proto.TCP, Listeners: 2, Listening: 1,
						BindErrors: 1, BindError: "tcp 0.0.0.0:2456: bind: address already in use"},
					{ID: "r_2", State: proto.StatusOK, Proto: proto.UDP, Listeners: 1, Listening: 1},
				}
			}))),
			want:     []wantCheck{{agentCheckListeners, statusFailed, agentReasonListenerError}},
			wantExit: 1,
			wantDetail: map[string]string{
				agentCheckListeners: "1 of 2 rules cannot serve: r_1 tcp: 1 of 2 listeners open, 1 cannot bind: tcp 0.0.0.0:2456: bind: address already in use",
			},
			wantNext: map[string]string{agentCheckListeners: "another process on this host already holds"},
		},
		{
			// 待ち受けは開いていて宛先に届かないリスナーは、bind の失敗と別に数える。運用者の
			// 次の行動が違う(10.2c 節)。
			name: "a listener is open but its target cannot be reached",
			dial: fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
				st.Rules = []agent.DoctorRule{{ID: "r_1", State: proto.StatusError, Proto: proto.TCP, Listeners: 1, Listening: 1,
					TargetErrors: 1, TargetError: "tcp 0.0.0.0:2456: dial 192.168.1.20:2456: connection refused"}}
			}))),
			want:       []wantCheck{{agentCheckListeners, statusFailed, agentReasonListenerError}},
			wantExit:   1,
			wantDetail: map[string]string{agentCheckListeners: "1 cannot reach the target: tcp 0.0.0.0:2456: dial 192.168.1.20:2456: connection refused"},
		},
		{
			// トンネルはあるが誤りを報告し、転送に使える解決済みのエンドポイントが残っていない
			// 実行。FAILED とする(10.2c 節)。
			name: "the tunnel reports an error and holds no endpoint",
			dial: fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
				st.Tunnel.State, st.Tunnel.Reason, st.Tunnel.Endpoint = proto.StatusError, "resolve vps.example.net: no such host", ""
			}))),
			want:     []wantCheck{{agentCheckTunnelLocal, statusFailed, agentReasonTunnelErrorNoEndpoint}},
			wantExit: 1,
		},
		{
			// 初回の名前解決に失敗したトンネルは、解決済みのエンドポイントを持たないまま
			// 最終ハンドシェイクも無い。ts.Err を先に見る順序がそのまま効き、handshake_pending の
			// UNKNOWN にはならない(10.2c 節)。順序を逆にすると、転送に使えるエンドポイントを
			// 一度も持たないトンネルが UNKNOWN になり、前段の決定と食い違う。
			name: "the tunnel never resolved an endpoint and has no handshake",
			dial: fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
				st.Tunnel.State, st.Tunnel.Reason = proto.StatusError, "resolve vps.example.net: no such host"
				st.Tunnel.Endpoint, st.Tunnel.LastHandshake = "", time.Time{}
			}))),
			want:     []wantCheck{{agentCheckTunnelLocal, statusFailed, agentReasonTunnelErrorNoEndpoint}},
			wantExit: 1,
		},
		{
			// 同じ誤りでも、解決済みのエンドポイントが残っていれば UNKNOWN とする。誤りの種類でも、
			// どの呼び出しが失敗したかでも分けない(10.2c 節)。
			name: "the tunnel reports an error but keeps its endpoint",
			dial: fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
				st.Tunnel.State, st.Tunnel.Reason = proto.StatusError, "resolve vps.example.net: no such host"
			}))),
			want:       []wantCheck{{agentCheckTunnelLocal, statusUnknown, agentReasonTunnelErrorEndpointKept}},
			wantExit:   0,
			wantDetail: map[string]string{agentCheckTunnelLocal: "which can keep carrying traffic"},
		},
		{
			// カーネルモードのエージェントが wg 設定を拒んだ場合も同じ状態と符号だが、server が拒んだ設定で
			// 動く間は転送が止まりうるので、エンドポイントが転送を続けられるとは言わない(設計文書 7b.1 節)。
			name: "the agent refused the wg configuration",
			dial: fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
				st.Tunnel.State = proto.StatusError
				st.Tunnel.Reason = agent.ReasonWGRefused + " of generation 5; the tunnel and rules stay as generation 4 left them: the server sent the tunnel address 10.201.0.2/24"
			}))),
			want:       []wantCheck{{agentCheckTunnelLocal, statusUnknown, agentReasonTunnelErrorEndpointKept}},
			wantExit:   0,
			wantDetail: map[string]string{agentCheckTunnelLocal: "refused the wg configuration the server sent and keeps the interface"},
			wantNext:   map[string]string{agentCheckTunnelLocal: "traffic through the tunnel stops"},
		},
		{
			// トンネルを閉じた直後は正常な遷移でも生じる。FAILED にすると一過性の状態を故障として
			// 扱うことになる(10.2c 節)。
			name: "there is no tunnel after it was closed",
			dial: fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
				st.Tunnel = agent.DoctorTunnel{State: proto.StatusError, Reason: "no tunnel"}
				st.Rules, st.Budgets = nil, nil
			}))),
			want:     []wantCheck{{agentCheckTunnelLocal, statusUnknown, agentReasonNoTunnel}},
			wantExit: 0,
		},
		{
			// トンネルが無く stream にまだ繋がっていない通常の起動直後の状態も UNKNOWN である。
			name: "the full state has not arrived yet",
			dial: fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
				st.Tunnel = agent.DoctorTunnel{State: proto.StatusError, Reason: "no tunnel; full state not received"}
				st.Rules, st.Budgets = nil, nil
			}))),
			want:     []wantCheck{{agentCheckTunnelLocal, statusUnknown, agentReasonFullStatePending}},
			wantExit: 0,
		},
		{
			// 制御ストリームが切れている実行。総合判定は動かさない。受け取り済みのルールを転送し
			// 続けている間も起こるためである(10.2c 節)。
			name: "the control stream is down",
			dial: fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {}, func(s *agent.DoctorStream) {
				s.Connected = false
				s.DisconnectedAt = time.Date(2026, 9, 23, 11, 59, 0, 0, time.UTC)
				s.DisconnectReason = "read tcp: connection reset by peer"
				s.Backoff = 30 * time.Second
				s.RetryAt = time.Date(2026, 9, 23, 12, 0, 20, 0, time.UTC)
			}))),
			want: []wantCheck{
				{agentCheckStreamConn, statusUnknown, agentReasonReconnecting},
				{agentCheckStreamBackfl, statusUnknown, agentReasonNoThreshold},
			},
			wantExit: 0,
			wantDetail: map[string]string{
				agentCheckStreamConn:   "connection reset by peer",
				agentCheckStreamBackfl: "the last reconnect wait was 30s; the next attempt is due at 2026-09-23T12:00:20Z, in 20s",
			},
		},
		{
			// 宛先の許可一覧を持たない稼働中のエージェントは、そのことを事実として示す。
			name: "the running agent enforces no allowlist",
			dial: fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {}, func(s *agent.DoctorStream) {}, func(a *agent.DoctorAllowTargets) {
				a.Set, a.List = false, ""
			}))),
			want:       []wantCheck{{agentCheckAllowTargets, statusOK, ""}},
			wantExit:   0,
			wantDetail: map[string]string{agentCheckAllowTargets: "enforces no target allowlist"},
		},
		{
			// ファイルのパーミッションで繋げない実行。3 つの原因のうちこの 1 つだけが終了コード 2
			// である(10.2c 節)。
			name: "the control socket refuses this command's permissions",
			dial: func(string) (net.Conn, error) { return nil, &net.OpError{Op: "dial", Err: syscall.EACCES} },
			want: []wantCheck{
				{agentCheckControl, statusFailed, agentReasonControlUnreachable},
				{agentCheckTunnelLocal, statusSkipped, agentReasonControlUnreachable},
				{agentCheckListeners, statusSkipped, agentReasonControlUnreachable},
				{agentCheckAllowTargets, statusSkipped, agentReasonControlUnreachable},
			},
			wantExit: 2,
			wantNext: map[string]string{agentCheckControl: "run this command as the user the agent runs as"},
		},
		{
			// ソケットのパスが sun_path の上限を超えている実行。エージェントは転送を担い続ける
			// ので、終了コードは 0 のままである(10.2c 節)。
			name:     "the socket path is longer than sun_path holds",
			longPath: true,
			dial:     func(string) (net.Conn, error) { return nil, &net.OpError{Op: "dial", Err: syscall.EINVAL} },
			want: []wantCheck{
				{agentCheckControl, statusFailed, agentReasonControlPathTooLong},
				{agentCheckTunnelLocal, statusSkipped, agentReasonControlPathTooLong},
			},
			wantExit: 0,
			wantDetail: map[string]string{
				agentCheckControl: "Unix socket paths hold at most 107 bytes on Linux and Windows and 103 on macOS",
			},
			wantNext: map[string]string{agentCheckControl: "move the data directory to a shorter path"},
		},
		{
			// エージェントがソケットを開けないまま動いている実行。これも終了コードは 0 である。
			name: "the agent runs without having opened its control socket",
			dial: func(string) (net.Conn, error) { return nil, &net.OpError{Op: "dial", Err: syscall.ENOENT} },
			want: []wantCheck{
				{agentCheckControl, statusFailed, agentReasonControlUnreachable},
				{agentCheckAllowTargets, statusSkipped, agentReasonControlUnreachable},
			},
			wantExit: 0,
			// この枝は既定の受け皿であり、ソケットを開けないまま動いている実行も、常駐プロセスが
			// 消し忘れたソケットのファイルが残っている実行も入る。次の一手は、その両方に届く形に
			// する。
			wantNext: map[string]string{agentCheckControl: "it prints a line when it cannot open the socket. If it printed none, the socket file at that path is a leftover"},
		},
		{
			// 繋げたが応答を読めない実行。
			name: "the reply is not a doctor response",
			dial: fakeDoctorSocket(t, "not json at all\n"),
			want: []wantCheck{
				{agentCheckControl, statusUnknown, agentReasonDoctorUnreadable},
				{agentCheckTunnelLocal, statusSkipped, agentReasonDoctorUnreadable},
			},
			wantExit: 0,
		},
		{
			// 3 つのどれでもない応答も、この型が約束する形を満たしていない。
			name: "the reply carries none of the three shapes",
			dial: fakeDoctorSocket(t, liveReply(&agent.DoctorResponse{Stream: &agent.DoctorStream{}})),
			want: []wantCheck{
				{agentCheckControl, statusUnknown, agentReasonDoctorUnreadable},
				{agentCheckAllowTargets, statusSkipped, agentReasonDoctorUnreadable},
			},
			wantExit: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := testAgentDoctorInput(t, t.TempDir())
			if tc.longPath {
				useLongSocketPath(t, &in)
			}
			writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
			holdTheLock(t, in.CredentialsPath)
			in.Dial = tc.dial
			rep := agentDiagnose(in)
			for _, w := range tc.want {
				got, ok := findAgentCheck(rep, w.id)
				if !ok {
					t.Errorf("%s is missing from the report", w.id)
					continue
				}
				if got.Status != w.status || got.Reason != w.reason {
					t.Errorf("%s = %s/%q, want %s/%q; detail: %s", w.id, got.Status, got.Reason, w.status, w.reason, got.Detail)
				}
				if got.Status == statusFailed && got.Next == "" {
					t.Errorf("%s is FAILED with nothing to check next; design 10.2a and 10.2c require it", w.id)
				}
			}
			for id, want := range tc.wantDetail {
				got, _ := findAgentCheck(rep, id)
				if !strings.Contains(got.Detail, want) {
					t.Errorf("%s does not show %q: %q", id, want, got.Detail)
				}
			}
			for id, want := range tc.wantNext {
				got, _ := findAgentCheck(rep, id)
				if !strings.Contains(got.Next, want) {
					t.Errorf("%s does not say %q as the next step: %q", id, want, got.Next)
				}
			}
			if code := agentDoctorExitCode(rep); code != tc.wantExit {
				t.Errorf("exit code = %d, want %d", code, tc.wantExit)
			}
		})
	}
}

// 制御ソケットに繋げない 3 つの原因は、別々に扱う(10.2c 節)。終了コードも次に見るものも違うので、
// 1 つに畳んではならない。
func TestAgentDoctorSeparatesTheThreeUnreachableCauses(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		exit     int
		longPath bool
		reason   string
	}{
		{name: "permission", err: &net.OpError{Op: "dial", Err: syscall.EACCES}, exit: 2, reason: agentReasonControlUnreachable},
		{name: "sun_path", err: &net.OpError{Op: "dial", Err: syscall.EINVAL}, exit: 0, longPath: true, reason: agentReasonControlPathTooLong},
		{name: "no socket", err: &net.OpError{Op: "dial", Err: syscall.ENOENT}, exit: 0, reason: agentReasonControlUnreachable},
	}
	seen := map[string]string{}
	for _, tc := range cases {
		in := testAgentDoctorInput(t, t.TempDir())
		if tc.longPath {
			useLongSocketPath(t, &in)
		}
		writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
		holdTheLock(t, in.CredentialsPath)
		in.Dial = func(string) (net.Conn, error) { return nil, tc.err }
		rep := agentDiagnose(in)
		c, _ := findAgentCheck(rep, agentCheckControl)
		if c.Status != statusFailed || c.Reason != tc.reason {
			t.Errorf("%s: agent.control = %s/%q, want %s/%q", tc.name, c.Status, c.Reason, statusFailed, tc.reason)
		}
		if got := agentDoctorExitCode(rep); got != tc.exit {
			t.Errorf("%s: exit code = %d, want %d", tc.name, got, tc.exit)
		}
		if prev, ok := seen[c.Next]; ok {
			t.Errorf("%s and %s give the same next step, so the two causes were folded into one: %q", tc.name, prev, c.Next)
		}
		seen[c.Next] = tc.name
		// 権限の場合だけが層 2 である。
		if want := tc.name == "permission"; c.evidenceUnreachable != want {
			t.Errorf("%s: agent.control counts as unreachable evidence = %v, want %v", tc.name, c.evidenceUnreachable, want)
		}
	}
}

// 実行時の排他を取れなかった実行の `agent.control` は OK である。制御ソケットに繋げて doctor の
// 応答も得ているので、この検査が答える問いは満たされている(10.2c 節)。古い常駐プロセスの
// UNKNOWN とは扱いが違う。
func TestAgentDoctorControlIsOKWhenOnlyTheRuntimeStateIsMissing(t *testing.T) {
	in := testAgentDoctorInput(t, t.TempDir())
	writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
	holdTheLock(t, in.CredentialsPath)
	in.Dial = fakeDoctorSocket(t, liveReply(&agent.DoctorResponse{
		AllowTargets:        &agent.DoctorAllowTargets{Set: true, List: "192.168.1.0/24", Env: allowtargets.Env},
		Stream:              &agent.DoctorStream{Connected: true},
		RuntimeStateTimeout: 2 * time.Second,
	}))
	rep := agentDiagnose(in)
	c, _ := findAgentCheck(rep, agentCheckControl)
	if c.Status != statusOK || c.Reason != "" {
		t.Fatalf("agent.control = %s/%q, want %s with no reason; the socket answered", c.Status, c.Reason, statusOK)
	}
	if c.evidenceUnreachable {
		t.Error("agent.control counts as unreachable evidence; the reply was read, so no evidence was refused by permissions")
	}
	// 排他を要らない検査は、この実行でも実際の値で埋まる。
	for _, id := range []string{agentCheckStreamConn, agentCheckAllowTargets} {
		got, _ := findAgentCheck(rep, id)
		if got.Status == statusSkipped {
			t.Errorf("%s is SKIPPED although its value does not need the runtime lock: %q", id, got.Detail)
		}
	}
	if got := agentDoctorExitCode(rep); got != 0 {
		t.Errorf("exit code = %d, want 0; no evidence was refused by permissions", got)
	}
}

// 制御ソケットに送る要求は `doctor` の 1 行である。ソケットの framing は変えない(10.2c 節)。
func TestAgentDoctorSendsTheDoctorLine(t *testing.T) {
	got := make(chan string, 1)
	in := testAgentDoctorInput(t, t.TempDir())
	writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
	holdTheLock(t, in.CredentialsPath)
	in.Dial = func(string) (net.Conn, error) {
		cli, srv := net.Pipe()
		go func() {
			defer srv.Close()
			line, err := bufio.NewReader(srv).ReadString('\n')
			if err != nil {
				return
			}
			got <- line
			io.WriteString(srv, liveReply(healthyLiveResponse()))
		}()
		return cli, nil
	}
	agentDiagnose(in)
	select {
	case line := <-got:
		if line != "doctor\n" {
			t.Errorf("the request line is %q, want %q", line, "doctor\n")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the command sent no request to the control socket")
	}
}

// 応答の文字列は internal/agent の側で 512 バイトに切られ、切ったことが添えてある。表示の側で
// 二重に切らない(10.2c 節の応答の上限)。
func TestAgentDoctorDoesNotTruncateTheReplyAgain(t *testing.T) {
	long := strings.Repeat("x", 512) + "... truncated"
	in := testAgentDoctorInput(t, t.TempDir())
	writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
	holdTheLock(t, in.CredentialsPath)
	in.Dial = fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
		st.Rules = []agent.DoctorRule{{ID: "r_1", State: proto.StatusError, Proto: proto.TCP, Listeners: 1,
			BindErrors: 1, BindError: long}}
	})))
	c, _ := findAgentCheck(agentDiagnose(in), agentCheckListeners)
	if !strings.Contains(c.Detail, long) {
		t.Errorf("relay.listeners cut the reason the agent had already clipped: %q", c.Detail)
	}
}

// 稼働中のエージェントの制御ソケットにファイルのパーミッションで繋げない実行を、実物の Unix
// ソケットで確かめる。差し替えた入口ではなく、既定の入口が誤りをどう返すかを見る。
func TestAgentDoctorAgainstAnUnreadableSocket(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("this scenario needs a socket that refuses the running user; root refuses nothing and Windows does not answer os.Chmod that way")
	}
	dir := t.TempDir()
	in := testAgentDoctorInput(t, dir)
	writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
	holdTheLock(t, in.CredentialsPath)
	sock := agent.ControlPath(in.CredentialsPath)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("this host cannot open a unix socket at %s: %v", sock, err)
	}
	defer ln.Close()
	if err := os.Chmod(sock, 0); err != nil {
		t.Fatal(err)
	}
	in.Dial = nil // 既定の入口を使う
	rep := agentDiagnose(in)
	c, _ := findAgentCheck(rep, agentCheckControl)
	if c.Status != statusFailed || c.Reason != agentReasonControlUnreachable || !c.evidenceUnreachable {
		t.Fatalf("agent.control = %s/%q, unreachable evidence %v; want %s/%q and true",
			c.Status, c.Reason, c.evidenceUnreachable, statusFailed, agentReasonControlUnreachable)
	}
	if got := agentDoctorExitCode(rep); got != 2 {
		t.Errorf("exit code = %d, want 2", got)
	}
}

// 実物の Unix ソケットの上でも、稼働中の検査が実際の値で埋まる。
func TestAgentDoctorAgainstARealSocket(t *testing.T) {
	dir := t.TempDir()
	in := testAgentDoctorInput(t, dir)
	writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
	holdTheLock(t, in.CredentialsPath)
	sock := agent.ControlPath(in.CredentialsPath)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("this host cannot open a unix socket at %s: %v", sock, err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
					return
				}
				io.WriteString(c, liveReply(healthyLiveResponse()))
			}()
		}
	}()
	in.Dial = nil // 既定の入口を使う
	rep := agentDiagnose(in)
	for _, id := range []string{agentCheckControl, agentCheckStreamConn, agentCheckTunnelLocal, agentCheckListeners} {
		c, _ := findAgentCheck(rep, id)
		if c.Status != statusOK {
			t.Errorf("%s = %s/%q over a real socket, want ok; detail: %s", id, c.Status, c.Reason, c.Detail)
		}
	}
	if got := agentDoctorExitCode(rep); got != 0 {
		t.Errorf("exit code = %d, want 0", got)
	}
}

// 人向けの出力は、稼働中のエージェントに対しても群ごとに並び、FAILED には次に見るものが付く。
func TestAgentDoctorHumanOutputForARunningAgent(t *testing.T) {
	in := testAgentDoctorInput(t, t.TempDir())
	writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
	holdTheLock(t, in.CredentialsPath)
	in.Dial = fakeDoctorSocket(t, liveReply(healthyLiveResponse()))
	var b strings.Builder
	writeAgentDoctorReport(&b, agentDiagnose(in))
	out := b.String()
	for _, want := range []string{
		"control socket     OK",
		"control connection OK",
		"tunnel             OK",
		"listeners          OK",
		"target allowlist   OK",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output has no %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "its live state was not read") {
		t.Errorf("the output still says the live state was not read although the socket answered:\n%s", out)
	}
}

// 値だけを示し合否を持たない 6 つの検査(agentLiveOnly の valueOnly)は、判定済みの検査の後に来る
// 「Observed values」節に入り、UNKNOWN の実行では大きな状態語を出さない。判定済みの検査は群の中に
// 残り、これまでどおり状態語を出す(10.2c 節、2026-09-24 の所有者の決定)。
func TestAgentDoctorHumanOutputSeparatesObservedValues(t *testing.T) {
	in := testAgentDoctorInput(t, t.TempDir())
	healthyAgentForTest(t, &in)
	rep := agentDiagnose(in)
	var b strings.Builder
	writeAgentDoctorReport(&b, rep)
	out := b.String()

	relayAt := strings.Index(out, "Relay\n")
	observedAt := strings.Index(out, "\nObserved values\n")
	if relayAt < 0 || observedAt < 0 || observedAt < relayAt {
		t.Fatalf("Observed values does not come after the five groups:\n%s", out)
	}
	historyAt := strings.Index(out, "\nHistory\n")
	if historyAt < observedAt {
		t.Fatalf("History does not follow Observed values:\n%s", out)
	}
	section := out[observedAt:historyAt]

	for _, spec := range agentLiveOnly {
		if !spec.valueOnly {
			continue
		}
		c, ok := findAgentCheck(rep, spec.ID)
		if !ok {
			t.Fatalf("%s is missing from the report", spec.ID)
		}
		if c.Status != statusUnknown {
			t.Fatalf("test setup: %s is %s, want unknown for a healthy running agent; fix the scenario", spec.ID, c.Status)
		}
		if humanHasLine(out, spec.Label, statusWord(statusUnknown)) {
			t.Errorf("%s still prints its status word %s in the human output:\n%s", spec.Label, statusWord(statusUnknown), out)
		}
		if at := strings.Index(out, spec.Label); at < observedAt {
			t.Errorf("%s is not printed inside the Observed values section:\n%s", spec.Label, out)
		}
		// 値を読めた行は Next を出さない。読み方はヘルプと --json の next が持つ(10.2c 節)。
		if c.Next == "" {
			t.Fatalf("test setup: %s carries no Next, so this test cannot see it left out", spec.ID)
		}
		if strings.Contains(normalizeWhitespace(section), normalizeWhitespace(c.Next)) {
			t.Errorf("%s prints its Next text in the Observed values section:\n%s", spec.Label, section)
		}
	}
	if strings.Contains(section, "Check:") {
		t.Errorf("the Observed values section prints a Check: line for a value that was read:\n%s", section)
	}

	// 判定済みの検査は変わらず、群の中で状態語を出す。
	for _, want := range []string{
		"control socket     OK",
		"control connection OK",
		"tunnel             OK",
		"listeners          OK",
		"target allowlist   OK",
	} {
		at := strings.Index(out, want)
		if at < 0 {
			t.Errorf("the output has no %q:\n%s", want, out)
			continue
		}
		if at > observedAt {
			t.Errorf("%q moved into the Observed values section:\n%s", want, out)
		}
	}
}

// エージェントが止まっていて値そのものを読めない実行では、値だけを示す検査も Observed values 節の
// 中で SKIPPED の状態語を保つ。値が無いことは、値と取り違えられてはならない(10.2c 節)。
func TestAgentDoctorHumanOutputKeepsTheStatusWordWhenAnObservedValueIsSkipped(t *testing.T) {
	in := testAgentDoctorInput(t, t.TempDir())
	stoppedAgentForTest(t, &in)
	rep := agentDiagnose(in)
	var b strings.Builder
	writeAgentDoctorReport(&b, rep)
	out := b.String()

	observedAt := strings.Index(out, "\nObserved values\n")
	if observedAt < 0 {
		t.Fatalf("no Observed values section:\n%s", out)
	}
	for _, spec := range agentLiveOnly {
		if !spec.valueOnly {
			continue
		}
		c, ok := findAgentCheck(rep, spec.ID)
		if !ok {
			t.Fatalf("%s is missing from the report", spec.ID)
		}
		if c.Status != statusSkipped {
			t.Fatalf("test setup: %s is %s, want skipped for a stopped agent; fix the scenario", spec.ID, c.Status)
		}
		if !humanHasLine(out[observedAt:], spec.Label, statusWord(statusSkipped)) {
			t.Errorf("%s does not print its status word %s inside Observed values:\n%s", spec.Label, statusWord(statusSkipped), out)
		}
	}
}

// Observed values 節で値を読めた行は、ラベルと同じ行から値を始め、長い値は値の桁(21 桁目)で
// 折り返す。「Not tested by this command」の節と同じ形である(10.2c 節)。
func TestAgentDoctorObservedValuesStartOnTheLabelLine(t *testing.T) {
	detail := strings.Repeat("word ", 30) + "end"
	var b strings.Builder
	writeAgentDoctorObserved(&b, []agentDoctorCheck{{
		ID: agentCheckTransfer, Label: "transfer", Status: statusUnknown, Reason: agentReasonNoThreshold,
		Detail: detail, valueOnly: true,
	}})
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	// lines[0] は空行、lines[1] は節の見出しである。
	if len(lines) < 4 || lines[1] != "Observed values" {
		t.Fatalf("want the heading, the label line and at least one continuation line:\n%s", b.String())
	}
	first := fmt.Sprintf("  %-*s word ", labelWidth, "transfer")
	if !strings.HasPrefix(lines[2], first) {
		t.Errorf("the value does not start on the label's line; want the prefix %q:\n%s", first, b.String())
	}
	valueColumn := 2 + labelWidth + 1
	for _, line := range lines[3:] {
		if len(line) <= valueColumn || strings.TrimSpace(line[:valueColumn]) != "" || line[valueColumn] == ' ' {
			t.Errorf("continuation line %q does not start at the value column %d:\n%s", line, valueColumn+1, b.String())
		}
	}
	if got := normalizeWhitespace(strings.Join(lines[2:], " ")); got != "transfer "+normalizeWhitespace(detail) {
		t.Errorf("the value was not printed whole: %q", got)
	}
}

// Observed values 節で UNKNOWN 以外の状態になった行は、判定済みの検査と同じく状態語と Next を
// 出す。値そのものを読めなかったことと、その次に見るものを落とさないためである(10.2c 節)。
func TestAgentDoctorObservedValuesKeepNextWhenNotAValue(t *testing.T) {
	var b strings.Builder
	writeAgentDoctorObserved(&b, []agentDoctorCheck{{
		ID: agentCheckTransfer, Label: "transfer", Status: statusSkipped, Reason: agentReasonRuntimeBusy,
		Detail: "not read", Next: "look at the tunnel line", valueOnly: true,
	}})
	out := b.String()
	if !humanHasLine(out, "transfer", statusWord(statusSkipped)) {
		t.Errorf("a SKIPPED observed value lost its status word:\n%s", out)
	}
	if !strings.Contains(out, "Check: look at the tunnel line") {
		t.Errorf("a SKIPPED observed value lost its Next:\n%s", out)
	}
}

// --- 助け ---

// fakeDoctorSocket は、制御ソケットの代わりに 1 行の応答を返すエージェントを模す。要求が
// `doctor` でなければ、古い常駐プロセスと同じ既定の分岐を返す。
func fakeDoctorSocket(t *testing.T, reply string) func(string) (net.Conn, error) {
	t.Helper()
	return func(string) (net.Conn, error) {
		cli, srv := net.Pipe()
		go func() {
			defer srv.Close()
			line, err := bufio.NewReader(srv).ReadString('\n')
			if err != nil {
				return
			}
			if strings.TrimSpace(line) != agent.DoctorCommand {
				io.WriteString(srv, "error: unknown command\n")
				return
			}
			io.WriteString(srv, reply)
		}()
		return cli, nil
	}
}

// liveReply は応答を制御ソケットが流す 1 行に写す。
func liveReply(resp *agent.DoctorResponse) string {
	b, err := json.Marshal(resp)
	if err != nil {
		panic(err)
	}
	return string(b) + "\n"
}

// testLiveNow は、testAgentDoctorInput が与える今の時刻である。
var testLiveNow = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

// healthyLiveResponse は、何も壊れていない稼働中のエージェントの応答である。
func healthyLiveResponse() *agent.DoctorResponse {
	return runtimeResponse(func(*agent.DoctorRuntimeState) {})
}

// runtimeResponse は正常な応答を組み、渡された手で書き換える。場面ごとに違うのは 1 か所か 2 か所
// なので、その差だけを場面の側に書く。
func runtimeResponse(edit func(*agent.DoctorRuntimeState), more ...any) *agent.DoctorResponse {
	st := &agent.DoctorRuntimeState{
		Generation: 12,
		Tunnel: agent.DoctorTunnel{
			Present:       true,
			State:         proto.StatusOK,
			Endpoint:      "203.0.113.10:51820",
			LastHandshake: testLiveNow.Add(-30 * time.Second),
			RxBytes:       1024,
			TxBytes:       2048,
			StartedAt:     testLiveNow.Add(-time.Hour),
			Watchdog:      agent.DoctorWatchdog{RebuildInterval: 5 * time.Minute},
		},
		Rules: []agent.DoctorRule{
			{ID: "r_1", State: proto.StatusOK, Proto: proto.TCP, Listeners: 1, Listening: 1, Sessions: 2, Flows: 1},
		},
		Budgets: []agent.DoctorBudget{
			{Proto: proto.TCP, Total: 1024, InUse: 1, Rules: 1},
			{Proto: proto.UDP, Total: 4096, Rules: 1},
		},
		RefusalsSince: testLiveNow.Add(-time.Hour),
	}
	edit(st)
	stream := &agent.DoctorStream{
		Connected:  true,
		LastPingAt: testLiveNow.Add(-20 * time.Second),
		LastPongAt: testLiveNow.Add(-20 * time.Second),
	}
	allow := &agent.DoctorAllowTargets{Set: true, List: "192.168.1.0/24", Env: allowtargets.Env}
	for _, m := range more {
		switch f := m.(type) {
		case func(*agent.DoctorStream):
			f(stream)
		case func(*agent.DoctorAllowTargets):
			f(allow)
		default:
			panic(fmt.Sprintf("unknown editor %T", m))
		}
	}
	return &agent.DoctorResponse{AllowTargets: allow, Stream: stream, RuntimeState: st}
}

// 拒否の累計は、今のトンネルを作った時刻を起点として示す(10.2c 節)。
func TestAgentDoctorShowsRefusalsAgainstTheirStart(t *testing.T) {
	in := testAgentDoctorInput(t, t.TempDir())
	writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
	holdTheLock(t, in.CredentialsPath)
	in.Dial = fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
		st.Budgets[0].Refusals = []agent.DoctorRefusal{{RuleID: "r_1", Reason: resource.ReasonBudget, Count: 7}}
	})))
	c, _ := findAgentCheck(agentDiagnose(in), agentCheckRefusals)
	if c.Status != statusUnknown || c.Reason != agentReasonNoThreshold {
		t.Fatalf("relay.refusals = %s/%q, want %s/%q", c.Status, c.Reason, statusUnknown, agentReasonNoThreshold)
	}
	for _, want := range []string{"7 flows refused", "r_1 tcp budget 7", "since this tunnel was built at 2026-09-23T11:00:00Z"} {
		if !strings.Contains(c.Detail, want) {
			t.Errorf("relay.refusals does not show %q: %q", want, c.Detail)
		}
	}
}

// 読み取りの入口の振り分けそのものを、誤りから直接確かめる。
func TestDialFailureKind(t *testing.T) {
	long := "/" + strings.Repeat("a", agent.ControlPathLimit)
	for _, tc := range []struct {
		name string
		path string
		err  error
		want agentLiveKind
	}{
		{"permission", "/run/agent.json.sock", &net.OpError{Err: syscall.EACCES}, liveDenied},
		{"permission through fs", "/run/agent.json.sock", fs.ErrPermission, liveDenied},
		{"sun_path", long, &net.OpError{Err: syscall.EINVAL}, livePathTooLong},
		// 短いパスの invalid argument は、長さのせいではない。
		{"short invalid", "/run/agent.json.sock", &net.OpError{Err: syscall.EINVAL}, liveUnreachable},
		{"missing", "/run/agent.json.sock", &net.OpError{Err: syscall.ENOENT}, liveUnreachable},
		{"refused", "/run/agent.json.sock", errors.New("connection refused"), liveUnreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dialFailureKind(tc.path, tc.err); got != tc.want {
				t.Errorf("dialFailureKind = %d, want %d", got, tc.want)
			}
		})
	}
}

// データディレクトリの深さが sun_path の上限を超える配置では、既定の入口がそのことを言う。
func TestAgentDoctorNamesALongSocketPath(t *testing.T) {
	deep := filepath.Join(t.TempDir(), strings.Repeat("d/", 60))
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Skipf("this host cannot hold a path that long: %v", err)
	}
	in := testAgentDoctorInput(t, deep)
	in.CredentialsPath = filepath.Join(deep, "agent.json")
	writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
	holdTheLock(t, in.CredentialsPath)
	in.Dial = nil // 既定の入口を使う
	c, _ := findAgentCheck(agentDiagnose(in), agentCheckControl)
	if c.Status != statusFailed || c.Reason != agentReasonControlPathTooLong {
		t.Fatalf("agent.control = %s/%q, want %s/%q", c.Status, c.Reason, statusFailed, agentReasonControlPathTooLong)
	}
	if !strings.Contains(c.Detail, "Unix socket paths hold at most") {
		t.Errorf("agent.control does not name the limit it hit: %q", c.Detail)
	}
	if !strings.Contains(c.Next, "shorter path") {
		t.Errorf("agent.control does not say to use a shorter data directory: %q", c.Next)
	}
}

// ルールの並びは上限で打ち切り、打ち切ったことを末尾に書く。ルールの本数に上限が無いので、
// 1 行が際限なく伸びないようにする一方、切ったことが読み取れないと運用者は並びが全部だと読む。
//
// 上限の値は、実装の定数ではなく数そのもので書く。定数を読むと、上限を変える変異でこの試験の
// 期待も一緒に動き、変えたことが誰にも見えない。
func TestAgentDoctorCapsTheRuleLines(t *testing.T) {
	const rules = 6
	in := testRunningAgent(t, runtimeResponse(func(st *agent.DoctorRuntimeState) {
		st.Rules = nil
		for i := 0; i < rules; i++ {
			st.Rules = append(st.Rules, agent.DoctorRule{ID: fmt.Sprintf("r_%d", i), State: proto.StatusOK,
				Proto: proto.TCP, Listeners: 1, Listening: 1})
		}
	}))
	rep := agentDiagnose(in)
	for _, id := range []string{agentCheckListeners, agentCheckSessions} {
		c, _ := findAgentCheck(rep, id)
		// 6 本のうち、名前で出るのは先頭の 4 本だけで、残る 2 本は件数になる。
		for _, want := range []string{"r_0", "r_1", "r_2", "r_3", "and 2 more"} {
			if !strings.Contains(c.Detail, want) {
				t.Errorf("%s does not show %q: %q", id, want, c.Detail)
			}
		}
		for _, unwanted := range []string{"r_4", "r_5"} {
			if strings.Contains(c.Detail, unwanted) {
				t.Errorf("%s names %s past the cap: %q", id, unwanted, c.Detail)
			}
		}
	}
	// 上限に満たない並びには、印を付けない。
	c, _ := findAgentCheck(agentDiagnose(testRunningAgent(t, healthyLiveResponse())), agentCheckListeners)
	if strings.Contains(c.Detail, "more") {
		t.Errorf("relay.listeners says the list was cut although it holds every rule: %q", c.Detail)
	}
}

// 拒否の並びも上限で打ち切り、打ち切ったことを末尾に書く。拒否はルールと理由の組ごとに立つので、
// 組の数にも上限が無い。上限の値を数そのもので書く理由は、ルールの並びの試験と同じである。
func TestAgentDoctorCapsTheRefusalLines(t *testing.T) {
	const groups = 8
	in := testRunningAgent(t, runtimeResponse(func(st *agent.DoctorRuntimeState) {
		st.Budgets[0].Refusals = nil
		for i := 0; i < groups; i++ {
			st.Budgets[0].Refusals = append(st.Budgets[0].Refusals,
				agent.DoctorRefusal{RuleID: fmt.Sprintf("r_%d", i), Reason: resource.ReasonBudget, Count: 1})
		}
	}))
	c, _ := findAgentCheck(agentDiagnose(in), agentCheckRefusals)
	// 8 組のうち、名前で出るのは先頭の 6 組だけで、残る 2 組は件数になる。合計はすべてを数える。
	for _, want := range []string{"8 flows refused", "r_0", "r_1", "r_2", "r_3", "r_4", "r_5", "and 2 more"} {
		if !strings.Contains(c.Detail, want) {
			t.Errorf("relay.refusals does not show %q: %q", want, c.Detail)
		}
	}
	for _, unwanted := range []string{"r_6", "r_7"} {
		if strings.Contains(c.Detail, unwanted) {
			t.Errorf("relay.refusals names %s past the cap: %q", unwanted, c.Detail)
		}
	}
}

// 制御ソケットの応答が載せるハンドシェイク待ちの理由は、別に組み上げた常駐プロセスが書いた
// 文字列である。この試験はその文字列を直に書いて、読み手がそれを見分けることを固定する。
// internal/agent の側でこの文言だけを変えると、新しい CLI が、まだ入れ替えていない常駐プロセスの
// 応答を読み違えるので、この試験が落ちる。
func TestAgentDoctorReadsTheHandshakePendingReasonAReleasedAgentSends(t *testing.T) {
	const sent = "handshake not established"
	if agent.ReasonHandshakePending != sent {
		t.Fatalf("the agent now sends %q for a pending handshake; agent doctor reads %q, so a CLI newer than the running process misreads it",
			agent.ReasonHandshakePending, sent)
	}
	in := testRunningAgent(t, runtimeResponse(func(st *agent.DoctorRuntimeState) {
		st.Tunnel.State, st.Tunnel.Reason = proto.StatusError, sent
		st.Tunnel.LastHandshake = time.Time{}
	}))
	c, _ := findAgentCheck(agentDiagnose(in), agentCheckTunnelLocal)
	if c.Status != statusUnknown || c.Reason != agentReasonHandshakePending {
		t.Errorf("tunnel.local = %s/%q for the reason a released agent sends, want %s/%q",
			c.Status, c.Reason, statusUnknown, agentReasonHandshakePending)
	}
}

// testRunningAgent は、稼働中のエージェントに対する実行の入力を組む。
func testRunningAgent(t *testing.T, resp *agent.DoctorResponse) agentDoctorInput {
	t.Helper()
	in := testAgentDoctorInput(t, t.TempDir())
	writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
	holdTheLock(t, in.CredentialsPath)
	in.Dial = fakeDoctorSocket(t, liveReply(resp))
	return in
}
