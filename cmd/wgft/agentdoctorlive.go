package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/rahanahu/wgft/internal/agent"
	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは `wgft agent doctor`(設計文書 10.2c 節)の、稼働中のプロセスの制御ソケットから
// しか取れない検査を持つ。節の表で「停止中」が「成立しない」の行である。
//
// 証拠は、認証情報ファイルの隣の `agent.json.sock` に `doctor` の 1 行を送って得た 1 行の JSON で
// ある。応答の型は internal/agent の DoctorResponse で、その形だけで 3 つの状態を区別できる。
// error だけがあれば応答を組む処理が panic した実行、runtime_state が無く runtime_state_timeout が
// あれば実行時の排他を期限内に取れなかった実行、runtime_state があれば正常な実行である。
// allow_targets と stream は実行時の排他を要らないので、排他を取れなかった応答にも載る。
//
// 応答の文字列には internal/agent の側で 512 バイトの上限が掛かっており、超えた分は切って印が
// 付いている。表示の側で二重に切らない。

// agentControlDialTimeout は制御ソケットに繋ぐまでの期限である。
const agentControlDialTimeout = 5 * time.Second

// agentControlReplyTimeout は、要求を書いてから応答の 1 行を読み終えるまでの期限である。
//
// 稼働中のエージェントは実行時の排他を 2 秒だけ待って応答を組むので(internal/agent の
// defaultDoctorLockWait)、答えが返るまでの時間はその桁に収まる。5 倍の余裕を取ってなお、
// 制御ソケットの接続に常駐プロセスが掛ける 30 秒より十分に短い。診断はトラブルの最中に繰り返し
// 使うコマンドなので、答えないソケットの前で 30 秒止まるより、答えなかった事実を返すほうがよい。
const agentControlReplyTimeout = 10 * time.Second

// agentLiveKind は、制御ソケットから実行時の状態を読んだ結果の区分である。10.2c 節の
// 「制御ソケットから実行時の状態を取れない場合」が分ける場合を、そのまま値にしてある。
type agentLiveKind int

const (
	// liveNotAttempted は、エージェントが稼働していないか、稼働しているかどうかを判定できないため
	// 制御ソケットに繋がなかった実行である。
	liveNotAttempted agentLiveKind = iota
	// liveOK は、実行時の状態まで載った応答を得た実行である。
	liveOK
	// liveRuntimeBusy は、エージェントが実行時の状態を守る排他を期限内に取れなかった実行である。
	// 排他を要らない allow_targets と stream は応答に載っている。
	liveRuntimeBusy
	// liveAgentError は、応答を組む処理が panic した実行である。
	liveAgentError
	// liveUnsupported は、古い常駐プロセスが `error: unknown command` を返した実行である。
	liveUnsupported
	// liveReplyUnreadable は、繋げたが応答を読めなかった実行である。
	liveReplyUnreadable
	// liveDenied は、ファイルのパーミッションで繋げない実行である。
	liveDenied
	// livePathTooLong は、ソケットのパスが sun_path の上限を超えている実行である。
	livePathTooLong
	// liveUnreachable は、上のどれでもない理由で繋げない実行である。エージェントがソケットを
	// 開けないまま動いている場合が当たる。
	liveUnreachable
)

// 稼働中のプロセスから読む検査の理由の符号。agentdoctor.go の符号と同じく、JSON の "reason" の
// 値であり、1 つの符号は 1 つの事実だけを表す(設計文書 10.2c 節の「機械向けの出力」)。
const (
	// agentReasonControlUnreachable は、稼働中のエージェントの制御ソケットに繋げない場合である。
	// 10.2c 節が定める符号であり、接続そのものができない場合だけに当てる。パスが長すぎる場合は
	// agentReasonControlPathTooLong であり、この符号に含めない。
	agentReasonControlUnreachable = "control_socket_unreachable"
	// agentReasonControlPathTooLong は、制御ソケットのパスが sun_path の上限を超えていて、原理的に
	// 繋げない場合である。パスを変えない限り続く事実であり、対処もデータディレクトリを短いパスに
	// 移すことなので、他の繋げない場合と分ける(10.2c 節)。
	agentReasonControlPathTooLong = "control_socket_path_too_long"
	// agentReasonDoctorUnsupported は、古い常駐プロセスが doctor に対応していない場合である。
	// 接続はできているので control_socket_unreachable には当たらない(10.2c 節)。
	agentReasonDoctorUnsupported = "doctor_unsupported"
	// agentReasonDoctorFailed は、エージェントが自分の状態を組めなかったと答えた場合である。
	agentReasonDoctorFailed = "doctor_failed"
	// agentReasonDoctorUnreadable は、繋げたが応答を読めなかった場合である。
	agentReasonDoctorUnreadable = "doctor_reply_unreadable"
	// agentReasonRuntimeBusy は、エージェントが実行時の状態を守る排他を期限内に取れなかった
	// 場合である。
	agentReasonRuntimeBusy = "runtime_state_busy"
	// agentReasonNoThreshold は、値は読めたが、その値の良し悪しを言う閾値をこのコマンドが
	// 持たない場合である(10.2c 節が tunnel.transfer に定める符号)。
	agentReasonNoThreshold = "no_threshold"
	// agentReasonReconnecting は、制御ストリームが切れて繋ぎ直している場合である(10.2c 節)。
	agentReasonReconnecting = "reconnecting"
	// agentReasonHandshakePending は、トンネルはあるがハンドシェイクがまだ成立していない場合で
	// ある(10.2c 節)。
	agentReasonHandshakePending = "handshake_pending"
	// agentReasonNoTunnel は、トンネルが今無いことである。tunnel.local では、原因が
	// agentReasonFullStatePending と agentReasonTunnelBuildFailed のどちらにも当たらない場合に
	// 当てる。tunnel.transfer では原因を問わずに当てる。
	agentReasonNoTunnel = "no_tunnel"
	// agentReasonFullStatePending は、トンネルが無く、稼働中のエージェントが全体状態をまだ持って
	// いない場合である。agent.json が全体状態を持たないこと(agentReasonNoLastState)とは別の
	// 事実であり、稼働中のプロセスから読む。
	agentReasonFullStatePending = "full_state_pending"
	// agentReasonTunnelBuildFailed は、トンネルの構築が実際に失敗している場合である。
	agentReasonTunnelBuildFailed = "tunnel_build_failed"
	// agentReasonTunnelErrorNoEndpoint は、トンネルが誤りを報告していて、転送に使える解決済みの
	// エンドポイントも残っていない場合である。
	agentReasonTunnelErrorNoEndpoint = "tunnel_error_no_endpoint"
	// agentReasonTunnelErrorEndpointKept は、トンネルが誤りを報告しているが、解決済みの
	// エンドポイントは残っている場合である。
	agentReasonTunnelErrorEndpointKept = "tunnel_error_endpoint_kept"
	// agentReasonListenerError は、ルール 1 本以上の状態が error の場合である。
	agentReasonListenerError = "listener_error"
	// agentReasonNoRelay は、中継がまだ無い場合である。中継はトンネルと一緒に作られるので、
	// トンネルが無い間は中継も無い。
	agentReasonNoRelay = "no_relay"
	// agentReasonAgentDisabled は、server がこのエージェントを無効にしている場合である
	// (仕様 5.1 節、設計文書 10.2c 節の relay.listeners の粒度)。無効を示すための新しい検査は
	// 作らない。カーネルモードの dataplane.interface、dataplane.table、host.forwarding(同節の
	// 「カーネルモードのエージェント」の項)も同じ符号を使う。
	agentReasonAgentDisabled = "agent_disabled"
)

// 所見に並べる項目の数の上限。ルールの本数にも拒否の組み合わせの数にも上限が無いので、1 行が
// 際限なく伸びないように先頭のいくつかだけを並べ、残りは件数で示す。ルールより拒否を多く出すのは、
// 拒否がルールと理由の組ごとに立ち、1 本のルールが 3 つの理由を持ちうるためである。
const (
	// agentMaxRuleLines はルールを並べる本数の上限である。
	agentMaxRuleLines = 4
	// agentMaxRefusalLines は拒否の組を並べる数の上限である。
	agentMaxRefusalLines = 6
)

// agentAndMore は、上限で打ち切った並びの末尾に添える句である。切ったことを運用者が読み取れる
// ようにする。
func agentAndMore(rest int) string {
	return fmt.Sprintf("and %d more", rest)
}

// agentLive は制御ソケットから読んだ実行時の状態である。
type agentLive struct {
	Kind agentLiveKind
	// Path は繋ぎに行った制御ソケットの場所である。
	Path string
	// Err は繋げなかった、または応答を読めなかった理由である。
	Err error
	// Resp は得た応答である。Kind が liveOK、liveRuntimeBusy、liveAgentError のときだけ値を持つ。
	Resp *agent.DoctorResponse
	// Reply は JSON として読めなかった応答の本文である。
	Reply string
}

// readAgentLive は稼働中のエージェントの制御ソケットから実行時の状態を読む。稼働していない実行と
// 稼働を判定できない実行では繋ぎに行かない。
func readAgentLive(in agentDoctorInput, run agentRunState) agentLive {
	if !run.running() {
		return agentLive{Kind: liveNotAttempted}
	}
	path := agent.ControlPath(in.CredentialsPath)
	c, err := in.Dial(path)
	if err != nil {
		return agentLive{Kind: dialFailureKind(path, err), Path: path, Err: err}
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(agentControlReplyTimeout))
	if _, err := fmt.Fprintln(c, agent.DoctorCommand); err != nil {
		return agentLive{Kind: liveReplyUnreadable, Path: path, Err: err}
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return agentLive{Kind: liveReplyUnreadable, Path: path, Err: err}
	}
	return classifyDoctorReply(path, line)
}

// dialFailureKind は、繋げなかった理由を 10.2c 節が分ける 3 つの場合に振り分ける。終了コードが
// 分かれるので、1 つに畳まない。ファイルのパーミッションで繋げない場合だけが終了コード 2 である。
func dialFailureKind(path string, err error) agentLiveKind {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return liveDenied
	case errors.Is(err, syscall.EINVAL) && len(path) > agent.ControlPathLimit:
		// Go の net は sun_path に収まらない名前を OS を呼ぶ前に EINVAL で拒むので、もとの誤りは
		// invalid argument としか言わない(internal/agent/control.go)。
		return livePathTooLong
	default:
		return liveUnreachable
	}
}

// classifyDoctorReply は応答の 1 行を区分に写す。応答の形だけで 3 つの状態を区別できる
// (internal/agent/doctor.go)。
func classifyDoctorReply(path, line string) agentLive {
	text := strings.TrimSpace(line)
	if text == "error: unknown command" {
		// 新しい実行ファイルを置いてから常駐プロセスを再起動するまでの間に出る応答である
		// (10.2c 節の「制御ソケットの拡張」)。
		return agentLive{Kind: liveUnsupported, Path: path, Reply: text}
	}
	var resp agent.DoctorResponse
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		return agentLive{Kind: liveReplyUnreadable, Path: path, Err: err, Reply: text}
	}
	switch {
	case resp.Error != "":
		return agentLive{Kind: liveAgentError, Path: path, Resp: &resp}
	case resp.RuntimeState != nil:
		return agentLive{Kind: liveOK, Path: path, Resp: &resp}
	case resp.RuntimeStateTimeout > 0:
		return agentLive{Kind: liveRuntimeBusy, Path: path, Resp: &resp}
	}
	// 3 つのどれでもない応答は、この型が約束する形を満たしていない。
	return agentLive{Kind: liveReplyUnreadable, Path: path,
		Err: errors.New("the reply carries neither a runtime state, a timeout nor an error"), Reply: text}
}

// dialAgentControl は制御ソケットに繋ぐ既定の入口である。
func dialAgentControl(path string) (net.Conn, error) {
	return net.DialTimeout("unix", path, agentControlDialTimeout)
}

// --- 検査の組み立て ---

// agentLiveChecks は、稼働中のプロセスの制御ソケットからしか取れない検査を組み立てる。項目ごと
// 落とす案は採らない。実行の状態によって項目そのものが消えると、機械が処理しにくくなるためで
// ある(10.2c 節)。agentName は relay.listeners の所見が名指す、このエージェントの登録名である。
//
// mode はエージェントのモードである。カーネルモードでは、試す対象の無い検査を、実行の状態によらず
// NOT TESTED にする(10.2c 節の「カーネルモードのエージェント」)。
func agentLiveChecks(in agentDoctorInput, run agentRunState, live agentLive, agentName, mode string) []agentDoctorCheck {
	out := make([]agentDoctorCheck, 0, len(agentLiveOnly))
	for _, spec := range agentLiveOnly {
		c := agentDoctorCheck{ID: spec.ID, Group: spec.Group, Label: spec.Label, verdict: spec.verdict, valueOnly: spec.valueOnly}
		if mode == credentials.ModeKernel && agentKernelOnlyNotTested(spec.ID) {
			agentKernelNotTested(&c)
			out = append(out, c)
			continue
		}
		if spec.ID == agentCheckControl {
			agentControlCheck(&c, run, live)
			out = append(out, c)
			continue
		}
		if !agentLiveValueRead(spec.ID, live) {
			agentLiveSkip(&c, run, live)
			if spec.ID == agentCheckAllowTargets && live.Kind == liveNotAttempted {
				// 宛先の許可一覧だけは、停止中と稼働を判定できない実行で UNKNOWN になる
				// (10.2c 節)。稼働中に繋げない実行は SKIPPED のままである。
				agentAllowTargetsState(&c, run)
			}
			out = append(out, c)
			continue
		}
		agentLiveValueCheck(&c, in, live.Resp, agentName)
		out = append(out, c)
	}
	return out
}

// agentLiveValueRead は、その検査の値がこの実行で読めたかどうかを返す。実行時の排他を取れなかった
// 応答にも allow_targets と stream は載っているので、その 4 つだけは読める。
func agentLiveValueRead(id string, live agentLive) bool {
	switch live.Kind {
	case liveOK:
		return live.Resp != nil && live.Resp.RuntimeState != nil && live.Resp.Stream != nil && live.Resp.AllowTargets != nil
	case liveRuntimeBusy:
		return !agentLiveNeedsRuntimeState(id) && live.Resp != nil && live.Resp.Stream != nil && live.Resp.AllowTargets != nil
	default:
		return false
	}
}

// agentLiveNeedsRuntimeState は、その検査が実行時の排他の下でしか読めない値を見るかどうかである。
func agentLiveNeedsRuntimeState(id string) bool {
	switch id {
	case agentCheckTunnelLocal, agentCheckWatchdog, agentCheckTransfer,
		agentCheckListeners, agentCheckSessions, agentCheckRefusals:
		return true
	}
	return false
}

// agentLiveSkip は、値を読めなかった検査を SKIPPED にする。理由の符号は場合ごとに分ける。
func agentLiveSkip(c *agentDoctorCheck, run agentRunState, live agentLive) {
	c.Status = statusSkipped
	switch live.Kind {
	case liveNotAttempted:
		if run.undetermined() {
			// 手前の agent.process の符号をそのまま持つ(10.2c 節)。
			c.Reason = agentReasonLockUnreadable
			c.Detail = "whether the agent is running could not be determined, so its live state was not read"
			return
		}
		c.Reason = agentReasonNotRunning
		c.Detail = "the agent is not running, so its live state was not read"
	case liveDenied, livePathTooLong, liveUnreachable:
		// 手前の agent.control の符号をそのまま持つ(10.2c 節)。
		c.Reason = agentReasonControlUnreachable
		if live.Kind == livePathTooLong {
			c.Reason = agentReasonControlPathTooLong
		}
		c.Detail = "the agent is running, but its control socket could not be reached, so its live state was not read"
		c.Next = "the control socket line above says why; this value comes from the running process alone"
	case liveUnsupported:
		c.Reason = agentReasonDoctorUnsupported
		c.Detail = "the running agent does not answer doctor, so its live state was not read"
		c.Next = agentRestartForDoctorNext
	case liveAgentError:
		c.Reason = agentReasonDoctorFailed
		c.Detail = "the running agent could not collect its own state, so this value was not read"
		c.Next = agentDoctorFailedNext
	case liveReplyUnreadable:
		c.Reason = agentReasonDoctorUnreadable
		c.Detail = "the running agent's reply could not be read, so its live state was not read"
		c.Next = "the control socket line above says why; run this command again, and read the agent's log if it keeps answering that way"
	case liveRuntimeBusy:
		c.Reason = agentReasonRuntimeBusy
		c.Detail = fmt.Sprintf("the running agent did not take the lock that guards its runtime state within %s, so this value was not read",
			live.Resp.RuntimeStateTimeout.Round(time.Millisecond))
		c.Next = agentRuntimeBusyNext
	}
}

// agentRestartForDoctorNext は、古い常駐プロセスに当たった実行に添える次の手である。
const agentRestartForDoctorNext = "the running process was started from an older binary than this one; restart the agent so it runs the installed binary, " +
	"with systemctl restart wgft-agent, or docker restart for a container"

// agentDoctorFailedNext は、エージェントが自分の状態を組めなかった実行に添える次の手である。
const agentDoctorFailedNext = "the agent logs the failure and its stack; read it with journalctl -u wgft-agent, or docker logs for a container. " +
	"Forwarding is not stopped by this, so the rules it already holds keep running"

// agentRuntimeBusyNext は、実行時の排他を取れなかった実行に添える次の手である。
const agentRuntimeBusyNext = "the agent is alive but busy inside: its 30s round of target checks holds that lock while it dials every target, " +
	"and a target that never answers stretches the round. Read which targets answer, and run this command again"

// agentControlCheck は agent.control を組み立てる。総合判定は動かさない。制御ソケットに繋げない
// ことは、終了コード 1 が答える問いに対して偽だからである(10.2c 節)。
func agentControlCheck(c *agentDoctorCheck, run agentRunState, live agentLive) {
	switch live.Kind {
	case liveNotAttempted:
		agentLiveSkip(c, run, live)
	case liveOK:
		c.Status = statusOK
		c.Detail = "the running agent answered doctor on its control socket at " + live.Path
	case liveRuntimeBusy:
		// 制御ソケットに繋げて応答も得ているので、この検査が答える問いは満たされている。欠けた
		// のは実行時の部分だけであり、そのことは続く検査の SKIPPED が述べる(10.2c 節)。
		c.Status = statusOK
		c.Detail = "the running agent answered doctor on its control socket at " + live.Path +
			"; its reply left out the runtime state, and the lines below say so"
	case liveUnsupported:
		// 接続そのものは成功しているので SKIPPED には当たらず、FAILED にすると転送が健全な配置に
		// 対しても壊れている印象を与える(10.2c 節)。
		c.Status, c.Reason = statusUnknown, agentReasonDoctorUnsupported
		c.Detail = "the control socket at " + live.Path + " answered, but the running agent does not carry the doctor command: it replied " + live.Reply
		c.Next = agentRestartForDoctorNext
	case liveAgentError:
		c.Status, c.Reason = statusUnknown, agentReasonDoctorFailed
		c.Detail = "the control socket at " + live.Path + " answered, but the agent could not collect its own state: " + live.Resp.Error
		c.Next = agentDoctorFailedNext
	case liveReplyUnreadable:
		c.Status, c.Reason = statusUnknown, agentReasonDoctorUnreadable
		c.Detail = "the control socket at " + live.Path + " answered, but its reply could not be read: " + errText(live.Err)
		c.Next = "run this command again; if the reply stays unreadable, restart the agent so both sides run the installed binary"
	case liveDenied:
		// 制御ソケットへ権限の不足で接続できず、総合判定を動かす検査まで取れないので、診断そのもの
		// が十分に成立しなかった場合に当たる(10.2c 節)。3 つの原因のうちこの 1 つだけが 2 である。
		c.Status, c.Reason, c.evidenceUnreachable = statusFailed, agentReasonControlUnreachable, true
		c.Detail = "the agent is running, but its control socket at " + live.Path + " refuses this command's permissions: " + errText(live.Err)
		c.Next = agentSamePrincipalNext
	case livePathTooLong:
		c.Status, c.Reason = statusFailed, agentReasonControlPathTooLong
		c.Detail = fmt.Sprintf("the agent is running, but its control socket path is %d bytes: %s. Unix socket paths hold at most 107 bytes on Linux and Windows and 103 on macOS, "+
			"so this path cannot be opened at all", len(live.Path), live.Path)
		c.Next = "move the data directory to a shorter path and restart the agent; forwarding itself is not affected, only this socket. " +
			"Set it with WGFT_DATA_DIR, the same way agent rotate-key needs it"
	case liveUnreachable:
		c.Status, c.Reason = statusFailed, agentReasonControlUnreachable
		c.Detail = "the agent is running, but its control socket at " + live.Path + " could not be reached: " + errText(live.Err)
		c.Next = "the agent keeps forwarding without this socket, so this is not a forwarding fault. Read its log with journalctl -u wgft-agent, " +
			"or docker logs for a container: it prints a line when it cannot open the socket. If it printed none, the socket file at that path is " +
			"a leftover of a process that did not remove it, and restarting the agent replaces it"
	}
}

// agentLiveValueCheck は、読めた値を検査に写す。
func agentLiveValueCheck(c *agentDoctorCheck, in agentDoctorInput, resp *agent.DoctorResponse, agentName string) {
	switch c.ID {
	case agentCheckStreamConn:
		agentStreamConnCheck(c, in, resp.Stream)
	case agentCheckStreamBackfl:
		agentStreamBackoffCheck(c, in, resp.Stream)
	case agentCheckStreamLive:
		agentStreamLivenessCheck(c, in, resp.Stream)
	case agentCheckAllowTargets:
		agentAllowTargetsValue(c, resp.AllowTargets)
	case agentCheckTunnelLocal:
		agentTunnelLocalCheck(c, in, resp.RuntimeState)
	case agentCheckWatchdog:
		agentWatchdogCheck(c, in, resp.RuntimeState)
	case agentCheckTransfer:
		agentTransferCheck(c, in, resp.RuntimeState)
	case agentCheckListeners:
		agentListenersCheck(c, resp.RuntimeState, agentName)
	case agentCheckSessions:
		agentSessionsCheck(c, resp.RuntimeState)
	case agentCheckRefusals:
		agentRefusalsCheck(c, in, resp.RuntimeState)
	}
}

// --- Connection 群 ---

// agentStreamConnCheck は制御ストリームが今つながっているかを示す。総合判定は動かさない。切れて
// いることは、受け取り済みのルールを転送し続けている間も起こるためである(10.2c 節)。
func agentStreamConnCheck(c *agentDoctorCheck, in agentDoctorInput, s *agent.DoctorStream) {
	if s.Connected {
		c.Status = statusOK
		c.Detail = "the control stream to the server is up"
		return
	}
	c.Status, c.Reason = statusUnknown, agentReasonReconnecting
	// 示す理由には、接続が切れた理由だけでなく、接続に至らなかった試みの失敗も入る(10.2c 節)。
	switch {
	case s.DisconnectedAt.IsZero():
		c.Detail = "the control stream to the server is not up, and no attempt has ended yet"
	default:
		c.Detail = "the control stream to the server is not up; the last attempt ended " + agentWhen(in.Now, s.DisconnectedAt) +
			": " + reasonOr(s.DisconnectReason, "no reason was recorded")
	}
	c.Next = "the agent retries by itself, so this alone is not a fault. Rules it already holds keep being forwarded while the stream is down. " +
		"If it stays down, read the reason above and the server's log on the VPS"
}

// agentStreamBackoffCheck は、直近に待った再接続の間隔と、待っている場合の次に試す時刻を示す。
// 値を述べるだけの検査なので、状態は UNKNOWN、理由の符号は no_threshold とする。良し悪しを言う
// 閾値をこのコマンドは持たない(10.2c 節が tunnel.transfer に与えたのと同じ扱い)。
func agentStreamBackoffCheck(c *agentDoctorCheck, in agentDoctorInput, s *agent.DoctorStream) {
	c.Status, c.Reason = statusUnknown, agentReasonNoThreshold
	parts := []string{}
	if s.Backoff > 0 {
		parts = append(parts, "the last reconnect wait was "+s.Backoff.Round(time.Second).String())
	} else {
		parts = append(parts, "no reconnect wait has been recorded on this connection yet")
	}
	if s.RetryAt.IsZero() {
		parts = append(parts, "no attempt is waiting now")
	} else {
		parts = append(parts, "the next attempt is due "+agentDue(in.Now, s.RetryAt))
	}
	c.Detail = strings.Join(parts, "; ")
	c.Next = "read it with the control connection above: a wait that keeps growing while the stream stays down points at the server or the line to it, " +
		"not at this host"
}

// agentStreamLivenessCheck は、直近の ping と pong の時刻と、pong を待っている最中かどうかを示す。
func agentStreamLivenessCheck(c *agentDoctorCheck, in agentDoctorInput, s *agent.DoctorStream) {
	c.Status, c.Reason = statusUnknown, agentReasonNoThreshold
	var parts []string
	switch {
	case s.LastPingAt.IsZero():
		parts = append(parts, "no ping has been sent on this connection")
	default:
		parts = append(parts, "the last ping went out "+agentWhen(in.Now, s.LastPingAt))
	}
	switch {
	case s.LastPongAt.IsZero():
		parts = append(parts, "no pong has come back on it")
	default:
		parts = append(parts, "the last pong came back "+agentWhen(in.Now, s.LastPongAt))
	}
	if s.AwaitingPong {
		parts = append(parts, "a pong is outstanding right now")
	}
	c.Detail = strings.Join(parts, "; ")
	c.Next = "these are the agent's own keepalives on the control stream. They are cleared whenever it reconnects, " +
		"so an empty pair on a stream that is up means the connection is new"
}

// --- Tunnel 群 ---

// agentTunnelLocalCheck はトンネルの状態を示す。総合判定を動かす検査である。判定は、エージェントが
// ハートビートのために計算している状態をそのまま入力とし、doctor のための 2 つ目の計算を持たない
// (10.2c 節)。最終ハンドシェイクが健全かどうかは言わない。その判定と 3 分の閾値は 10.2a 節が
// 持っている。
func agentTunnelLocalCheck(c *agentDoctorCheck, in agentDoctorInput, st *agent.DoctorRuntimeState) {
	t := st.Tunnel
	if t.State != proto.StatusError {
		c.Status = statusOK
		c.Detail = "the tunnel is up to " + orDash(t.Endpoint) + "; " + agentHandshakeText(in.Now, t.LastHandshake)
		return
	}
	if !t.Present {
		agentNoTunnelCheck(c, t.Reason)
		return
	}
	// トンネルがある場合は、ts.Err があることを先に見て、LastHandshake が無いことを後に見る。
	// ハートビートの分岐がこの順であり、両方が成り立つ実行の理由は ts.Err の側になる(10.2c 節)。
	if t.Reason == agent.ReasonHandshakePending {
		c.Status, c.Reason = statusUnknown, agentReasonHandshakePending
		c.Detail = "the tunnel is up to " + orDash(t.Endpoint) + ", but no handshake has been established on it yet"
		c.Next = "a tunnel that was just built always passes through this state. If it stays here, the VPS's WireGuard UDP port, this line's firewall or the ISP " +
			"may be dropping the tunnel's UDP; run wgft server doctor on the VPS to see the same tunnel from the other side"
		return
	}
	// 誤りの種類でも、どの呼び出しが失敗したかでも分けない。判定に使えるのは、その時点で転送に
	// 使える解決済みのエンドポイントが残っているかどうかだけである(10.2c 節)。
	if t.Endpoint == "" {
		c.Status, c.Reason = statusFailed, agentReasonTunnelErrorNoEndpoint
		c.Detail = "the tunnel reports an error and holds no resolved endpoint to carry traffic: " + t.Reason
		c.Next = "read the agent's log for what it says while building and driving the tunnel, with journalctl -u wgft-agent, or docker logs for a container. " +
			"The wg endpoint resolve line above says whether the peer's name resolves from here"
		return
	}
	c.Status, c.Reason = statusUnknown, agentReasonTunnelErrorEndpointKept
	// wg 設定の拒否では、インタフェースは直前の設定のまま残るが、server が拒んだ設定で動く間はトンネルの
	// 中の宛先が合わず、転送が止まりうる。エンドポイントが転送を続けられるとは言わない(設計文書 7b.1 節)
	if strings.HasPrefix(t.Reason, agent.ReasonWGRefused) {
		c.Detail = "the agent refused the wg configuration the server sent and keeps the interface and rules of the last configuration it applied, " +
			"with the endpoint " + t.Endpoint + ": " + t.Reason
		c.Next = "while the server runs with the configuration this agent refused, such as another tunnel address, traffic through the tunnel stops, since the two sides no longer agree. " +
			"If the server's operator moved the range on purpose, register this agent again with a new join string; otherwise find out who changed the server"
		return
	}
	c.Detail = "the tunnel reports an error but still holds the resolved endpoint " + t.Endpoint + ", which can keep carrying traffic: " + t.Reason
	c.Next = "read the agent's log for the same error with its context, with journalctl -u wgft-agent, or docker logs for a container. " +
		"Traffic can still flow over the endpoint it resolved earlier, so this is not by itself a stop"
}

// agentNoTunnelCheck は、トンネルが無い場合の判定である。理由ごとに定める(10.2c 節)。正常な
// 遷移でも生じる理由を FAILED にすると、一過性の状態を故障として扱うことになる。
func agentNoTunnelCheck(c *agentDoctorCheck, reason string) {
	// 理由の文字列は internal/agent の tunnelSnapshotLocked が組み立てる 4 通りである。知らない
	// 理由は UNKNOWN の側に倒す。壊れていると断じるより、判定できないと述べるほうが害が小さい。
	switch {
	case strings.HasPrefix(reason, "no tunnel; building it failed"):
		c.Status, c.Reason = statusFailed, agentReasonTunnelBuildFailed
		c.Detail = "there is no tunnel: " + reason
		c.Next = "read why the build failed in the agent's log, with journalctl -u wgft-agent, or docker logs for a container. " +
			"The wg configuration comes from the server, so wgft rule ls and the server's log on the VPS say what it was told to build"
	case strings.Contains(reason, "full state not received"):
		c.Status, c.Reason = statusUnknown, agentReasonFullStatePending
		c.Detail = "there is no tunnel yet: " + reason
		c.Next = "this is where an agent sits until the server answers it. The control connection line above says whether the stream is up"
	default:
		c.Status, c.Reason = statusUnknown, agentReasonNoTunnel
		c.Detail = "there is no tunnel right now: " + reason
		c.Next = "closing the tunnel is also a normal step, after agent rotate-key or while the agent stops, so this alone is not a fault. " +
			"Run this command again to see whether one comes back"
	}
}

// agentHandshakeText は最終ハンドシェイクを事実として述べる。健全かどうかは言わない(10.2c 節)。
func agentHandshakeText(now, h time.Time) string {
	if h.IsZero() {
		return "no handshake has been established on it"
	}
	return "the last handshake was " + agentWhen(now, h)
}

// agentWatchdogCheck は、今のトンネルを作った時刻、作り直しの間隔の実効値、試し直しを待っている
// 場合の予定を示す。次の作り直しまでの残り時間は示さない。値が保持されておらず、示すには起点を
// 求める規則を診断の側に写すことになる(10.2c 節)。
func agentWatchdogCheck(c *agentDoctorCheck, in agentDoctorInput, st *agent.DoctorRuntimeState) {
	c.Status, c.Reason = statusUnknown, agentReasonNoThreshold
	t := st.Tunnel
	var parts []string
	switch {
	case t.StartedAt.IsZero():
		parts = append(parts, "no tunnel is up to watch")
	default:
		parts = append(parts, "the tunnel in place was built "+agentWhen(in.Now, t.StartedAt))
	}
	parts = append(parts, "the rebuild interval in force is "+t.Watchdog.RebuildInterval.Round(time.Second).String())
	switch {
	case t.Watchdog.RetryAt.IsZero():
		parts = append(parts, "no rebuild is waiting to be retried")
	default:
		parts = append(parts, "a failed build is due to be retried "+agentDue(in.Now, t.Watchdog.RetryAt))
	}
	c.Detail = strings.Join(parts, "; ")
	c.Next = "the interval is the value the agent judges by, not a countdown: the time left is not kept anywhere, so it is not shown. " +
		"A rebuild pending here means the tunnel line above says why the last build failed"
}

// agentTransferCheck はトンネルの送受信バイト数を示す。状態は UNKNOWN とし、理由の符号を
// no_threshold とする。多い少ないは、それだけでは健全さを意味しない(10.2c 節)。
func agentTransferCheck(c *agentDoctorCheck, in agentDoctorInput, st *agent.DoctorRuntimeState) {
	t := st.Tunnel
	if !t.Present {
		c.Status, c.Reason = statusUnknown, agentReasonNoTunnel
		c.Detail = "there is no tunnel now, so it carries no counters"
		c.Next = "the tunnel line above says why there is none"
		return
	}
	c.Status, c.Reason = statusUnknown, agentReasonNoThreshold
	c.Detail = fmt.Sprintf("%d bytes received and %d bytes sent on the tunnel built %s", t.RxBytes, t.TxBytes, agentWhen(in.Now, t.StartedAt))
	if st.Mode == credentials.ModeKernel {
		// カーネルは数をインタフェースを作ったときから数え、エージェントの再起動では 0 に戻さない
		// (10.2c 節)。エージェントが立てた時刻を起点として示さない
		c.Detail = fmt.Sprintf("%d bytes received and %d bytes sent on the kernel's WireGuard interface, counted since the kernel created it", t.RxBytes, t.TxBytes)
	}
	c.Next = "a tunnel that nobody is using stays at these numbers and is healthy, so this command sets no threshold on them. " +
		"Run it twice while traffic should be flowing to see whether they move"
}

// --- Relay 群 ---

// agentListenersCheck はルールごとのリスナーを示す。総合判定を動かす検査である。判定も所見も
// ルール単位とし、FAILED になるのはルール単位の状態が error の場合だけである。リスナー 1 つずつは
// 並べない(10.2c 節)。
//
// server がこのエージェントを無効にしている場合(仕様 5.1 節)は、中継の有無を見るより先に
// SKIPPED とする(設計文書 10.2c 節の relay.listeners の粒度)。無効なエージェントは宣言どおり
// リスナーを 1 つも持たなくなるので、中継そのものは生きていても「ルールを持たない健全な配置」
// (agentNoRelay の下の分岐)と区別が付かない。無効を示すための新しい検査は作らない。
func agentListenersCheck(c *agentDoctorCheck, st *agent.DoctorRuntimeState, agentName string) {
	if st.AgentDisabled {
		agentDisabledSkip(c)
		c.Detail = "the server has disabled this agent; it opens no listeners until wgft agent enable " + orDash(agentName) + " is run on the VPS"
		return
	}
	if agentNoRelay(c, st, "which listeners are open") {
		return
	}
	if len(st.Rules) == 0 {
		c.Status = statusOK
		c.Detail = "the relay holds no rules, so it opens no listeners"
		return
	}
	var bad, good []agent.DoctorRule
	for _, r := range st.Rules {
		if r.State == proto.StatusError {
			bad = append(bad, r)
			continue
		}
		good = append(good, r)
	}
	if len(bad) == 0 {
		c.Status = statusOK
		c.Detail = fmt.Sprintf("%d rule%s, all listening: %s", len(good), pluralS(len(good)), strings.Join(agentRuleLines(good), "; "))
		return
	}
	c.Status, c.Reason = statusFailed, agentReasonListenerError
	c.Detail = fmt.Sprintf("%d of %d rule%s cannot serve: %s", len(bad), len(st.Rules), pluralS(len(st.Rules)), strings.Join(agentRuleLines(bad), "; "))
	if len(good) > 0 {
		c.Detail += fmt.Sprintf(". The other %d rule%s listen", len(good), pluralS(len(good)))
	}
	c.Next = "a listener that cannot bind names a port another process on this host already holds; free it, or have the server publish another public port. " +
		"A target that cannot be reached names the LAN service; check that it is up and that this host can reach it"
}

// agentRuleLines はルールごとの 1 句を組み立てる。長くなりすぎないよう先頭のいくつかだけを返す。
// 誤りの文字列は internal/agent の側で既に 512 バイトに切られているので、ここでは切らない。
func agentRuleLines(rules []agent.DoctorRule) []string {
	out := make([]string, 0, agentMaxRuleLines+1)
	for i, r := range rules {
		if i == agentMaxRuleLines {
			out = append(out, agentAndMore(len(rules)-agentMaxRuleLines))
			break
		}
		line := fmt.Sprintf("%s %s: %d of %d listener%s open", r.ID, orDash(string(r.Proto)), r.Listening, r.Listeners, pluralS(r.Listeners))
		if r.BindErrors > 0 {
			line += fmt.Sprintf(", %d cannot bind: %s", r.BindErrors, r.BindError)
		}
		if r.TargetErrors > 0 {
			line += fmt.Sprintf(", %d cannot reach the target: %s", r.TargetErrors, r.TargetError)
		}
		if r.BindErrors == 0 && r.TargetErrors == 0 && r.Reason != "" {
			line += ", " + r.Reason
		}
		out = append(out, line)
	}
	return out
}

// agentSessionsCheck はルールごとの公開側の接続の数と、フロー予算の使用量と上限を示す。上限の
// 対象である公開側の接続の数を示す(10.2c 節)。
func agentSessionsCheck(c *agentDoctorCheck, st *agent.DoctorRuntimeState) {
	if agentNoRelay(c, st, "how many connections it carries") {
		return
	}
	c.Status, c.Reason = statusUnknown, agentReasonNoThreshold
	var parts []string
	for _, b := range st.Budgets {
		part := fmt.Sprintf("%s budget %d, %d in use, %d rule%s admitted", b.Proto, b.Total, b.InUse, b.Rules, pluralS(b.Rules))
		if b.Rules > 1 {
			part += fmt.Sprintf(", cap %d per rule, reserve %d", b.RuleCap, b.Reserve)
		}
		parts = append(parts, part)
	}
	if len(st.Rules) == 0 {
		parts = append(parts, "the relay holds no rules")
	} else {
		parts = append(parts, strings.Join(agentSessionLines(st.Rules), "; "))
	}
	c.Detail = strings.Join(parts, "; ")
	c.Next = "flows are what the budget counts: one per public-side connection for TCP, one per source address and port for UDP. " +
		"Sessions count both sides of a TCP relay, so the two numbers differ by design"
}

// agentSessionLines はルールごとの接続の数の 1 句を組み立てる。
func agentSessionLines(rules []agent.DoctorRule) []string {
	out := make([]string, 0, agentMaxRuleLines+1)
	for i, r := range rules {
		if i == agentMaxRuleLines {
			out = append(out, agentAndMore(len(rules)-agentMaxRuleLines))
			break
		}
		out = append(out, fmt.Sprintf("%s %d flow%s in %d session%s", r.ID, r.Flows, pluralS(r.Flows), r.Sessions, pluralS(r.Sessions)))
	}
	return out
}

// agentRefusalsCheck は、今のトンネルを作ってからのフロー予算の拒否の累計を示す。フロー予算は
// トンネルを立て直すたびに中継ごと作り直され、累計はそのたびに 0 に戻るので、起点を並べて示す
// (10.2c 節)。
func agentRefusalsCheck(c *agentDoctorCheck, in agentDoctorInput, st *agent.DoctorRuntimeState) {
	if agentNoRelay(c, st, "how many flows it refused") {
		return
	}
	c.Status, c.Reason = statusUnknown, agentReasonNoThreshold
	start := "since this tunnel was built " + agentWhen(in.Now, st.RefusalsSince)
	// 拒否は、ルールと理由の組ごとに立つ。組の数にも上限が無いので、並べる数を抑え、抑えたことを
	// 末尾に書く。切ったことが読み取れないと、運用者は並びが全部だと読む。
	var lines []string
	var total uint64
	groups := 0
	for _, b := range st.Budgets {
		for _, r := range b.Refusals {
			total += r.Count
			groups++
			if len(lines) < agentMaxRefusalLines {
				lines = append(lines, fmt.Sprintf("%s %s %s %d", r.RuleID, b.Proto, r.Reason, r.Count))
			}
		}
	}
	if groups > len(lines) {
		lines = append(lines, agentAndMore(groups-len(lines)))
	}
	if total == 0 {
		c.Detail = "no flow has been refused " + start
	} else {
		c.Detail = fmt.Sprintf("%d flow%s refused %s: %s", total, pluralS(int(total)), start, strings.Join(lines, "; "))
	}
	c.Next = "the count starts again at zero whenever the tunnel is rebuilt, so read it against the time above. " +
		"budget means the whole process was full, rule_cap means that one rule hit its share, reserve means the room left was held for other rules"
}

// agentNoRelay は、中継がまだ無い実行の扱いを当てる。中継はトンネルと一緒に作られるので、
// トンネルが無い間は中継も無い。フロー予算の項目の有無が、中継の有無をそのまま表す。
func agentNoRelay(c *agentDoctorCheck, st *agent.DoctorRuntimeState, what string) bool {
	if len(st.Budgets) > 0 {
		return false
	}
	c.Status, c.Reason = statusSkipped, agentReasonNoRelay
	c.Detail = "there is no relay running, so " + what + " could not be read: the relay is built with the tunnel, and there is no tunnel now"
	c.Next = "the tunnel line above says why there is none"
	return true
}

// agentDisabledSkip は状態と理由の符号を SKIPPED / agent_disabled に置く。呼び出し側が Detail を
// 組み立てる。relay.listeners と、カーネルモードの 3 つの検査(agentdoctorkernel.go)が使う。
func agentDisabledSkip(c *agentDoctorCheck) {
	c.Status, c.Reason = statusSkipped, agentReasonAgentDisabled
}

// agentAllowTargetsValue は、稼働中のエージェントが実際に持っている宛先の許可一覧を示す。組み立てた
// 値ではなく、常駐プロセスが enforce している値である(10.2c 節)。
func agentAllowTargetsValue(c *agentDoctorCheck, a *agent.DoctorAllowTargets) {
	c.Status = statusOK
	env := a.Env
	if env == "" {
		env = allowtargets.Env
	}
	if !a.Set {
		c.Detail = "the running agent enforces no target allowlist, so the server can name any target this host can reach"
		c.Next = "set " + env + " on this host and restart the agent to hold it to a list"
		return
	}
	c.Detail = "the running agent enforces " + env + "=" + a.List
	c.Next = "a rule whose target is outside this list is refused here, and the server shows that refusal as the rule's reason"
}

// --- 時刻の書き方 ---

// agentWhen は過ぎた時刻を、その時刻と今からの隔たりで表す。
func agentWhen(now, t time.Time) string {
	return "at " + t.UTC().Format(time.RFC3339) + ", " + since(now, t).String() + " ago"
}

// agentDue はこれから来る時刻を、その時刻と今からの隔たりで表す。
func agentDue(now, t time.Time) string {
	d := t.Sub(now).Truncate(time.Second)
	if d <= 0 {
		return "at " + t.UTC().Format(time.RFC3339) + ", now"
	}
	return "at " + t.UTC().Format(time.RFC3339) + ", in " + d.String()
}
