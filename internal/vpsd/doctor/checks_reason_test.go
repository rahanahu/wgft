package doctor

import (
	"strings"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// TestTargetReasonCode は、エージェントが報告する人向けの文言を、targetReasonCode がどの機械向けの
// 符号に写すかを確かめる。文言はいずれも実装が返しうるものである。timeout の行は、
// ユーザー空間モードの中継(internal/dataplane/userspace/relay)の probeTarget が返す確認の期限
// 切れの文言そのものであり、以前はどの case にも当たらず target_error に落ちていた(target が
// 黙って SYN を捨てるルールをラボで作って確認した)。"listen tcp4 ...: bind: ..." の行は、Go の
// net.Listen がそのまま返す文言である。"tcp/8461: bind tcp ...: ..." と "udp/8462: bind udp ...:
// ..." の行は、エージェントのユーザー空間モードの中継が bind の失敗で実際に組み立てる文言の形
// である。internal/agent/dataplane_userspace.go の ruleStatuses は "<Key>: <Err>" を組む。
// エージェントは gVisor の netstack の上で待ち受けを開くので、bind の失敗はその Err に Go の
// net.OpError がそのまま乗り、internal/nettun/listen.go の ListenTCP と gonet.DialUDP(UDP の
// リスナーが経由する。同ファイル ListenUDP)のどちらも Op を "listen" ではなく "bind" にするため、
// "bind tcp <addr>: <err>" / "bind udp <addr>: <err>" の形になる(net.Listen の
// "listen ...: bind: ..." とは組み立てが違う)。"<Key>: <Err>" の組み立てと、bind ではなく
// dial・connect の失敗でもこの形になることは、ラボで実際に起こした dial の失敗
// ("tcp/9000: dial tcp 192.168.50.3:25580: connect: connection refused")で確かめた。#211 で
// 直した今の版のエージェントでも、bind の失敗そのものに利用者の操作から実際に至る道筋を 1 つ、
// ラボで確かめた。宛先が先に閉じるセッション(接続を受けて 1 行送ってから子プロセスの終了と
// ともに閉じる待ち受け)を 1 本通した直後にそのルールを削除して同じポートへ追加し直すと、
// TIME_WAIT の間ポートを保持する経路(design.md 7 節)からこの文言に実際に至った。2 本のルール
// に同じ待ち受けポートを与える経路(server が rule add 自体を拒む)は、依然として再現しなかった
// (design.md 改訂の記録)。
func TestTargetReasonCode(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		want   string
	}{
		{
			name:   "agent probe timeout, did not answer",
			reason: "target 192.168.50.50:25579 did not answer within 2s",
			want:   ReasonTargetTimeout,
		},
		{
			name:   "classic timeout wording",
			reason: "dial tcp 192.168.50.50:2456: i/o timeout",
			want:   ReasonTargetTimeout,
		},
		{
			name:   "timed out wording",
			reason: "dial tcp 192.168.50.50:2456: connect timed out",
			want:   ReasonTargetTimeout,
		},
		{
			name:   "go net.Listen bind error",
			reason: "listen tcp4 0.0.0.0:2456: bind: address already in use",
			want:   ReasonListenerBindFailed,
		},
		{
			name:   "agent's own bind failed wording",
			reason: "bind failed: address already in use",
			want:   ReasonListenerBindFailed,
		},
		{
			name:   "agent's userspace relay TCP listener bind, real net.OpError wording",
			reason: "tcp/8461: bind tcp 10.200.0.2:8461: port is in use",
			want:   ReasonListenerBindFailed,
		},
		{
			name:   "agent's userspace relay UDP listener bind, real net.OpError wording",
			reason: "udp/8462: bind udp 10.200.0.2:8462: port is in use",
			want:   ReasonListenerBindFailed,
		},
		{
			// 実機(#211 より前の版のエージェント。stream が切れた後もリレーのポートを空けず、
			// ルールの無効化と直後の有効化などでしばらく in use のままだった)で、agent のログの
			// 行がこの文言("listener tcp/40000: bind tcp 10.200.0.2:40000: port is in use"、
			// internal/dataplane/userspace/relay の Logf の形)になったことと、その時
			// `server doctor --json` が rule.target を target_error に誤分類していたことを観測
			// した。ここではその原因である、server が実際に受け取る報告の形("<Key>: <Err>"。
			// ログの行から "listener " の接頭辞を除いたもの)を入力にする。
			name:   "field observation, pre-#211 agent leaving a relay port bound after a cut session",
			reason: "tcp/40000: bind tcp 10.200.0.2:40000: port is in use",
			want:   ReasonListenerBindFailed,
		},
		{
			name:   "connection refused",
			reason: "dial tcp 192.168.50.50:2456: connect: connection refused",
			want:   ReasonConnectionRefused,
		},
		{
			name:   "not allowed by allowtargets",
			reason: "target 192.168.50.50:2456 is not allowed",
			want:   ReasonTargetNotAllowed,
		},
		{
			name:   "resolve failure",
			reason: "lookup home.example.invalid: no such host",
			want:   ReasonResolveFailed,
		},
		{
			name:   "kernel-mode loopback target",
			reason: "target 127.0.0.1 is a loopback address; kernel mode does not forward to loopback targets, use this host's LAN address",
			want:   ReasonTargetLoopbackUnsupported,
		},
		{
			name:   "kernel-mode unspecified target",
			reason: "target 0.0.0.0 is the unspecified address, which reaches this host's loopback; kernel mode does not forward to loopback targets, use this host's LAN address",
			want:   ReasonTargetLoopbackUnsupported,
		},
		{
			name:   "kernel-mode name that stopped resolving and whose last address is loopback",
			reason: "name resolution of target host \"a.lan\" failed: no such host; the address from the last successful resolution is not usable either: target 127.0.0.1 is a loopback address; kernel mode does not forward to loopback targets, use this host's LAN address",
			want:   ReasonResolveFailed,
		},
		{
			name:   "kernel-mode allowlist refusal",
			reason: "target 192.168.50.3:25567 is not in WGFT_AGENT_ALLOW_TARGETS",
			want:   ReasonTargetNotAllowed,
		},
		{
			// この変更より前のカーネルモードのエージェントの文言である。「this host」はエージェントの
			// ホストを指すが、VPS で読むと VPS に読める。
			name:   "kernel-mode agent host with ip_forward 0, older wording",
			reason: "net.ipv4.ip_forward is 0; the kernel does not forward to a target that is not this host",
			want:   ReasonAgentIPForwardOff,
		},
		{
			name:   "kernel-mode agent host with ip_forward 0",
			reason: "on the agent host, net.ipv4.ip_forward is 0; its kernel does not forward to a target other than the agent host itself",
			want:   ReasonAgentIPForwardOff,
		},
		{
			// 書けなかった場合の文言は下層の誤りを包む。包んだ誤りの語に引きずられない。
			name:   "kernel-mode agent host that could not set ip_forward",
			reason: "on the agent host, net.ipv4.ip_forward is not 1 and cannot be set: open /proc/sys/net/ipv4/ip_forward: read-only file system; its kernel does not forward to a target other than the agent host itself",
			want:   ReasonAgentIPForwardOff,
		},
		{
			name:   "unrecognized text falls back to target_error",
			reason: "dial tcp 192.168.50.50:2456: some future wrapped error nobody has seen yet",
			want:   ReasonTargetError,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := targetReasonCode(tc.reason); got != tc.want {
				t.Errorf("targetReasonCode(%q) = %q, want %q", tc.reason, got, tc.want)
			}
		})
	}
}

// エージェントのホストの ip_forward が 0 のルールは、所見と次の一手がエージェントのホストを名指し、
// 宛先のサービスを疑わせない。VPS で読むと「this host」は VPS に読めるためである。
func TestAgentIPForwardOffNamesTheAgentHost(t *testing.T) {
	r := testRuleForReason()
	next := agentRuleNextStep("net.ipv4.ip_forward is 0; the kernel does not forward to a target that is not this host", r)
	for _, want := range []string{`agent "home"`, "not on this VPS", "sysctl -w net.ipv4.ip_forward=1", "wgft agent doctor"} {
		if !strings.Contains(next, want) {
			t.Errorf("next step lacks %q: %s", want, next)
		}
	}
	if strings.Contains(next, "Check that a service is listening") {
		t.Errorf("next step blames the service: %s", next)
	}
}

func testRuleForReason() proto.Rule {
	return proto.Rule{ID: "r_01M2R009AAAAAAAAAAAAAAAAA", Agent: "home", Proto: proto.TCP,
		ListenPort: proto.PortRange{Lo: 4000, Hi: 4000}, Target: "192.168.50.2:4000", VPSMode: proto.ModeKernel, Enabled: true}
}
