package doctor

import "testing"

// TestTargetReasonCode は、エージェントが報告する人向けの文言を、targetReasonCode がどの機械向けの
// 符号に写すかを確かめる。文言はいずれも実装が返しうるものである。timeout の行は、
// ユーザー空間モードの中継(internal/dataplane/userspace/relay)の probeTarget が返す確認の期限
// 切れの文言そのものであり、以前はどの case にも当たらず target_error に落ちていた(target が
// 黙って SYN を捨てるルールをラボで作って確認した)。"listen tcp4 ...: bind: ..." の行は、Go の
// net.Listen がそのまま返す文言である。"tcp/8461: bind tcp ...: ..." と "udp/8462: bind udp ...:
// ..." の行は、エージェントのユーザー空間モードの中継が bind の失敗で実際に組み立てる文言の形
// である。internal/dataplane/userspace/dataplane_userspace.go の ruleStatuses は
// "<Key>: <Err>" を組む。エージェントは gVisor の netstack の上で待ち受けを開くので、bind の
// 失敗はその Err に Go の net.OpError がそのまま乗り、internal/nettun/listen.go の ListenTCP と
// gonet.DialUDP(UDP のリスナーが経由する。同ファイル ListenUDP)のどちらも Op を "listen" では
// なく "bind" にするため、"bind tcp <addr>: <err>" / "bind udp <addr>: <err>" の形になる
// (net.Listen の "listen ...: bind: ..." とは組み立てが違う)。この形は、試験用の実機(#211 より
// 前の版のエージェント)で実際に観測されている。"port is in use" の行はその観測に基づく。
// "<Key>: <Err>" の組み立てと、bind ではなく dial・connect の失敗でもこの形になることは、ラボで
// 実際に起こした dial の失敗("tcp/9000: dial tcp 192.168.50.3:25580: connect: connection
// refused")で確かめた。#211 で直した今の版のエージェントで、bind の失敗そのもの、つまりこの
// 経路に利用者の操作から実際に至る道筋は、2 本のルールに同じ待ち受けポートを与える経路(server
// が rule add 自体を拒む)と、同じポートでルールを削除して即座に追加し直す経路(繰り返した回数は
// PR の本文に書く)の 2 つをラボで試し、どちらも再現しなかった(設計文書 10.2a 節の改訂の記録に
// 記載の、以前からの未確認と同じ)。
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
			// ルールの無効化と直後の有効化などでしばらく in use のままだった)で実際に観測した
			// 文言そのもの。上の 2 つの case が確かめる net.OpError の組み立てと同じ形である。
			name:   "field observation, pre-#211 agent leaving a relay port bound after a cut session",
			reason: "listener tcp/40000: bind tcp 10.200.0.2:40000: port is in use",
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
