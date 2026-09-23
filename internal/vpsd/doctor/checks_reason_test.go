package doctor

import "testing"

// TestTargetReasonCode は、エージェントが報告する人向けの文言を、targetReasonCode がどの機械向けの
// 符号に写すかを確かめる。文言はいずれも実際にエージェントが返すものである。timeout の行は、
// ユーザー空間モードの中継(internal/dataplane/userspace/relay)の probeTarget が返す確認の期限
// 切れの文言そのものであり、以前はどの case にも当たらず target_error に落ちていた(target が
// 黙って SYN を捨てるルールをラボで作って確認した)。bind: の行は、Go の net.Listen がそのまま
// 返す文言であり、この形の bind 失敗はユーザー空間モードの中継では実際には再現できていない
// (設計文書 10.2a 節の改訂の記録)。それでも符号を当てられることは確かめておく。
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
