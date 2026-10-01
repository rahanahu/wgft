package stream

import (
	"strings"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// sanitizeHeartbeat は、トンネルとルールの理由を HeartbeatReason と同じ形にして保存する。エージェントの
// 理由と server doctor の分類を結ぶ試験(internal/agent の reason_roundtrip_test.go)は
// HeartbeatReason を通すので、hub の実際の切り詰めと同じであることをここで固定する。
func TestSanitizeHeartbeatClipsReasonsLikeHeartbeatReason(t *testing.T) {
	long := strings.Repeat("name resolution of target host \"a.lan\" failed\x1b[2J; ", 40)
	if len(long) <= maxHeartbeatReasonLen {
		t.Fatalf("the reason is %d bytes; it must pass the %d-byte cap", len(long), maxHeartbeatReasonLen)
	}
	want := HeartbeatReason(long)
	if len(want) >= len(long) || strings.Contains(want, "\x1b") {
		t.Fatalf("HeartbeatReason did not clip and escape the reason: %d bytes", len(want))
	}
	got := sanitizeHeartbeat(&proto.Heartbeat{
		Tunnel: proto.TunnelStatus{State: proto.StatusError, Reason: long},
		Rules:  []proto.RuleStatus{{ID: "r1", State: proto.StatusError, Reason: long}},
	})
	if got.Tunnel.Reason != want {
		t.Errorf("Tunnel.Reason = %q, want HeartbeatReason's %q", got.Tunnel.Reason, want)
	}
	if got.Rules[0].Reason != want {
		t.Errorf("Rules[0].Reason = %q, want HeartbeatReason's %q", got.Rules[0].Reason, want)
	}
}
