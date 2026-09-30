package relay

import (
	"testing"
	"time"
)

// 奪われた VPS が全体状態の wg.udp_timeout_stream に桁あふれする秒の値を送ると、internal/agent の
// 呼び出し側で `* time.Second` が極めて短い値(例:512ns)に巻き戻ることがある。sweepInterval は
// そのような極端に短い UDPIdleTimeout でも、掃除の goroutine の ticker が minSweepInterval を
// 下回らないことを確かめる、呼び出し側の防御の 2 段目である。
func TestSweepInterval(t *testing.T) {
	tests := []struct {
		name string
		idle time.Duration
		want time.Duration
	}{
		{"normal default: a quarter of the idle timeout", 120 * time.Second, 30 * time.Second},
		{"small but legitimate test value: still a quarter", 200 * time.Millisecond, 50 * time.Millisecond},
		{"overflowed to a tiny duration: floored", 512, minSweepInterval},
		{"zero: floored", 0, minSweepInterval},
		{"negative: floored", -time.Second, minSweepInterval},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sweepInterval(tt.idle); got != tt.want {
				t.Errorf("sweepInterval(%v) = %v, want %v", tt.idle, got, tt.want)
			}
		})
	}
}
