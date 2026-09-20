package resource

import (
	"testing"
)

// 既定の上限と、256 MiB の VPS 向けの目安でのソフト上限(仕様 7 節の値)。
func TestMemoryLimit(t *testing.T) {
	if got := (Limits{}).MemoryLimit() >> 20; got != 216 {
		t.Errorf("default limit = %d MiB, want 216", got)
	}
	if got := (Limits{UDPTotal: 2048, TCPTotal: 1024}).MemoryLimit() >> 20; got != 100 {
		t.Errorf("small limit = %d MiB, want 100", got)
	}
}
