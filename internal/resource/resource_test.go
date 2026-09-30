package resource

import (
	"testing"
)

// 既定の上限と、上限を下げた設定 (UDP 2048、TCP 1024) でのソフト上限。
func TestMemoryLimit(t *testing.T) {
	if got := (Limits{}).MemoryLimit() >> 20; got != 216 {
		t.Errorf("default limit = %d MiB, want 216", got)
	}
	if got := (Limits{UDPTotal: 2048, TCPTotal: 1024}).MemoryLimit() >> 20; got != 100 {
		t.Errorf("small limit = %d MiB, want 100", got)
	}
}
