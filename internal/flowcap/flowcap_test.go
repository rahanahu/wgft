package flowcap

import (
	"net/netip"
	"testing"
)

func TestCounterLimits(t *testing.T) {
	a, b, c := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")
	cnt := &Counter{Total: 3, PerSource: 2}
	if !cnt.Acquire(a) || !cnt.Acquire(a) {
		t.Fatal("first two flows of a source must pass")
	}
	if cnt.Acquire(a) {
		t.Error("third flow of the same source must be refused")
	}
	if !cnt.Acquire(b) {
		t.Error("another source must pass")
	}
	if cnt.Acquire(c) {
		t.Error("flow over the total must be refused")
	}
	if cnt.Len() != 3 {
		t.Errorf("Len = %d, want 3 (refused flows are not counted)", cnt.Len())
	}
	cnt.Release(a)
	if !cnt.Acquire(c) {
		t.Error("a released slot must be reusable")
	}
	cnt.Release(a)
	cnt.Release(b)
	cnt.Release(c)
	if cnt.Len() != 0 || len(cnt.bySrc) != 0 {
		t.Errorf("after release: Len = %d, bySrc = %v", cnt.Len(), cnt.bySrc)
	}
}

// エージェントは接続元ごとに数えない。nil はどこも制限しない。
func TestCounterWithoutPerSourceAndNil(t *testing.T) {
	a := netip.MustParseAddr("10.200.0.1")
	cnt := &Counter{Total: 2}
	if !cnt.Acquire(a) || !cnt.Acquire(a) || cnt.Acquire(a) {
		t.Error("only the total applies")
	}
	var none *Counter
	if !none.Acquire(a) {
		t.Error("nil counter must admit")
	}
	none.Release(a)
}

func TestLogGate(t *testing.T) {
	var g LogGate
	if !g.Allow() || g.Allow() {
		t.Error("the gate must open once per minute")
	}
}

// 既定の上限と、256 MiB の VPS 向けの目安でのソフト上限(仕様 7 節の値)。
func TestMemoryLimit(t *testing.T) {
	if got := (Limits{}).MemoryLimit() >> 20; got != 216 {
		t.Errorf("default limit = %d MiB, want 216", got)
	}
	if got := (Limits{UDPTotal: 2048, TCPTotal: 1024}).MemoryLimit() >> 20; got != 100 {
		t.Errorf("small limit = %d MiB, want 100", got)
	}
}
