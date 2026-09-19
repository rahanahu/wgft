package flowcap

import (
	"net/netip"
	"testing"
)

func TestCounterLimits(t *testing.T) {
	a, b, c := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")
	cnt := &Counter{Total: 3, PerSource: 2}
	for i := 1; i <= 2; i++ {
		if !cnt.Acquire(a) {
			t.Fatalf("flow %d of a source must pass", i)
		}
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
	for i := 1; i <= 2; i++ {
		if !cnt.Acquire(a) {
			t.Errorf("flow %d must pass: only the total applies", i)
		}
	}
	if cnt.Acquire(a) {
		t.Error("flow over the total must be refused")
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

// ルールごとの上限はプロセス全体の上限の半分で、以前の値を下回らない(仕様 7 節)。既定の上限では、
// この仕組みを導入する前の固定値(UDP 4096、TCP 1024)と一致する。
func TestPerRuleCap(t *testing.T) {
	if got := (Limits{}).UDPPerRuleCap(); got != 4096 {
		t.Errorf("default UDPPerRuleCap = %d, want 4096", got)
	}
	if got := (Limits{}).TCPPerRuleCap(); got != 1024 {
		t.Errorf("default TCPPerRuleCap = %d, want 1024", got)
	}
	// 全体を上げれば半分まで上がる
	if got := (Limits{UDPTotal: 20000}).UDPPerRuleCap(); got != 10000 {
		t.Errorf("UDPPerRuleCap(20000) = %d, want 10000", got)
	}
	if got := (Limits{TCPTotal: 8000}).TCPPerRuleCap(); got != 4000 {
		t.Errorf("TCPPerRuleCap(8000) = %d, want 4000", got)
	}
	// 全体を下げた構成では、以前の値(固定値と全体の小さいほう)を下回らない
	for _, c := range []struct{ total, want int }{{2048, 2048}, {4096, 4096}, {6000, 4096}, {TotalMin, TotalMin}} {
		if got := (Limits{UDPTotal: c.total}).UDPPerRuleCap(); got != c.want {
			t.Errorf("UDPPerRuleCap(%d) = %d, want %d", c.total, got, c.want)
		}
	}
	if got := (Limits{TCPTotal: 512}).TCPPerRuleCap(); got != 512 {
		t.Errorf("TCPPerRuleCap(512) = %d, want 512", got)
	}
}

// 接続元ごとの上限は、ゼロ値なら既定値、PerSourceOff なら上限なし(実効値 0)になる。
// ゼロ値の Limits で守りが外れないことを確かめる。
func TestPerSourceCap(t *testing.T) {
	var zero Limits
	if zero.UDPPerSourceCap() != UDPPerSource || zero.TCPPerSourceCap() != TCPPerSource {
		t.Errorf("zero Limits: got %d/%d, want the defaults %d/%d", zero.UDPPerSourceCap(), zero.TCPPerSourceCap(), UDPPerSource, TCPPerSource)
	}
	off := Limits{UDPPerSource: PerSourceOff, TCPPerSource: PerSourceOff}
	if off.UDPPerSourceCap() != 0 || off.TCPPerSourceCap() != 0 {
		t.Errorf("PerSourceOff: got %d/%d, want 0/0", off.UDPPerSourceCap(), off.TCPPerSourceCap())
	}
	set := Limits{UDPPerSource: 999, TCPPerSource: 111}
	if set.UDPPerSourceCap() != 999 || set.TCPPerSourceCap() != 111 {
		t.Errorf("explicit values: got %d/%d, want 999/111", set.UDPPerSourceCap(), set.TCPPerSourceCap())
	}
}

// Counter は PerSource が 0 なら接続元ごとに数えない(上限なし)。設定で無効にした場合と
// エージェント(元々 PerSource を渡さない)の両方に当てはまる。
func TestCounterPerSourceZeroMeansUnlimited(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.1")
	cnt := &Counter{Total: 1000, PerSource: 0}
	for i := 0; i < 500; i++ {
		if !cnt.Acquire(a) {
			t.Fatalf("flow %d from the same source must pass when PerSource is 0", i)
		}
	}
}

// 接続元ごとの上限は動作中に変えられる。上限なしの間に数えたフローも、上限を付けた後の判定に入る。
func TestCounterSetPerSource(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.1")
	cnt := &Counter{}
	for i := 0; i < 3; i++ {
		if !cnt.Acquire(a) {
			t.Fatalf("flow %d must pass without a per-source cap", i+1)
		}
	}
	cnt.SetPerSource(2)
	if cnt.Acquire(a) {
		t.Fatal("with 3 flows held, a cap of 2 must refuse a new flow")
	}
	cnt.Release(a)
	cnt.Release(a)
	if !cnt.Acquire(a) {
		t.Fatal("with 1 flow held, a cap of 2 must admit a new flow")
	}
	cnt.SetPerSource(0)
	if !cnt.Acquire(a) {
		t.Fatal("cap 0 means no per-source cap")
	}
	for i := 0; i < 3; i++ {
		cnt.Release(a)
	}
	if cnt.Len() != 0 || len(cnt.bySrc) != 0 {
		t.Fatalf("after release: Len = %d, bySrc = %v", cnt.Len(), cnt.bySrc)
	}
	var none *Counter
	none.SetPerSource(1)
}
