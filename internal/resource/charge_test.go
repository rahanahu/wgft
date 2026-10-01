package resource

import "testing"

// Charge は Lease を先に、policy の枠を後に返す。policy の関数が呼ばれた時点で、Pool の枠は既に
// 返っている。
func TestChargeReleasesLeaseThenPolicy(t *testing.T) {
	p := NewPool(8)
	l := p.Listener("a")
	var c Charge
	inUseAtPolicy := -1
	c.HoldPolicy(func() { inUseAtPolicy = p.InUse() })
	x, _, o := l.Take()
	if o != Granted {
		t.Fatalf("take: %v", o)
	}
	c.HoldLease(x)
	c.Release()
	if inUseAtPolicy != 0 {
		t.Fatalf("pool in use %d when the policy slot was returned, want 0", inUseAtPolicy)
	}
	if lg := mustLedger(t, p); lg.InUse != 0 || lg.DoubleReleases != 0 {
		t.Fatalf("ledger %+v", lg)
	}
}

// 2 度目の Release は Lease.Release と policy の関数にそのまま届き、Pool の帳簿は二重の返却を数える。
func TestChargeSecondReleaseReachesBoth(t *testing.T) {
	p := NewPool(8)
	l := p.Listener("a")
	var c Charge
	policyCalls := 0
	c.HoldPolicy(func() { policyCalls++ })
	x, _, _ := l.Take()
	c.HoldLease(x)
	c.Release()
	c.Release()
	if lg := mustLedger(t, p); lg.InUse != 0 || lg.DoubleReleases != 1 {
		t.Fatalf("ledger %+v, want in use 0 and one double release", lg)
	}
	if policyCalls != 2 {
		t.Fatalf("policy release called %d times, want 2", policyCalls)
	}
}

// 枠を持つ前の Release は、持っている分だけを返す。ゼロ値の Release は何もしない。
func TestChargeReleasesOnlyWhatItHolds(t *testing.T) {
	var zero Charge
	zero.Release()

	p := NewPool(8)
	var c Charge
	policyCalls := 0
	c.HoldPolicy(func() { policyCalls++ })
	c.Release()
	if policyCalls != 1 {
		t.Fatalf("policy release called %d times, want 1", policyCalls)
	}
	if lg := mustLedger(t, p); lg.InUse != 0 || lg.DoubleReleases != 0 {
		t.Fatalf("ledger %+v", lg)
	}
}
