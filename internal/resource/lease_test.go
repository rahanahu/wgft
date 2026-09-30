package resource

import "testing"

func mustLedger(t *testing.T, p *Pool) Ledger {
	t.Helper()
	if err := p.CheckLedger(); err != nil {
		t.Fatal(err)
	}
	lg := p.Ledger()
	if lg.Orphans != 0 {
		t.Fatalf("orphans = %d", lg.Orphans)
	}
	return lg
}

func TestTakeRefusesNonAcceptingHandles(t *testing.T) {
	p := NewPool(8)
	pend := p.PendingListener("a")
	if _, _, o := pend.Take(); o != NotAccepting {
		t.Fatalf("pending: %v", o)
	}
	l := p.Listener("a")
	x, _, o := l.Take()
	if o != Granted {
		t.Fatalf("accepting: %v", o)
	}
	l.StopAccepting()
	if _, _, o := l.Take(); o != NotAccepting {
		t.Fatalf("retiring: %v", o)
	}
	l.Accept()
	y, _, o := l.Take()
	if o != Granted {
		t.Fatalf("resumed: %v", o)
	}
	l.Close()
	if _, _, o := l.Take(); o != NotAccepting {
		t.Fatalf("closed: %v", o)
	}
	lg := mustLedger(t, p)
	if lg.NotAccepting != 3 || len(p.Refusals()) != 0 || lg.InUse != 2 || lg.RetiredFlows != 2 {
		t.Fatalf("ledger %+v refusals %v", lg, p.Refusals())
	}
	if !x.Release() || x.Release() || !y.Release() {
		t.Fatal("release not exactly once")
	}
	lg = mustLedger(t, p)
	if lg.InUse != 0 || lg.DoubleReleases != 1 || lg.RetiredFlows != 0 || l.Flows() != 0 {
		t.Fatalf("after release %+v flows %d", lg, l.Flows())
	}
}

// 統合: other の最後の待ち受けの付け替えで other の登録が退役し、lease は統合先の登録へ移る。
func TestMergeMovesLeases(t *testing.T) {
	p := NewPool(64)
	a := p.Listener("a")
	b := p.Listener("b")
	xa, _, _ := a.Take()
	xb, _, _ := b.Take()
	b.SetRule("a")
	lg := mustLedger(t, p)
	if lg.RegFlows["a"] != 2 || lg.RetiredFlows != 0 {
		t.Fatalf("%+v", lg)
	}
	xb.Release()
	xa.Release()
	if lg = mustLedger(t, p); lg.RegFlows["a"] != 0 || lg.InUse != 0 {
		t.Fatalf("%+v", lg)
	}
}

// 再開: Retiring の間は退役した登録に残り、Accept の加入で今の登録へ移る。
func TestResumeJoinMovesLeases(t *testing.T) {
	p := NewPool(64)
	l := p.Listener("u")
	x, _, _ := l.Take()
	l.StopAccepting()
	lg := mustLedger(t, p)
	if lg.RetiredFlows != 1 || lg.RegFlows["u"] != 0 {
		t.Fatalf("%+v", lg)
	}
	l.Accept()
	if lg = mustLedger(t, p); lg.RetiredFlows != 0 || lg.RegFlows["u"] != 1 {
		t.Fatalf("%+v", lg)
	}
	x.Release()
	mustLedger(t, p)
}

// 閉じた待ち受けの lease は移らない。分割元の削除では分割先のポートの lease が移る。
func TestSplitThenDeleteHead(t *testing.T) {
	p := NewPool(64)
	h1 := p.Listener("b")
	h2 := p.Listener("b")
	x1, _, _ := h1.Take()
	x2, _, _ := h2.Take()
	h2.SetRule("d") // 分割: 生きている登録どうしは移さない
	lg := mustLedger(t, p)
	if lg.RegFlows["b"] != 2 || lg.RegFlows["d"] != 0 {
		t.Fatalf("split %+v", lg)
	}
	h1.Close()
	lg = mustLedger(t, p)
	if lg.RegFlows["d"] != 1 || lg.RetiredFlows != 1 {
		t.Fatalf("delete head %+v", lg)
	}
	x1.Release()
	x2.Release()
	mustLedger(t, p)
}
