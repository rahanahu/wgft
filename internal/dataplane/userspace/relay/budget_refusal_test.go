package relay

// Pool の予算の拒否(Refused)の分岐で、フロー 1 本の Admission Policy の枠がちょうど 1 度返り、Pool の
// 枠を取らないことを確かめる。ほかの拒否の分岐は、停止や閉鎖との競合を止めて確かめる試験
// (tcp_stop_admit_test.go、udp_close_race_test.go ほか)が通る。

import (
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
)

// fillBudget は待ち受けの Pool の枠を、取れなくなるまで取って持つ。持った枠は試験の終わりに返す。
func fillBudget(t *testing.T, l *listener) []*resource.Lease {
	t.Helper()
	var held []*resource.Lease
	for {
		x, _, o := l.budget.Take()
		if o != resource.Granted {
			break
		}
		held = append(held, x)
	}
	if len(held) == 0 {
		t.Fatal("the fixture took no slot")
	}
	t.Cleanup(func() {
		for _, x := range held {
			x.Release()
		}
	})
	return held
}

// waitTickets は Admission Policy の枠が want 個出て、全部が返るのを待つ。
func waitTickets(t *testing.T, k *ticketLedger, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for (k.issued.Load() < want || k.outstanding() != 0) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond)
	if got := k.issued.Load(); got != want {
		t.Fatalf("policy tickets issued %d, want %d", got, want)
	}
	k.settle(t)
}

func (r *stopRig) listenerOf(k Key) *listener {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	return r.m.listeners[k]
}

// TCP の予算の拒否は、Admission Policy の枠を 1 度だけ返し、Pool の枠を取らない。
func TestTCPBudgetRefusalReturnsPolicySlot(t *testing.T) {
	r := newStopRigT(t, true, "r1", false, 8, true)
	held := fillBudget(t, r.listenerOf(r.key))
	// Commit の到達確認も宛先へ dial するので、接続の前の数からの増分を見る
	dialsBefore := r.relayedDials()
	// 拒否の RST は、connect が戻る前に届くこともある
	c, err := dialLoopback(r.key.Port)
	switch {
	case err != nil && !isReset(err):
		t.Fatal(err)
	case err == nil:
		defer c.Close()
		if end, err := ending(c, 2*time.Second); end != "rst" {
			t.Fatalf("refused connection ended with %s (%v), want rst", end, err)
		}
	}
	waitTickets(t, &r.tickets, 1)
	lg := checkPool(t, r.pool)
	if dials := r.relayedDials() - dialsBefore; lg.InUse != len(held) || dials != 0 {
		t.Errorf("in use %d, want the fixture's %d; dials %d, want 0", lg.InUse, len(held), dials)
	}
}

// UDP の予算の拒否は、Admission Policy の枠を 1 度だけ返し、Pool の枠を取らず、宛先へ dial しない。
func TestUDPBudgetRefusalReturnsPolicySlot(t *testing.T) {
	r := newUDPRig(t, 8)
	held := fillBudget(t, r.listener())
	c := r.client(t)
	if udpRoundTrip(c, 200*time.Millisecond) {
		t.Fatal("a datagram was relayed past a full budget")
	}
	waitTickets(t, &r.tickets, 1)
	lg := checkPool(t, r.pool)
	if lg.InUse != len(held) || r.dials.Load() != 0 {
		t.Errorf("in use %d, want the fixture's %d; dials %d, want 0", lg.InUse, len(held), r.dials.Load())
	}
}
