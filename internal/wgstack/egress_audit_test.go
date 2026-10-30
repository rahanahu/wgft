package wgstack

import (
	"testing"
	"time"
)

// TestNoEgressSpinAfterTLPInTimeWait は、FIN_WAIT_1 で期限が来た TLP の probe の印が TIME_WAIT に残らず、
// Poll が回り続けないことを確かめる。中継の CloseWrite の後に PTO が来て、probe を作る前に相手の FIN が届く
// 順で起きた(監査で FuzzCore が見つけた)。
func TestNoEgressSpinAfterTLPInTimeWait(t *testing.T) {
	n, c, cs, q, _ := rackConnApp(t, 3)
	// CloseWrite で FIN を送る
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	n.drain()
	// PTO の期限を来させるが、Poll はしない
	cs.mu.Lock()
	tlpAt := cs.tlpAt
	cs.mu.Unlock()
	if tlpAt == 0 {
		t.Fatalf("no TLP armed")
	}
	n.clk.Advance(time.Duration(tlpAt-int64(n.clk.Now())) + time.Millisecond)
	n.d.Tick()
	cs.mu.Lock()
	probe := cs.tlpProbe
	cs.mu.Unlock()
	if !probe {
		t.Fatalf("PTO did not set tlpProbe")
	}
	// 相手が FIN までを確認し、自分の FIN を送る
	q.p.rcv = cs.sndMax
	q.p.fin()
	cs.mu.Lock()
	st := cs.state
	cs.mu.Unlock()
	t.Logf("state %v", st)
	done := make(chan int, 1)
	go func() {
		k := 0
		for range 10 {
			if n.d.Poll(make([]byte, 65536)) == 0 {
				break
			}
			k++
		}
		done <- k
	}()
	select {
	case k := <-done:
		t.Logf("poll returned after %d packets", k)
	case <-time.After(3 * time.Second):
		t.Fatalf("Poll did not return: egress spins (state %v)", st)
	}
}
