package relay

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// TestTCPStopWhileAdmitting の netstack 版 (エージェントの公開側): 止めた worker の接続が RST で終わる。
func TestTCPStopWhileAdmittingNetstack(t *testing.T) {
	const port = 7100
	k := Key{proto.TCP, port}
	for _, op := range []string{"Apply close", "Apply reopen"} {
		for _, at := range []string{"before Take", "after Take"} {
			t.Run(op+"/"+at, func(t *testing.T) {
				client, agent := netstackPair(t)
				target, other := tcpEcho(t), tcpEcho(t)
				pool := resource.NewPool(8)
				var armAdmit, armTake atomic.Bool
				entered, proceed := make(chan struct{}), make(chan struct{})
				var releases atomic.Int32
				pause := func() { close(entered); <-proceed }
				m := New(agent, Options{Logf: testLogf(t), TCPPool: pool,
					Admit: func(string, netip.Addr, int) (func(), bool) {
						if armAdmit.CompareAndSwap(true, false) {
							pause()
						}
						return func() { releases.Add(1) }, true
					}})
				m.testHookAfterTake = func(*listener) {
					if armTake.CompareAndSwap(true, false) {
						pause()
					}
				}
				defer m.Close()
				m.Apply(map[Key]Desired{k: {target, "r1"}})
				if at == "before Take" {
					armAdmit.Store(true)
				} else {
					armTake.Store(true)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				c, err := client.DialTCP(ctx, netip.AddrPortFrom(cutAgentAddr, port))
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("worker did not pause")
				}
				if op == "Apply close" {
					m.Apply(nil)
				} else {
					m.Apply(map[Key]Desired{k: {other, "r1"}})
				}
				close(proceed)
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, err = c.Read(make([]byte, 1))
				end := "eof-or-timeout"
				if isCutByReset(err) {
					end = "rst"
				}
				deadline := time.Now().Add(5 * time.Second)
				for (pool.InUse() != 0 || releases.Load() != 1) && time.Now().Before(deadline) {
					time.Sleep(5 * time.Millisecond)
				}
				lg := checkPool(t, pool)
				if lg.InUse != 0 || releases.Load() != 1 || len(pool.Refusals()) != 0 {
					t.Errorf("in use %d, releases %d, refusals %v", lg.InUse, releases.Load(), pool.Refusals())
				}
				if end != "rst" {
					t.Errorf("ending %s (%v), want RST", end, err)
				}
				t.Logf("op=%q at=%q ending=%s err=%v notAccepting=%d", op, at, end, err, lg.NotAccepting)
			})
		}
	}
}
