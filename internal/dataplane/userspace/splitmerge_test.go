package userspace

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/proto"
)

// A split or merge moves a listener to another rule ID without closing it (design.md 7 節). The
// evaluator is updated before the relay relabels its listeners, so for a moment a listener still
// carries the old ID; the evaluator keeps judging a removed ID by its old policy until the next
// Update, so no new connection is refused in between (design.md 7a.9 節). This test relabels one
// port back and forth many times while a client keeps opening connections: a refusal by admission
// is an RST (abortRefused), while an admitted connection ends with EOF because the tunnel is not
// up and the relay cannot dial the agent.
func TestSplitAndMergeRefuseNoNewConnections(t *testing.T) {
	port := freeTCPPort(t)
	plan := func(id string) planner.Plan {
		rules, err := model.NormalizeRules([]proto.Rule{{ID: id, Agent: "home", Proto: proto.TCP,
			ListenPort: proto.PortRange{Lo: port, Hi: port}, Target: "192.168.1.30:80", VPSMode: proto.ModeKernel, Enabled: true}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return planner.Build(planner.Input{Rules: rules,
			Agents: []planner.Agent{{Name: "home", Addr: netip.MustParseAddr("10.200.0.2")}}})
	}
	b := New(Options{Logf: func(string, ...any) {}})
	defer b.relay.Close()
	commit := func(p planner.Plan) {
		t.Helper()
		prep, err := b.Prepare(dataplane.Desired{Plan: p})
		if err != nil {
			t.Fatal(err)
		}
		if len(prep.Failed()) != 0 {
			t.Fatalf("Failed = %v", prep.Failed())
		}
		if _, err := prep.Commit(nil); err != nil {
			t.Fatal(err)
		}
	}
	commit(plan("r_a"))

	var refused, served, other, attempts atomic.Int64
	var otherErrs sync.Map // collects the "other" bucket's error strings, for a failure to show
	stop := make(chan struct{})
	var wg sync.WaitGroup
	addr := "127.0.0.1:" + strconv.Itoa(int(port))
	// pace bounds each goroutine's connection rate. Left unthrottled, a tight dial/read/close loop on
	// loopback opens on the order of 10^5 connections a second; sustained across many runs (this test
	// alone, repeated, or alongside the rest of the suite) that floods the host's netfilter conntrack
	// table, which is system-wide and shared with everything else on the machine, and once it is full
	// the kernel drops new SYNs outright. The dropped SYN surfaces here as a plain
	// net.Dial "i/o timeout" (never ECONNREFUSED and never ECONNRESET, since the packet never reaches
	// the listening socket), which looks exactly like the "other" bucket this test watches for but has
	// nothing to do with the split/merge code under test. Paced at this rate the test still drives
	// several hundred connection attempts across the 300 relabels, comfortably enough to still fail if
	// a real refusal or drop happens.
	const pace = 5 * time.Millisecond
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1)
			for {
				select {
				case <-stop:
					return
				default:
				}
				attempts.Add(1)
				c, err := net.DialTimeout("tcp4", addr, time.Second)
				if err != nil {
					if errors.Is(err, syscall.ECONNRESET) {
						refused.Add(1)
					} else {
						other.Add(1)
						otherErrs.Store(fmt.Sprintf("dial: %v", err), true)
					}
					time.Sleep(pace)
					continue
				}
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, err := c.Read(buf)
				switch {
				case errors.Is(err, syscall.ECONNRESET):
					refused.Add(1)
				case err != nil:
					served.Add(1)
				default:
					other.Add(1)
					otherErrs.Store(fmt.Sprintf("read: n=%d err=%v buf=%q", n, err, buf[:n]), true)
				}
				c.Close()
				time.Sleep(pace)
			}
		}()
	}
	for i := range 300 {
		commit(plan([]string{"r_b", "r_a"}[i%2]))
		time.Sleep(2 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	t.Logf("served %d, refused %d, attempts %d", served.Load(), refused.Load(), attempts.Load())
	if refused.Load() != 0 {
		t.Errorf("%d connections were refused while the port moved between rule IDs (%d served)", refused.Load(), served.Load())
	}
	if served.Load() == 0 || other.Load() != 0 {
		var msgs []string
		otherErrs.Range(func(k, _ any) bool { msgs = append(msgs, k.(string)); return true })
		t.Errorf("served %d, unexpected outcomes %d; the probe did not exercise the relay; errors: %v", served.Load(), other.Load(), msgs)
	}
}
