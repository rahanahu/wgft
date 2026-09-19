package userspace

import (
	"errors"
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

	var refused, served, other atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	addr := "127.0.0.1:" + strconv.Itoa(int(port))
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
				c, err := net.DialTimeout("tcp4", addr, time.Second)
				if err != nil {
					if errors.Is(err, syscall.ECONNRESET) {
						refused.Add(1)
					} else {
						other.Add(1)
					}
					continue
				}
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, err = c.Read(buf)
				switch {
				case errors.Is(err, syscall.ECONNRESET):
					refused.Add(1)
				case err != nil:
					served.Add(1)
				default:
					other.Add(1)
				}
				c.Close()
			}
		}()
	}
	for i := range 300 {
		commit(plan([]string{"r_b", "r_a"}[i%2]))
		time.Sleep(2 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	t.Logf("served %d, refused %d", served.Load(), refused.Load())
	if refused.Load() != 0 {
		t.Errorf("%d connections were refused while the port moved between rule IDs (%d served)", refused.Load(), served.Load())
	}
	if served.Load() == 0 || other.Load() != 0 {
		t.Errorf("served %d, unexpected outcomes %d; the probe did not exercise the relay", served.Load(), other.Load())
	}
}
