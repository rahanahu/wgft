package relay

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

func TestTCPSetupFailurePreservesEmptyPeerEOF(t *testing.T) {
	pool := resource.NewPool(8)
	lb := &loopback{}
	var releases atomic.Int32
	m := New(lb, Options{TCPPool: pool, Logf: testLogf(t), Dial: func(string, string) (net.Conn, error) { return nil, errors.New("dial failure") }, Admit: func(string, netip.Addr, int) (func(), bool) { return func() { releases.Add(1) }, true }})
	t.Cleanup(m.Close)
	port := reserveTCP(t, lb)
	m.Prepare(map[Key]Desired{{Proto: proto.TCP, Port: port}: {Target: "127.0.0.1:1", RuleID: "rule"}}).Commit(nil)
	c, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(make([]byte, 1))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty setup peer ended with %d bytes, %v; want EOF", n, err)
	}
	waitUntil(t, func() string { return "setup failure did not release its charges" }, func() bool { return pool.InUse() == 0 && releases.Load() == 1 })
	if pool.Ledger().DoubleReleases != 0 {
		t.Fatal("setup failure released its pool slot twice")
	}
}

func TestTCPSetupFailureCannotResurrectAfterCut(t *testing.T) {
	pool := resource.NewPool(8)
	lb := &loopback{}
	entered, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	resume := func() { once.Do(func() { close(proceed) }) }
	t.Cleanup(resume)
	var releases, dials atomic.Int32
	m := New(lb, Options{TCPPool: pool, Logf: testLogf(t), Dial: func(string, string) (net.Conn, error) {
		dials.Add(1)
		close(entered)
		<-proceed
		return nil, errors.New("dial failure")
	}, Admit: func(string, netip.Addr, int) (func(), bool) { return func() { releases.Add(1) }, true }})
	t.Cleanup(m.Close)
	port := reserveTCP(t, lb)
	m.Prepare(map[Key]Desired{{Proto: proto.TCP, Port: port}: {Target: "127.0.0.1:1", RuleID: "rule"}}).Commit(nil)
	c, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("committed Dial did not begin")
	}
	m.Close()
	if pool.InUse() != 1 || releases.Load() != 0 {
		t.Fatal("cut released the committed worker before Dial ended")
	}
	resume()
	waitUntil(t, func() string { return "cut setup did not release its charges" }, func() bool { return pool.InUse() == 0 && releases.Load() == 1 })
	if dials.Load() != 1 || pool.Ledger().DoubleReleases != 0 {
		t.Fatal("cut setup lost single-worker ownership")
	}
}
