package relay

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/rahanahu/wgft/proto"
)

// tcpEcho is a TCP server on the loopback that echoes every line back.
func tcpEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func dialLoopback(port uint16) (net.Conn, error) {
	return net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), time.Second)
}

func echoLine(c net.Conn, msg string) (string, error) {
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte(msg + "\n")); err != nil {
		return "", err
	}
	return bufio.NewReader(c).ReadString('\n')
}

// Prepare binds without serving; a rule with one port that cannot be bound fails as a whole and
// none of its ports is kept bound (design.md 7a.3 節: a partial range is never forwarded).
func TestStagedBindFailureFailsWholeRule(t *testing.T) {
	// bind the blocker itself on port 0 and read back the assigned port, instead of picking a
	// number with freePort and then binding it: nothing else can ever steal a number that was
	// never released.
	blocker, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	blocked := uint16(blocker.Addr().(*net.TCPAddr).Port)
	lb := &loopback{}
	// free と blocked belong to the same rule, and Prepare skips binding a rule's later ports once
	// an earlier one has already failed (design.md 7a.3 節). Depending on which port sorts first,
	// Manager may never claim free's reservation at all, so free stays with plain freePort (its own,
	// separate, and much smaller race) rather than a held-open reservation that this test's own
	// re-bind check below would then find still in use.
	free := freePort(t)
	other := reserveTCP(t, lb)
	m := New(lb, Options{Logf: t.Logf})
	defer m.Close()

	s := m.Prepare(map[Key]Desired{
		{proto.TCP, free}:    {"127.0.0.1:9", "r_range"},
		{proto.TCP, blocked}: {"127.0.0.1:9", "r_range"},
		{proto.TCP, other}:   {"127.0.0.1:9", "r_other"},
	})
	if err := s.Failed()["r_range"]; err == nil || len(s.Failed()) != 1 {
		t.Fatalf("Failed = %v, want only r_range", s.Failed())
	}
	// the free port of the failed rule was released again
	if l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(free)}); err != nil {
		t.Errorf("port %d of the failed rule is still bound: %v", free, err)
	} else {
		l.Close()
	}
	s.Commit(nil)
	if c, err := dialLoopback(free); err == nil {
		c.Close()
		t.Errorf("port %d of the failed rule serves after Commit", free)
	}
	st := m.Status()
	if len(st) != 1 || st[0].RuleID != "r_other" {
		t.Errorf("listeners after Commit = %+v, want only r_other", st)
	}
}

// Rollback closes what Prepare bound and leaves the serving listeners alone.
func TestStagedRollback(t *testing.T) {
	echo := tcpEcho(t)
	lb := &loopback{}
	oldPort, newPort := reserveTCP(t, lb), reserveTCP(t, lb)
	m := New(lb, Options{Logf: t.Logf})
	defer m.Close()
	m.Prepare(map[Key]Desired{{proto.TCP, oldPort}: {echo, "r_old"}}).Commit(nil)
	s := m.Prepare(map[Key]Desired{{proto.TCP, newPort}: {echo, "r_new"}})
	s.Rollback()
	s.Commit(nil) // after Rollback, Commit does nothing
	if l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(newPort)}); err != nil {
		t.Errorf("the rolled back port %d is still bound: %v", newPort, err)
	} else {
		l.Close()
	}
	c, err := dialLoopback(oldPort)
	if err != nil {
		t.Fatalf("the serving listener was closed: %v", err)
	}
	defer c.Close()
	if got, err := echoLine(c, "hi"); err != nil || got != "hi\n" {
		t.Errorf("echo through the old listener = %q, %v", got, err)
	}
}

// A retiring TCP listener stops accepting and keeps the established connections its keep
// function admits; once the rule is no longer retiring, the listener and its connections are
// closed (design.md 7a.3 節).
func TestStagedRetiringTCP(t *testing.T) {
	echo := tcpEcho(t)
	lb := &loopback{}
	port := reserveTCP(t, lb)
	// bind the blocker itself on port 0 and read back the assigned port, instead of picking a
	// number with freePort and then binding it: nothing else can ever steal a number that was
	// never released.
	blocker, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	blocked := uint16(blocker.Addr().(*net.TCPAddr).Port)
	m := New(lb, Options{Logf: t.Logf})
	defer m.Close()
	m.Prepare(map[Key]Desired{{proto.TCP, port}: {echo, "r_x"}}).Commit(nil)
	c, err := dialLoopback(port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got, err := echoLine(c, "before"); err != nil || got != "before\n" {
		t.Fatalf("echo = %q, %v", got, err)
	}

	// r_x moves to a port that cannot be bound: fail-closed, retiring to its old listener
	s := m.Prepare(map[Key]Desired{{proto.TCP, blocked}: {echo, "r_x"}})
	if s.Failed()["r_x"] == nil {
		t.Fatal("want r_x to fail")
	}
	s.Commit(map[string]func(netip.Addr) bool{"r_x": func(netip.Addr) bool { return true }})
	if got, err := echoLine(c, "after"); err != nil || got != "after\n" {
		t.Errorf("the established connection did not survive: %q, %v", got, err)
	}
	if nc, err := dialLoopback(port); err == nil {
		nc.Close()
		t.Error("a retiring listener still accepts new connections")
	}
	if got := m.Retiring(); len(got) != 1 || got[0] != (Key{proto.TCP, port}) {
		t.Errorf("Retiring = %v", got)
	}

	// the new declaration now refuses the source: the established connection is closed
	s = m.Prepare(map[Key]Desired{{proto.TCP, blocked}: {echo, "r_x"}})
	s.Commit(map[string]func(netip.Addr) bool{"r_x": func(netip.Addr) bool { return false }})
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = c.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Errorf("a connection the new declaration refuses must be closed, read err = %v", err)
	}
}

// A retiring UDP listener keeps its socket and the established sessions, drops datagrams from new
// sources, and serves again when the declaration takes the port back.
func TestStagedRetiringUDP(t *testing.T) {
	echoAddr, _ := udpEcho(t)
	lb := &loopback{}
	port := reserveUDP(t, lb)
	// bind the blocker itself on port 0 and read back the assigned port, instead of picking a
	// number with freePort and then binding it: nothing else can ever steal a number that was
	// never released.
	blocker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	blocked := uint16(blocker.LocalAddr().(*net.UDPAddr).Port)
	m := New(lb, Options{Logf: t.Logf})
	defer m.Close()
	m.Prepare(map[Key]Desired{{proto.UDP, port}: {echoAddr, "r_u"}}).Commit(nil)
	dial := func() *net.UDPConn {
		c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	roundtrip := func(c *net.UDPConn, msg string, wait time.Duration) (string, error) {
		c.SetDeadline(time.Now().Add(wait))
		if _, err := c.Write([]byte(msg)); err != nil {
			return "", err
		}
		b := make([]byte, 100)
		n, err := c.Read(b)
		return string(b[:n]), err
	}
	established := dial()
	defer established.Close()
	if got, err := roundtrip(established, "one", 2*time.Second); err != nil || got != "one" {
		t.Fatalf("roundtrip = %q, %v", got, err)
	}

	s := m.Prepare(map[Key]Desired{{proto.UDP, blocked}: {echoAddr, "r_u"}})
	if s.Failed()["r_u"] == nil {
		t.Fatal("want r_u to fail")
	}
	s.Commit(map[string]func(netip.Addr) bool{"r_u": func(netip.Addr) bool { return true }})
	if got, err := roundtrip(established, "two", 2*time.Second); err != nil || got != "two" {
		t.Errorf("the established session did not survive: %q, %v", got, err)
	}
	fresh := dial()
	defer fresh.Close()
	if _, err := roundtrip(fresh, "new", 300*time.Millisecond); err == nil {
		t.Error("a retiring UDP listener created a session for a new source")
	}

	// the declaration takes the port back: the kept socket serves new sources again
	m.Prepare(map[Key]Desired{{proto.UDP, port}: {echoAddr, "r_u"}}).Commit(nil)
	if got, err := roundtrip(fresh, "again", 2*time.Second); err != nil || got != "again" {
		t.Errorf("after the port came back: %q, %v", got, err)
	}
	if len(m.Retiring()) != 0 {
		t.Errorf("Retiring = %v, want none", m.Retiring())
	}
}
