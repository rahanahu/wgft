package userspace

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// The host listeners of the userspace relay are IPv4 only (design.md 7a.9 節「IPv4 だけを扱う v1 の
// 守り」): an IPv4 client reaches them, an IPv6 client does not.
func TestHostListenersAreIPv4Only(t *testing.T) {
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	probe.Close()

	// The number is picked and closed before the binds, and the TCP and UDP listeners need the
	// same number, so a number taken in between is picked again.
	var port uint16
	var ln net.Listener
	var pc net.PacketConn
	retryOnBindCollision(t, func() bool {
		port = freeTCPPort(t)
		l, err := hostNetwork{}.ListenTCP(port)
		if bindCollision(err) {
			return true
		}
		if err != nil {
			t.Fatal(err)
		}
		p, err := hostNetwork{}.ListenUDP(port)
		if bindCollision(err) {
			l.Close()
			return true
		}
		if err != nil {
			l.Close()
			t.Fatal(err)
		}
		ln, pc = l, p
		return false
	})
	defer ln.Close()
	defer pc.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	p := strconv.Itoa(int(port))
	if c, err := net.DialTimeout("tcp4", "127.0.0.1:"+p, time.Second); err != nil {
		t.Errorf("IPv4 client: %v", err)
	} else {
		c.Close()
	}
	if c, err := net.DialTimeout("tcp6", "[::1]:"+p, time.Second); err == nil {
		c.Close()
		t.Error("an IPv6 client reached the TCP listener")
	}

	if got := pc.LocalAddr().(*net.UDPAddr).IP; got.To4() == nil {
		t.Errorf("UDP listener address %v is not IPv4", got)
	}
	if v6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: int(port)}); err != nil {
		t.Errorf("the UDP listener must leave the IPv6 port free: %v", err)
	} else {
		v6.Close()
	}
}
