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

	port := freeTCPPort(t)
	ln, err := hostNetwork{}.ListenTCP(port)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
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

	pc, err := hostNetwork{}.ListenUDP(port)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if got := pc.LocalAddr().(*net.UDPAddr).IP; got.To4() == nil {
		t.Errorf("UDP listener address %v is not IPv4", got)
	}
	if v6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: int(port)}); err != nil {
		t.Errorf("the UDP listener must leave the IPv6 port free: %v", err)
	} else {
		v6.Close()
	}
}
