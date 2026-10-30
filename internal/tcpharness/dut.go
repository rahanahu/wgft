package tcpharness

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// DUT is one engine under test, seen from the tunnel side the way wgft's agent sees it: IPv4
// packets go in and come out, and a passive-open socket API sits on top. A DUT owns one IPv4
// address and a fixed MTU, and the testbench is the only peer.
//
// Time is real time unless the DUT is also a ClockedDUT. Linux cannot run on a fake clock, and a
// scenario has to mean the same on every engine, so the scenarios assert on order and on
// generous bounds and report the measured intervals instead of asserting exact timer values.
//
// An engine joins through an adapter package of its own that builds the engine the way wgft's
// product code does and offers New(addr, mtu) and Engine(known), as gvisordut and linuxdut do.
type DUT interface {
	// Name is the engine's name in logs and in the expected-difference lists.
	Name() string
	// Addr is the DUT's own address. MTU is its link MTU.
	Addr() netip.Addr
	MTU() int
	// Inject hands one IPv4 packet to the engine as if it had arrived from the tunnel.
	Inject(pkt []byte) error
	// Emitted carries every IPv4 packet the engine sends towards the tunnel, in order. The
	// channel is closed when the DUT is closed. A ClockedDUT may return nil: it is read with Poll.
	Emitted() <-chan []byte
	// Listen opens a TCP listener on the DUT's address and port.
	Listen(port uint16) (Listener, error)
	// ListenUDP opens an unconnected UDP socket on the DUT's address and port, the way wgft's
	// relay receives UDP. Datagrams come from ReadFrom with the sender's *net.UDPAddr.
	ListenUDP(port uint16) (net.PacketConn, error)
	// Close releases the engine. Every Listener and Conn of it stops working.
	Close() error
}

// ClockedDUT is a DUT whose engine runs its timers on a clock the harness drives, as a stack
// written for wgft can. The harness then never sleeps: Peer.Next pulls packets with Poll and,
// when there are none, advances the clock in small steps.
//
// The engine is synchronous towards the harness: Inject and Advance return after the engine has
// handled them, and what they make the engine send waits inside the engine until Poll takes it,
// the way wireguard-go's Read pulls packets from a tun.Device. Because the engine never pushes
// into a channel of fixed capacity, a scenario that injects many segments before it reads cannot
// block its own goroutine inside Inject.
type ClockedDUT interface {
	DUT
	// Now is the engine's current time.
	Now() time.Time
	// Advance moves the engine's clock forward by d and fires the timers that fall due.
	Advance(d time.Duration)
	// Poll returns the next packet the engine sends now, or false when it has none.
	Poll() ([]byte, bool)
}

// Listener is a listening socket of a DUT.
type Listener interface {
	// Accept returns the next established connection, or ctx's error.
	Accept(ctx context.Context) (Conn, error)
	Close() error
}

// Conn is an accepted connection of a DUT, driven the way wgft's relay drives one.
type Conn interface {
	net.Conn
	CloseWrite() error
	// Abort closes the connection with a RST instead of a FIN.
	Abort() error
}

// The relay and internal/netpipe look these methods up on a connection by type assertion, so an
// engine for the agent offers them and the reference engine does not. A scenario checks them
// only where the engine offers them.
type (
	// Deliverer reports whether a closed connection has delivered everything it had to send.
	Deliverer interface{ Delivered() bool }
	// DeliveryCloser closes a connection that keeps its slot until it has delivered its data.
	DeliveryCloser interface{ CloseForDelivery() error }
	// Booster registers f to learn when the connection gets or loses its large buffers.
	Booster interface {
		OnBoost(f func(boosted bool) bool)
	}
)
