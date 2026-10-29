package tcpharness

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// DUT is one TCP engine under test, seen from the tunnel side the way wgft's agent sees it: IPv4
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
	// channel is closed when the DUT is closed.
	Emitted() <-chan []byte
	// Listen opens a TCP listener on the DUT's address and port.
	Listen(port uint16) (Listener, error)
	// Close releases the engine. Every Listener and Conn of it stops working.
	Close() error
}

// ClockedDUT is a DUT whose engine runs its timers on a clock the harness drives, as a stack
// written for wgft can. The harness then never sleeps: Peer.Next advances the clock in small steps
// and looks at Emitted between them. The engine must be synchronous towards the harness:
// whatever Inject or Advance makes it send is in Emitted before the call returns.
type ClockedDUT interface {
	DUT
	// Now is the engine's current time.
	Now() time.Time
	// Advance moves the engine's clock forward by d and fires the timers that fall due.
	Advance(d time.Duration)
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
