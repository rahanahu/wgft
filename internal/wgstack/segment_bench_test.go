package wgstack

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// The per-segment benchmarks of the Rust core's criterion benches (crates/wgft-wgstack-bench),
// written the same way for the Go wgstack, so docs/design/v2/wgstack-rs.md can compare the two
// on one machine: the same MTU and MSS, a peer that builds every packet into one buffer and
// computes its checksums, 1, 64 and 1024 connections visited in turn, 10 µs of clock and one
// timer pass per segment, and the rig's own cost measured apart (BenchmarkSegmentRigOverhead).
//
//	go test -run '^$' -bench 'Segment' -benchmem ./internal/wgstack
//
// The Go wgstack runs on its manual clock without its timer goroutine; the application reads and
// writes through Conn, as the Go agent's relay does.

const (
	segMTU = 1420
	segMSS = segMTU - 40 // the MSS of a connection without timestamps, as the Rust rig's
)

var segConns = []int{1, 64, 1024}

// segPeer is one connection of the peer: its numbers and the core's connection.
type segPeer struct {
	c        *Conn
	port     uint16
	snd, rcv uint32
}

// segRig is a Go wgstack Device and the tunnel-side peer of n connections.
type segRig struct {
	d     *Device
	clk   *ManualClock
	peers []segPeer
	pkt   []byte
	out   []byte
	data  []byte
	rd    []byte
	in    [][]byte
}

// ones adds b to the 16-bit one's complement sum as the Rust rig's ones does.
func ones(sum uint32, b []byte) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func fold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// build writes the peer's TCP packet from sport into r.pkt without allocating, as the Rust rig's
// build does.
func (r *segRig) build(sport uint16, seq, ack uint32, flags uint8, opts, payload []byte) []byte {
	thl := 20 + len(opts)
	total := 20 + thl + len(payload)
	b := r.pkt[:total]
	clear(b[:20+thl])
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	b[6] = 0x40
	b[8] = 64
	b[9] = 6
	src, dst := peerAddr.As4(), dutAddr.As4()
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	binary.BigEndian.PutUint16(b[10:], fold(ones(0, b[:20])))
	t := b[20:]
	binary.BigEndian.PutUint16(t[0:], sport)
	binary.BigEndian.PutUint16(t[2:], 80)
	binary.BigEndian.PutUint32(t[4:], seq)
	binary.BigEndian.PutUint32(t[8:], ack)
	t[12] = byte(thl/4) << 4
	t[13] = flags
	binary.BigEndian.PutUint16(t[14:], 0xffff)
	copy(t[20:thl], opts)
	copy(t[thl:], payload)
	pseudo := ones(ones(0, src[:]), dst[:]) + 6 + uint32(thl+len(payload))
	binary.BigEndian.PutUint16(t[16:], fold(ones(pseudo, t)))
	return b
}

// segParse is the destination port, the sequence number and the payload length of a packet the
// core sent.
func segParse(p []byte) (uint16, uint32, int) {
	hl := int(p[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(p[2:]))
	t := p[hl:total]
	thl := int(t[12]>>4) * 4
	return binary.BigEndian.Uint16(t[2:]), binary.BigEndian.Uint32(t[4:]), len(t) - thl
}

func (r *segRig) inject(p []byte) {
	r.in[0] = p
	if _, err := r.d.Write(r.in, 0); err != nil {
		panic(err)
	}
}

// newSegRig listens on port 80 and opens conns connections from the peer with MSS 1380, window
// scale 7 and, with sack, SACK-permitted, as the Rust rig does.
func newSegRig(tb testing.TB, conns int, sack bool) *segRig {
	clk := NewManualClock()
	d, err := newDevice(Config{Addr: dutAddr, MTU: segMTU, Clock: clk, Rand: seededRand()}, defaultLimits(0), newBoostPool(boostSlots))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { d.Close() })
	r := &segRig{d: d, clk: clk, pkt: make([]byte, segMTU+64), out: make([]byte, segMTU), data: make([]byte, segMSS),
		rd: make([]byte, segMSS), in: make([][]byte, 1)}
	for i := range r.data {
		r.data[i] = 0x5a
	}
	l, err := d.ListenTCP(netip.AddrPortFrom(dutAddr, 80))
	if err != nil {
		tb.Fatal(err)
	}
	opts := []byte{2, 4, 0x05, 0x64, 1, 3, 3, 7}
	if sack {
		opts = []byte{2, 4, 0x05, 0x64, 1, 3, 3, 7, 1, 1, 4, 2}
	}
	for i := range conns {
		port := uint16(10_000 + i)
		r.inject(r.build(port, 1000, 0, flagSYN, opts, nil))
		n := d.Poll(r.out)
		if n == 0 {
			tb.Fatal("no SYN-ACK")
		}
		_, iss, _ := segParse(r.out[:n])
		r.inject(r.build(port, 1001, iss+1, flagACK, nil, nil))
		c, err := l.Accept()
		if err != nil {
			tb.Fatal(err)
		}
		r.peers = append(r.peers, segPeer{c: c.(*Conn), port: port, snd: 1001, rcv: iss + 1})
	}
	for d.Poll(r.out) > 0 {
	}
	return r
}

// tick moves the clock 10 µs and runs the timers that are due, as the Rust rig's tick does.
func (r *segRig) tick() {
	r.clk.Advance(10 * time.Microsecond)
	r.d.Tick()
}

// rigOnly is the rig's cost alone: the packet recvOne builds and its checksums, and the parse of
// an ACK-sized packet, without the core.
func (r *segRig) rigOnly(k int) {
	p := r.peers[k]
	pkt := r.build(p.port, p.snd, p.rcv, flagACK|flagPSH, nil, r.data)
	copy(r.out[:40], pkt[:40])
	binary.BigEndian.PutUint16(r.out[2:], 40)
	port, seq, n := segParse(r.out[:40])
	segSink += int(port) + int(seq) + n + len(pkt)
}

var segSink int

// recvOne delivers one in-order full segment from peer k, takes the core's output and has the
// application read it.
func (r *segRig) recvOne(k int) {
	r.tick()
	p := &r.peers[k]
	r.inject(r.build(p.port, p.snd, p.rcv, flagACK|flagPSH, nil, r.data))
	p.snd += segMSS
	for r.d.Poll(r.out) > 0 {
	}
	// Conn.Read waits when nothing is there, so read exactly what arrived
	for got := 0; got < segMSS; {
		n, err := p.c.Read(r.rd[got:])
		if err != nil {
			panic(err)
		}
		got += n
	}
}

// sendOne writes one segment's worth on connection k, takes the segments the core sends and
// acknowledges them from the peer.
func (r *segRig) sendOne(k int) {
	r.tick()
	p := &r.peers[k]
	if _, err := p.c.Write(r.data); err != nil {
		panic(err)
	}
	acked := p.rcv
	for {
		n := r.d.Poll(r.out)
		if n == 0 {
			break
		}
		port, seq, l := segParse(r.out[:n])
		if end := seq + uint32(l); port == p.port && int32(end-acked) > 0 {
			acked = end
		}
	}
	p.rcv = acked
	r.inject(r.build(p.port, p.snd, acked, flagACK, nil, nil))
	for r.d.Poll(r.out) > 0 {
	}
}

func benchSegment(b *testing.B, sack bool, op func(*segRig, int)) {
	for _, n := range segConns {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			r := newSegRig(b, n, sack)
			b.SetBytes(segMSS)
			b.ReportAllocs()
			k := 0
			for b.Loop() {
				op(r, k)
				k = (k + 1) % n
			}
		})
	}
}

func BenchmarkSegmentRecv(b *testing.B) { benchSegment(b, false, (*segRig).recvOne) }

func BenchmarkSegmentRecvSACK(b *testing.B) { benchSegment(b, true, (*segRig).recvOne) }

func BenchmarkSegmentSend(b *testing.B) { benchSegment(b, false, (*segRig).sendOne) }

func BenchmarkSegmentSendSACK(b *testing.B) { benchSegment(b, true, (*segRig).sendOne) }

func BenchmarkSegmentRigOverhead(b *testing.B) {
	r := newSegRig(b, 1, false)
	b.SetBytes(segMSS)
	b.ReportAllocs()
	for b.Loop() {
		r.rigOnly(0)
	}
}

// TestSegmentRigMovesData checks the benchmark rig on both paths with and without SACK, and that
// the sender's numbers survive the sequence wrap, as the Rust rig's tests do.
func TestSegmentRigMovesData(t *testing.T) {
	for _, sack := range []bool{false, true} {
		r := newSegRig(t, 4, sack)
		r.rigOnly(0)
		for i := range 200 {
			r.recvOne(i % 4)
			r.sendOne(i % 4)
		}
	}
	r := newSegRig(t, 1, false)
	for range 4_000_000 / segMSS {
		r.sendOne(0)
	}
	before := r.peers[0].rcv
	r.sendOne(0)
	if got := r.peers[0].rcv - before; got != segMSS {
		t.Fatalf("one sendOne past the wrap acknowledged %d bytes, want %d", got, segMSS)
	}
}
