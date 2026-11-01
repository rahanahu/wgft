package wgstack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/dutproto"
)

var (
	dutAddr  = netip.MustParseAddr("10.9.0.1")
	peerAddr = netip.MustParseAddr("10.9.0.2")
)

const testMTU = 1420

// smallLimits は試験の表の大きさ。上界の試験は表が満ちるところを見るので小さくする。
func smallLimits() limits {
	return limits{maxFlows: 16, acceptQ: 8, synRows: 16, twRows: 32, ctlSlots: 16}
}

// seededRand は固定の種。
func seededRand() *bytes.Reader { return bytes.NewReader(bytes.Repeat([]byte{7}, 64)) }

// testNet は手で進める時計の Device と、トンネルの側の相手。
type testNet struct {
	t   testing.TB
	d   *Device
	clk *ManualClock
	buf []byte
	rec *netRecorder // 記録を求めた試験だけ (record_test.go)
}

func newTestNet(t testing.TB, lim limits) *testNet {
	t.Helper()
	return newTestNetPool(t, lim, newBoostPool(boostSlots))
}

func newTestNetPool(t testing.TB, lim limits, pool *boostPool) *testNet {
	t.Helper()
	clk := NewManualClock()
	d, err := newDevice(Config{Addr: dutAddr, MTU: testMTU, Clock: clk, Rand: seededRand()}, lim, pool)
	if err != nil {
		t.Fatal(err)
	}
	n := &testNet{t: t, d: d, clk: clk, buf: make([]byte, 65536)}
	t.Cleanup(func() { d.Close() })
	return n
}

// tseg は相手が送る segment。
type tseg struct {
	sport, dport uint16
	src          netip.Addr // 0 なら peerAddr
	seq, ack     uint32
	flags        uint8
	wnd          uint16
	mss          uint16
	ws           int // -1 なら付けない
	sackOK       bool
	ts           bool
	tsVal, tsEcr uint32
	sack         []sackBlock
	payload      []byte
}

func buildPeer(s tseg) []byte {
	var o optWriter
	if s.mss != 0 {
		o.mss(s.mss)
	}
	if s.sackOK {
		o.sackPerm()
	}
	if s.ts {
		o.ts(s.tsVal, s.tsEcr)
	}
	if s.ws >= 0 && s.flags&flagSYN != 0 {
		o.wscale(uint8(s.ws))
	}
	if len(s.sack) > 0 {
		o.sack(s.sack)
	}
	src := s.src
	if !src.IsValid() {
		src = peerAddr
	}
	b := make([]byte, ipHeaderLen+tcpHeaderLen+maxOptionLen+len(s.payload))
	h := tcpHeader{tup: tuple{laddr: addrBits(src), raddr: addrBits(dutAddr), lport: s.sport, rport: s.dport}, seq: s.seq, ack: s.ack, flags: s.flags, wnd: s.wnd}
	off := writeTCP(b, 1, h, &o, len(s.payload))
	copy(b[off:], s.payload)
	n := finishTCP(b)
	return b[:n]
}

func (n *testNet) inject(s tseg) {
	n.t.Helper()
	pkt := buildPeer(s)
	if _, err := n.writePkts(pkt); err != nil {
		n.t.Fatalf("Write: %v", err)
	}
}

// out は Device が送った segment。
type out struct {
	ip  ipv4
	seg segment
}

func (o out) String() string {
	f := ""
	for _, x := range []struct {
		b uint8
		s string
	}{{flagSYN, "S"}, {flagFIN, "F"}, {flagRST, "R"}, {flagPSH, "P"}, {flagACK, "."}} {
		if o.seg.flags&x.b != 0 {
			f += x.s
		}
	}
	return fmt.Sprintf("%s seq=%d ack=%d len=%d wnd=%d sack=%v", f, o.seg.seq, o.seg.ack, len(o.seg.payload), o.seg.wnd, o.seg.opt.sack[:o.seg.opt.nsack])
}

// drain は Device が今送るものをすべて読む。
func (n *testNet) drain() []out {
	n.t.Helper()
	var res []out
	for range 100000 {
		k := n.poll(n.buf)
		if k == 0 {
			return res
		}
		pkt := append([]byte(nil), n.buf[:k]...)
		ip, d := parseIPv4(pkt)
		if d != ipv4OK {
			n.t.Fatalf("Device sent a bad IPv4 packet: %v", d)
		}
		if ip.proto != protoTCP {
			n.t.Fatalf("Device sent protocol %d", ip.proto)
		}
		seg, td := parseTCP(&ip)
		if td != tcpOK {
			n.t.Fatalf("Device sent a bad TCP segment: %v", td)
		}
		if k > testMTU {
			n.t.Fatalf("packet of %d bytes exceeds the MTU", k)
		}
		res = append(res, out{ip: ip, seg: seg})
	}
	n.t.Fatal("Device kept sending")
	return nil
}

func (n *testNet) advance(d time.Duration) {
	n.clk.Advance(d)
	n.d.Tick()
	if n.rec != nil {
		n.rec.emit(&dutproto.Advance{D: d}, &dutproto.Time{Now: n.clk.Now()}, false)
	}
}

// accepted は 80 番で待ち受け、相手の 40000 番から窓の scale を付けて接続を開き、Accept で受け取った接続と
// 相手の側の接続を返す。握手の出力は読み捨てる。ts と sack は相手が timestamp と SACK を求めるかである。
func (n *testNet) accepted(ts, sack bool) (*Conn, *peerConn) {
	n.t.Helper()
	l := listen(n.t, n, 80)
	p := n.handshake(40000, 80, ts, sack, true)
	c := acceptOne(n.t, l)
	n.drain()
	return c, p
}

// peerConn は相手の側の 1 つの接続の番号を追う。
type peerConn struct {
	n      *testNet
	sport  uint16
	dport  uint16
	iss    uint32 // 相手の ISN
	snd    uint32 // 相手の次の番号
	rcv    uint32 // 相手が次に受ける番号(DUT の番号)
	dutISS uint32
	ts     bool
	tsVal  uint32
	dutTS  uint32
	wnd    uint16
	sackOK bool
	wsOK   bool
	synAck out
}

// handshake は相手から接続を開き、Device の SYN-ACK に最後の ACK を返す。
func (n *testNet) handshake(sport, dport uint16, ts, sack, ws bool) *peerConn {
	n.t.Helper()
	p := &peerConn{n: n, sport: sport, dport: dport, iss: 1000, ts: ts, tsVal: 5000, wnd: 65535, sackOK: sack, wsOK: ws}
	wsv := -1
	if ws {
		wsv = 7
	}
	n.inject(tseg{sport: sport, dport: dport, seq: p.iss, flags: flagSYN, wnd: 65535, mss: 1380, ws: wsv, sackOK: sack, ts: ts, tsVal: p.tsVal})
	outs := n.drain()
	if len(outs) != 1 || outs[0].seg.flags != flagSYN|flagACK {
		n.t.Fatalf("expected one SYN-ACK, got %v", outs)
	}
	sa := outs[0]
	if sa.seg.ack != p.iss+1 {
		n.t.Fatalf("SYN-ACK acks %d, want %d", sa.seg.ack, p.iss+1)
	}
	p.synAck = sa
	p.dutISS = sa.seg.seq
	p.snd = p.iss + 1
	p.rcv = sa.seg.seq + 1
	p.dutTS = sa.seg.opt.tsVal
	p.ack(nil)
	return p
}

// segment は相手の今の番号の segment。
func (p *peerConn) seg(flags uint8, payload []byte) tseg {
	p.tsVal++
	return tseg{sport: p.sport, dport: p.dport, seq: p.snd, ack: p.rcv, flags: flags, wnd: p.wnd, ws: -1, ts: p.ts, tsVal: p.tsVal, tsEcr: p.dutTS, payload: payload}
}

// ack は相手から中身を送る(nil なら中身の無い ACK)。
func (p *peerConn) ack(payload []byte) {
	p.n.inject(p.seg(flagACK, payload))
	p.snd += uint32(len(payload))
}

func (p *peerConn) fin() {
	p.n.inject(p.seg(flagACK|flagFIN, nil))
	p.snd++
}

// absorb は Device の segment を受けて、相手の受ける番号を進める。順序どおりのものだけを数える。
func (p *peerConn) absorb(outs []out) []byte {
	var data []byte
	for _, o := range outs {
		if o.seg.tup.lport != p.sport || o.seg.tup.rport != p.dport {
			continue
		}
		if o.seg.opt.hasTS {
			p.dutTS = o.seg.opt.tsVal
		}
		if o.seg.seq == p.rcv {
			data = append(data, o.seg.payload...)
			p.rcv += uint32(len(o.seg.payload))
			if o.seg.has(flagFIN) {
				p.rcv++
			}
		}
	}
	return data
}

// acceptOne は待ち受けから 1 つ受け取る。
func acceptOne(t testing.TB, l *TCPListener) *Conn {
	t.Helper()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := l.Accept()
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("Accept: %v", r.err)
		}
		return r.c.(*Conn)
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return")
	}
	return nil
}

func netipAP(port uint16) netip.AddrPort { return netip.AddrPortFrom(dutAddr, port) }

// drainRaw は Device が今送る packet をそのまま読む。
func (n *testNet) drainRaw() [][]byte {
	n.t.Helper()
	var res [][]byte
	for range 100000 {
		k := n.poll(n.buf)
		if k == 0 {
			return res
		}
		if k > testMTU {
			n.t.Fatalf("packet of %d bytes exceeds the MTU", k)
		}
		if _, d := parseIPv4(n.buf[:k]); d != ipv4OK {
			n.t.Fatalf("Device sent a bad IPv4 packet: %v", d)
		}
		res = append(res, append([]byte(nil), n.buf[:k]...))
	}
	n.t.Fatal("Device kept sending")
	return nil
}

// buildUDP は peer から Device への UDP の datagram を作る。
func buildUDP(src netip.AddrPort, dport uint16, payload []byte) []byte {
	ulen := udpHeaderLen + len(payload)
	b := make([]byte, ipHeaderLen+ulen)
	writeIPv4Header(b, len(b), 7, protoUDP, addrBits(src.Addr()), addrBits(dutAddr))
	u := b[ipHeaderLen:]
	binary.BigEndian.PutUint16(u[0:2], src.Port())
	binary.BigEndian.PutUint16(u[2:4], dport)
	binary.BigEndian.PutUint16(u[4:6], uint16(ulen))
	copy(u[8:], payload)
	cs := ^checksum(pseudoSum(addrBits(src.Addr()), addrBits(dutAddr), protoUDP, ulen), u)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:8], cs)
	return b
}

// buildICMP は peer から Device への ICMP の message を作る。
func buildICMP(src netip.Addr, msg []byte) []byte {
	b := make([]byte, ipHeaderLen+len(msg))
	writeIPv4Header(b, len(b), 9, protoICMP, addrBits(src), addrBits(dutAddr))
	m := b[ipHeaderLen:]
	copy(m, msg)
	m[2], m[3] = 0, 0
	binary.BigEndian.PutUint16(m[2:4], ^checksum(0, m))
	return b
}

func (n *testNet) write(pkt []byte) {
	n.t.Helper()
	if _, err := n.writePkts(pkt); err != nil {
		n.t.Fatalf("Write: %v", err)
	}
}
