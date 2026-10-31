package wgstack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

var peerUDP = netip.AddrPortFrom(peerAddr, 5000)

func listenUDP(t *testing.T, n *testNet, port uint16) *UDPConn {
	t.Helper()
	pc, err := n.d.ListenUDP(netip.AddrPortFrom(dutAddr, port))
	if err != nil {
		t.Fatal(err)
	}
	return pc.(*UDPConn)
}

func readUDP(t *testing.T, pc *UDPConn, size int) ([]byte, net.Addr) {
	t.Helper()
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, size)
	k, from, err := pc.ReadFrom(b)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	return b[:k], from
}

// reassembleUDP は Device が送った UDP の断片を組み立て、UDP の header と中身を返す。checksum を確かめる。
func reassembleUDP(t *testing.T, pkts [][]byte) []byte {
	t.Helper()
	var out []byte
	var id uint16
	for i, p := range pkts {
		ip, _ := parseIPv4(p)
		if ip.proto != protoUDP {
			t.Fatalf("packet %d is protocol %d", i, ip.proto)
		}
		fl := binary.BigEndian.Uint16(p[6:8])
		if fl&0x4000 != 0 {
			t.Fatalf("packet %d has DF set", i)
		}
		pid := binary.BigEndian.Uint16(p[4:6])
		if pid == 0 || (i > 0 && pid != id) {
			t.Fatalf("packet %d IP ID %d", i, pid)
		}
		id = pid
		if int(fl&0x1fff)*8 != len(out) {
			t.Fatalf("fragment %d at offset %d, want %d", i, int(fl&0x1fff)*8, len(out))
		}
		more := fl&0x2000 != 0
		if more != (i < len(pkts)-1) {
			t.Fatalf("fragment %d MF %v", i, more)
		}
		out = append(out, ip.payload...)
	}
	ip, _ := parseIPv4(pkts[0])
	if ^checksum(pseudoSum(ip.src, ip.dst, protoUDP, len(out)), out) != 0 {
		t.Fatal("UDP checksum is wrong")
	}
	return out
}

func TestUDPRoundTrip(t *testing.T) {
	n := newTestNet(t, smallLimits())
	pc := listenUDP(t, n, 53)
	n.write(buildUDP(peerUDP, 53, []byte("query")))
	got, from := readUDP(t, pc, 100)
	if string(got) != "query" || from.String() != "10.9.0.2:5000" {
		t.Fatalf("ReadFrom %q from %v", got, from)
	}
	if _, ok := from.(*net.UDPAddr); !ok {
		t.Fatalf("source is %T", from)
	}
	if _, err := pc.WriteTo([]byte("answer"), from); err != nil {
		t.Fatal(err)
	}
	pkts := n.drainRaw()
	if len(pkts) != 1 {
		t.Fatalf("%d packets", len(pkts))
	}
	u := reassembleUDP(t, pkts)
	if binary.BigEndian.Uint16(u[0:2]) != 53 || binary.BigEndian.Uint16(u[2:4]) != 5000 || string(u[8:]) != "answer" {
		t.Fatalf("reply %x", u)
	}
}

func TestUDPFragmentedSend(t *testing.T) {
	n := newTestNet(t, smallLimits())
	pc := listenUDP(t, n, 53)
	for _, size := range []int{testMTU - 28, testMTU - 27, 5000, 20000, udpMaxPayload} {
		msg := make([]byte, size)
		for i := range msg {
			msg[i] = byte(i * 13)
		}
		if _, err := pc.WriteTo(msg, net.UDPAddrFromAddrPort(peerUDP)); err != nil {
			t.Fatal(err)
		}
		u := reassembleUDP(t, n.drainRaw())
		if !bytes.Equal(u[8:], msg) {
			t.Fatalf("size %d: the reassembled datagram differs", size)
		}
	}
	if _, err := pc.WriteTo(make([]byte, udpMaxPayload+1), net.UDPAddrFromAddrPort(peerUDP)); err == nil {
		t.Fatal("an oversized datagram was accepted")
	}
	if st := checkUDPHeld(t, n); st[dirTx][0] != 0 {
		t.Fatalf("send budget still holds %v", st)
	}
}

func TestUDPPortUnreachable(t *testing.T) {
	n := newTestNet(t, smallLimits())
	q := buildUDP(peerUDP, 9999, []byte("x"))
	n.write(q)
	pkts := n.drainRaw()
	if len(pkts) != 1 {
		t.Fatalf("%d packets", len(pkts))
	}
	ip, _ := parseIPv4(pkts[0])
	if ip.proto != protoICMP || ip.payload[0] != 3 || ip.payload[1] != 3 || !bytes.Equal(ip.payload[8:], q) {
		t.Fatalf("Port Unreachable %x", pkts[0])
	}
}

func TestUDPReadSemantics(t *testing.T) {
	n := newTestNet(t, smallLimits())
	pc := listenUDP(t, n, 53)
	// 短い読み取りは切り、残りを捨てる
	n.write(buildUDP(peerUDP, 53, []byte("0123456789")))
	n.write(buildUDP(peerUDP, 53, []byte("next")))
	got, _ := readUDP(t, pc, 4)
	if string(got) != "0123" {
		t.Fatalf("short read %q", got)
	}
	got, _ = readUDP(t, pc, 100)
	if string(got) != "next" {
		t.Fatalf("next read %q", got)
	}
	// 期限
	pc.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	_, _, err := pc.ReadFrom(make([]byte, 10))
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("read after the deadline: %v", err)
	}
	// Close は待ちを net.ErrClosed で解く
	pc.SetReadDeadline(time.Time{})
	done := make(chan error, 1)
	go func() {
		_, _, err := pc.ReadFrom(make([]byte, 10))
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	pc.Close()
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read unblocked by Close: %v", err)
	}
	if _, _, err := pc.ReadFrom(make([]byte, 10)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after Close: %v", err)
	}
	// ポートはその場で空く
	listenUDP(t, n, 53)
}

func TestUDPChecksumHandling(t *testing.T) {
	n := newTestNet(t, smallLimits())
	pc := listenUDP(t, n, 53)
	bad := buildUDP(peerUDP, 53, []byte("bad"))
	bad[len(bad)-1] ^= 1
	n.write(bad)
	none := buildUDP(peerUDP, 53, []byte("none"))
	none[ipHeaderLen+6], none[ipHeaderLen+7] = 0, 0 // checksum 0 は確かめない
	n.write(none)
	got, _ := readUDP(t, pc, 100)
	if string(got) != "none" {
		t.Fatalf("read %q", got)
	}
}

// checkUDPHeld は UDP の会計を数え直し、予算と endpoint の上限の内側にあることを確かめる。返す値は
// [向き][byte, 件数] である。
func checkUDPHeld(t *testing.T, n *testNet) [2][2]int64 {
	t.Helper()
	u := &n.d.s.udp
	u.mu.Lock()
	defer u.mu.Unlock()
	var res [2][2]int64
	chunks := map[int32]bool{}
	for d := range 2 {
		var count int64
		for i := range u.dg[d] {
			g := &u.dg[d][i]
			if g.ep == nil {
				continue
			}
			count++
			if g.class == udpLarge {
				for k := 0; k*chunkSize < g.n; k++ {
					chunks[g.ck[k]] = true
				}
			} else {
				chunks[g.ck[0]] = true
			}
		}
		b := &u.budget[d]
		if b.count != count || b.count > b.maxCount || b.bytes > b.maxBytes {
			t.Fatalf("direction %d: budget %+v, %d datagrams held", d, *b, count)
		}
		res[d] = [2]int64{b.bytes, b.count}
	}
	held := int64(len(u.ck)-len(u.ckFree)) * chunkSize
	if held != u.budget[0].bytes+u.budget[1].bytes || int64(len(chunks))*chunkSize > held {
		t.Fatalf("chunks held %d, budgets %d + %d, %d chunks in use", held, u.budget[0].bytes, u.budget[1].bytes, len(chunks))
	}
	for _, ep := range u.eps {
		for d := range 2 {
			if b := ep.budget[d]; b.count > b.maxCount || b.bytes > b.maxBytes {
				t.Fatalf("endpoint %v direction %d over its share: %+v", ep.local, d, b)
			}
		}
	}
	return res
}

func TestBoundUDPReceive(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
	}{{"small", 100}, {"class 2", 1000}, {"class 3", 9000}, {"large", 60000}} {
		t.Run(tc.name, func(t *testing.T) {
			n := newTestNet(t, smallLimits())
			var pcs []*UDPConn
			for p := range 6 {
				pcs = append(pcs, listenUDP(t, n, uint16(100+p)))
			}
			// 読まない endpoint への洪水
			for i := 0; i < 3*udpRxDatagrams; i++ {
				n.write(buildUDP(peerUDP, uint16(100+i%6), make([]byte, tc.size)))
			}
			checkHeld(t, n)
			held := checkUDPHeld(t, n)
			if held[dirRx][0] > udpRxBytes || held[dirRx][1] > udpRxDatagrams {
				t.Fatalf("receive holds %v", held[dirRx])
			}
			st := n.d.Stats()
			if st.UDPDropped == 0 {
				t.Fatal("no drops counted")
			}
			t.Logf("held %d bytes in %d datagrams", held[dirRx][0], held[dirRx][1])
			// 読み手が読めば戻る
			for _, pc := range pcs {
				pc.Close()
			}
			if held := checkUDPHeld(t, n); held[dirRx] != [2]int64{} {
				t.Fatalf("after Close %v", held[dirRx])
			}
		})
	}
}

func TestBoundUDPSendWaits(t *testing.T) {
	n := newTestNet(t, smallLimits())
	pc := listenUDP(t, n, 53)
	to := net.UDPAddrFromAddrPort(peerUDP)
	// 出力を読まない間、送信は endpoint の上限で待つ
	sent := 0
	pc.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	for {
		if _, err := pc.WriteTo(make([]byte, 1000), to); err != nil {
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				t.Fatalf("WriteTo: %v", err)
			}
			break
		}
		sent++
	}
	held := checkUDPHeld(t, n)
	if held[dirTx][1] != udpTxDatagrams/udpEndpointShare || sent != udpTxDatagrams/udpEndpointShare {
		t.Fatalf("sent %d, held %v", sent, held[dirTx])
	}
	// 詰まりが解けると予約が返る
	if got := len(n.drainRaw()); got != sent {
		t.Fatalf("%d packets out, %d sent", got, sent)
	}
	if held := checkUDPHeld(t, n); held[dirTx] != [2]int64{} {
		t.Fatalf("after the output drained %v", held[dirTx])
	}
	pc.SetWriteDeadline(time.Time{})
	if _, err := pc.WriteTo([]byte("x"), to); err != nil {
		t.Fatal(err)
	}
}

func TestICMPEcho(t *testing.T) {
	n := newTestNet(t, smallLimits())
	req := []byte{icmpEcho, 0, 0, 0, 0x12, 0x34, 0, 1, 'h', 'i'}
	n.write(buildICMP(peerAddr, req))
	pkts := n.drainRaw()
	if len(pkts) != 1 {
		t.Fatalf("%d packets", len(pkts))
	}
	ip, _ := parseIPv4(pkts[0])
	m := ip.payload
	if ip.proto != protoICMP || ip.dst != addrBits(peerAddr) || m[0] != icmpEchoReply || !bytes.Equal(m[4:], req[4:]) || ^checksum(0, m) != 0 {
		t.Fatalf("echo reply %x", pkts[0])
	}
	// echo の応答は DF を立てず、IPv4 の header の checksum は正しい
	if pkts[0][6]&0x40 != 0 || ^checksum(0, pkts[0][:ipHeaderLen]) != 0 {
		t.Fatalf("echo reply header %x: DF set or bad checksum", pkts[0][:ipHeaderLen])
	}
}

func TestDialPing(t *testing.T) {
	n := newTestNet(t, smallLimits())
	conn, err := n.d.DialPing(dutAddr, peerAddr)
	if err != nil {
		t.Fatal(err)
	}
	pc := conn.(*PingConn)
	if _, err := pc.Write([]byte{icmpEcho, 0, 0, 0, 0, 1, 0, 7, 'w', 'g', 'f', 't'}); err != nil {
		t.Fatal(err)
	}
	pkts := n.drainRaw()
	if len(pkts) != 1 {
		t.Fatalf("%d packets", len(pkts))
	}
	ip, _ := parseIPv4(pkts[0])
	if ip.dst != addrBits(peerAddr) || ip.payload[0] != icmpEcho || ^checksum(0, ip.payload) != 0 {
		t.Fatalf("echo request %x", pkts[0])
	}
	ident := binary.BigEndian.Uint16(ip.payload[4:6])
	reply := append([]byte(nil), ip.payload...)
	reply[0] = icmpEchoReply
	n.write(buildICMP(peerAddr, reply))
	other := append([]byte(nil), reply...)
	other[7] = 8
	n.write(buildICMP(peerAddr, other)) // 1 つ持つ間に届いた応答は捨てる
	pc.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 100)
	k, err := pc.Read(b)
	if err != nil || k != len(reply) || binary.BigEndian.Uint16(b[4:6]) != ident || b[7] != 7 {
		t.Fatalf("Read %x %v", b[:k], err)
	}
	pc.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := pc.Read(b); err == nil {
		t.Fatal("a second reply was held")
	}
	// 表は 16 件で満ちる
	var conns []net.Conn
	for range pingEndpoints - 1 {
		c, err := n.d.DialPing(dutAddr, peerAddr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	if _, err := n.d.DialPing(dutAddr, peerAddr); err == nil {
		t.Fatal("DialPing past the table")
	}
	pc.Close()
	if _, err := pc.Read(b); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read after Close: %v", err)
	}
	if _, err := n.d.DialPing(dutAddr, peerAddr); err != nil {
		t.Fatalf("DialPing after a Close: %v", err)
	}
	for _, c := range conns {
		c.Close()
	}
	if _, err := n.d.DialPing(peerAddr, dutAddr); err == nil {
		t.Fatal("DialPing from a foreign source")
	}
}

func TestICMPErrorSourceCheck(t *testing.T) {
	n := newTestNet(t, smallLimits())
	c, p := n.accepted(true, false)
	c.Write(make([]byte, 3000))
	outs := n.drain()
	quote := append(append([]byte(nil), outs[0].ip.header...), outs[0].ip.payload[:8]...)
	frag := func(src netip.Addr, mtu uint16) []byte {
		m := make([]byte, 8+len(quote))
		m[0], m[1] = icmpDstUnreach, 4
		binary.BigEndian.PutUint16(m[6:8], mtu)
		copy(m[8:], quote)
		return buildICMP(src, m)
	}
	cs := &n.d.s.conns[c.c.id]
	n.write(frag(netip.MustParseAddr("10.9.0.3"), 1000)) // 引用の宛先と違う送信元
	n.write(frag(peerAddr, 500))                         // 552 より小さい
	if cs.pmtu != testMTU {
		t.Fatalf("PMTU %d after refused errors", cs.pmtu)
	}
	n.write(frag(peerAddr, 1000))
	if cs.pmtu != 1000 {
		t.Fatalf("PMTU %d, want 1000", cs.pmtu)
	}
	_ = p
}

func TestBoundEchoFloodFillsOnlyTheControlRing(t *testing.T) {
	n := newTestNet(t, smallLimits())
	pc := listenUDP(t, n, 53)
	for i := 0; i < 1000; i++ {
		n.write(buildICMP(peerAddr, []byte{icmpEcho, 0, 0, 0, 0, 1, byte(i >> 8), byte(i)}))
	}
	st := checkHeld(t, n)
	if st.CtlQueued != n.d.s.lim.ctlSlots || st.CtlDropped == 0 {
		t.Fatalf("echo flood %+v", st)
	}
	// UDP の出力は組の配分の分だけ進み続ける
	if _, err := pc.WriteTo([]byte("still here"), net.UDPAddrFromAddrPort(peerUDP)); err != nil {
		t.Fatal(err)
	}
	udp := false
	for i := 0; i < 2*n.d.s.mtu/28 && !udp; i++ {
		k := n.d.Poll(n.buf)
		if k == 0 {
			break
		}
		ip, _ := parseIPv4(n.buf[:k])
		udp = ip.proto == protoUDP
	}
	if !udp {
		t.Fatal("the UDP class was starved by the control ring")
	}
}
