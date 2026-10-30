package wgstack

import (
	"net/netip"
	"testing"
	"time"
)

// TestIdleDeviceSweepsAHeldFragment は、TCP のタイマーを持たない Device が実際の時計で 1 つの断片を保持したとき、
// タイマーの goroutine が寿命の後に項目を外して Time Exceeded を返すことを確かめる。ManualClock の Tick は
// advance を直接呼ぶので、眠っている goroutine を起こし忘れても他の試験は気づかない。
func TestIdleDeviceSweepsAHeldFragment(t *testing.T) {
	old := fragLimits
	fragLimits.Lifetime = 200 * time.Millisecond
	t.Cleanup(func() { fragLimits = old })
	d, err := New(Config{Addr: dutAddr, MTU: testMTU})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close(); d.Wait() })
	pc, err := d.ListenUDP(netip.AddrPortFrom(dutAddr, 53))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	time.Sleep(50 * time.Millisecond) // the timer goroutine is asleep with no deadline
	frags := splitIPv4(buildUDP(peerUDP, 53, make([]byte, 3000)), 1000, 78)
	if _, err := d.Write([][]byte{frags[0]}, 0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65536)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if k := d.Poll(buf); k > 0 {
			ip, _ := parseIPv4(buf[:k])
			if ip.proto == protoICMP && ip.payload[0] == icmpTimeExceeded {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, entries, _ := d.s.frag.Usage()
	t.Fatalf("no Time Exceeded within 3s of a 200ms lifetime; entries still held: %d", entries)
}

func fragWithOptions(offset int, more bool, opts, data []byte) []byte {
	hlen := 20 + len(opts)
	p := make([]byte, hlen+len(data))
	p[0] = 0x40 | byte(hlen/4)
	p[2], p[3] = byte(len(p)>>8), byte(len(p))
	p[4], p[5] = 0x12, 0x34
	fl := uint16(offset / 8)
	if more {
		fl |= 0x2000
	}
	p[6], p[7] = byte(fl>>8), byte(fl)
	p[8], p[9] = 64, protoUDP
	pa, da := peerAddr.As4(), dutAddr.As4()
	copy(p[12:16], pa[:])
	copy(p[16:20], da[:])
	copy(p[20:], opts)
	copy(p[hlen:], data)
	cs := ^checksum(0, p[:hlen])
	p[10], p[11] = byte(cs>>8), byte(cs)
	return p
}

// TestParamProblemForFragmentOptions は、不正な option を持つ断片に、最初の断片でも後の断片でも Parameter Problem を
// 返し、pointer が option の位置を指すことを確かめる。
func TestParamProblemForFragmentOptions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int
		more   bool
	}{{"first", 0, true}, {"later", 8, false}} {
		t.Run(tc.name, func(t *testing.T) {
			n := newTestNet(t, smallLimits())
			listenUDP(t, n, 53)
			n.write(fragWithOptions(tc.offset, tc.more, []byte{0x82, 1, 0, 0}, []byte("abcdefgh")))
			pkts := n.drainRaw()
			if len(pkts) != 1 {
				t.Fatalf("%d packets; stats %+v", len(pkts), n.d.Stats())
			}
			ip, _ := parseIPv4(pkts[0])
			if ip.proto != protoICMP || ip.payload[0] != icmpParamProblem || ip.payload[4] != 20 {
				t.Fatalf("got %x", pkts[0])
			}
		})
	}
}

// TestFragNeededOutsideTheSendWindowIsIgnored は、引用した sequence が SND.UNA 以上 SND.NXT 未満にない
// Fragmentation Needed で PMTU を下げず、内側にあるものでだけ下げることを確かめる(RFC 5927)。
func TestFragNeededOutsideTheSendWindowIsIgnored(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Write(make([]byte, 3000))
	outs := n.drain()
	quote := append(append([]byte(nil), outs[0].ip.header...), outs[0].ip.payload[:8]...)
	hl := len(outs[0].ip.header)
	cs := &n.d.s.conns[c.c.id]
	mk := func(seq uint32) []byte {
		q := append([]byte(nil), quote...)
		q[hl+4], q[hl+5], q[hl+6], q[hl+7] = byte(seq>>24), byte(seq>>16), byte(seq>>8), byte(seq)
		m := make([]byte, 8+len(q))
		m[0], m[1] = icmpDstUnreach, 4
		m[6], m[7] = 1000>>8, 1000&0xff
		copy(m[8:], q)
		return buildICMP(peerAddr, m)
	}
	n.write(mk(cs.sndNxt))     // at SND.NXT: outside
	n.write(mk(cs.sndUna - 1)) // below SND.UNA
	if cs.pmtu != testMTU {
		t.Fatalf("PMTU %d after out-of-window errors", cs.pmtu)
	}
	n.write(mk(cs.sndUna))
	if cs.pmtu != 1000 {
		t.Fatalf("PMTU %d, want 1000", cs.pmtu)
	}
}
