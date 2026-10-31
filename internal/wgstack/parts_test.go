package wgstack

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

func TestTCPRoundTrip(t *testing.T) {
	b := buildPeer(tseg{sport: 1234, dport: 80, seq: 1, ack: 2, flags: flagSYN | flagACK, wnd: 999, mss: 1380, ws: 7, sackOK: true, ts: true, tsVal: 11, tsEcr: 12, payload: []byte("abc")})
	ip, d := parseIPv4(b)
	if d != ipv4OK {
		t.Fatal(d)
	}
	s, td := parseTCP(&ip)
	if td != tcpOK {
		t.Fatal(td)
	}
	o := s.opt
	if s.seq != 1 || s.ack != 2 || s.wnd != 999 || string(s.payload) != "abc" || !o.hasMSS || o.mss != 1380 ||
		!o.hasWS || o.wscale != 7 || !o.sackOK || !o.hasTS || o.tsVal != 11 || o.tsEcr != 12 {
		t.Fatalf("%+v", s)
	}
	// checksum を壊すと捨てる
	b[len(b)-1] ^= 1
	ip, _ = parseIPv4(b)
	if _, td := parseTCP(&ip); td != tcpBadChecksum {
		t.Fatal("bad checksum accepted")
	}
	// Total Length より後ろは切り捨てる
	b = buildPeer(tseg{sport: 1, dport: 2, flags: flagACK, ws: -1})
	ip, d = parseIPv4(append(b, 1, 2, 3))
	if d != ipv4OK || len(ip.payload) != tcpHeaderLen {
		t.Fatalf("trailing bytes: %v %d", d, len(ip.payload))
	}
}

func TestParseOptionsMalformed(t *testing.T) {
	o := parseOptions([]byte{1, 2, 5, 1, 2}, true) // option の長さが残りより長い
	if !o.malformed || o.hasMSS {
		t.Fatalf("%+v", o)
	}
	o = parseOptions([]byte{2, 4, 2, 0x18, 3, 3, 20}, true)
	if o.mss != 536 || o.wscale != 14 {
		t.Fatalf("%+v", o)
	}
	o = parseOptions([]byte{2, 4, 2, 0x18}, false) // SYN でなければ MSS を読まない
	if o.hasMSS {
		t.Fatal("MSS read outside SYN")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(buildPeer(tseg{sport: 1, dport: 2, flags: flagSYN, mss: 1380, ws: 7, sackOK: true, ts: true}))
	f.Add(buildPeer(tseg{sport: 1, dport: 2, flags: flagACK, ws: -1, sack: []sackBlock{{1, 2}, {3, 4}}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		ip, d := parseIPv4(b)
		if d != ipv4OK {
			return
		}
		switch ip.proto {
		case protoTCP:
			parseTCP(&ip)
		}
	})
}

func TestIndexBackwardShift(t *testing.T) {
	x := newIndex(64, sipKey{1, 2})
	r := rand.New(rand.NewPCG(1, 2))
	ref := map[tuple]int32{}
	for i := 0; i < 20000; i++ {
		tup := tuple{laddr: 1, raddr: uint32(r.IntN(8)), lport: 80, rport: uint16(r.IntN(16))}
		if _, ok := ref[tup]; ok && r.IntN(2) == 0 {
			if !x.remove(tup) {
				t.Fatal("remove failed")
			}
			delete(ref, tup)
		} else if len(ref) < 64 {
			id := int32(r.IntN(1000))
			x.insert(tup, id, 0)
			ref[tup] = id
		}
		for k, v := range ref {
			if got, _ := x.find(k); got != v {
				t.Fatalf("step %d: find %v = %d, want %d", i, k, got, v)
			}
		}
		used := 0
		for _, e := range x.ents {
			if e.id != 0 {
				used++
			}
		}
		if used != len(ref) {
			t.Fatalf("step %d: %d entries, want %d", i, used, len(ref))
		}
	}
}

func TestRingResizeAndTrim(t *testing.T) {
	var p chunkPool
	r := ring{pool: &p, cap: sendFloor}
	data := make([]byte, sendFloor)
	for i := range data {
		data[i] = byte(i * 7)
	}
	base := uint64(100)
	r.write(base, data)
	if r.heldChunks() != sendFloor/chunkSize {
		t.Fatalf("held %d chunks", r.heldChunks())
	}
	r.trim(base, base+chunkSize*3, base+sendFloor)
	if got := r.heldChunks(); got != sendFloor/chunkSize-2 {
		t.Fatalf("after trim %d chunks", got)
	}
	r.resize(boostSize, [][2]uint64{{base + chunkSize*3, base + sendFloor}})
	got := make([]byte, sendFloor-chunkSize*3)
	r.read(base+chunkSize*3, got)
	if !bytes.Equal(got, data[chunkSize*3:]) {
		t.Fatal("data moved wrong")
	}
	r.release()
	if p.heldChunks() != 0 {
		t.Fatalf("pool holds %d", p.heldChunks())
	}
}

func TestRecvIntervals(t *testing.T) {
	var p chunkPool
	b := recvBuf{r: ring{pool: &p, cap: recvFloor}, iv: make([]interval, floorIntervals)}
	limit := uint64(recvFloor)
	// H を超える区間を作る segment は捨てる
	for i := range floorIntervals {
		res := b.insert(uint64(100+i*10), []byte{1}, limit)
		if !res.ooo {
			t.Fatalf("interval %d not accepted", i)
		}
	}
	if res := b.insert(uint64(100+floorIntervals*10+5), []byte{1}, limit); !res.dropped {
		t.Fatal("interval beyond H accepted")
	}
	// 既存の区間を伸ばす segment は受け入れる
	if res := b.insert(101, []byte{1}, limit); !res.ooo || res.dropped {
		t.Fatalf("extension refused %+v", res)
	}
	// 窓の外は捨てる
	if res := b.insert(limit, []byte{1}, limit); !res.trimmed {
		t.Fatal("beyond limit accepted")
	}
	// 穴を埋めると全部取り込む
	res := b.insert(0, make([]byte, 100), limit)
	if !res.filled || b.nxtOff != 102 {
		t.Fatalf("fill %+v nxt=%d", res, b.nxtOff)
	}
	last := uint32(100 + (floorIntervals-1)*10)
	blocks := b.sackBlocks(make([]sackBlock, 0, 4), 0)
	if len(blocks) != 4 || blocks[0] != (sackBlock{last, last + 1}) || blocks[1] != (sackBlock{last - 10, last - 9}) {
		t.Fatalf("blocks %v", blocks)
	}
}

// TestRecvIntervalsCoverAFullBuffer は、MSS の下限の segment が 1 つおきに失われても、受信のバッファが
// 満ちるまで区間が尽きないことを確かめる。
func TestRecvIntervalsCoverAFullBuffer(t *testing.T) {
	for _, tier := range []struct {
		cap uint64
		h   int
	}{{recvFloor, floorIntervals}, {boostSize, boostIntervals}} {
		var p chunkPool
		b := recvBuf{r: ring{pool: &p, cap: tier.cap}, iv: make([]interval, tier.h)}
		seg := make([]byte, minMSS)
		for off := uint64(minMSS); off+minMSS <= tier.cap; off += 2 * minMSS {
			if res := b.insert(off, seg, tier.cap); res.dropped {
				t.Fatalf("capacity %d: segment at %d dropped with %d intervals", tier.cap, off, b.n)
			}
		}
		b.r.release()
	}
}

func TestWheel(t *testing.T) {
	w := newWheel(8)
	deadlines := []int64{5, 64, 65, 4096, 5000, 300_000, 1_000_000}
	for i, d := range deadlines {
		w.set(int32(i), d*tickNs)
	}
	var fired []int32
	got := map[int32]int64{}
	for now := int64(0); now <= 1_100_000; now += 7 {
		for _, n := range w.advance(now*tickNs, fired[:0]) {
			got[n] = now
		}
	}
	for i, d := range deadlines {
		at, ok := got[int32(i)]
		if !ok || at < d || at >= d+7 {
			t.Errorf("node %d deadline %d fired at %d (%v)", i, d, at, ok)
		}
	}
	w.set(7, 100*tickNs)
	w.cancel(7)
	if w.count != 0 {
		t.Fatalf("count %d", w.count)
	}
}
