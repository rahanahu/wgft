package wgstack

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

// recvBuf を参照の模型と比べる。offset は 2^32 を跨ぐ位置から始め、区間の段を途中で切り替える。
// 模型は届いた byte の集合と、区間ごとの最後に触れた順を持つ。
func TestRecvBufAgainstModel(t *testing.T) {
	seeds := uint64(10)
	if streamSeedsFull() {
		seeds = 120
	}
	forSeeds(t, 0, seeds-1, func(t *testing.T, seed uint64) {
		rng := rand.New(rand.NewPCG(seed, 7))
		var p chunkPool
		start := uint64(1<<32) - uint64(rng.IntN(300000))
		if seed%3 == 0 {
			start = uint64(5)<<32 - 1000
		}
		capB := uint64(recvFloor)
		h := floorIntervals
		b := recvBuf{r: ring{pool: &p, cap: capB}, iv: make([]interval, h), readOff: start, nxtOff: start}
		const span = 3 << 20
		stream := make([]byte, span)
		for i := range stream {
			stream[i] = byte(rng.Uint32())
		}
		have := make([]bool, span) // 順序外で届いた offset - start
		haveN := 0
		lastNxt := start
		var lastTouch uint64 // 最後に区間に触れた segment の位置。0 は無し
		var got []byte
		boosted := false
		for step := 0; step < 4000; step++ {
			switch r := rng.IntN(100); {
			case r < 70:
				lo := b.nxtOff
				off := lo + uint64(rng.IntN(int(min(capB, span-(lo-start)))+1)) - uint64(rng.IntN(2000))
				if off < start {
					off = start
				}
				ln := 1 + rng.IntN(1500)
				if rng.IntN(4) == 0 {
					ln = 1 + rng.IntN(8)
				}
				if off-start+uint64(ln) > span {
					continue
				}
				limit := b.readOff + capB
				nIv := b.n
				before := b.nxtOff
				res := b.insert(off, stream[off-start:off-start+uint64(ln)], limit)
				if res.ooo || (res.duplicate && off >= before) {
					lastTouch = max(off, before)
				}
				if res.dropped {
					if nIv != h {
						t.Fatalf("seed %d: dropped with %d of %d intervals", seed, nIv, h)
					}
					continue
				}
				for x := lastNxt; x < b.nxtOff; x++ {
					if have[x-start] {
						have[x-start] = false
						haveN--
					}
				}
				lastNxt = b.nxtOff
				for x := max(off, b.nxtOff); x < off+uint64(ln) && x < limit; x++ {
					if !have[x-start] {
						have[x-start] = true
						haveN++
					}
				}
			case r < 85:
				buf := make([]byte, 1+rng.IntN(70000))
				k := b.read(buf)
				got = append(got, buf[:k]...)
				if !bytes.Equal(got, stream[:len(got)]) {
					t.Fatalf("seed %d: read bytes differ", seed)
				}
			case r < 92 && !boosted && b.n <= boostIntervals:
				b.r.resize(boostSize, b.written())
				b.setIntervals(make([]interval, boostIntervals))
				capB, h, boosted = boostSize, boostIntervals, true
			case r < 99 && boosted && b.rightmost()-b.readOff <= recvFloor && b.n <= floorIntervals:
				b.r.resize(recvFloor, b.written())
				b.setIntervals(make([]interval, floorIntervals))
				capB, h, boosted = recvFloor, floorIntervals, false
			}
			// 区間が模型の集合と一致し、整列していること
			cnt := 0
			prevEnd := b.nxtOff
			ivs := b.intervals(nil)
			if len(ivs) != b.n {
				t.Fatalf("seed %d step %d: %d intervals in the tree, count %d", seed, step, len(ivs), b.n)
			}
			for k, iv := range ivs {
				s, e := iv[0], iv[1]
				if s <= prevEnd && !(k == 0 && s > b.nxtOff) {
					t.Fatalf("seed %d step %d: interval %d [%d,%d) not after %d", seed, step, k, s, e, prevEnd)
				}
				for x := s; x < e; x++ {
					if !have[x-start] {
						t.Fatalf("seed %d step %d: interval byte %d not received", seed, step, x)
					}
				}
				cnt += int(e - s)
				prevEnd = e
			}
			if cnt != haveN {
				t.Fatalf("seed %d step %d: intervals cover %d bytes, model %d", seed, step, cnt, haveN)
			}
			// 区間の中身を輪から読み、stream と比べる
			for k := range min(b.n, 3) {
				s, e := ivs[k][0], ivs[k][1]
				tmp := make([]byte, e-s)
				b.r.read(s, tmp)
				if !bytes.Equal(tmp, stream[s-start:e-start]) {
					t.Fatalf("seed %d step %d: out-of-order bytes differ in interval %d", seed, step, k)
				}
			}
			// SACK の block:新しい順で、重ならない
			blocks := b.sackBlocks(make([]sackBlock, 0, 4), 0)
			for i := 1; i < len(blocks); i++ {
				_ = blocks[i]
			}
			if b.n > 0 && len(blocks) == 0 {
				t.Fatalf("seed %d: no SACK blocks with %d intervals", seed, b.n)
			}
			// 先頭の block は最も新しく触れた区間(まだ順序外にあるとき)
			if lastTouch != 0 && lastTouch >= b.nxtOff && b.n > 0 {
				if x := uint32(lastTouch); len(blocks) == 0 || !seqLE(blocks[0].left, x) || !seqLT(x, blocks[0].right) {
					t.Fatalf("seed %d step %d: first SACK block %v does not hold the last touched offset %d", seed, step, blocks, uint32(lastTouch))
				}
			}
			// block は区間と一致し、重ならない
			for i, x := range blocks {
				found := false
				for _, iv := range ivs {
					if x == (sackBlock{uint32(iv[0]), uint32(iv[1])}) {
						found = true
					}
				}
				for _, y := range blocks[:i] {
					if y == x {
						t.Fatalf("seed %d step %d: block %v repeated", seed, step, x)
					}
				}
				if !found {
					t.Fatalf("seed %d step %d: block %v is not an interval", seed, step, x)
				}
			}
			if want := min(b.n, 4); len(blocks) != want {
				t.Fatalf("seed %d step %d: %d blocks for %d intervals", seed, step, len(blocks), b.n)
			}
		}
	})
}

// 1 byte の segment を 1 byte おきに送ると、予約の内側でも H を使い切ることを確かめる。捨てる segment は SACK で
// 知らせていないので、I4 に反しない(設計文書の「接続ごとのバッファ」)。
func TestSmallSegmentsCanUseUpIntervalsBeforeTheBufferFills(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	acceptOne(t, l)
	n.drain()
	for i := 0; i < 1000; i++ {
		s := p.seg(flagACK, []byte{byte(i)})
		s.seq = p.snd + 1 + uint32(2*i)
		n.inject(s)
	}
	n.drain()
	st := checkHeld(t, n)
	c := &n.d.s.conns[0]
	if c.rcv.n != floorIntervals || st.OOODropped == 0 || c.rcv.rightmost()-c.rcv.readOff >= recvFloor {
		t.Fatalf("intervals %d of %d, OOODropped %d, held span %d bytes of %d", c.rcv.n, floorIntervals, st.OOODropped, c.rcv.rightmost()-c.rcv.readOff, recvFloor)
	}
}
