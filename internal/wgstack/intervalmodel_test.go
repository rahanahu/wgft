package wgstack

import (
	"fmt"
	"math/rand/v2"
	"testing"
)

// 区間の treap を、整列した区間の list の模型と比べる試験。順序外と順序どおりの挿入、重複、窓の端、offset の
// 32 bit の巻き戻り、表の大きさの切り替え、表が満杯の場合を混ぜ、結果、区間、木と空きの list の形、SACK の
// block の規則を毎回比べる。

type rmIv struct{ s, e uint64 }

type rmModel struct {
	nxt   uint64
	iv    []rmIv
	limit int // table size
}

type rmRes struct {
	accepted                      int
	trimmed, dropped, ooo, filled bool
	advanced, duplicate           bool
	dupLo, dupHi                  uint64
}

func (m *rmModel) insert(off uint64, n int, lim uint64) rmRes {
	var res rmRes
	end := off + uint64(n)
	if end > lim {
		if off >= lim {
			res.trimmed = n > 0
			return res
		}
		end = lim
		res.trimmed = true
	}
	if off < m.nxt {
		if end <= m.nxt {
			res.duplicate = end > off
			res.dupLo, res.dupHi = off, end
			return res
		}
		res.dupLo, res.dupHi = off, m.nxt
		off = m.nxt
	}
	if end == off {
		return res
	}
	if off == m.nxt {
		res.accepted = int(end - off)
		res.advanced = true
		k := 0
		for k < len(m.iv) && m.iv[k].s <= end {
			if m.iv[k].s < end && res.dupHi <= res.dupLo {
				res.dupLo, res.dupHi = m.iv[k].s, min(end, m.iv[k].e)
			}
			end = max(end, m.iv[k].e)
			k++
		}
		if k > 0 {
			m.iv = append([]rmIv(nil), m.iv[k:]...)
			res.filled = true
		}
		m.nxt = end
		return res
	}
	i := 0
	for i < len(m.iv) && m.iv[i].e < off {
		i++
	}
	j := i
	for j < len(m.iv) && m.iv[j].s <= end {
		j++
	}
	if i == j {
		if len(m.iv) == m.limit {
			res.dropped = true
			return res
		}
		m.iv = append(m.iv[:i], append([]rmIv{{off, end}}, m.iv[i:]...)...)
	} else {
		if m.iv[i].s <= off && end <= m.iv[i].e && j == i+1 {
			res.duplicate = true
			res.dupLo, res.dupHi = off, end
			return res
		}
		if lo, hi := max(off, m.iv[i].s), min(end, m.iv[i].e); lo < hi && res.dupHi <= res.dupLo {
			res.dupLo, res.dupHi = lo, hi
		}
		ns, ne := min(off, m.iv[i].s), max(end, m.iv[j-1].e)
		m.iv = append(m.iv[:i], append([]rmIv{{ns, ne}}, m.iv[j:]...)...)
	}
	res.accepted = int(end - off)
	res.ooo = true
	return res
}

func pat(off uint64) byte { return byte(off*131 + off>>9) }

// checkTree verifies the treap invariants and returns the in-order intervals.
func checkTree(t *testing.T, b *recvBuf, ctx string) {
	t.Helper()
	seen := make(map[int16]bool)
	var prevEnd uint64
	first := true
	cnt := 0
	var held uint64
	var walk func(k int16, lo, hi uint64, maxPri uint32, depth int)
	walk = func(k int16, lo, hi uint64, maxPri uint32, depth int) {
		if k == 0 {
			return
		}
		if k < 1 || int(k) > int(b.used) || int(k) > len(b.iv) {
			t.Fatalf("%s: node %d out of range (used %d len %d)", ctx, k, b.used, len(b.iv))
		}
		if seen[k] {
			t.Fatalf("%s: node %d reached twice", ctx, k)
		}
		seen[k] = true
		x := b.node(k)
		if x.pri > maxPri {
			t.Fatalf("%s: heap order broken at %d", ctx, k)
		}
		s, e := b.kStart(k), b.kEnd(k)
		if s >= e || s < lo || e > hi {
			t.Fatalf("%s: BST order or bounds broken at %d: [%d,%d) not in [%d,%d)", ctx, k, s, e, lo, hi)
		}
		walk(x.l, lo, s, x.pri, depth+1)
		if !first && s <= prevEnd {
			t.Fatalf("%s: intervals overlap or touch: prev end %d, start %d", ctx, prevEnd, s)
		}
		if s <= b.nxtOff {
			t.Fatalf("%s: interval [%d,%d) at or below nxtOff %d", ctx, s, e, b.nxtOff)
		}
		first = false
		prevEnd = e
		cnt++
		held += e - s
		walk(x.r, e, hi, x.pri, depth+1)
	}
	walk(b.root, 0, ^uint64(0), ^uint32(0), 0)
	if cnt != b.n {
		t.Fatalf("%s: tree has %d nodes, n=%d", ctx, cnt, b.n)
	}
	if held != b.ooo {
		t.Fatalf("%s: intervals hold %d bytes, ooo=%d", ctx, held, b.ooo)
	}
	// free list
	nf := 0
	for k := b.free; k != 0; k = b.node(k).l {
		if seen[k] {
			t.Fatalf("%s: node %d both in tree and free list", ctx, k)
		}
		seen[k] = true
		nf++
		if nf > len(b.iv) {
			t.Fatalf("%s: free list loops", ctx)
		}
	}
	if nf+cnt != int(b.used) {
		t.Fatalf("%s: free %d + tree %d != used %d", ctx, nf, cnt, b.used)
	}
}

// treapModelSeeds は種の数。WGFT_WGSTACK_STREAM_SEEDS=full では 3000 にする。
func treapModelSeeds() int {
	if streamSeedsFull() {
		return 3000
	}
	return 30
}

var rvStats struct{ drops, merges, resizes, fills, blocks, deviate, deviateCap4 int }

func TestIntervalTreeAgainstModel(t *testing.T) {
	rvStats = struct{ drops, merges, resizes, fills, blocks, deviate, deviateCap4 int }{}
	for seed := 1; seed <= treapModelSeeds(); seed++ {
		runTreapModel(t, uint64(seed))
	}
	t.Logf("stats %+v", rvStats)
	// SACK の block が理想の順(新しく触れた順)からずれる割合。最近の区間の印は 4 つしかないので、ずれは 0 に
	// ならないが、古い印で枠を使わなければ数 % に留まる
	if rvStats.deviate*100 > rvStats.blocks*8 {
		t.Errorf("SACK blocks differ from the most-recent order in %d of %d options", rvStats.deviate, rvStats.blocks)
	}
}

func runTreapModel(t *testing.T, seed uint64) {
	rng := rand.New(rand.NewPCG(seed, seed*7+1))
	var pool chunkPool
	tables := []int{1, 2, 3, 5, 8, 16, floorIntervals}
	size := tables[rng.IntN(len(tables))]
	capb := uint64(boostSize)
	if rng.IntN(2) == 0 {
		capb = recvFloor
	}
	b := &recvBuf{r: ring{pool: &pool, cap: capb}, iv: make([]interval, size), seed: rng.Uint64()}
	m := &rmModel{limit: size}
	// big start offset to exercise the uint32 wrap of stored positions
	if rng.IntN(3) == 0 {
		st := uint64(1)<<32 - uint64(rng.IntN(200000))
		b.nxtOff, b.readOff = st, st
		m.nxt = st
	}
	span := uint64(64 + rng.IntN(4000))
	maxLen := 1 + rng.IntN(300)
	var touches []uint64
	lastTouch := int64(-1) // offset of the most recently accepted or duplicate OOO byte, or -1
	ops := 3000
	for op := 0; op < ops; op++ {
		ctx := fmt.Sprintf("seed %d op %d size %d", seed, op, size)
		limit := b.readOff + capb
		var off uint64
		switch r := rng.IntN(20); {
		case r == 0:
			off = b.nxtOff
		case r == 1 && b.nxtOff > 50:
			off = b.nxtOff - uint64(rng.IntN(50))
		case r == 2:
			off = limit - uint64(rng.IntN(30))
		case r == 3 && len(m.iv) > 0:
			// right at an interval edge
			x := m.iv[rng.IntN(len(m.iv))]
			if rng.IntN(2) == 0 {
				off = x.e
			} else {
				off = x.s - uint64(min(int(x.s-b.nxtOff), 1+rng.IntN(maxLen)))
			}
		default:
			off = b.nxtOff + 1 + uint64(rng.Int64N(int64(span)))
		}
		n := 1 + rng.IntN(maxLen)
		if rng.IntN(30) == 0 {
			n = 0
		}
		data := make([]byte, n)
		for i := range data {
			data[i] = pat(off + uint64(i))
		}
		want := m.insert(off, n, limit)
		got := b.insert(off, data, limit)
		g := rmRes(got)
		if g.dupHi <= g.dupLo {
			g.dupLo, g.dupHi = 0, 0
		}
		if want.dupHi <= want.dupLo {
			want.dupLo, want.dupHi = 0, 0
		}
		if g != want {
			t.Fatalf("%s: insert(%d,%d) lim %d nxt %d: got %+v want %+v", ctx, off, n, limit, b.nxtOff, g, want)
		}
		if b.nxtOff != m.nxt {
			t.Fatalf("%s: nxt %d want %d", ctx, b.nxtOff, m.nxt)
		}
		checkTree(t, b, ctx)
		ivs := b.intervals(nil)
		if len(ivs) != len(m.iv) {
			t.Fatalf("%s: %d intervals want %d", ctx, len(ivs), len(m.iv))
		}
		for i, x := range ivs {
			if x[0] != m.iv[i].s || x[1] != m.iv[i].e {
				t.Fatalf("%s: interval %d [%d,%d) want [%d,%d)", ctx, i, x[0], x[1], m.iv[i].s, m.iv[i].e)
			}
		}
		if got.dropped {
			rvStats.drops++
		}
		if got.filled {
			rvStats.fills++
		}
		if got.ooo && len(m.iv) < len(ivs)+0 {
			rvStats.merges++
		}
		if got.ooo || (got.duplicate && off > b.nxtOff) {
			touches = append(touches, off)
			lastTouch = int64(off)
		} else if got.advanced {
			// no requirement; an in-order segment may or may not leave lastTouch valid
			if lastTouch >= 0 && uint64(lastTouch) < b.nxtOff {
				lastTouch = -1
			}
		}
		// SACK blocks
		for _, capd := range []int{4, 3, 2, 1} {
			var dst [4]sackBlock
			const base = 1000
			blks := b.sackBlocks(dst[:0:capd], base)
			if len(blks) != min(len(m.iv), capd) {
				t.Fatalf("%s: %d blocks with cap %d and %d intervals", ctx, len(blks), capd, len(m.iv))
			}
			lefts := map[uint32]bool{}
			for _, bl := range blks {
				ok := false
				for _, x := range m.iv {
					if bl.left == base+uint32(x.s) && bl.right == base+uint32(x.e) {
						ok = true
					}
				}
				if !ok {
					t.Fatalf("%s: block %v is not an interval", ctx, bl)
				}
				if lefts[bl.left] {
					t.Fatalf("%s: repeated block %v", ctx, bl)
				}
				lefts[bl.left] = true
			}
			// ideal recency: newest touches first, mapped to their current interval, deduped
			var ideal []uint32
			idealSeen := map[uint64]bool{}
			for ti := len(touches) - 1; ti >= 0 && len(ideal) < capd; ti-- {
				for _, x := range m.iv {
					if x.s <= touches[ti] && touches[ti] < x.e && !idealSeen[x.s] {
						idealSeen[x.s] = true
						ideal = append(ideal, base+uint32(x.s))
					}
				}
			}
			for _, x := range m.iv {
				if len(ideal) >= capd {
					break
				}
				if !idealSeen[x.s] {
					idealSeen[x.s] = true
					ideal = append(ideal, base+uint32(x.s))
				}
			}
			rvStats.blocks++
			for bi := range blks {
				if blks[bi].left != ideal[bi] {
					rvStats.deviate++
					if capd == 4 {
						rvStats.deviateCap4++
						if rvStats.deviateCap4 <= 3 {
							t.Logf("%s: blocks %v ideal %v recent %v n %d last touches %v", ctx, blks, ideal, b.recent[:b.nrecent], len(m.iv), touches[max(0, len(touches)-6):])
						}
					}
					break
				}
			}
			if (got.ooo || (got.duplicate && off > b.nxtOff)) && len(blks) > 0 {
				f := blks[0]
				x := uint32(off) + base
				if !(seqLE(f.left, x) && seqLT(x, f.right)) {
					t.Fatalf("%s: first block %v does not hold the triggering offset %d", ctx, f, off)
				}
			}
		}
		// reads
		if rng.IntN(4) == 0 && b.unread() > 0 {
			k := 1 + rng.IntN(int(min(b.unread(), 2000)))
			dst := make([]byte, k)
			ro := b.readOff
			got := b.read(dst)
			for i := 0; i < got; i++ {
				if dst[i] != pat(ro+uint64(i)) {
					t.Fatalf("%s: read byte %d at %d is %d want %d", ctx, i, ro+uint64(i), dst[i], pat(ro+uint64(i)))
				}
			}
		}
		// resize like boost and demote
		if rng.IntN(200) == 0 {
			ns := tables[rng.IntN(len(tables))]
			ok := b.setIntervals(make([]interval, ns))
			if ok != (len(m.iv) <= ns) {
				t.Fatalf("%s: setIntervals(%d) = %v with %d intervals", ctx, ns, ok, len(m.iv))
			}
			if ok {
				rvStats.resizes++
				size = ns
				m.limit = ns
			}
			checkTree(t, b, ctx+" after resize")
		}
	}
	b.r.release()
}
