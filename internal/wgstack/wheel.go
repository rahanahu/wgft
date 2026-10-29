package wgstack

import (
	"math/bits"
	"sync"
)

// wheel はタイマーの輪(階層の timing wheel)。節は接続の枠に固定で埋め込んだタイマーの数だけ作成の時に
// 確保し、張り直すときは輪の中で動かすだけで確保しない(設計文書の「タイマー」)。時刻の単位は 1 ms の
// tick で、3 段の 64 個の桶が 64 ms、4.096 秒、262 秒を覆う。それより先の期限は最上段の桶 0 に置き、
// 次に最上段を一周したときに置き直す。
//
// 段 L の桶 b は、今の tick T と同じ 64^(L+1) ms の窓の中の期限 t のうち、(t >> 6L) & 63 == b のものを
// 持つ。T が窓の境目を越えるとき、上の段の桶を下の段へ置き直す。錠は末端の錠で、持ったまま他の錠を
// 取らない。
type wheel struct {
	mu    sync.Mutex
	tick  int64 // 処理を終えた tick
	dl    []int64
	next  []int32
	prev  []int32
	where []int16 // 節の桶(段 * 64 + 桶)。-1 は輪の外
	heads [wheelLevels * 64]int32
	bm    [wheelLevels]uint64
	count int
}

const (
	wheelLevels = 3
	tickNs      = 1_000_000
	noTick      = int64(1) << 62
)

func newWheel(nodes int) *wheel {
	w := &wheel{
		dl:    make([]int64, nodes),
		next:  make([]int32, nodes),
		prev:  make([]int32, nodes),
		where: make([]int16, nodes),
	}
	for i := range w.where {
		w.where[i] = -1
	}
	for i := range w.heads {
		w.heads[i] = -1
	}
	return w
}

// toTick は ns の期限を、早く発火しないように切り上げた tick にする。
func toTick(ns int64) int64 { return (ns + tickNs - 1) / tickNs }

func (w *wheel) unlink(n int32) {
	b := w.where[n]
	if b < 0 {
		return
	}
	p, x := w.prev[n], w.next[n]
	if p >= 0 {
		w.next[p] = x
	} else {
		w.heads[b] = x
		if x < 0 {
			w.bm[b/64] &^= 1 << (b % 64)
		}
	}
	if x >= 0 {
		w.prev[x] = p
	}
	w.where[n] = -1
	w.count--
}

func (w *wheel) link(n int32, b int16) {
	h := w.heads[b]
	w.next[n], w.prev[n] = h, -1
	if h >= 0 {
		w.prev[h] = n
	}
	w.heads[b] = n
	w.bm[b/64] |= 1 << (b % 64)
	w.where[n] = b
	w.count++
}

// place は期限 t の節を桶に入れる。t は今の tick より後であること。
func (w *wheel) place(n int32, t int64) {
	T := w.tick
	switch {
	case t>>6 == T>>6:
		w.link(n, int16(t&63))
	case t>>12 == T>>12:
		w.link(n, int16(64+(t>>6)&63))
	case t>>18 == T>>18:
		w.link(n, int16(128+(t>>12)&63))
	default:
		w.link(n, 128) // 次の最上段の一周で置き直す
	}
}

// set は節 n の期限を ns にする。輪に入っていれば動かす。
func (w *wheel) set(n int32, ns int64) {
	t := toTick(ns)
	w.mu.Lock()
	w.unlink(n)
	t = max(t, w.tick+1)
	w.dl[n] = t
	w.place(n, t)
	w.mu.Unlock()
}

// cancel は節 n を輪から外す。
func (w *wheel) cancel(n int32) {
	w.mu.Lock()
	w.unlink(n)
	w.mu.Unlock()
}

// nextBit は bm の from 以上の最も小さい立った bit を返す。無ければ -1 を返す。
func nextBit(bm uint64, from int64) int64 {
	if from >= 64 {
		return -1
	}
	m := bm >> uint(from)
	if m == 0 {
		return -1
	}
	return from + int64(bits.TrailingZeros64(m))
}

// drain は桶 b の節をすべて外し、期限の来た節を fired に足し、残りを置き直す。
// 桶の list を先に切り離すので、同じ桶へ置き直す節(最上段の桶 0)で繰り返しが終わらなくなることはない。
func (w *wheel) drain(b int16, fired []int32) []int32 {
	n := w.heads[b]
	w.heads[b] = -1
	w.bm[b/64] &^= 1 << (b % 64)
	for n >= 0 {
		next := w.next[n]
		w.where[n] = -1
		w.count--
		if w.dl[n] <= w.tick {
			fired = append(fired, n)
		} else {
			w.place(n, w.dl[n])
		}
		n = next
	}
	return fired
}

// advance は時刻を ns まで進め、期限の来た節を外して fired に足して返す。
func (w *wheel) advance(ns int64, fired []int32) []int32 {
	now := ns / tickNs
	w.mu.Lock()
	defer w.mu.Unlock()
	for w.tick < now {
		if w.count == 0 {
			w.tick = now
			break
		}
		T := w.tick
		if b := nextBit(w.bm[0], T&63+1); b >= 0 {
			t := T&^63 | b
			if t > now {
				w.tick = now
				break
			}
			w.tick = t
			fired = w.drain(int16(b), fired)
			continue
		}
		// 下の段の今の窓は空。次に中身のある段 1 の桶の窓か、段 2 の境目へ飛ぶ
		var target int64
		if b1 := nextBit(w.bm[1], (T>>6)&63+1); b1 >= 0 {
			target = T&^4095 | b1<<6
		} else {
			target = T | 4095 + 1
		}
		if target > now {
			w.tick = now
			break
		}
		w.tick = target
		if target&4095 == 0 {
			fired = w.drain(int16(128+(target>>12)&63), fired)
		}
		fired = w.drain(int16(64+(target>>6)&63), fired)
		fired = w.drain(int16(target&63), fired)
	}
	return fired
}

// nextTick は次に節の期限が来うる最も早い tick を返す。節が無ければ noTick を返す。段 1 と段 2 の
// 値は下限で、その時刻に置き直した後に改めて求める。
func (w *wheel) nextTick() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.count == 0 {
		return noTick
	}
	T := w.tick
	if b := nextBit(w.bm[0], T&63+1); b >= 0 {
		return T&^63 | b
	}
	if b := nextBit(w.bm[1], (T>>6)&63+1); b >= 0 {
		return T&^4095 | b<<6
	}
	if b := nextBit(w.bm[2], (T>>12)&63+1); b >= 0 {
		return T&^262143 | b<<12
	}
	return T | 262143 + 1
}
