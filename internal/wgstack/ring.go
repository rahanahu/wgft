package wgstack

import "sync"

// chunk はバッファの中身の 16 KiB。
type chunk [chunkSize]byte

// chunkPool は Device の chunk の置き場。予約の内側で確保した chunk を返すと、上限の数まで次の
// 確保に使い回す。上限を超えて返った chunk は GC に任せる。置き場の chunk はどの予約にも数えず、
// 上限の分を M_fix に数える。held は輪が今持つ chunk の数である。
type chunkPool struct {
	mu     sync.Mutex
	free   []*chunk
	held   int64
	closed bool // Device を閉じた後は置き場に残さない
}

const chunkPoolKeep = 64 // 置き場に残す chunk の上限(1 MiB)

func (p *chunkPool) get() *chunk {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.held++
	if n := len(p.free); n > 0 {
		c := p.free[n-1]
		p.free[n-1] = nil
		p.free = p.free[:n-1]
		return c
	}
	return new(chunk)
}

func (p *chunkPool) put(c *chunk) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.held--
	if !p.closed && len(p.free) < chunkPoolKeep {
		p.free = append(p.free, c)
	}
}

func (p *chunkPool) heldChunks() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.held
}

// ring は予約した容量の byte の輪。位置は接続の始めから数える 64 bit の offset で、offset o の
// byte は輪の o mod cap に置く。cap は floor か boost の大きさ(どちらも chunk の倍数の 2 のべき乗)
// で、chunk は書く時に確保する。生きている範囲 [lo, hi) は cap を超えない。生きている範囲に掛からない
// chunk は返すので、輪が持つ chunk は予約の cap を超えない。
type ring struct {
	pool   *chunkPool
	cap    uint64
	chunks [boostSize / chunkSize]*chunk
}

func (r *ring) slots() uint64 { return r.cap >> chunkShift }

func (r *ring) slot(off uint64) (*chunk, uint64) {
	p := off & (r.cap - 1)
	return r.chunks[p>>chunkShift], p & (chunkSize - 1)
}

// write は data を offset off から書く。必要な chunk はここで確保する。
func (r *ring) write(off uint64, data []byte) {
	for len(data) > 0 {
		p := off & (r.cap - 1)
		i := p >> chunkShift
		if r.chunks[i] == nil {
			r.chunks[i] = r.pool.get()
		}
		n := copy(r.chunks[i][p&(chunkSize-1):], data)
		data = data[n:]
		off += uint64(n)
	}
}

// read は offset off からの byte を dst に写す。範囲は書いた byte の内側であること。
func (r *ring) read(off uint64, dst []byte) {
	for len(dst) > 0 {
		c, p := r.slot(off)
		var n int
		if c == nil {
			// 書いていない位置(順序外の穴)は読まない呼び出し側の約束だが、守りとして 0 を返す
			n = min(len(dst), int(chunkSize-p))
			clear(dst[:n])
		} else {
			n = copy(dst, c[p:])
		}
		dst = dst[n:]
		off += uint64(n)
	}
}

// live は、生きている範囲 [lo, hi) が輪の位置 i の chunk に掛かるかを返す。
func (r *ring) live(i, lo, hi uint64) bool {
	if hi <= lo {
		return false
	}
	n := r.slots()
	a0, a1 := lo>>chunkShift, (hi-1)>>chunkShift
	if a1-a0+1 >= n {
		return true
	}
	return (i+n-a0%n)%n <= a1-a0
}

// trim は、生きている範囲が [oldLo, hi) から [lo, hi) に縮んだ後、どこにも掛からなくなった chunk を返す。
func (r *ring) trim(oldLo, lo, hi uint64) {
	if lo <= oldLo {
		return
	}
	n := r.slots()
	first, last := oldLo>>chunkShift, (lo-1)>>chunkShift
	if last-first+1 >= n {
		first, last = 0, n-1
	}
	for a := first; a <= last; a++ {
		i := a % n
		if r.chunks[i] != nil && !r.live(i, lo, hi) {
			r.pool.put(r.chunks[i])
			r.chunks[i] = nil
		}
	}
}

// retain は、生きている範囲 [lo, hi) に掛からない chunk をすべて返す。
func (r *ring) retain(lo, hi uint64) {
	for i := range r.slots() {
		if r.chunks[i] != nil && !r.live(i, lo, hi) {
			r.pool.put(r.chunks[i])
			r.chunks[i] = nil
		}
	}
}

// release はすべての chunk を返す。
func (r *ring) release() {
	for i, c := range r.chunks {
		if c != nil {
			r.pool.put(c)
			r.chunks[i] = nil
		}
	}
}

// resize は cap を newCap に変え、[lo, hi) の中身を新しい位置へ移す。written は移す範囲のうち
// 書いた byte の区間(受信の輪は穴を持つ)。呼び出し側は hi-lo <= newCap を保証する。移す間は、
// 新旧の chunk を合わせて生きている範囲の 2 倍まで持つ。
func (r *ring) resize(newCap uint64, written [][2]uint64) {
	if newCap == r.cap {
		return
	}
	old := *r
	r.cap = newCap
	r.chunks = [len(r.chunks)]*chunk{}
	var buf [1024]byte
	for _, w := range written {
		for off := w[0]; off < w[1]; {
			n := min(uint64(len(buf)), w[1]-off)
			old.read(off, buf[:n])
			r.write(off, buf[:n])
			off += n
		}
	}
	old.release()
}

func (r *ring) heldChunks() int {
	n := 0
	for _, c := range r.chunks {
		if c != nil {
			n++
		}
	}
	return n
}
