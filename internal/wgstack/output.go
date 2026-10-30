package wgstack

import "sync"

// 出力の組(設計文書の「出力」)。接続の組と行の組は packet を待ち行列に積まず、送るものがある枠と行の
// 番号を順番の list に並べ、Read の時に先頭の 1 つが packet を 1 つ作る。list の節は固定の配列に置くので、
// 出力の保持は接続と行の数で決まる。制御の組だけが、MTU の大きさの枠を固定の数だけ持つ輪に packet を
// 積む。UDP の組は次の段階で加える。Read は送るもののある組の間で、MTU 1 つ分ずつの byte の
// deficit round robin で組を選ぶ。

const (
	classConn = iota // 接続の枠の segment
	classRow         // 握手の途中の行と TIME_WAIT の行の segment
	classUDP         // UDP の datagram(次の段階)
	classCtl         // 制御の輪
	numClasses
)

// dlist は固定の配列の上の両方向の list。節 i の印 in[i] が list に入っているかを示す。
type dlist struct {
	head, tail int32
	next, prev []int32
	in         []bool
	n          int
}

func newDlist(nodes int) dlist {
	return dlist{head: -1, tail: -1, next: make([]int32, nodes), prev: make([]int32, nodes), in: make([]bool, nodes)}
}

func (l *dlist) pushBack(i int32) {
	if l.in[i] {
		return
	}
	l.in[i] = true
	l.next[i], l.prev[i] = -1, l.tail
	if l.tail >= 0 {
		l.next[l.tail] = i
	} else {
		l.head = i
	}
	l.tail = i
	l.n++
}

func (l *dlist) remove(i int32) {
	if !l.in[i] {
		return
	}
	l.in[i] = false
	p, x := l.prev[i], l.next[i]
	if p >= 0 {
		l.next[p] = x
	} else {
		l.head = x
	}
	if x >= 0 {
		l.prev[x] = p
	} else {
		l.tail = p
	}
	l.n--
}

func (l *dlist) popFront() int32 {
	i := l.head
	if i >= 0 {
		l.remove(i)
	}
	return i
}

// ctlRing は制御の出力の輪。枠の数と大きさは作成の時に固定し、満杯なら新しい packet を捨てる。
type ctlRing struct {
	buf  []byte // slots * size
	lens []int
	size int
	head int
	n    int
}

func newCtlRing(slots, size int) ctlRing {
	return ctlRing{buf: make([]byte, slots*size), lens: make([]int, slots), size: size}
}

// slot は次に積む枠を返す。満杯なら nil。
func (r *ctlRing) slot() []byte {
	if r.n == len(r.lens) {
		return nil
	}
	i := (r.head + r.n) % len(r.lens)
	return r.buf[i*r.size : (i+1)*r.size]
}

func (r *ctlRing) commit(n int) {
	i := (r.head + r.n) % len(r.lens)
	r.lens[i] = n
	r.n++
}

func (r *ctlRing) pop(dst []byte) int {
	i := r.head
	n := copy(dst, r.buf[i*r.size:i*r.size+r.lens[i]])
	r.head = (r.head + 1) % len(r.lens)
	r.n--
	return n
}

// output は出力の組の状態。mu は末端の錠で、接続の錠と表の錠の後に取り、持ったまま他の錠を取らない。
type output struct {
	mu    sync.Mutex
	conns dlist // 送るもののある接続の枠
	rows  dlist // 送るもののある行。握手の途中の行は 0 から、TIME_WAIT の行は synRows から
	ctl   ctlRing
	// udpQueued は UDP の送信の FIFO にある datagram の数。FIFO は UDP の錠が守る
	udpQueued int
	// deficit round robin の状態。Read の錠(Device.readMu)の中でだけ使う
	cur     int
	deficit [numClasses]int
	notify  chan struct{} // 送るものができたときに知らせる(容量 1)
}

func (o *output) kick() {
	select {
	case o.notify <- struct{}{}:
	default:
	}
}

// queueConn は接続の枠 id を接続の組の list の末尾に入れる。既に入っていれば何もしない。
func (o *output) queueConn(id int32) {
	o.mu.Lock()
	was := o.conns.in[id]
	o.conns.pushBack(id)
	o.mu.Unlock()
	if !was {
		o.kick()
	}
}

func (o *output) unqueueConn(id int32) {
	o.mu.Lock()
	o.conns.remove(id)
	o.mu.Unlock()
}

func (o *output) queueRow(id int32) {
	o.mu.Lock()
	was := o.rows.in[id]
	o.rows.pushBack(id)
	o.mu.Unlock()
	if !was {
		o.kick()
	}
}

func (o *output) unqueueRow(id int32) {
	o.mu.Lock()
	o.rows.remove(id)
	o.mu.Unlock()
}

// pushCtl は build が枠に書いた packet を制御の輪に積む。build は書いた長さを返し、0 なら積まない。
// 輪が満杯なら積まずに偽を返す。
func (o *output) pushCtl(build func(b []byte) int) bool {
	o.mu.Lock()
	b := o.ctl.slot()
	if b == nil {
		o.mu.Unlock()
		return false
	}
	n := build(b)
	if n > 0 {
		o.ctl.commit(n)
	}
	o.mu.Unlock()
	if n > 0 {
		o.kick()
	}
	return true
}

func (o *output) classEmpty(c int) bool {
	switch c {
	case classConn:
		return o.conns.n == 0
	case classRow:
		return o.rows.n == 0
	case classCtl:
		return o.ctl.n == 0
	case classUDP:
		return o.udpQueued == 0
	}
	return true
}
