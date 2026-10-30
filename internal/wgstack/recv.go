package wgstack

// recvBuf は受信のバッファ。順序どおりの未読のデータ [readOff, nxtOff) と順序外のデータを同じ輪の
// 位置に置き、順序外の届いた範囲を区間の表で持つ(設計文書の「接続ごとのバッファ」)。区間の数の上限は
// 受信の予約から決め(floorIntervals と boostIntervals)、表は予約の段ごとの固定の配列である。offset は
// 接続の受信の始め(相手の ISN + 1)から数える。
//
// 区間の表は、固定の配列を節の置き場にした treap である。区間は重ならず接しないので、始まりの順と終わりの
// 順は同じで、どちらでも探せる。segment 1 つの手間は、区間の数 H の対数と、その segment がまとめる区間の数に
// 比例する。優先度は接続ごとの秘密の種から作るので、相手は木の形を選べない。SACK の block は最近触れた区間
// の始まりを sackRecent 個まで覚えて選ぶ(RFC 2018 4 節)。
type recvBuf struct {
	r       ring
	readOff uint64 // 最も古い未読の byte
	nxtOff  uint64 // 次に順序どおりに受ける byte(RCV.NXT)
	iv      []interval
	n       int    // 使っている区間の数
	root    int16  // 木の根の節。節の番号は iv の位置 + 1 で、0 は無し
	free    int16  // 空きの節の list の頭
	used    int16  // iv のうち一度でも節に使った数
	seed    uint64 // 優先度の種(接続ごとの秘密)
	ctr     uint64
	recent  [sackRecent]uint32 // 最近触れた区間の始まり(offset の下位 32 bit)。新しい順
	nrecent int
}

// sackRecent は SACK の block を選ぶために覚える最近の区間の数。block は高々 4 つである。
const sackRecent = 4

// interval は順序外の 1 つの区間 [start, end) と木の節。位置は offset の下位 32 bit で持つ。区間はどれも
// nxtOff から受信の予約(4 MiB 以下)の内側にあるので、nxtOff から元の offset を復元できる。空きの節では l が
// 次の空きの節である。
type interval struct {
	start, end uint32
	l, r       int16
	pri        uint32
}

// 節の番号は int16 に収める。
const _ = uint(32767 - boostIntervals)

func (b *recvBuf) full(x uint32) uint64   { return b.nxtOff + uint64(x-uint32(b.nxtOff)) }
func (b *recvBuf) node(k int16) *interval { return &b.iv[k-1] }
func (b *recvBuf) kStart(k int16) uint64  { return b.full(b.node(k).start) }
func (b *recvBuf) kEnd(k int16) uint64    { return b.full(b.node(k).end) }

func (b *recvBuf) unread() uint64 { return b.nxtOff - b.readOff }

// rightmost は保持する最も右の byte の次の offset(順序外のデータを含む)。
func (b *recvBuf) rightmost() uint64 {
	if b.root != 0 {
		return max(b.nxtOff, b.kEnd(b.lastNode(b.root)))
	}
	return b.nxtOff
}

// empty は、順序どおりの未読のデータも順序外のデータも持たないかを返す。
func (b *recvBuf) empty() bool { return b.nxtOff == b.readOff && b.n == 0 }

// setIntervals は区間の表を iv に移し、移せたかを返す。使っている区間が iv に入らなければ、区間を切り捨てずに
// 今の表を持ち続けて偽を返す。
func (b *recvBuf) setIntervals(iv []interval) bool {
	if b.n > len(iv) {
		return false
	}
	ivs := b.intervals(make([][2]uint64, 0, b.n))
	b.iv, b.root, b.free, b.used = iv, 0, 0, 0
	for _, x := range ivs {
		b.root = b.merge(b.root, b.alloc(x[0], x[1]))
	}
	return true
}

// alloc は節を 1 つ取り、区間 [s, e) を入れて返す。空きが無ければ 0 を返す。
func (b *recvBuf) alloc(s, e uint64) int16 {
	k := b.free
	switch {
	case k != 0:
		b.free = b.node(k).l
	case int(b.used) < len(b.iv):
		b.used++
		k = b.used
	default:
		return 0
	}
	b.ctr++
	*b.node(k) = interval{start: uint32(s), end: uint32(e), pri: uint32(splitmix64(b.seed + b.ctr))}
	return k
}

// splitmix64 は種から優先度を作る混ぜ合わせ。
func splitmix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// release は木 t の節をすべて空きに返し、その数を返す。
func (b *recvBuf) release(t int16) int {
	if t == 0 {
		return 0
	}
	x := b.node(t)
	l, r := x.l, x.r
	x.l, x.r = b.free, 0
	b.free = t
	return 1 + b.release(l) + b.release(r)
}

// merge は、a のどの区間も c のどの区間より前にある 2 つの木をつなぐ。
func (b *recvBuf) merge(a, c int16) int16 {
	if a == 0 {
		return c
	}
	if c == 0 {
		return a
	}
	if x, y := b.node(a), b.node(c); x.pri >= y.pri {
		x.r = b.merge(x.r, c)
		return a
	} else {
		y.l = b.merge(a, y.l)
		return c
	}
}

// splitEndBefore は木 t を、終わりが off より前の区間と残りに分ける。
func (b *recvBuf) splitEndBefore(t int16, off uint64) (int16, int16) {
	if t == 0 {
		return 0, 0
	}
	x := b.node(t)
	if b.full(x.end) < off {
		l, r := b.splitEndBefore(x.r, off)
		x.r = l
		return t, r
	}
	l, r := b.splitEndBefore(x.l, off)
	x.l = r
	return l, t
}

// splitStartUpTo は木 t を、始まりが end 以下の区間と残りに分ける。
func (b *recvBuf) splitStartUpTo(t int16, end uint64) (int16, int16) {
	if t == 0 {
		return 0, 0
	}
	x := b.node(t)
	if b.full(x.start) <= end {
		l, r := b.splitStartUpTo(x.r, end)
		x.r = l
		return t, r
	}
	l, r := b.splitStartUpTo(x.l, end)
	x.l = r
	return l, t
}

func (b *recvBuf) firstNode(t int16) int16 {
	for b.node(t).l != 0 {
		t = b.node(t).l
	}
	return t
}

func (b *recvBuf) lastNode(t int16) int16 {
	for b.node(t).r != 0 {
		t = b.node(t).r
	}
	return t
}

// containing は offset x を含む区間の節を返す。無ければ 0 を返す。
func (b *recvBuf) containing(x uint64) int16 {
	t := b.root
	for t != 0 {
		switch {
		case x < b.kStart(t):
			t = b.node(t).l
		case x >= b.kEnd(t):
			t = b.node(t).r
		default:
			return t
		}
	}
	return 0
}

// touchRecent は始まりが s の区間を最も新しく触れた区間として覚える。
func (b *recvBuf) touchRecent(s uint64) {
	v := uint32(s)
	k := 0
	for k < b.nrecent-1 && b.recent[k] != v {
		k++
	}
	if b.nrecent < sackRecent && (b.nrecent == 0 || b.recent[k] != v) {
		k = b.nrecent
		b.nrecent++
	}
	copy(b.recent[1:k+1], b.recent[:k])
	b.recent[0] = v
}

// intervals は区間を始まりの順に dst に足して返す。
func (b *recvBuf) intervals(dst [][2]uint64) [][2]uint64 { return b.walk(b.root, dst, -1) }

// walk は木 t の区間を順に dst に足す。limit が 0 以上なら、dst がその長さになったら止める。
func (b *recvBuf) walk(t int16, dst [][2]uint64, limit int) [][2]uint64 {
	if t == 0 || (limit >= 0 && len(dst) >= limit) {
		return dst
	}
	x := b.node(t)
	dst = b.walk(x.l, dst, limit)
	if limit < 0 || len(dst) < limit {
		dst = append(dst, [2]uint64{b.full(x.start), b.full(x.end)})
	}
	return b.walk(x.r, dst, limit)
}

// insertResult は insert の結果。
type insertResult struct {
	accepted  int  // 輪に入れた byte
	trimmed   bool // 上限の外の分を捨てた
	dropped   bool // H を超える区間を作るので segment を捨てた
	ooo       bool // 順序外のデータを入れた
	filled    bool // 順序外の区間を順序どおりの範囲に取り込んだ
	advanced  bool // nxtOff が進んだ
	duplicate bool // 中身がすべて既に届いていた
	// dupLo と dupHi は、既に届いていた部分の最初の範囲(offset)。dupHi > dupLo のときだけ意味を持つ。D-SACK
	// の block にする(RFC 2883、Linux の tcp_dsack_set)
	dupLo, dupHi uint64
}

// insert は offset off からの data を入れる。limit を超える分は捨てる。limit は広告した窓の右端と
// readOff + cap の小さい方である。順序外のデータで新しい区間が要り、区間が H 個あるときは、
// segment 全体を捨てる。既存の区間を伸ばすか穴を埋める segment は受け入れる。
func (b *recvBuf) insert(off uint64, data []byte, limit uint64) insertResult {
	var res insertResult
	end := off + uint64(len(data))
	if end > limit {
		if off >= limit {
			res.trimmed = len(data) > 0
			return res
		}
		data = data[:limit-off]
		end = limit
		res.trimmed = true
	}
	if off < b.nxtOff {
		if end <= b.nxtOff {
			res.duplicate = len(data) > 0
			res.dupLo, res.dupHi = off, end
			return res
		}
		res.dupLo, res.dupHi = off, b.nxtOff // 前半だけが重複
		data = data[b.nxtOff-off:]
		off = b.nxtOff
	}
	if len(data) == 0 {
		return res
	}
	if off == b.nxtOff {
		b.r.write(off, data)
		res.accepted = len(data)
		res.advanced = true
		// 届いた順序外の区間を取り込む。区間は接しないので、end 以下で始まる区間をまとめて外せばよい。区間の
		// 位置は nxtOff を動かす前の値で復元する
		m, rest := b.splitStartUpTo(b.root, end)
		if m != 0 {
			f := b.firstNode(m)
			if st, en := b.kStart(f), b.kEnd(f); st < end && res.dupHi <= res.dupLo {
				res.dupLo, res.dupHi = st, min(end, en) // 届いていた区間と重なる部分
			}
			end = max(end, b.kEnd(b.lastNode(m)))
			b.n -= b.release(m)
			res.filled = true
		}
		b.root = rest
		b.nxtOff = end
		return res
	}
	// 順序外:重なるか接する区間を木から切り出す
	l, rest := b.splitEndBefore(b.root, off)
	m, r := b.splitStartUpTo(rest, end)
	if m == 0 {
		k := b.alloc(off, end)
		if k == 0 {
			b.root = b.merge(l, r)
			res.dropped = true
			return res
		}
		b.n++
		b.root = b.merge(b.merge(l, k), r)
		b.touchRecent(off)
	} else {
		f, g := b.firstNode(m), b.lastNode(m)
		if f == g && b.kStart(f) <= off && end <= b.kEnd(f) {
			// すべて既に届いている。RFC 2018 の順のために最近の印だけ付け直す
			b.root = b.merge(b.merge(l, m), r)
			b.touchRecent(b.kStart(f))
			res.duplicate = true
			res.dupLo, res.dupHi = off, end
			return res
		}
		if lo, hi := max(off, b.kStart(f)), min(end, b.kEnd(f)); lo < hi && res.dupHi <= res.dupLo {
			res.dupLo, res.dupHi = lo, hi // 既存の区間と重なる部分
		}
		ns, ne := min(off, b.kStart(f)), max(end, b.kEnd(g))
		b.n -= b.release(m)
		k := b.alloc(ns, ne) // 返したばかりの節があるので取れる
		b.n++
		b.root = b.merge(b.merge(l, k), r)
		b.touchRecent(ns)
	}
	b.r.write(off, data)
	res.accepted = len(data)
	res.ooo = true
	return res
}

// read は未読のデータを dst に写して読んだ分を外し、写した数を返す。
func (b *recvBuf) read(dst []byte) int {
	n := int(min(uint64(len(dst)), b.unread()))
	if n == 0 {
		return 0
	}
	b.r.read(b.readOff, dst[:n])
	old := b.readOff
	b.readOff += uint64(n)
	b.r.trim(old, b.readOff, b.rightmost())
	return n
}

// sackBlocks は、最も新しく触れた区間を先頭に、区間を最大 cap(dst) 個の SACK の block にする(RFC 2018 4 節)。
// 最近触れた区間で足りなければ、始まりの順に残りの区間で埋める。base は offset 0 のシーケンス番号である。
func (b *recvBuf) sackBlocks(dst []sackBlock, base uint32) []sackBlock {
	out := dst[:0]
	if b.n == 0 || cap(dst) == 0 {
		return out
	}
	var seen [sackRecent]int16
	ns := 0
	has := func(k int16) bool {
		for _, x := range seen[:ns] {
			if x == k {
				return true
			}
		}
		return false
	}
	for i := 0; i < b.nrecent && len(out) < cap(dst); i++ {
		k := b.containing(b.full(b.recent[i]))
		if k == 0 || has(k) {
			continue
		}
		seen[ns] = k
		ns++
		out = append(out, sackBlock{base + uint32(b.kStart(k)), base + uint32(b.kEnd(k))})
	}
	if len(out) < cap(dst) && len(out) < b.n {
		var buf [2 * sackRecent][2]uint64
		for _, x := range b.walk(b.root, buf[:0], cap(dst)+ns) {
			if len(out) == cap(dst) {
				break
			}
			if b.chosen(out, base, x) {
				continue
			}
			out = append(out, sackBlock{base + uint32(x[0]), base + uint32(x[1])})
		}
	}
	return out
}

// chosen は区間 x が既に block に選ばれているかを返す。
func (b *recvBuf) chosen(out []sackBlock, base uint32, x [2]uint64) bool {
	for _, o := range out {
		if o.left == base+uint32(x[0]) {
			return true
		}
	}
	return false
}

// written は、輪の中身を移す時の書いた範囲(未読の範囲と順序外の区間)を返す。
func (b *recvBuf) written() [][2]uint64 {
	w := make([][2]uint64, 0, 1+b.n)
	if b.nxtOff > b.readOff {
		w = append(w, [2]uint64{b.readOff, b.nxtOff})
	}
	return b.intervals(w)
}
