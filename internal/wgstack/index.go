package wgstack

// シーケンス番号の比較(RFC 9293 3.4)。
func seqLT(a, b uint32) bool { return int32(a-b) < 0 }
func seqLE(a, b uint32) bool { return int32(a-b) <= 0 }
func seqGT(a, b uint32) bool { return int32(a-b) > 0 }
func seqGE(a, b uint32) bool { return int32(a-b) >= 0 }

// seqMin は a と b の前の方を返す。
func seqMin(a, b uint32) uint32 {
	if seqLT(a, b) {
		return a
	}
	return b
}

// seqMax は a と b の後ろの方を返す。
func seqMax(a, b uint32) uint32 {
	if seqGT(a, b) {
		return a
	}
	return b
}

// index は 4 つ組から行の番号を引く、開番地法(線形探索)の固定の大きさの hash の表。削除は後ろの
// 項目を前へ詰める(backward-shift deletion)ので、墓標を持たず、探索の長さが削除で伸びない。
// 容量は作成の時に決め、行の数の 2 倍以上の 2 のべき乗にする。hash は作成の時の乱数で鍵を付ける。
// 錠は呼び出し側が持つ(Device の表の錠)。
type index struct {
	key  sipKey
	mask uint32
	ents []indexEnt
}

type indexEnt struct {
	tup  tuple
	hash uint32
	id   int32 // 行の番号 + 1。0 は空き
	gen  uint32
}

func newIndex(rows int, key sipKey) index {
	n := 1
	for n < 2*rows {
		n <<= 1
	}
	return index{key: key, mask: uint32(n - 1), ents: make([]indexEnt, n)}
}

func (x *index) hash(t tuple) uint32 { return uint32(x.key.hashTuple(t)) }

// find は t の行の番号と、入れた時の世代を返す。無ければ -1 を返す。
func (x *index) find(t tuple) (int32, uint32) {
	h := x.hash(t)
	for i := h & x.mask; ; i = (i + 1) & x.mask {
		e := &x.ents[i]
		if e.id == 0 {
			return -1, 0
		}
		if e.hash == h && e.tup == t {
			return e.id - 1, e.gen
		}
	}
}

// insert は t を行 id として入れる。同じ t が既にあれば入れ替える。表は行の数の 2 倍以上の
// 容量を持つので満杯にならない。
func (x *index) insert(t tuple, id int32, gen uint32) {
	h := x.hash(t)
	for i := h & x.mask; ; i = (i + 1) & x.mask {
		e := &x.ents[i]
		if e.id == 0 || (e.hash == h && e.tup == t) {
			*e = indexEnt{tup: t, hash: h, id: id + 1, gen: gen}
			return
		}
	}
}

// remove は t を外し、外したかを返す。外した位置の後ろに続く項目のうち、本来の位置が外した位置か
// それより前にあるものを順に詰める。
func (x *index) remove(t tuple) bool {
	h := x.hash(t)
	i := h & x.mask
	for {
		e := &x.ents[i]
		if e.id == 0 {
			return false
		}
		if e.hash == h && e.tup == t {
			break
		}
		i = (i + 1) & x.mask
	}
	for {
		x.ents[i] = indexEnt{}
		j := i
		for {
			j = (j + 1) & x.mask
			e := &x.ents[j]
			if e.id == 0 {
				return true
			}
			home := e.hash & x.mask
			// home が (i, j] の巡回の区間に入るなら、e は i へ動かせない
			if (j > i && (home <= i || home > j)) || (j < i && home <= i && home > j) {
				x.ents[i] = *e
				i = j
				break
			}
		}
	}
}
