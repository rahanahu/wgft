package wgstack

// recvBuf は受信のバッファ。順序どおりの未読のデータ [readOff, nxtOff) と順序外のデータを同じ輪の
// 位置に置き、順序外の届いた範囲を区間の表で持つ(設計文書の「接続ごとのバッファ」)。区間の数の上限は
// 受信の予約から決め(floorIntervals と boostIntervals)、表は予約の段ごとの固定の配列である。offset は
// 接続の受信の始め(相手の ISN + 1)から数える。
type recvBuf struct {
	r       ring
	readOff uint64 // 最も古い未読の byte
	nxtOff  uint64 // 次に順序どおりに受ける byte(RCV.NXT)
	iv      []interval
	n       int    // 使っている区間の数。iv[:n] は start の順
	touch   uint32 // 区間を最後に伸ばした順を数える
}

// interval は順序外の 1 つの区間 [start, end)。位置は offset の下位 32 bit で持つ。区間はどれも nxtOff
// から受信の予約(4 MiB 以下)の内側にあるので、nxtOff から元の offset を復元できる。touched は最後に
// 伸びた順で、touch との差が小さいほど最近である。
type interval struct {
	start, end uint32
	touched    uint32
}

func (b *recvBuf) full(x uint32) uint64 { return b.nxtOff + uint64(x-uint32(b.nxtOff)) }
func (b *recvBuf) ivStart(k int) uint64 { return b.full(b.iv[k].start) }
func (b *recvBuf) ivEnd(k int) uint64   { return b.full(b.iv[k].end) }

func (b *recvBuf) unread() uint64 { return b.nxtOff - b.readOff }

// rightmost は保持する最も右の byte の次の offset(順序外のデータを含む)。
func (b *recvBuf) rightmost() uint64 {
	if b.n > 0 {
		return max(b.nxtOff, b.ivEnd(b.n-1))
	}
	return b.nxtOff
}

// empty は、順序どおりの未読のデータも順序外のデータも持たないかを返す。
func (b *recvBuf) empty() bool { return b.nxtOff == b.readOff && b.n == 0 }

// setIntervals は区間の表を iv に移し、移せたかを返す。使っている区間が iv に入らなければ、区間を切り捨てずに
// 今の表を持ち続けて偽を返す。切り捨てると b.n が表の長さを超え、次の insert が表の外を指す。
func (b *recvBuf) setIntervals(iv []interval) bool {
	if b.n > len(iv) {
		return false
	}
	copy(iv, b.iv[:b.n])
	b.iv = iv
	return true
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
		// 届いた順序外の区間を取り込む。区間の位置は nxtOff を動かす前の値で復元する
		old := b.nxtOff
		k := 0
		for k < b.n {
			st := old + uint64(b.iv[k].start-uint32(old))
			if st > end {
				break
			}
			if en := old + uint64(b.iv[k].end-uint32(old)); st < end && res.dupHi <= res.dupLo {
				res.dupLo, res.dupHi = st, min(end, en) // 届いていた区間と重なる部分
			}
			end = max(end, old+uint64(b.iv[k].end-uint32(old)))
			k++
		}
		b.nxtOff = end
		if k > 0 {
			copy(b.iv, b.iv[k:b.n])
			b.n -= k
			res.filled = true
		}
		return res
	}
	// 順序外:重なるか接する区間 [i, j) を二分探索で探す
	lo, hi := 0, b.n
	for lo < hi {
		m := (lo + hi) / 2
		if b.ivEnd(m) < off {
			lo = m + 1
		} else {
			hi = m
		}
	}
	i := lo
	j := i
	for j < b.n && b.ivStart(j) <= end {
		j++
	}
	if i == j {
		if b.n == len(b.iv) {
			res.dropped = true
			return res
		}
		copy(b.iv[i+1:b.n+1], b.iv[i:b.n])
		b.n++
		b.touch++
		b.iv[i] = interval{start: uint32(off), end: uint32(end), touched: b.touch}
	} else {
		if b.ivStart(i) <= off && end <= b.ivEnd(i) && j == i+1 {
			// すべて既に届いている。RFC 2018 の順のために最近の印だけ付け直す
			b.touch++
			b.iv[i].touched = b.touch
			res.duplicate = true
			res.dupLo, res.dupHi = off, end
			return res
		}
		if lo, hi := max(off, b.ivStart(i)), min(end, b.ivEnd(i)); lo < hi && res.dupHi <= res.dupLo {
			res.dupLo, res.dupHi = lo, hi // 既存の区間と重なる部分
		}
		ns, ne := min(off, b.ivStart(i)), max(end, b.ivEnd(j-1))
		b.touch++
		b.iv[i] = interval{start: uint32(ns), end: uint32(ne), touched: b.touch}
		copy(b.iv[i+1:], b.iv[j:b.n])
		b.n -= j - i - 1
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

// sackBlocks は、最も新しく伸びた区間を先頭に、区間を最大 len(dst) 個の SACK の block にする
// (RFC 2018 4 節)。base は offset 0 のシーケンス番号である。
func (b *recvBuf) sackBlocks(dst []sackBlock, base uint32) []sackBlock {
	if b.n == 0 {
		return dst[:0]
	}
	// 新しい順に選ぶ。block は高々 4 つなので、毎回最も新しいものを選ぶ。新しさは touch との差で比べる
	out := dst[:0]
	bound := ^uint32(0)
	for len(out) < cap(dst) {
		best := -1
		var bestAge uint32
		for k := range b.n {
			age := b.touch - b.iv[k].touched
			if (bound == ^uint32(0) || age > bound) && (best < 0 || age < bestAge) {
				best, bestAge = k, age
			}
		}
		if best < 0 {
			break
		}
		bound = bestAge
		out = append(out, sackBlock{base + uint32(b.ivStart(best)), base + uint32(b.ivEnd(best))})
	}
	return out
}

// written は、輪の中身を移す時の書いた範囲(未読の範囲と順序外の区間)を返す。
func (b *recvBuf) written() [][2]uint64 {
	w := make([][2]uint64, 0, 1+b.n)
	if b.nxtOff > b.readOff {
		w = append(w, [2]uint64{b.readOff, b.nxtOff})
	}
	for k := range b.n {
		w = append(w, [2]uint64{b.ivStart(k), b.ivEnd(k)})
	}
	return w
}
