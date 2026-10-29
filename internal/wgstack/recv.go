package wgstack

// recvBuf は受信のバッファ。順序どおりの未読のデータ [readOff, nxtOff) と順序外のデータを同じ輪の
// 位置に置き、順序外の届いた範囲を固定の数 H の区間の表で持つ(設計文書の「接続ごとのバッファ」)。
// offset は接続の受信の始め(相手の ISN + 1)から数える。
type recvBuf struct {
	r       ring
	readOff uint64 // 最も古い未読の byte
	nxtOff  uint64 // 次に順序どおりに受ける byte(RCV.NXT)
	iv      [oooIntervals]interval
	n       int    // 使っている区間の数。iv[:n] は start の順
	touch   uint64 // 区間を最後に伸ばした順を数える
}

// interval は順序外の 1 つの区間 [start, end)。touched が大きいほど最近伸びた。
type interval struct {
	start, end uint64
	touched    uint64
}

func (b *recvBuf) unread() uint64 { return b.nxtOff - b.readOff }

// rightmost は保持する最も右の byte の次の offset(順序外のデータを含む)。
func (b *recvBuf) rightmost() uint64 {
	if b.n > 0 {
		return max(b.nxtOff, b.iv[b.n-1].end)
	}
	return b.nxtOff
}

// empty は、順序どおりの未読のデータも順序外のデータも持たないかを返す。
func (b *recvBuf) empty() bool { return b.nxtOff == b.readOff && b.n == 0 }

// insertResult は insert の結果。
type insertResult struct {
	accepted  int  // 輪に入れた byte
	trimmed   bool // 上限の外の分を捨てた
	dropped   bool // H を超える区間を作るので segment を捨てた
	ooo       bool // 順序外のデータを入れた
	filled    bool // 順序外の区間を順序どおりの範囲に取り込んだ
	advanced  bool // nxtOff が進んだ
	duplicate bool // 中身がすべて既に届いていた
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
			return res
		}
		data = data[b.nxtOff-off:]
		off = b.nxtOff
	}
	if len(data) == 0 {
		return res
	}
	if off == b.nxtOff {
		b.r.write(off, data)
		res.accepted = len(data)
		b.nxtOff = end
		res.advanced = true
		// 届いた順序外の区間を取り込む
		k := 0
		for k < b.n && b.iv[k].start <= b.nxtOff {
			b.nxtOff = max(b.nxtOff, b.iv[k].end)
			k++
		}
		if k > 0 {
			copy(b.iv[:], b.iv[k:b.n])
			b.n -= k
			res.filled = true
		}
		return res
	}
	// 順序外:重なるか接する区間 [i, j) を探す
	i := 0
	for i < b.n && b.iv[i].end < off {
		i++
	}
	j := i
	for j < b.n && b.iv[j].start <= end {
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
		b.iv[i] = interval{start: off, end: end, touched: b.touch}
	} else {
		if b.iv[i].start <= off && end <= b.iv[i].end && j == i+1 {
			// すべて既に届いている。RFC 2018 の順のために最近の印だけ付け直す
			b.touch++
			b.iv[i].touched = b.touch
			res.duplicate = true
			return res
		}
		ns, ne := min(off, b.iv[i].start), max(end, b.iv[j-1].end)
		b.touch++
		b.iv[i] = interval{start: ns, end: ne, touched: b.touch}
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
	// 新しい順に選ぶ。block は高々 4 つなので、毎回最大を選ぶ
	out := dst[:0]
	var bound uint64 = ^uint64(0)
	for len(out) < cap(dst) {
		best := -1
		for k := range b.n {
			if t := b.iv[k].touched; t < bound && (best < 0 || t > b.iv[best].touched) {
				best = k
			}
		}
		if best < 0 {
			break
		}
		bound = b.iv[best].touched
		out = append(out, sackBlock{base + uint32(b.iv[best].start), base + uint32(b.iv[best].end)})
	}
	return out
}

// written は、輪の中身を移す時の書いた範囲(未読の範囲と順序外の区間)を返す。
func (b *recvBuf) written() [][2]uint64 {
	w := make([][2]uint64, 0, 1+b.n)
	if b.nxtOff > b.readOff {
		w = append(w, [2]uint64{b.readOff, b.nxtOff})
	}
	for _, v := range b.iv[:b.n] {
		w = append(w, [2]uint64{v.start, v.end})
	}
	return w
}
