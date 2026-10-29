package wgstack

// record は送った segment 1 つの記録。開始の番号、長さ、送った時刻、印を持つ。prev と next は、後の
// 段階の RACK が送った時刻の順にたどる list の節で、今は使わない(設計文書の「後の段階の機能」)。
type record struct {
	sentAt int64  // 送った時刻(ns)
	seq    uint32 // 開始のシーケンス番号
	prev   int32
	next   int32
	length uint16 // 中身の長さ。FIN を含む segment は FIN の 1 を足す
	flags  uint8
}

const (
	recRetransmitted uint8 = 1 << iota
	recSacked              // 後の段階の SACK の scoreboard の印
	recLost                // 後の段階の損失の印
)

// recordRing は送信の記録の固定の容量の輪。容量は送信のバッファの予約を minSegPayload で割った数で、
// floor では floorRecords、boost では boostRecords である。満杯の間は新しい segment を送らない。
type recordRing struct {
	recs []record
	head int
	n    int
}

func (r *recordRing) full() bool { return r.n == len(r.recs) }

func (r *recordRing) at(i int) *record { return &r.recs[(r.head+i)%len(r.recs)] }

func (r *recordRing) push(rec record) {
	r.recs[(r.head+r.n)%len(r.recs)] = rec
	r.n++
}

func (r *recordRing) pop() {
	r.head = (r.head + 1) % len(r.recs)
	r.n--
}

func (r *recordRing) reset() { r.head, r.n = 0, 0 }

// resize は容量を newRecs 件の配列に移す。呼び出し側は r.n <= len(newRecs) を保証する。
func (r *recordRing) resize(newRecs []record) {
	for i := range r.n {
		newRecs[i] = *r.at(i)
	}
	r.recs, r.head = newRecs, 0
}
