package wgstack

// record は送った segment 1 つの記録。開始の番号、長さ、送った時刻、印を持つ。記録の境目は送った時のまま
// 変えず、再送は既存の記録をたどる(wgstack-performance.md の「scoreboard の記録の扱い」)。prev と next は、
// RACK の送った時刻の順の list と損失の待ち行列の節で、自分からの記録の数の差で持つ(rack.go)。skip、
// sackGen、rtxGen は SACK の scoreboard の欄で、scoreboard.go が使う。
type record struct {
	sentAt  int64  // 送った時刻(ns)。再送のたびに更新する
	seq     uint32 // 開始のシーケンス番号
	prev    int32
	next    int32
	skip    int32  // SACK 済みの記録から、SACK 済みでないかもしれない次の記録までの数
	length  uint16 // 中身の長さ。FIN を含む segment は FIN の 1 を足す
	flags   uint8
	sackGen uint8 // recSacked を付けた時の接続の SACK の世代
	rtxGen  uint8 // recRtx を付けた時の接続の再送の世代
}

const (
	recRetransmitted uint8 = 1 << iota // 1 度でも再送した(Karn の規則)
	recSacked                          // SACK 済み。sackGen が接続の世代と等しいときだけ有効
	recRtx                             // 再送が送り残し(pipe)に入っている。rtxGen が接続の世代と等しいときだけ有効
	recInT                             // 送った時刻の順の list にある(rack.go)。rtxGen と同じ世代で有効
	recInQ                             // RACK の損失の待ち行列にある。rtxGen と同じ世代で有効
	recLost                            // RACK が失われたとみなした。rtxGen と同じ世代で有効
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

// resize は容量を newRecs 件の配列に移す。呼び出し側は r.n <= len(newRecs) を保証する。
func (r *recordRing) resize(newRecs []record) {
	for i := range r.n {
		newRecs[i] = *r.at(i)
	}
	r.recs, r.head = newRecs, 0
}
