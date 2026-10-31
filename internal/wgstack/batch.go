package wgstack

import (
	"crypto/rand"
	"encoding/binary"
	"sync/atomic"
)

// 送信の向きのバッチ(設計文書 wgstack-batching.md の「送信の向きの予算」)。Read は 1 回に k_eff 個までの
// packet を作り、作ったすべての buffer の末尾の 16 byte に送った番号の印を書く。2 個以上の packet を返した
// Read は台帳に行を足し、Send を見る層が 1 回遅れで知らせた番号 W 以下の行を外す。門は L + R + n ≤ P_max を
// 守るので、2 個以上の packet の入れ物の buffer は P_max 以下に保たれる。

// SendBatch は送信の向きのバッチの設定。ゼロ値はバッチを使わず、Read は今と同じく 1 個ずつ返す。
type SendBatch struct {
	// Packets は予算 P_max(2 個以上の packet の入れ物が持つ buffer の数の上限)。0 ならバッチを使わない
	Packets int
	// Size は k_tx で、BatchSize が返す値。2 以上 MaxSendBatch 以下でバッチを使う
	Size int
	// Callers は C で、wireguard-go の SendStagedPackets を同じピアについて同時に動かしうる呼び出しの数。
	// device を作る時の runtime.NumCPU() + 6 である。2 以上でバッチを使う(1 以下はバッチを使わない)。
	// 台帳は、ピアが 1 つで差し替わらない device の前提で作っている
	Callers int
	// BufferSize は wireguard-go が Read に渡す buffer の大きさ S(MaxMessageSize)。印を書ける条件の判定に
	// 使う
	BufferSize int
}

// MaxSendBatch は k_tx の上限。wireguard-go の Send が使う message の配列(conn.IdealBatchSize)の長さで、
// これを超える buffer を 1 回の Send に渡すと配列の外を指す。トンネルの試験が依存の値と一致することを
// 確かめる。
const MaxSendBatch = 128

// maxSendPackets は Packets の上限。トンネルは P_upper = N_tx × k_tx で丸めて渡すが、台帳の輪(⌊P_max / 2⌋ 行)
// の大きさを渡す側の丸めに頼らないよう、init でも丸める。N_tx = 1024 + 128 + 1 + CPU の数 + 6 で、CPU が
// 1,000 個なら約 2,160、P_upper は k_tx が 32 なら約 69,000、128 なら約 276,000 である。この上限が効くのは
// CPU が約 31,600 個を超えるときで、実際の設定は丸めに触れない。
const maxSendPackets = 1 << 20

const (
	tagSize = 16
	// sealOverhead は wireguard-go が packet の後ろに足しうる byte の上限で、詰め物の 15 byte と認証の tag
	// の 16 byte である
	sealOverhead = 15 + 16
	// transportType と keepaliveSize は wireguard-go の MessageTransportType と MessageKeepaliveSize
	transportType = 4
	keepaliveSize = 32
	// tagDomain は確認の値の入力の 2 語目。同じ鍵を別の用途に使っても値が重ならないようにする
	tagDomain = 0x7478_6261_7463_6801
)

// ledgerRow は台帳の 1 行で、2 個以上の packet を返した Read の番号と個数である。
type ledgerRow struct {
	seq uint64
	n   int64
}

// sendLedger は送信の向きの予算の状態。持ち主で欄が 3 つに分かれる。on から key までは init が作成の時に
// 決め、後で変えない。rows、head、count、held、next は Read の goroutine だけが readMu の中で触れる。issued、
// acked、pending は atomic で、Send を見る層も触れる。key は秘密なので Config.Rand ではなく crypto/rand から
// 読む(stack の説明の乱数の例外)。
type sendLedger struct {
	on      bool
	size    int    // k_tx
	keff    int    // k_eff
	pmax    int64  // P_max
	reserve int64  // R = (C - 1) × k_eff
	mtu     int    // 印を書ける条件の判定に使う
	key     sipKey // 確認の値の鍵。Device ごとに作る

	rows  []ledgerRow // 固定の輪。大きさは ⌊P_max / 2⌋
	head  int
	count int
	held  int64  // L:台帳に残る行の個数の和
	next  uint64 // 次の Read に付ける番号 s。1 から始める

	issued  atomic.Uint64 // 最後に出した番号。0 はまだ何も出していない
	acked   atomic.Uint64 // W:知らされた番号の最大。0 はまだ何も知らされていない
	pending atomic.Uint64 // Send を見る層の手元の番号。data の message の Send を呼ぶ goroutine だけが更新する
	// off は Read が印を書けない buffer を受け取ったときに立て、立てたら戻さない。立った後は Read が印を
	// 書かず、observe が印を受け入れないので、古い印が W を進めることはない
	off atomic.Bool
}

// clampPackets は init が Packets に課す上限を適用した P_max を返す。
func clampPackets(packets int) int { return min(packets, maxSendPackets) }

// init は cfg から台帳を作る。バッチを使えない設定なら on を偽のままにし、BatchSize は 1 になる。
func (l *sendLedger) init(cfg SendBatch, mtu int) {
	l.next = 1
	l.size = 1
	// Callers が 1 以下の設定は、並行して動く呼び出しを持たないので k_eff の式が成り立たず、使わない
	if cfg.Packets <= 0 || cfg.Size < 2 || cfg.Callers < 2 {
		return
	}
	cfg.Packets = clampPackets(cfg.Packets)
	size := min(cfg.Size, MaxSendBatch)
	keff := min(size, cfg.Packets/(2*(cfg.Callers-1)))
	// 印を書ける条件:offset(wireguard-go の MessageTransportHeaderSize の 16)+ packet の長さ + 詰め物 + 認証の
	// tag ≤ buffer の容量 - 16。Read は呼ぶたびに実際の offset と buffer の長さでも確かめる
	if keff < 2 || 16+mtu+sealOverhead > cfg.BufferSize-tagSize {
		return
	}
	l.on = true
	l.size = size
	l.keff = keff
	l.pmax = int64(cfg.Packets)
	l.reserve = int64(cfg.Callers-1) * int64(keff)
	l.mtu = mtu
	l.rows = make([]ledgerRow, cfg.Packets/2)
	var seed [16]byte
	_, _ = rand.Read(seed[:])
	l.key = sipKey{binary.LittleEndian.Uint64(seed[0:]), binary.LittleEndian.Uint64(seed[8:])}
}

// fits は buf に offset から MTU の packet を作り、wireguard-go が詰め物と認証の tag を足しても、末尾の
// 16 byte の印に届かないかを返す。長さが容量より短い buffer には合わない。印は長さの末尾に書くが、
// observe は容量の末尾を読むので、2 つが違う位置を指すからである。
func (l *sendLedger) fits(buf []byte, offset int) bool {
	return len(buf) == cap(buf) && offset >= 0 && offset+l.mtu+sealOverhead <= len(buf)-tagSize
}

// limit は台帳から W 以下の行を外し、次の Read が作ってよい packet の数を返す。値は 1 以上 avail 以下で、
// 2 以上なら L + R + n ≤ P_max を満たす。
func (l *sendLedger) limit(avail int) int {
	w := l.acked.Load()
	for l.count > 0 && l.rows[l.head].seq <= w {
		l.held -= l.rows[l.head].n
		l.head++
		if l.head == len(l.rows) {
			l.head = 0
		}
		l.count--
	}
	if l.count == len(l.rows) {
		return 1
	}
	n := min(int64(l.keff), int64(avail), l.pmax-l.held-l.reserve)
	if n < 2 {
		return 1
	}
	return int(n)
}

// commit は n 個の packet を返す Read の番号を出し、n が 2 以上なら台帳に行を足す。Read が戻る前に呼ぶ。
// limit が返した値以下の n だけを渡す。
func (l *sendLedger) commit(n int) uint64 {
	seq := l.next
	l.next++
	if n >= 2 {
		i := l.head + l.count
		if i >= len(l.rows) {
			i -= len(l.rows)
		}
		l.rows[i] = ledgerRow{seq: seq, n: int64(n)}
		l.count++
		l.held += int64(n)
	}
	return seq
}

// publish は commit が出した番号を Send を見る層に見せる。印を書いた後、Read が戻る前に呼ぶ。
func (l *sendLedger) publish(seq uint64) { l.issued.Store(seq) }

// writeTag は buf の末尾の 16 byte に番号 seq と確認の値を書く。
func (l *sendLedger) writeTag(buf []byte, seq uint64) {
	t := buf[len(buf)-tagSize:]
	binary.LittleEndian.PutUint64(t[0:], seq)
	binary.LittleEndian.PutUint64(t[8:], l.key.sum(seq, tagDomain))
}

// readTag は message の slice を容量まで広げた末尾の 16 byte から番号を読む。確認の値が合わなければ 0 を
// 返す。
func (l *sendLedger) readTag(msg []byte) uint64 {
	if cap(msg)-len(msg) < tagSize {
		return 0
	}
	full := msg[:cap(msg)]
	t := full[len(full)-tagSize:]
	seq := binary.LittleEndian.Uint64(t[0:])
	if seq == 0 || binary.LittleEndian.Uint64(t[8:]) != l.key.sum(seq, tagDomain) {
		return 0
	}
	return seq
}

// observe は Send を見る層が内側の Send を呼ぶ前に呼ぶ。data の message(型が transport で長さが
// keepalive より長い message)を持たない呼び出しでは何もしない。持つ呼び出しでは、前に data の message を
// 持つ呼び出しで読んだ最大の番号を W に知らせ(1 回遅れの知らせ)、この呼び出しで読んだ最大の番号を手元に
// 置く。
func (l *sendLedger) observe(bufs [][]byte) {
	if l.off.Load() {
		return
	}
	issued := l.issued.Load()
	var top uint64
	data := false
	for _, b := range bufs {
		if len(b) <= keepaliveSize || binary.LittleEndian.Uint32(b) != transportType {
			continue
		}
		data = true
		if seq := l.readTag(b); seq <= issued && seq > top {
			top = seq
		}
	}
	if !data {
		return
	}
	prev := l.pending.Swap(top)
	for {
		w := l.acked.Load()
		if prev <= w || l.acked.CompareAndSwap(w, prev) {
			return
		}
	}
}

// ObserveSend は wireguard-go のバインドの Send を見る層が、内側の Send を呼ぶ前に、Send が受けた message
// の列を渡す関数。message を読むだけで、書き換えず、保持しない。バッチを使わない Device では何もしない。
func (d *Device) ObserveSend(bufs [][]byte) {
	if d.s.txb.on && !d.s.txb.off.Load() {
		d.s.txb.observe(bufs)
	}
}

// Batching は、この Device が送信の向きのバッチを使うかを返す。偽なら BatchSize は 1 で、Send を見る層は
// 要らない。
func (d *Device) Batching() bool { return d.s.txb.on }

// readBatch は readMu の中で、送るものがあれば 1 個以上の packet を bufs に作り、個数を返す。
func (d *Device) readBatch(bufs [][]byte, sizes []int, offset int, now int64) int {
	l := &d.s.txb
	first := bufs[0]
	if l.on && !l.off.Load() && !l.fits(first, offset) {
		// 印を書けない buffer を受け取ったら、この Device はバッチを止める。前の Read の印が配列に残って
		// いても、長さが容量より短くても、以後 observe が印を受け入れないので W は進まない
		l.off.Store(true)
	}
	if !l.on || l.off.Load() {
		n := d.s.poll(first[offset:], now)
		if n > 0 {
			sizes[0] = n
			return 1
		}
		return 0
	}
	limit := l.limit(min(len(bufs), len(sizes)))
	n := d.s.poll(first[offset:len(first)-tagSize], now)
	if n == 0 {
		return 0
	}
	sizes[0] = n
	cnt := 1
	for cnt < limit {
		b := bufs[cnt]
		if !l.fits(b, offset) {
			break
		}
		m := d.s.poll(b[offset:len(b)-tagSize], now)
		if m == 0 {
			break
		}
		sizes[cnt] = m
		cnt++
	}
	seq := l.commit(cnt)
	for i := range cnt {
		l.writeTag(bufs[i], seq)
	}
	l.publish(seq)
	return cnt
}
