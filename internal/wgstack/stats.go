package wgstack

import (
	"sync"
	"unsafe"
)

// Stats は Device が数える保持と事象。保持の欄は会計が数える今の量で、上界の試験と fuzzing が上界の式と
// 比べる。数は `wgft status`、管理用 API、wire protocol に載せない(設計文書の「尽きたときの動作」)。
type Stats struct {
	Conns         int   // 使っている接続の枠
	SynRows       int   // 握手の途中の行
	TWRows        int   // TIME_WAIT と FIN_WAIT_2 の行
	AcceptQueued  int   // accept の待ち行列の接続(移している途中の行を含む)
	CtlQueued     int   // 制御の輪に積んだ packet
	ChunkBytes    int64 // 送信と受信の輪が持つ chunk の byte
	RecordBytes   int64 // 送信の記録の輪がヒープに持つ byte(floor の輪と boost の輪。heapBytes で切り上げる)
	IntervalBytes int64 // 順序外の区間の表がヒープに持つ byte(floor の表と boost の表。heapBytes で切り上げる)
	Boosted       int   // boost の枠を持つこの Device の接続
	Reserved      int64 // 使っている接続の枠の送信と受信の容量の和

	UDPRxBytes, UDPRxDatagrams int64 // UDP の受信が持つ chunk の byte と datagram の数
	UDPTxBytes, UDPTxDatagrams int64 // UDP の送信が持つ chunk の byte と datagram の数
	FragBytes                  int   // 再組み立ての表が数える保持 byte(固定の管理領域を含む)
	PingEndpoints              int   // 使っている echo の endpoint

	MSSFloorDrops    uint64
	SynTableFull     uint64
	AcceptOverflow   uint64
	TWEvicted        uint64
	CtlDropped       uint64
	OOODropped       uint64
	RecvTrimmed      uint64
	ChallengeLimited uint64
	FragmentsDropped uint64
	UDPDropped       uint64
	ICMPDropped      uint64
	Malformed        uint64
	BadChecksum      uint64
	NotLocal         uint64
	RetransmitAborts uint64
	ProbeAborts      uint64
	BoostGranted     uint64
	BoostReclaimed   uint64

	// 送り手の事象(wgstack-performance.md の「安く確かめる手順」)
	RTOs                 uint64 // 再送のタイマーの期限で送り直した回数。窓の probe は数えない
	RTOsBackedOff        uint64 // 累積の確認が進む前に続いた RTO(再送した segment も失われた)
	RTOsShortOfDupThresh uint64 // 回復の外で、重複した ACK を 1 つか 2 つ受けた後の RTO
	FastRecoveries       uint64 // 高速の回復に入った回数
	PartialAcks          uint64 // 回復の中の部分の確認
	RetransFast          uint64 // 高速の再送の segment
	RetransPartial       uint64 // 部分の確認による再送の segment
	RetransRTO           uint64 // RTO の後に SND.MAX より手前を送り直した segment
	RetransPMTU          uint64 // PMTU の引き下げの後に SND.MAX より手前を送り直した segment
	DupAcksIn            uint64 // 受けた重複した ACK
	AcksDelayed          uint64 // 遅延 ACK のタイマーが求めた ACK を運んだ segment
	AcksImmediate        uint64 // 即座に求めた ACK を運んだ segment
	SACKReneging         uint64 // RTO の処理で SACK 済みの印を取り消した回数
	RACKLost             uint64 // RACK が失われたとみなした記録(RFC 8985)
	ReorderTimeouts      uint64 // 並べ替えの期限で RACK の判定をした回数
	TLPProbes            uint64 // 送った TLP の probe
	TLPRecoveries        uint64 // probe が損失を直したとみなして輻輳の窓を下げた回数
	RetransTLP           uint64 // TLP の probe として送り直した segment
	HyStartCSS           uint64 // HyStart++ が Conservative Slow Start に入った回数
	HyStartExits         uint64 // HyStart++ が CSS の後に slow start を終えた回数
	DSACKsIn             uint64 // 並べ替えの窓を広げた D-SACK の往復
	SpuriousUndos        uint64 // 再送が不要だったと分かり輻輳の窓を戻した回数
	SpuriousRTOs         uint64 // F-RTO が不要と決めた RTO
	AccountingFaults     uint64 // 会計の不整合で閉じた接続
	HeldChunksInPool     int64  // 輪が持つ chunk の数(chunkPool の会計)
	ReclaimableInBoost   int    // プロセスの boost の枠のうち使っている数
}

// Stats は今の保持と数を返す。
func (d *Device) Stats() Stats { return d.s.stats() }

func (s *stack) stats() Stats {
	var st Stats
	for i := range s.conns {
		c := &s.conns[i]
		c.mu.Lock()
		r, iv := c.arrayBytes()
		st.RecordBytes += r
		st.IntervalBytes += iv
		if c.state != stFree {
			st.Conns++
			st.ChunkBytes += int64(c.snd.heldChunks()+c.rcv.r.heldChunks()) * chunkSize
			st.Reserved += int64(c.sndCap + c.rcvCap)
			if c.boosted {
				st.Boosted++
			}
		}
		c.mu.Unlock()
	}
	s.tmu.Lock()
	st.SynRows = s.syn.n
	st.TWRows = s.tw.n
	st.AcceptQueued = s.queued
	s.tmu.Unlock()
	s.out.mu.Lock()
	st.CtlQueued = s.out.ctl.n
	s.out.mu.Unlock()
	st.UDPRxBytes, st.UDPRxDatagrams, st.UDPTxBytes, st.UDPTxDatagrams = s.udpHeld()
	st.FragBytes, _, _ = s.frag.Usage()
	s.ping.mu.Lock()
	for i := range s.ping.eps {
		if s.ping.eps[i].used {
			st.PingEndpoints++
		}
	}
	s.ping.mu.Unlock()
	st.HeldChunksInPool = s.chunks.heldChunks()
	st.ReclaimableInBoost = s.pool.held()
	st.MSSFloorDrops = s.mssFloor.Load()
	st.SynTableFull = s.synFull.Load()
	st.AcceptOverflow = s.acceptOverflow.Load()
	st.TWEvicted = s.twEvicted.Load()
	st.CtlDropped = s.ctlDropped.Load()
	st.OOODropped = s.oooDropped.Load()
	st.RecvTrimmed = s.rcvTrimmed.Load()
	st.ChallengeLimited = s.challengeLimit.Load()
	st.FragmentsDropped = s.fragments.Load()
	st.UDPDropped = s.udpDropped.Load()
	st.ICMPDropped = s.icmpDropped.Load()
	st.Malformed = s.malformed.Load()
	st.BadChecksum = s.badChecksum.Load()
	st.NotLocal = s.notLocal.Load()
	st.RetransmitAborts = s.rtxAborted.Load()
	st.ProbeAborts = s.probeAborted.Load()
	st.BoostGranted = s.boostGranted.Load()
	st.BoostReclaimed = s.boostReclaimed.Load()
	st.RTOs = s.rtos.Load()
	st.RTOsBackedOff = s.rtosBackedOff.Load()
	st.RTOsShortOfDupThresh = s.rtosShortOfDupThresh.Load()
	st.FastRecoveries = s.fastRecoveries.Load()
	st.PartialAcks = s.partialAcks.Load()
	st.RetransFast = s.retrans[rtxFast].Load()
	st.RetransPartial = s.retrans[rtxPartial].Load()
	st.RetransRTO = s.retrans[rtxRTO].Load()
	st.RetransPMTU = s.retrans[rtxPMTU].Load()
	st.DupAcksIn = s.dupAcksIn.Load()
	st.AcksDelayed = s.acksDelayed.Load()
	st.AcksImmediate = s.acksImmediate.Load()
	st.SACKReneging = s.sackReneging.Load()
	st.RACKLost = s.rackLost.Load()
	st.ReorderTimeouts = s.reoTimeouts.Load()
	st.TLPProbes = s.tlpProbes.Load()
	st.TLPRecoveries = s.tlpRecoveries.Load()
	st.RetransTLP = s.retrans[rtxTLP].Load()
	st.HyStartCSS = s.hystartCSS.Load()
	st.HyStartExits = s.hystartExits.Load()
	st.DSACKsIn = s.dsacksIn.Load()
	st.SpuriousUndos = s.spuriousUndos.Load()
	st.SpuriousRTOs = s.spuriousRTOs.Load()
	st.AccountingFaults = s.accountingFaults.Load()
	return st
}

// arrayBytes は枠が持つ送信の記録の輪と区間の表がヒープに持つ byte を返す。floor の輪と表は枠と共に
// 持ち続ける。今使っている輪と表が floor のものでなければ、boost の段の配列としてそれも数える。段の印では
// なく配列の同一性で見るので、印を消した後に残った boost の配列も数える。mu を持って呼ぶ。
func (c *tcb) arrayBytes() (recs, ivs int64) {
	recs = recordsBytes(len(c.floorRecs))
	if len(c.recs.recs) > 0 && (len(c.floorRecs) == 0 || &c.recs.recs[0] != &c.floorRecs[0]) {
		recs += recordsBytes(len(c.recs.recs))
	}
	ivs = intervalsBytes(len(c.floorIv))
	if len(c.rcv.iv) > 0 && (len(c.floorIv) == 0 || &c.rcv.iv[0] != &c.floorIv[0]) {
		ivs += intervalsBytes(len(c.rcv.iv))
	}
	return recs, ivs
}

// recordsBytes と intervalsBytes は配列の長さから数え、上界の項(terms)を使わない。会計を項から独立に
// 数えるので、項の誤りは上界の試験で比べたときに現れる。Stats は枠ごとに呼ぶので、枠が作る長さ(floor と
// boost)の値は 1 回だけ測って持つ(stageArrays)。
func recordsBytes(n int) int64 {
	switch a := stageArrays(); n {
	case floorRecords:
		return a.floorRecs
	case boostRecords:
		return a.boostRecs
	}
	return heapBytes(int64(n) * int64(unsafe.Sizeof(record{})))
}

func intervalsBytes(n int) int64 {
	switch a := stageArrays(); n {
	case floorIntervals:
		return a.floorIvs
	case boostIntervals:
		return a.boostIvs
	}
	return heapBytes(int64(n) * int64(unsafe.Sizeof(interval{})))
}

// stageArrays は floor と boost の段の記録の輪と区間の表がヒープに持つ大きさ。
var stageArrays = sync.OnceValue(func() (a struct{ floorRecs, boostRecs, floorIvs, boostIvs int64 }) {
	a.floorRecs = heapBytes(floorRecords * int64(unsafe.Sizeof(record{})))
	a.boostRecs = heapBytes(boostRecords * int64(unsafe.Sizeof(record{})))
	a.floorIvs = heapBytes(floorIntervals * int64(unsafe.Sizeof(interval{})))
	a.boostIvs = heapBytes(boostIntervals * int64(unsafe.Sizeof(interval{})))
	return a
})

// sliceBytes は s の長さの配列がヒープに持つ大きさ(heapBytes)を返す。
func sliceBytes[T any](s []T) int64 {
	var z T
	return heapBytes(int64(len(s)) * int64(unsafe.Sizeof(z)))
}

// mallocHeader は Go のヒープがポインタを含む小さな object に足す管理の頭の大きさ。
const mallocHeader = 8

var heapRound sync.Map // 要求の byte 数から、切り上げた大きさへ

// heapBytes は n byte の配列 1 つを Go のヒープが持つ大きさの上界を返す(設計文書の「上界の式」の確保の
// 丸め)。ヒープは object を大きさの区分(32 KiB まで)か 8 KiB の page の倍数(それより大きい)に切り上げて
// 持ち、ポインタを含む小さな object には管理の頭を足す。切り上げは runtime の表を読まずに、append が同じ
// 切り上げで決める []byte の容量で測る。管理の頭はポインタの有無によらず足す(上に振れるだけ)。
// 大きさごとに 1 回だけ測る。
func heapBytes(n int64) int64 {
	if n <= 0 {
		return 0
	}
	if v, ok := heapRound.Load(n); ok {
		return v.(int64)
	}
	m := int64(cap(append([]byte(nil), make([]byte, n+mallocHeader)...)))
	heapRound.Store(n, m)
	return m
}

// chunkHeap は chunk 1 つがヒープに持つ大きさ。chunk はポインタを含まないので管理の頭を足さない。
var chunkHeap = sync.OnceValue(func() int64 {
	return int64(cap(append([]byte(nil), make([]byte, chunkSize)...)))
})

// ringBytes は容量 n byte の chunk の輪がヒープに持つ大きさの上界。
func ringBytes(n int64) int64 { return n / chunkSize * chunkHeap() }

// slotTerms は接続の枠 1 つと boost の枠 1 つの項(設計文書の「上界の式」)を、ヒープが持つ大きさで数えた値。
type slotTerms struct {
	fs, fr, rf, hf   int64 // floor の送信と受信の輪、floor の記録の輪、floor の区間の表
	ds, dr, drec, dh int64 // boost が送信と受信の輪に加える分、boost の記録の輪の全体、boost の区間の表の全体
}

func (t slotTerms) floor() int64 { return t.fs + t.fr + t.rf + t.hf }
func (t slotTerms) boost() int64 { return t.ds + t.dr + t.drec + t.dh }

// terms は枠の項を返す。boost の間も floor の記録の輪と区間の表は枠に残るので、d_rec と d_h は floor との
// 差ではなく boost の配列の全体である。送信と受信の輪は段を変えるときに古い chunk を返すので、d_s と d_r は
// floor との差である。
var terms = sync.OnceValue(func() slotTerms {
	return slotTerms{
		fs: ringBytes(sendFloor), fr: ringBytes(recvFloor),
		rf: heapBytes(floorRecords * int64(unsafe.Sizeof(record{}))), hf: heapBytes(floorIntervals * int64(unsafe.Sizeof(interval{}))),
		ds: ringBytes(boostSize) - ringBytes(sendFloor), dr: ringBytes(boostSize) - ringBytes(recvFloor),
		drec: heapBytes(boostRecords * int64(unsafe.Sizeof(record{}))), dh: heapBytes(boostIntervals * int64(unsafe.Sizeof(interval{}))),
	}
})

// Bound は上界の式(設計文書の「上界の式」)の値を、この Device の表の大きさと、この build の構造の大きさで
// 求めた値。配列はヒープが持つ切り上げた大きさで数える(heapBytes)。boost の項は、プロセスの枠のすべてを
// この Device が持つとして数える。
type Bound struct {
	Fix       int64 // M_fix:核の構造(事象の数と観測の関数を含む)、接続の枠の構造、hash の表、行の表、タイマーの輪、出力の list と制御の輪、chunk の置き場
	FloorConn int64 // N_c x (f_s + f_r + r_f + h_f)
	Boost     int64 // B x (d_s + d_r + d_rec + d_h)。d_rec と d_h は boost の輪と表の全体で、floor の輪と表は枠に残るので FloorConn が数える
	UDPRx     int64 // M_udp_rx:受信の予算と管理の配列
	UDPTx     int64 // M_udp_tx:送信の予算と管理の配列
	Frag      int64 // M_frag:再組み立ての表の保持 byte の上限
	Ping      int64 // N_ping x c_ping
	Total     int64
	// 段を変える間の一時の保持(設計文書の「上界の式」が式に含めない項)。1 本の接続の錠の中で起きるので、
	// 同時に起きる数は boost の枠の数以下で、B x (f_s + f_r) で抑える
	Transient int64
}

// slotRuntime は接続の枠 1 つが表の外に持つ構造の上界。linux/amd64 の Go 1.27 で測ると、アプリケーションの
// handle の Conn と 2 つの TCPAddr が 176 byte、読み書きを起こす 2 つの channel が 224 byte、読み書きの
// 期限の 2 つの channel が 224 byte、2 つの期限のタイマーが 256 byte で、合わせて 880 byte である。
const slotRuntime = 1024

// Bound はこの Device の上界の式の値を返す。
func (d *Device) Bound() Bound { return d.s.bound() }

// bound は表の大きさが作成の時に決まるので、1 回だけ数える。
func (s *stack) bound() Bound {
	s.boundOnce.Do(func() { s.boundVal = s.countBound() })
	return s.boundVal
}

func (s *stack) countBound() Bound {
	n := int64(len(s.conns))
	dl := func(x dlist) int64 { return sliceBytes(x.next) + sliceBytes(x.prev) + sliceBytes(x.in) }
	var b Bound
	b.Fix = heapBytes(int64(unsafe.Sizeof(stack{}))) + sliceBytes(s.conns) + sliceBytes(s.free) +
		sliceBytes(s.connIdx.ents) + sliceBytes(s.syn.idx.ents) + sliceBytes(s.tw.idx.ents) +
		sliceBytes(s.syn.rows) + sliceBytes(s.syn.free) +
		sliceBytes(s.tw.rows) + sliceBytes(s.tw.free) +
		sliceBytes(s.wheel.dl) + sliceBytes(s.wheel.next) + sliceBytes(s.wheel.prev) + sliceBytes(s.wheel.where) +
		dl(s.out.conns) + dl(s.out.rows) +
		sliceBytes(s.out.ctl.buf) + sliceBytes(s.out.ctl.lens) +
		sliceBytes(s.fired[:cap(s.fired)]) +
		chunkPoolKeep*chunkHeap() + heapBytes(chunkPoolKeep*int64(unsafe.Sizeof((*chunk)(nil)))) +
		n*slotRuntime
	t := terms()
	b.FloorConn = n * t.floor()
	b.Boost = int64(len(s.pool.slots)) * t.boost()
	ck := sliceBytes(s.udp.ck) + sliceBytes(s.udp.ckFree)
	b.UDPRx = ringBytes(udpRxBytes) + sliceBytes(s.udp.dg[dirRx]) + sliceBytes(s.udp.dgFree[dirRx]) + (ck+1)/2
	b.UDPTx = ringBytes(udpTxBytes) + sliceBytes(s.udp.dg[dirTx]) + sliceBytes(s.udp.dgFree[dirTx]) + ck/2
	b.Frag = int64(fragLimits.Bytes)
	b.Ping = pingEndpoints * (heapBytes(int64(s.mtu)) + int64(unsafe.Sizeof(pingEP{})))
	b.Total = b.Fix + b.FloorConn + b.Boost + b.UDPRx + b.UDPTx + b.Frag + b.Ping
	b.Transient = int64(len(s.pool.slots)) * (t.fs + t.fr)
	return b
}
