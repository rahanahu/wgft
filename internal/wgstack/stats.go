package wgstack

import "unsafe"

// Stats は Device が数える保持と事象。保持の欄は会計が数える今の量で、上界の試験と fuzzing が上界の式と
// 比べる。数は `wgft status`、管理用 API、wire protocol に載せない(設計文書の「尽きたときの動作」)。
type Stats struct {
	Conns         int   // 使っている接続の枠
	SynRows       int   // 握手の途中の行
	TWRows        int   // TIME_WAIT と FIN_WAIT_2 の行
	AcceptQueued  int   // accept の待ち行列の接続(移している途中の行を含む)
	CtlQueued     int   // 制御の輪に積んだ packet
	ChunkBytes    int64 // 送信と受信の輪が持つ chunk の byte
	RecordBytes   int64 // 送信の記録の輪の byte(floor の輪と boost の輪)
	IntervalBytes int64 // 順序外の区間の表の byte(floor の表と boost の表)
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
	recSize := int64(unsafe.Sizeof(record{}))
	ivSize := int64(unsafe.Sizeof(interval{}))
	for i := range s.conns {
		c := &s.conns[i]
		c.mu.Lock()
		if c.floorRecs != nil {
			st.RecordBytes += int64(len(c.floorRecs)) * recSize
		}
		if c.floorIv != nil {
			st.IntervalBytes += int64(len(c.floorIv)) * ivSize
		}
		if c.state != stFree {
			st.Conns++
			st.ChunkBytes += int64(c.snd.heldChunks()+c.rcv.r.heldChunks()) * chunkSize
			st.Reserved += int64(c.sndCap + c.rcvCap)
			if c.boosted {
				st.Boosted++
				st.RecordBytes += int64(len(c.recs.recs)) * recSize
			}
			if c.rcvBoost {
				st.IntervalBytes += int64(len(c.rcv.iv)) * ivSize
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

// Bound は上界の式(設計文書の「上界の式」)の TCP の項を、この Device の表の大きさと、この build の構造の
// 大きさで求めた値。UDP、ICMP、再組み立ての項はこの段階に無いので含めない。boost の項は、プロセスの枠の
// すべてをこの Device が持つとして数える。
type Bound struct {
	Fix       int64 // M_fix:核の構造(事象の数と観測の関数を含む)、接続の枠の構造、hash の表、行の表、タイマーの輪、出力の list と制御の輪、chunk の置き場
	FloorConn int64 // N_c x (f_s + f_r + r_f)
	Boost     int64 // B x (d_s + d_r + d_rec + d_h)
	UDPRx     int64 // M_udp_rx:受信の予算と管理の配列
	UDPTx     int64 // M_udp_tx:送信の予算と管理の配列
	Frag      int64 // M_frag:再組み立ての表の保持 byte の上限
	Ping      int64 // N_ping x c_ping
	Total     int64
	// 移す間の一時の保持:boost を得るときと floor に戻るときに、送信と受信の輪の生きている範囲を新しい
	// chunk に写す間、古い chunk を合わせて持つ。1 本の接続の錠の中で起きるので、同時に起きる数は boost の
	// 枠の数以下で、最大で B x (f_s + f_r) である
	Transient int64
}

// Bound はこの Device の上界の式の値を返す。
func (d *Device) Bound() Bound { return d.s.bound() }

func (s *stack) bound() Bound {
	n := int64(len(s.conns))
	recSize := int64(unsafe.Sizeof(record{}))
	ivSize := int64(unsafe.Sizeof(interval{}))
	var b Bound
	b.Fix = int64(unsafe.Sizeof(stack{})) + n*int64(unsafe.Sizeof(tcb{})) +
		int64(len(s.connIdx.ents)+len(s.syn.idx.ents)+len(s.tw.idx.ents))*int64(unsafe.Sizeof(indexEnt{})) +
		int64(len(s.syn.rows))*int64(unsafe.Sizeof(synRow{})) + int64(len(s.syn.free))*4 +
		int64(len(s.tw.rows))*int64(unsafe.Sizeof(twRow{})) + int64(len(s.tw.free))*4 +
		int64(len(s.free))*4 +
		int64(len(s.wheel.dl))*(8+4+4+2) +
		int64(len(s.out.conns.next)+len(s.out.rows.next))*(4+4+1) +
		int64(len(s.out.ctl.buf)) + int64(len(s.out.ctl.lens))*8 +
		int64(cap(s.fired))*4 +
		chunkPoolKeep*chunkSize
	b.FloorConn = n * (sendFloor + recvFloor + floorRecords*recSize + floorIntervals*ivSize)
	b.Boost = int64(len(s.pool.slots)) * ((boostSize - sendFloor) + (boostSize - recvFloor) + (boostRecords-floorRecords)*recSize + (boostIntervals-floorIntervals)*ivSize)
	dg := int64(unsafe.Sizeof(udpDgram{}))
	ck := int64(unsafe.Sizeof(udpChunkRec{}))
	b.UDPRx = udpRxBytes + int64(len(s.udp.dg[dirRx]))*(dg+4) + int64(len(s.udp.ck))*(ck+4)/2
	b.UDPTx = udpTxBytes + int64(len(s.udp.dg[dirTx]))*(dg+4) + int64(len(s.udp.ck))*(ck+4)/2
	b.Frag = int64(fragLimits.Bytes)
	b.Ping = pingEndpoints * (int64(s.mtu) + int64(unsafe.Sizeof(pingEP{})))
	b.Total = b.Fix + b.FloorConn + b.Boost + b.UDPRx + b.UDPTx + b.Frag + b.Ping
	b.Transient = int64(len(s.pool.slots)) * (sendFloor + recvFloor)
	return b
}
