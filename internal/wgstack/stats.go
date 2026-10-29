package wgstack

import "unsafe"

// Stats は Device が数える保持と事象。保持の欄は会計が数える今の量で、上界の試験と fuzzing が上界の式と
// 比べる。数は `wgft status`、管理用 API、wire protocol に載せない(設計文書の「尽きたときの動作」)。
type Stats struct {
	Conns        int   // 使っている接続の枠
	SynRows      int   // 握手の途中の行
	TWRows       int   // TIME_WAIT と FIN_WAIT_2 の行
	AcceptQueued int   // accept の待ち行列の接続(移している途中の行を含む)
	CtlQueued    int   // 制御の輪に積んだ packet
	ChunkBytes   int64 // 送信と受信の輪が持つ chunk の byte
	RecordBytes  int64 // 送信の記録の輪の byte(floor の輪と boost の輪)
	Boosted      int   // boost の枠を持つこの Device の接続
	Reserved     int64 // 使っている接続の枠の送信と受信の容量の和

	MSSFloorDrops      uint64
	SynTableFull       uint64
	AcceptOverflow     uint64
	TWEvicted          uint64
	CtlDropped         uint64
	OOODropped         uint64
	RecvTrimmed        uint64
	ChallengeLimited   uint64
	FragmentsDropped   uint64
	UDPDropped         uint64
	ICMPDropped        uint64
	Malformed          uint64
	BadChecksum        uint64
	NotLocal           uint64
	RetransmitAborts   uint64
	ProbeAborts        uint64
	BoostGranted       uint64
	BoostReclaimed     uint64
	HeldChunksInPool   int64 // 輪が持つ chunk の数(chunkPool の会計)
	ReclaimableInBoost int   // プロセスの boost の枠のうち使っている数
}

// Stats は今の保持と数を返す。
func (d *Device) Stats() Stats { return d.s.stats() }

func (s *stack) stats() Stats {
	var st Stats
	recSize := int64(unsafe.Sizeof(record{}))
	for i := range s.conns {
		c := &s.conns[i]
		c.mu.Lock()
		if c.floorRecs != nil {
			st.RecordBytes += int64(len(c.floorRecs)) * recSize
		}
		if c.state != stFree {
			st.Conns++
			st.ChunkBytes += int64(c.snd.heldChunks()+c.rcv.r.heldChunks()) * chunkSize
			st.Reserved += int64(c.sndCap + c.rcvCap)
			if c.boosted {
				st.Boosted++
				st.RecordBytes += int64(len(c.recs.recs)) * recSize
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
	return st
}

// Bound は上界の式(設計文書の「上界の式」)の TCP の項を、この Device の表の大きさと、この build の構造の
// 大きさで求めた値。UDP、ICMP、再組み立ての項はこの段階に無いので含めない。boost の項は、プロセスの枠の
// すべてをこの Device が持つとして数える。
type Bound struct {
	Fix       int64 // M_fix:接続の枠の構造、hash の表、行の表、タイマーの輪、出力の list と制御の輪、chunk の置き場
	FloorConn int64 // N_c x (f_s + f_r + r_f)
	Boost     int64 // B x (d_s + d_r + d_rec)
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
	var b Bound
	b.Fix = n*int64(unsafe.Sizeof(tcb{})) +
		int64(len(s.connIdx.ents)+len(s.syn.idx.ents)+len(s.tw.idx.ents))*int64(unsafe.Sizeof(indexEnt{})) +
		int64(len(s.syn.rows))*int64(unsafe.Sizeof(synRow{})) + int64(len(s.syn.free))*4 +
		int64(len(s.tw.rows))*int64(unsafe.Sizeof(twRow{})) + int64(len(s.tw.free))*4 +
		int64(len(s.free))*4 +
		int64(len(s.wheel.dl))*(8+4+4+2) +
		int64(len(s.out.conns.next)+len(s.out.rows.next))*(4+4+1) +
		int64(len(s.out.ctl.buf)) + int64(len(s.out.ctl.lens))*8 +
		int64(cap(s.fired))*4 +
		chunkPoolKeep*chunkSize
	b.FloorConn = n * (sendFloor + recvFloor + floorRecords*recSize)
	b.Boost = int64(len(s.pool.slots)) * ((boostSize - sendFloor) + (boostSize - recvFloor) + (boostRecords-floorRecords)*recSize)
	b.Total = b.Fix + b.FloorConn + b.Boost
	b.Transient = int64(len(s.pool.slots)) * (sendFloor + recvFloor)
	return b
}
