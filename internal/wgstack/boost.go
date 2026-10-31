package wgstack

import (
	"slices"
	"sync"
)

// boost の枠(設計文書の「boost の取得と floor への戻り」と tcp-buffers.md)。枠はプロセスで 1 つの集まりで、
// 需要のある接続が 1 本につき 1 つを取る。空きが無いときは、1 秒の間どちらの向きにも需要の無い保有者を
// 探し、floor に戻せた 1 本の枠を受け取る。閉じた接続の枠は、接続の枠を返すときに返す。

// boostPool は枠の集まり。mu は末端の錠である。
type boostPool struct {
	mu    sync.Mutex
	slots []*tcb
}

func newBoostPool(n int) *boostPool { return &boostPool{slots: make([]*tcb, n)} }

// processBoost はプロセスのすべての Device が分け合う枠の集まり。
var processBoost = newBoostPool(boostSlots)

// demand は 1 つの向きの需要の区間。区間は入出力が成功したときに時刻で区切る(tcp-buffers.md)。
type demand struct {
	start int64
	n     int
	hit   bool
}

// add は now に n byte を記録し、この区間で初めて demandBytes に届いたときに真を返す。
func (d *demand) add(now int64, n int) bool {
	if now-d.start > int64(demandWindow) {
		d.start, d.n, d.hit = now, 0, false
	}
	d.n += n
	if d.n >= demandBytes && !d.hit {
		d.hit = true
		return true
	}
	return false
}

// boostDir は需要の向き。
type boostDir uint8

const (
	boostSend boostDir = iota
	boostRecv
)

// noteDemand は需要を記録する。枠を求める必要があれば真を返す。呼び出し側は接続の錠を離してから
// tryBoost を呼ぶ。受信の向きの需要で、すでに送信の向きの需要で枠を持つ接続は、同じ枠のまま受信の窓を
// 広げる。mu を持って呼ぶ。
func (c *tcb) noteDemand(dir boostDir, now int64) bool {
	c.lastDemand = now
	if c.s.boostPolicy == BoostNever {
		return false
	}
	if !c.boosted {
		return true
	}
	if dir == boostRecv && !c.rcvBoost {
		c.growRecv()
	}
	return false
}

// tryBoost は接続 c(世代 gen)に枠を求める。錠を持たずに呼ぶ。
func (s *stack) tryBoost(c *tcb, gen uint32, dir boostDir) {
	if !s.pool.acquire(c) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen || c.boosted || c.appClosed || c.state == stFree || c.state == stClosed {
		s.pool.release(c)
		return
	}
	s.boostGranted.Add(1)
	c.boosted = true
	c.recs.resize(make([]record, boostRecords))
	c.snd.resize(boostSize, [][2]uint64{{c.unaOff, c.tailOff}})
	c.sndCap = boostSize
	if dir == boostRecv {
		c.growRecv()
	}
	if c.onBoost != nil {
		c.onBoost(true)
	}
	c.signalWrite()
	c.afterInput(s.clock())
}

// growRecv は受信の窓を floor より先へ開く。mu を持ち、枠を持つ接続で呼ぶ。
func (c *tcb) growRecv() {
	c.rcvBoost = true
	c.rcv.r.resize(boostSize, c.rcv.written())
	c.rcv.setIntervals(make([]interval, boostIntervals))
	c.rcvCap = boostSize
	// 広げた窓を早く知らせる
	if uint64(c.rcvWindow())*2 <= c.rcvCap {
		c.ackNow = true
	}
}

// releaseBoost は枠を持っていれば返す。f は呼ばない(閉じた接続の枠を返すときには呼ばない約束)。
// 送信と受信の容量は呼び出し側が戻す。mu を持って呼ぶ。
func (c *tcb) releaseBoost() {
	if !c.boosted {
		return
	}
	c.boosted, c.rcvBoost = false, false
	c.s.pool.release(c)
}

// demote は需要の無い保有者を floor に戻せたかを返す。戻すのは次の条件がすべて成り立つときだけである。
// 受信は、保持する最も右の byte(順序外のデータを含む)が最も古い未読の byte から floor の内側にあること。
// 送信は、送信の輪の byte が floor 以下で、確認を待つ記録の数が floor の記録の輪の容量以下であること。
// 最後に、OnBoost で登録した関数が f(false) に真を返すこと。戻した後も広告した右端は縮めず、floor の
// 外に届いたデータは受信のバッファに入れずに捨てる(inputData の limit)。mu を持って呼ぶ。
func (c *tcb) demote(now int64) bool {
	if !c.boosted || now-c.lastDemand < int64(idleReclaim) {
		return false
	}
	if c.rcv.rightmost()-c.rcv.readOff > recvFloor || c.rcv.n > floorIntervals {
		return false
	}
	if c.tailOff-c.unaOff > sendFloor || c.recs.n > floorRecords {
		return false
	}
	if c.onBoost != nil && !c.onBoost(false) {
		return false
	}
	c.boosted, c.rcvBoost = false, false
	c.snd.resize(sendFloor, [][2]uint64{{c.unaOff, c.tailOff}})
	c.sndCap = sendFloor
	c.rcv.r.resize(recvFloor, c.rcv.written())
	c.rcv.setIntervals(c.floorIv)
	c.rcvCap = recvFloor
	c.recs.resize(c.floorRecs)
	c.s.boostReclaimed.Add(1)
	return true
}

// acquire は c に枠を 1 つ貸す。空きが無ければ、写しの保有者を順に TryLock で取り、需要の無い保有者を
// floor に戻して枠を受け取る。待たない。呼び出し側は c の錠を持たない。
func (p *boostPool) acquire(c *tcb) bool {
	p.mu.Lock()
	if slices.Contains(p.slots, c) {
		p.mu.Unlock()
		return false
	}
	if i := slices.Index(p.slots, nil); i >= 0 {
		p.slots[i] = c
		p.mu.Unlock()
		return true
	}
	snap := slices.Clone(p.slots)
	p.mu.Unlock()
	for _, h := range snap {
		if h == c || !h.mu.TryLock() {
			continue
		}
		ok := h.demote(h.s.clock())
		if ok {
			p.mu.Lock()
			if i := slices.Index(p.slots, h); i >= 0 {
				p.slots[i] = c
			} else {
				ok = false
			}
			p.mu.Unlock()
		}
		h.mu.Unlock()
		if ok {
			return true
		}
	}
	return false
}

func (p *boostPool) release(c *tcb) {
	p.mu.Lock()
	if i := slices.Index(p.slots, c); i >= 0 {
		p.slots[i] = nil
	}
	p.mu.Unlock()
}

func (p *boostPool) held() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, s := range p.slots {
		if s != nil {
			n++
		}
	}
	return n
}
