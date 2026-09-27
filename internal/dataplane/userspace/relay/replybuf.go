package relay

import (
	"sync"
	"sync/atomic"
	"time"
)

// replySlots は、UDP の応答のバッファをプロセス全体で同時に貸せる数(設計文書 7 節)。
// 応答のバッファの保持は、この数 × udpBufMax を上限に持つ。設定項目にはしない。
const replySlots = 64

// replyPool は UDP の応答のバッファの貸し出しである。上限がかかるのは同時に貸し出す数(枠)で、
// 返されて誰も借りていないバッファは sync.Pool が持ち、GC が回収する。枠が無いセッションは、
// 枠が空くか、そのセッションが閉じるまで待つ(待ち受けを閉じるとそのセッションも閉じる)。
// 待つ間、応答のデータグラムは宛先側の接続の受信のキュー(vpsd では netstack の endpoint、
// エージェントではカーネルのソケット)に留まるので、この待ちでデータグラムは失われない。
//
// 枠を持つ間の仕事は、バッファへの読み取り 1 回と公開側への送信の試み 1 回だけである。
// vpsd の公開側の送信はカーネルのソケットの送信バッファが満杯なら待たずに捨てる(sendonce_unix.go)
// ので、vpsd では 1 つの待ち受けの詰まりが枠を持ち続けることは無い。エージェントの公開側の送信は
// netstack の endpoint の送信バッファが使われている間は待つ(udp.go の waitingSender)。
type replyPool struct {
	slots chan struct{} // 空きの枠 1 つにつき値 1 つ
	bufs  sync.Pool

	// 待ちの観測。ログにも status にも出さず、試験とラボから読む(設計文書 7 節)
	waits     atomic.Uint64 // 枠が無くて待った回数(取り消された待ちを含む)
	cancelled atomic.Uint64 // 待ちのうち、セッションの終了で取り消された回数
	waitNanos atomic.Int64  // 枠を得た待ちの時間の合計。取り消された待ちは含めない
	maxWait   atomic.Int64  // 枠を得た待ちの最長。取り消された待ち(無通信で閉じたセッションの長い待ち)は含めない
	// Test-only observation after a wait has started. Nil in the product.
	waitHook func()
}

// defaultReplyPool はプロセス全体の貸し出しである。vpsd の Manager もエージェントのトンネルごとの
// Manager も、これを使う。エージェントがトンネルを作り直しても、枠の数はプロセスで 1 つのままである。
var defaultReplyPool = newReplyPool(replySlots)

func newReplyPool(k int) *replyPool {
	p := &replyPool{slots: make(chan struct{}, k), bufs: sync.Pool{New: func() any { b := make([]byte, udpBufMax); return &b }}}
	for i := 0; i < k; i++ {
		p.slots <- struct{}{}
	}
	return p
}

// acquire は枠を 1 つ取り、バッファを貸す。枠が無ければ、空くか、cancel が閉じるまで待つ。
// 待ちを取り消されたら偽を返す。cancel はセッションの closed で、待ち受けを閉じるときも
// その待ち受けのセッションを全部閉じるので、待ち受けの終了でも待ちは取り消される。
func (p *replyPool) acquire(cancel <-chan struct{}) (*[]byte, bool) {
	select {
	case <-p.slots:
		return p.bufs.Get().(*[]byte), true
	default:
	}
	// 枠が無い。待ちの時間を数える
	if p.waitHook != nil {
		p.waitHook()
	}
	start := time.Now()
	p.waits.Add(1)
	select {
	case <-p.slots:
		p.noteWait(time.Since(start))
		return p.bufs.Get().(*[]byte), true
	case <-cancel:
	}
	p.cancelled.Add(1)
	return nil, false
}

func (p *replyPool) noteWait(d time.Duration) {
	p.waitNanos.Add(int64(d))
	for {
		cur := p.maxWait.Load()
		if int64(d) <= cur || p.maxWait.CompareAndSwap(cur, int64(d)) {
			return
		}
	}
}

// release はバッファと枠を返す。
func (p *replyPool) release(b *[]byte) {
	p.bufs.Put(b)
	p.slots <- struct{}{}
}

// free は今空いている枠の数。試験用。
func (p *replyPool) free() int { return len(p.slots) }

// replyWaitStats は枠の待ちの観測値である。Total と Longest は枠を得た待ちだけの値で、
// 取り消された待ちは Cancelled に数える。
type replyWaitStats struct {
	Waits     uint64
	Cancelled uint64
	Total     time.Duration
	Longest   time.Duration
}

func (p *replyPool) stats() replyWaitStats {
	return replyWaitStats{Waits: p.waits.Load(), Cancelled: p.cancelled.Load(), Total: time.Duration(p.waitNanos.Load()), Longest: time.Duration(p.maxWait.Load())}
}
