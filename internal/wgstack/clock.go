package wgstack

import (
	"sync"
	"time"
)

// Clock は核が使う単調な時計。Now は任意の起点からの経過時間を返し、後ろへ戻らない。核は時計を
// 直接読まず、Device が読んだ値を核の操作に渡す(設計文書の「並行性と時計」)。
type Clock interface {
	Now() time.Duration
}

// monoClock は本番の時計。time.Since が使う単調な時計の値を返す。
type monoClock struct{ start time.Time }

func (c monoClock) Now() time.Duration { return time.Since(c.start) }

// ManualClock は試験が手で進める時計。ゼロ値から使え、時刻 0 から始まる。Config.Clock に渡すと、
// Device はタイマーの goroutine を作らず、呼び出し側が Advance の後に Device.Tick を呼ぶ。
type ManualClock struct {
	mu  sync.Mutex
	now time.Duration
}

// NewManualClock は時刻 0 の ManualClock を返す。
func NewManualClock() *ManualClock { return &ManualClock{} }

// Now は今の時刻を返す。
func (c *ManualClock) Now() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance は時刻を d だけ進める。負の d は無視する。
func (c *ManualClock) Advance(d time.Duration) {
	if d <= 0 {
		return
	}
	c.mu.Lock()
	c.now += d
	c.mu.Unlock()
}
