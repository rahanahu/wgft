//go:build linux

package vpsd

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// 鍵の変更の頻度の上限(設計文書 5.2 節)。登録ごとのトークンバケットで、続けて keyChangeBurst 回までと、
// その後は keyChangeEvery に 1 回までを通す。wgft は自分から鍵を変えず、正規の変更は運用者の操作
// (rotate-key、古い agent.json への戻し)だけなので、続けての数回を通せば足りる。カーネルモードでは
// 鍵の変更のたびに table inet wgft の全体を差し替え、全エージェントの meter と ct count の状態を
// 作り直すので、恒久トークンの持ち主が起こせる回数をこの上限で抑える。
const (
	keyChangeBurst = 3
	keyChangeEvery = 10 * time.Minute
)

// now は Daemon の時計である。単体テストは clock で差し替える。
func (d *Daemon) now() time.Time {
	if d.clock != nil {
		return d.clock()
	}
	return time.Now()
}

// keyChangeLimiter は登録(エージェントの名前と登録 identity の組)ごとのバケットを持つ。登録をし直すと
// identity が変わるので、新しい登録は満ちたバケットから始まる。満ちたバケットは持っていても
// 持っていなくても同じなので、試すたびに表から外し、表の大きさを最近鍵を変えた登録の数に留める。
// 状態はプロセスのメモリの上だけに持つ。ゼロ値から使える。
type keyChangeLimiter struct {
	mu    sync.Mutex
	byReg map[keyChangeReg]*rate.Limiter
}

type keyChangeReg struct{ name, identity string }

// allow は、その登録の鍵の変更を now の時点で 1 回通すかどうかを返し、通すなら 1 回分を使う。
func (l *keyChangeLimiter) allow(name, identity string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byReg == nil {
		l.byReg = make(map[keyChangeReg]*rate.Limiter)
	}
	for reg, lim := range l.byReg {
		if lim.TokensAt(now) >= keyChangeBurst {
			delete(l.byReg, reg)
		}
	}
	reg := keyChangeReg{name, identity}
	lim, ok := l.byReg[reg]
	if !ok {
		// 新しいバケットは満ちた状態から始まる
		lim = rate.NewLimiter(rate.Every(keyChangeEvery), keyChangeBurst)
		l.byReg[reg] = lim
	}
	return lim.AllowN(now, 1)
}
