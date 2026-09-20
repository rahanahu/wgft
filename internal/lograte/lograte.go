// Package lograte は、同じ理由で繰り返し出るログを間引く門を持つ(仕様 10.4 節)。
// 上限で拒んだこと(Resource Guard)と、宛先への dial の失敗の両方が使うので、どちらの
// package にも属さない小さな package に置く(設計文書 7a.10 節の型の分割)。
package lograte

import (
	"sync"
	"time"
)

// Gate は、同じ事象のログを 1 分に 1 回までに絞る。ゼロ値から使える。
type Gate struct {
	mu   sync.Mutex
	next time.Time
}

// Allow は今ログを出してよいか。
func (g *Gate) Allow() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if now.Before(g.next) {
		return false
	}
	g.next = now.Add(time.Minute)
	return true
}
