// Package flowcap は、同時に保持するフロー数の上限を数える(仕様 7 節の「同時フロー数の上限」)。
// エージェントの中継(relay)と vpsd のプロキシモードの中継(proxyrelay)が共有する。
// ルールごとの上限は、所属ルールが変わりうるので呼び出し側がリスナーの現在値で数える。
package flowcap

import (
	"net/netip"
	"sync"
	"time"
)

// 仕様 7 節の値。プロセス全体の上限だけが設定項目(WGFT_MAX_UDP_FLOWS、WGFT_MAX_TCP_FLOWS)で、ここはその既定値。
const (
	UDPPerRule   = 4096
	UDPTotal     = 8192
	UDPPerSource = 256
	TCPPerRule   = 1024
	TCPTotal     = 2048
	TCPPerSource = 128

	// プロセス全体の上限に設定できる範囲
	TotalMin = 16
	TotalMax = 65535
)

// Limits はプロセス全体の上限(設定値)。ゼロ値の項目は既定値を使う。
type Limits struct {
	UDPTotal int
	TCPTotal int
}

// WithDefaults はゼロ値の項目を既定値で埋める。
func (l Limits) WithDefaults() Limits {
	if l.UDPTotal <= 0 {
		l.UDPTotal = UDPTotal
	}
	if l.TCPTotal <= 0 {
		l.TCPTotal = TCPTotal
	}
	return l
}

// MemoryLimit は、この上限で動くプロセスに設定するメモリのソフト上限(バイト)。
// 係数はラボの実測からの定数で、ホストのメモリの量は見ない(仕様 7 節)。
func (l Limits) MemoryLimit() int64 {
	l = l.WithDefaults()
	return 32<<20 + int64(l.UDPTotal)*(12<<10) + int64(l.TCPTotal)*(44<<10)
}

// Counter はプロセス全体と接続元 IP ごとのフロー数を数える。ゼロ値は上限なし。
type Counter struct {
	Total     int // プロセス全体の上限。0 は上限なし
	PerSource int // 接続元 IP ごとの上限。0 は数えない(エージェント)

	mu    sync.Mutex
	total int
	bySrc map[netip.Addr]int
}

// Acquire はフロー 1 つ分の枠を取る。上限に達していれば偽を返し、何も数えない。
// 真を返したら、フローの終了時に同じ src で Release を 1 回呼ぶ。nil の Counter は常に真を返す。
func (c *Counter) Acquire(src netip.Addr) bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Total > 0 && c.total >= c.Total {
		return false
	}
	if c.PerSource > 0 {
		if c.bySrc[src] >= c.PerSource {
			return false
		}
		if c.bySrc == nil {
			c.bySrc = map[netip.Addr]int{}
		}
		c.bySrc[src]++
	}
	c.total++
	return true
}

// Release は Acquire で取った枠を返す。
func (c *Counter) Release(src netip.Addr) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total--
	if c.PerSource > 0 {
		if n := c.bySrc[src]; n <= 1 {
			delete(c.bySrc, src)
		} else {
			c.bySrc[src] = n - 1
		}
	}
}

// Len は現在のフロー数。
func (c *Counter) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

// LogGate は、上限で拒んだことのログを 1 分に 1 回までに絞る。
type LogGate struct {
	mu   sync.Mutex
	next time.Time
}

// Allow は今ログを出してよいか。
func (g *LogGate) Allow() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if now.Before(g.next) {
		return false
	}
	g.next = now.Add(time.Minute)
	return true
}
