// Package flowcap は、同時に保持するフロー数の上限を数える(仕様 7 節の「同時フロー数の上限」)。
// エージェントの中継(relay)と vpsd のプロキシモードの中継(proxyrelay)が共有する。
// ルールごとの上限は、所属ルールが変わりうるので呼び出し側がリスナーの現在値で数える。
package flowcap

import (
	"net/netip"
	"sync"
	"time"
)

// 仕様 7 節の値。プロセス全体の上限(WGFT_MAX_UDP_FLOWS、WGFT_MAX_TCP_FLOWS)と、
// 接続元 IP ごとの上限(WGFT_MAX_UDP_FLOWS_PER_SOURCE、WGFT_MAX_TCP_FLOWS_PER_SOURCE。
// vpsd だけの設定。11a 節)が設定項目で、ここはその既定値。ルールごとの上限は設定項目ではなく、
// プロセス全体の上限から導く(Limits.UDPPerRuleCap、TCPPerRuleCap)。
const (
	UDPTotal     = 8192
	UDPPerSource = 256
	TCPTotal     = 2048
	TCPPerSource = 128

	// ルールごとの上限の下限。設定項目にする前の固定値で、全体の上限を下げた構成で
	// ルール 1 本の上限が以前より下がらないようにする(Limits.UDPPerRuleCap)
	UDPPerRuleFloor = 4096
	TCPPerRuleFloor = 1024

	// プロセス全体の上限に設定できる範囲
	TotalMin = 16
	TotalMax = 65535
)

// Limits はプロセス全体と、接続元 IP ごとの上限(設定値)。どの項目もゼロ値なら既定値を使う
// (WithDefaults)。接続元ごとの上限を外すときは PerSourceOff を入れる。設定の 0(上限なし)は
// 設定層がこれに写す。ゼロ値を「上限なし」にすると、設定層を通らずに組み立てた Limits で
// 守りが黙って外れるためである。
type Limits struct {
	UDPTotal     int
	TCPTotal     int
	UDPPerSource int
	TCPPerSource int
}

// PerSourceOff は Limits.UDPPerSource/TCPPerSource で、接続元 IP ごとの上限を外すことを表す。
const PerSourceOff = -1

// WithDefaults はゼロ値の項目を既定値で埋める。
func (l Limits) WithDefaults() Limits {
	if l.UDPPerSource == 0 {
		l.UDPPerSource = UDPPerSource
	}
	if l.TCPPerSource == 0 {
		l.TCPPerSource = TCPPerSource
	}
	if l.UDPTotal <= 0 {
		l.UDPTotal = UDPTotal
	}
	if l.TCPTotal <= 0 {
		l.TCPTotal = TCPTotal
	}
	return l
}

// UDPPerSourceCap と TCPPerSourceCap は、接続元 IP ごとの上限の実効値。0 は数えない
// (Counter.PerSource と nft.Config の約束に合わせる)。
func (l Limits) UDPPerSourceCap() int { return max(l.WithDefaults().UDPPerSource, 0) }
func (l Limits) TCPPerSourceCap() int { return max(l.WithDefaults().TCPPerSource, 0) }

// UDPPerRuleCap と TCPPerRuleCap は、ルールごとの同時フロー数の上限をプロセス全体の上限から
// 導く(仕様 7 節)。全体の半分とするが、以前の固定値と全体の上限の小さいほうを下回らない。
// 全体を上げれば一緒に上がり、既定や全体を下げた構成では以前と同じ値になる。
func (l Limits) UDPPerRuleCap() int { return perRuleCap(l.WithDefaults().UDPTotal, UDPPerRuleFloor) }
func (l Limits) TCPPerRuleCap() int { return perRuleCap(l.WithDefaults().TCPTotal, TCPPerRuleFloor) }

func perRuleCap(total, floor int) int { return max(total/2, min(floor, total), 1) }

// MemoryLimit は、この上限で動くプロセスに設定するメモリのソフト上限(バイト)。
// 係数はラボの実測からの定数で、ホストのメモリの量は見ない(仕様 7 節)。
func (l Limits) MemoryLimit() int64 {
	l = l.WithDefaults()
	return 32<<20 + int64(l.UDPTotal)*(12<<10) + int64(l.TCPTotal)*(44<<10)
}

// Counter はプロセス全体と接続元 IP ごとのフロー数を数える。ゼロ値は上限なし。
type Counter struct {
	Total     int // プロセス全体の上限。0 は上限なし
	PerSource int // 接続元 IP ごとの上限。0 は数えない(エージェント、または設定で無効にした場合)

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
