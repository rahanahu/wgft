//go:build linux

package vpsd

import (
	"sync"
	"time"
)

// genLag は、エージェントごとに、server の今のルール集合の世代に追いついていない状態が
// いつ始まったかを持つ(設計文書 10.2a 節「ルール集合の世代の遅れ」)。管理用 API の
// エージェント一覧の generation_behind_since がこれを返し、`agent.rules_received` が
// 届きかけの遅れと止まった遅れを見分けるのに使う。
//
// 持つのはメモリの上だけである。server を再起動すると失われ、起動の後に初めて遅れを
// 観測した時刻から数え直す。起動の前から続いていた遅れの長さを server は知らないためである。
//
// 始まりの時刻は、そのエージェントが server の今の世代を報告したときにだけ消える。遅れの
// 間に server の世代がさらに進んでも、始まりの時刻は動かさない。動かすと、変更が続く間は
// いつまでも閾値に届かない。
//
// ゼロ値のまま使える。テストが組み立てる Daemon{} でも Agents() が動くようにするためである。
type genLag struct {
	mu     sync.Mutex
	server uint64 // 観測した server の世代の最大値
	agents map[string]*agentLag
}

type agentLag struct {
	gen   uint64    // 直近のハートビートが報告した世代
	since time.Time // 遅れの始まり。遅れていなければゼロ値
}

// serverAt は server の世代 gen を観測したことを記録する。世代は減らないので、古い読み取りが
// 後から届いても無視する。世代が進んだら、その世代を持たないエージェントのうち、まだ遅れの
// 始まりを持たないものに now を記録する。
func (g *genLag) serverAt(gen uint64, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if gen <= g.server {
		return
	}
	g.server = gen
	for _, a := range g.agents {
		if a.gen < gen && a.since.IsZero() {
			a.since = now
		}
	}
}

// reported は、エージェントがハートビートで世代 gen を報告したことを記録する。server の世代に
// 追いついていれば遅れの始まりを消し、追いついていなければ、まだ始まりが無い場合に限り now を
// 記録する。
func (g *genLag) reported(agent string, gen uint64, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.agents == nil {
		g.agents = map[string]*agentLag{}
	}
	a := g.agents[agent]
	if a == nil {
		a = &agentLag{}
		g.agents[agent] = a
	}
	a.gen = gen
	switch {
	case gen >= g.server:
		a.since = time.Time{}
	case a.since.IsZero():
		a.since = now
	}
}

// behindSince は、そのエージェントの遅れの始まりを返す。遅れていなければ ok は false である。
func (g *genLag) behindSince(agent string) (since time.Time, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	a := g.agents[agent]
	if a == nil || a.since.IsZero() {
		return time.Time{}, false
	}
	return a.since, true
}

// forget はエージェントの記録を消す。恒久トークンを無効化したときに呼ぶ。
func (g *genLag) forget(agent string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.agents, agent)
}
