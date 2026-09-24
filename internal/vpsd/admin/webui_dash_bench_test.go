package admin

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// benchDashServer は、n 本のルールを 10 台のエージェントに振り分けた Server を作る。どのエージェントも
// 接続していて、自分のルールをすべて ok と報告している。
func benchDashServer(b *testing.B, n int) *Server {
	b.Helper()
	st, err := store.Open(filepath.Join(b.TempDir(), "s.sqlite"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { st.Close() })
	const agentCount = 10
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		for i := 0; i < n; i++ {
			port := uint16(10000 + i)
			rules = append(rules, proto.Rule{ID: fmt.Sprintf("r_%04d", i), Agent: fmt.Sprintf("a%d", i%agentCount),
				Group: fmt.Sprintf("g%d", i%7), Proto: proto.TCP, ListenPort: proto.PortRange{Lo: port, Hi: port},
				Target: fmt.Sprintf("192.168.1.20:%d", port), VPSMode: proto.ModeKernel, Enabled: true})
		}
		return rules, nil
	}); err != nil {
		b.Fatal(err)
	}
	gen, err := st.Generation()
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	agents := make([]AgentInfo, agentCount)
	for a := range agents {
		agents[a] = AgentInfo{Name: fmt.Sprintf("a%d", a), Connected: true, Generation: gen,
			LastHeartbeat: now.Format(time.RFC3339), LastHandshake: now.Format(time.RFC3339),
			Tunnel: TunnelStatus{State: proto.StatusOK}}
	}
	for i := 0; i < n; i++ {
		a := &agents[i%agentCount]
		a.Rules = append(a.Rules, proto.RuleStatus{ID: fmt.Sprintf("r_%04d", i), State: proto.StatusOK})
	}
	return New(&countingBackend{fakeBackend: fakeBackend{st: st, agents: agents, warnings: []Warning{}}})
}

// BenchmarkBuildDash は、ダッシュボードの 1 回の組み立ての費用をルールの本数ごとに測る。ページ全体と
// 4 つの部分更新が 5 秒ごとにこれを呼ぶ。withRules=false はエージェント一覧と警告の部分更新である。診断の印の組み立てがルールの本数に対して線形であることは、
// 本数を 10 倍にしたときの時間の伸びで確かめる(go test -bench BuildDash -run '^$')。
func BenchmarkBuildDash(b *testing.B) {
	for _, n := range []int{100, 1000} {
		for _, withRules := range []bool{true, false} {
			b.Run(fmt.Sprintf("rules=%d/withRules=%v", n, withRules), func(b *testing.B) {
				s := benchDashServer(b, n)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := s.buildDash("en", withRules); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
