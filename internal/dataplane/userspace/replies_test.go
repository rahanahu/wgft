package userspace

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/proto"
)

func udpPlan(ports ...planner.PortPlan) planner.Plan { return planner.Plan{Ports: ports} }

func udpPort(id, agent, target string) planner.PortPlan {
	return planner.PortPlan{RuleID: id, Agent: agent, Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2456},
		Forwarding: model.Transparent, Target: target, AgentAddr: netip.MustParseAddr("10.200.0.2")}
}

// 観測の起点(設計文書 10.2a 節「UDP の応答の観測」)。同じルールの公開し直しでは起点を保ち、
// ルール ID、持ち主のエージェント、宛先のどれかが変わると、その時刻から始め直す。公開しなくなった
// ルールと TCP のルールは項目を持たない。起点より前に待ち受けが読んだ応答は、前の同一性のものなので
// 返さない。
func TestUserspaceUDPReplyWatch(t *testing.T) {
	t0 := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	now := t0
	b := New(Options{Logf: func(string, ...any) {}})
	defer b.relay.Close()
	b.now = func() time.Time { return now }

	tcp := udpPort("r_tcp", "home", "192.168.1.20:80")
	tcp.Proto = proto.TCP
	b.watchReplies(udpPlan(udpPort("r_a", "home", "192.168.1.20:2456"), udpPort("r_b", "home", "192.168.1.20:2457"), tcp))
	if _, ok := b.replies["r_tcp"]; ok {
		t.Fatal("a TCP rule is watched")
	}

	now = t0.Add(time.Minute)
	b.watchReplies(udpPlan(
		udpPort("r_a", "home", "192.168.1.20:2456"),   // 変わらない
		udpPort("r_b", "home", "192.168.1.21:2457"),   // 宛先が変わった
		udpPort("r_c", "office", "192.168.1.20:2458"), // 新しい
	))
	want := map[string]time.Time{"r_a": t0, "r_b": now, "r_c": now}
	if len(b.replies) != len(want) {
		t.Fatalf("watched %v, want %v", b.replies, want)
	}
	for id, since := range want {
		if got := b.replies[id].since; !got.Equal(since) {
			t.Errorf("%s since %v, want %v", id, got, since)
		}
	}

	// 持ち主のエージェントが変わっても始め直す
	later := now.Add(time.Minute)
	now = later
	b.watchReplies(udpPlan(udpPort("r_a", "office", "192.168.1.20:2456")))
	if got := b.replies["r_a"].since; !got.Equal(later) {
		t.Errorf("after the agent changed: since %v, want %v", got, later)
	}
	if len(b.replies) != 1 {
		t.Errorf("rules that left the plan are still watched: %v", b.replies)
	}

	got := udpRepliesOf(b.replies, map[string]time.Time{"r_a": later.Add(-time.Second)})
	if r := got["r_a"]; !r.Last.IsZero() || !r.Since.Equal(later) {
		t.Errorf("a reply before the watch began: %+v, want none", r)
	}
	seen := later.Add(5 * time.Second)
	got = udpRepliesOf(b.replies, map[string]time.Time{"r_a": seen})
	if r := got["r_a"]; !r.Last.Equal(seen) {
		t.Errorf("a reply after the watch began: %+v, want last %v", r, seen)
	}

	// 公開ポートとエージェントのアドレスが変わっても始め直す(安全側に加えた同一性)
	for _, tc := range []struct {
		name string
		edit func(*planner.PortPlan)
	}{
		{"ports", func(pp *planner.PortPlan) { pp.ListenPort = proto.PortRange{Lo: 2456, Hi: 2458} }},
		{"agent address", func(pp *planner.PortPlan) { pp.AgentAddr = netip.MustParseAddr("10.200.0.9") }},
	} {
		base := udpPort("r_id", "home", "192.168.1.20:2456")
		b.watchReplies(udpPlan(base))
		start := b.replies["r_id"].since
		now = now.Add(time.Minute)
		changed := base
		tc.edit(&changed)
		b.watchReplies(udpPlan(changed))
		if got := b.replies["r_id"].since; got.Equal(start) || !got.Equal(now) {
			t.Errorf("after the %s changed: since %v, want %v", tc.name, got, now)
		}
	}
}
