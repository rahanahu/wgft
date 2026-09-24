//go:build linux

package linuxkernel

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/proto"
)

// replyClock は単体テストの時計。進めた分だけ進む。
type replyClock struct{ t time.Time }

func (c *replyClock) now() time.Time          { return c.t }
func (c *replyClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newReplyClock() *replyClock {
	return &replyClock{t: time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)}
}
func udpPort(id, agent, target string) planner.PortPlan {
	return planner.PortPlan{RuleID: id, Agent: agent, Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2457},
		Forwarding: model.Transparent, Target: target, AgentAddr: netip.MustParseAddr("10.200.0.2")}
}

func commitPlan(t *testing.T, b *Backend, ports ...planner.PortPlan) {
	t.Helper()
	p, err := b.Prepare(dataplane.Desired{Plan: planner.Plan{Ports: ports}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Commit(nil); err != nil {
		t.Fatal(err)
	}
}

func replyOf(t *testing.T, b *Backend, id string) dataplane.UDPReply {
	t.Helper()
	r, ok := b.UDPReplies()[id]
	if !ok {
		t.Fatalf("no reply entry for %s in %v", id, b.UDPReplies())
	}
	return r
}

// 起動の直後の最初の読み取りは基準にしかならない。前のプロセスが残したテーブルのカウンタが
// 0 でなくても、過去の応答の時刻を作らない(所有者の決定)。その後は、カウンタが増えた読み取りの
// 時刻だけが最後の応答になる。
func TestUDPReplyFirstReadIsOnlyABaseline(t *testing.T) {
	clk := newReplyClock()
	// 起動の後の最初の読み取りが 0 でない値を読む場合(前のプロセスのテーブルの値)を作る。
	// その値は基準にしかならない
	k := &fakeKernel{replyCounts: map[string]uint64{"r_a": 40}, keepReplies: true}
	b := newTestBackend(k)
	b.now = clk.now
	start := clk.t
	commitPlan(t, b, udpPort("r_a", "home", "192.168.1.20:2456"))
	clk.advance(10 * time.Second)
	b.PollUDPReplies()
	r := replyOf(t, b, "r_a")
	if !r.Last.IsZero() || !r.Since.Equal(start) || r.Err != nil {
		t.Fatalf("after the baseline: %+v, want since %v and no reply", r, start)
	}

	k.replyCounts["r_a"] = 41
	clk.advance(10 * time.Second)
	seen := clk.t
	b.PollUDPReplies()
	if r := replyOf(t, b, "r_a"); !r.Last.Equal(seen) || !r.Since.Equal(start) {
		t.Fatalf("after an increase: %+v, want last %v", r, seen)
	}
	// 増えなければ最後の応答の時刻は動かない
	clk.advance(10 * time.Second)
	b.PollUDPReplies()
	if r := replyOf(t, b, "r_a"); !r.Last.Equal(seen) {
		t.Fatalf("without an increase: %+v, want last %v", r, seen)
	}
}

// テーブルの差し替えでカウンタは 0 に戻る。差し替えの直前の読み取りが直前の周期からの増加を拾い、
// 差し替えの後は新しいテーブルの値を基準にする。基準を付け直さないと、差し替えの後の増加が
// 差し替えの前の値を超えるまで見えない。
func TestUDPReplyTableRebuildResetsTheBaseline(t *testing.T) {
	clk := newReplyClock()
	k := &fakeKernel{}
	b := newTestBackend(k)
	b.now = clk.now
	start := clk.t
	a := udpPort("r_a", "home", "192.168.1.20:2456")
	commitPlan(t, b, a)
	k.replyCounts["r_a"] = 50
	clk.advance(10 * time.Second)
	b.PollUDPReplies()

	// 直前の周期からの増加は、差し替えの直前の読み取りが拾う
	k.replyCounts["r_a"] = 52
	clk.advance(3 * time.Second)
	rebuilt := clk.t
	other := udpPort("r_b", "home", "192.168.1.20:3000")
	other.ListenPort = proto.PortRange{Lo: 3000, Hi: 3000}
	commitPlan(t, b, a, other)
	if r := replyOf(t, b, "r_a"); !r.Last.Equal(rebuilt) || !r.Since.Equal(start) {
		t.Fatalf("after the rebuild: %+v, want last %v (read before the flush) and since %v", r, rebuilt, start)
	}

	// 新しいテーブルの値は 0 から始まり、差し替えの前の値(52)より小さいまま増える
	k.replyCounts["r_a"] = 3
	clk.advance(10 * time.Second)
	seen := clk.t
	b.PollUDPReplies()
	if r := replyOf(t, b, "r_a"); !r.Last.Equal(seen) || !r.Since.Equal(start) {
		t.Fatalf("an increase after the rebuild: %+v, want last %v and since %v unchanged", r, seen, start)
	}
	// 差し替えで加わったルールは、差し替えの時刻から観測を始める
	if r := replyOf(t, b, "r_b"); !r.Since.Equal(rebuilt) || !r.Last.IsZero() {
		t.Fatalf("new rule: %+v, want since %v", r, rebuilt)
	}
}

// 持ち主のエージェント、宛先、ルール ID のどれかが変わったら、観測を捨てて始め直す。
// 無効にしたルールと消したルールの項目は無くなる。
func TestUDPReplyDiscardedWhenTheRuleChanges(t *testing.T) {
	cases := []struct {
		name string
		next planner.PortPlan
		id   string
	}{
		{"target", udpPort("r_a", "home", "192.168.1.21:2456"), "r_a"},
		{"agent", udpPort("r_a", "office", "192.168.1.20:2456"), "r_a"},
		{"rule id", udpPort("r_split", "home", "192.168.1.20:2456"), "r_split"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := newReplyClock()
			k := &fakeKernel{}
			b := newTestBackend(k)
			b.now = clk.now
			commitPlan(t, b, udpPort("r_a", "home", "192.168.1.20:2456"))
			k.replyCounts["r_a"] = 5
			clk.advance(10 * time.Second)
			b.PollUDPReplies()
			if replyOf(t, b, "r_a").Last.IsZero() {
				t.Fatal("no reply seen before the change")
			}
			clk.advance(time.Minute)
			changed := clk.t
			commitPlan(t, b, tc.next)
			r := replyOf(t, b, tc.id)
			if !r.Last.IsZero() || !r.Since.Equal(changed) {
				t.Fatalf("after the change: %+v, want no reply and since %v", r, changed)
			}
			if tc.id != "r_a" {
				if _, ok := b.UDPReplies()["r_a"]; ok {
					t.Fatalf("the old rule id still has an entry: %v", b.UDPReplies())
				}
			}
		})
	}

	// 無効にしたルール(Plan に現れない)は項目を持たない
	k := &fakeKernel{}
	b := newTestBackend(k)
	commitPlan(t, b, udpPort("r_a", "home", "192.168.1.20:2456"))
	commitPlan(t, b)
	if got := b.UDPReplies(); len(got) != 0 {
		t.Fatalf("after the rule left the plan: %v, want no entry", got)
	}
}

// カウンタを読めない間は、未観測と区別して「観測できない」を返す。読めるようになった最初の読み取りは
// 基準にしかならず、そこから観測を始め直す。
func TestUDPReplyReadFailureIsNotNoReply(t *testing.T) {
	clk := newReplyClock()
	k := &fakeKernel{}
	b := newTestBackend(k)
	b.now = clk.now
	commitPlan(t, b, udpPort("r_a", "home", "192.168.1.20:2456"))
	k.replyCounts["r_a"] = 5
	clk.advance(10 * time.Second)
	b.PollUDPReplies()

	k.replyErr = errors.New("netlink: permission denied")
	clk.advance(10 * time.Second)
	b.PollUDPReplies()
	if r := replyOf(t, b, "r_a"); r.Err == nil || !r.Since.IsZero() || !r.Last.IsZero() {
		t.Fatalf("while unreadable: %+v, want an error and nothing else", r)
	}

	k.replyErr = nil
	k.replyCounts["r_a"] = 9 // 読めない間に増えた分は、時刻が分からないので数えない
	clk.advance(10 * time.Second)
	back := clk.t
	b.PollUDPReplies()
	if r := replyOf(t, b, "r_a"); r.Err != nil || !r.Last.IsZero() || !r.Since.Equal(back) {
		t.Fatalf("after recovering: %+v, want since %v and no reply", r, back)
	}
}

// 行が消えたルールは観測できない。カウンタが wgft の外で減らされたら、その間の応答が分からないので
// 始め直す。差し替えが失敗したら、差し替わったかどうかが分からないので始め直す。
func TestUDPReplyContinuityLoss(t *testing.T) {
	clk := newReplyClock()
	k := &fakeKernel{}
	b := newTestBackend(k)
	b.now = clk.now
	a := udpPort("r_a", "home", "192.168.1.20:2456")
	commitPlan(t, b, a)
	k.replyCounts["r_a"] = 5
	clk.advance(10 * time.Second)
	b.PollUDPReplies()

	k.replyCounts["r_a"] = 2
	clk.advance(10 * time.Second)
	reset := clk.t
	b.PollUDPReplies()
	if r := replyOf(t, b, "r_a"); !r.Last.IsZero() || !r.Since.Equal(reset) {
		t.Fatalf("after the counter went down: %+v, want since %v and no reply", r, reset)
	}

	delete(k.replyCounts, "r_a")
	b.PollUDPReplies()
	if r := replyOf(t, b, "r_a"); !errors.Is(r.Err, errReplyRowMissing) {
		t.Fatalf("without its row: %+v, want %v", r, errReplyRowMissing)
	}

	k.replyCounts["r_a"] = 7
	b.PollUDPReplies()
	k.replyCounts["r_a"] = 8
	clk.advance(10 * time.Second)
	b.PollUDPReplies()
	if replyOf(t, b, "r_a").Last.IsZero() {
		t.Fatal("no reply seen before the failed flush")
	}
	k.flushErr = errors.New("ENOBUFS")
	p, err := b.Prepare(dataplane.Desired{Plan: planner.Plan{Ports: []planner.PortPlan{a}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Commit(nil); err == nil {
		t.Fatal("Commit succeeded with a failing flush")
	}
	p.Rollback()
	k.flushErr = nil
	clk.advance(10 * time.Second)
	again := clk.t
	b.PollUDPReplies()
	if r := replyOf(t, b, "r_a"); !r.Last.IsZero() || !r.Since.Equal(again) {
		t.Fatalf("after a failed flush: %+v, want since %v and no reply", r, again)
	}
}
