package admissiontest_test

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/rahanahu/wgft/internal/policy/admissiontest"
	"github.com/rahanahu/wgft/internal/policy/goengine"
)

// newGoEngine は、fixture の IR から internal/policy/goengine の評価器を作り、仮想の時計で出来事を
// 流す admissiontest.Engine を作る(設計文書 7a.9 節の検査の手順 1)。
//
// 出来事は本番の中継と同じ呼び出しに写す。Transparent のルールの新しいフローは AdmitFlow、Relay の
// ルールの新しい接続は、移行の手順 4 までは userspace モードの Relay の中継と同じく AdmitSourceFlow、
// 成立済みのフローのパケットは AdmitPacket(TCP のルールでは判定しない)、フローの終わりは枠の
// Release である。
func newGoEngine(fx *admissiontest.Fixture) (admissiontest.Engine, error) {
	plan, err := fx.Plan()
	if err != nil {
		return nil, err
	}
	g := &goEngine{relay: map[string]bool{}, tickets: map[string]*goengine.Ticket{}, base: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	g.clock = g.base
	g.e = goengine.New(func() time.Time { return g.clock })
	g.e.Update(plan.Admission)
	for _, r := range fx.Policy.Rules {
		g.relay[r.ID] = r.Forwarding == "relay"
	}
	return g, nil
}

type goEngine struct {
	e       *goengine.Engine
	base    time.Time
	clock   time.Time
	relay   map[string]bool
	tickets map[string]*goengine.Ticket // 成立済みのフロー
}

func (g *goEngine) Handle(at time.Duration, ev admissiontest.Event) (string, error) {
	g.clock = g.base.Add(at)
	t, established := g.tickets[ev.Flow]
	switch ev.Op {
	case admissiontest.OpEnd:
		t.Release()
		delete(g.tickets, ev.Flow)
		return "", nil
	case admissiontest.OpFlow:
		if established {
			return "", fmt.Errorf("flow %s is already established", ev.Flow)
		}
		src := netip.MustParseAddr(ev.Src)
		var d goengine.Decision
		if g.relay[ev.Rule] {
			d, t = g.e.AdmitSourceFlow(ev.Rule, src)
		} else {
			d, t = g.e.AdmitFlow(ev.Rule, src, 0)
		}
		if d.Allow {
			g.tickets[ev.Flow] = t
		}
		return outcome(d), nil
	case admissiontest.OpPacket:
		if !established {
			return "", fmt.Errorf("packet for flow %s, which is not established", ev.Flow)
		}
		return outcome(g.e.AdmitPacket(ev.Rule, 0)), nil
	}
	return "", fmt.Errorf("unknown op %q", ev.Op)
}

func outcome(d goengine.Decision) string {
	switch {
	case d.Allow:
		return admissiontest.Admit
	case d.Kind == "":
		return admissiontest.Drop
	default:
		return admissiontest.DropOf(d.Kind)
	}
}

func (g *goEngine) Drops() map[string]map[string]uint64 {
	out := map[string]map[string]uint64{}
	for _, d := range g.e.Drops() {
		if out[d.RuleID] == nil {
			out[d.RuleID] = map[string]uint64{}
		}
		out[d.RuleID][d.Kind] += d.Packets
	}
	return out
}
