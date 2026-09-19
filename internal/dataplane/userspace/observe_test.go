package userspace

import (
	"testing"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/internal/planner"
)

// The userspace backend keeps its state inside the process, where nothing outside wgft can
// change it: it subscribes to no notifications (it is not a dataplane.Sensor), and Observe after a
// Commit reports no drift, so the periodic Observe never republishes (design.md 7a.3 節: 実際の
// 状態への収束).
func TestUserspaceHasNoDrift(t *testing.T) {
	b := New(Options{Limits: flowcap.Limits{UDPPerSource: 1, TCPPerSource: 1}})
	if _, ok := any(b).(dataplane.Sensor); ok {
		t.Error("the userspace backend must not watch kernel notifications")
	}
	p, err := b.Prepare(dataplane.Desired{Plan: planner.Plan{Generation: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Commit(nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		obs, err := b.Observe()
		if err != nil || len(obs.Drift) > 0 {
			t.Fatalf("Observe after a commit: %+v, %v; want no drift", obs, err)
		}
	}
}
