package vpsd

import (
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// TestOwnPortTargets は、vpsd 自身の待ち受けポートの一覧が WireGuard(UDP)と agent API(TCP)の
// 2 つだけであり、admin API(既定 Unix ソケット。design.md 6.1 節参照)を含まないことを確かめる。
func TestOwnPortTargets(t *testing.T) {
	opts := Options{WGPort: 51820, AgentAPIAddr: "0.0.0.0:8443"}
	got := ownPortTargets(opts)
	if len(got) != 2 {
		t.Fatalf("targets = %+v, want 2 (WireGuard, agent API)", got)
	}
	if got[0].purpose != "WireGuard" || got[0].proto != proto.UDP || got[0].port != 51820 {
		t.Errorf("WireGuard target = %+v", got[0])
	}
	if got[1].purpose != "agent API" || got[1].proto != proto.TCP || got[1].port != 8443 {
		t.Errorf("agent API target = %+v", got[1])
	}
	for _, target := range got {
		if target.purpose == "admin API" {
			t.Errorf("admin API must not be a target: %+v", got)
		}
	}
}
