package nft

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/proto"
)

// A rule made fail-closed (design.md 7a.3 節) is left out of the Plan the table is built from
// (planner.Plan.Without): the next full table has no row of it at all, neither its dispatch nor
// its admission rows, while the other rules keep theirs. No partial update of the table is
// involved.
func TestEmitOmitsFailClosedRule(t *testing.T) {
	rules := []proto.Rule{
		{ID: "r_failed", Agent: "home", Proto: proto.TCP, ListenPort: pr(8000, 8000), Target: "192.168.1.20:80",
			VPSMode: proto.ModeKernel, Enabled: true, SourceDeny: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		{ID: "r_ok", Agent: "home", Proto: proto.TCP, ListenPort: pr(25565, 25565), Target: "192.168.1.22:25565",
			VPSMode: proto.ModeKernel, Enabled: true},
	}
	full := buildTestPlan(t, rules, testAgentAddr, flowcap.Limits{})
	rec := newRecorder()
	if err := emit(rec, full, nil, testCfg); err != nil {
		t.Fatal(err)
	}
	rec.row(t, "nat_pre", Comment("r_failed", "dnat")) // the unfiltered Plan has it

	rec = newRecorder()
	if err := emit(rec, full.Without(map[string]bool{"r_failed": true}), nil, testCfg); err != nil {
		t.Fatal(err)
	}
	for _, chain := range []string{"filter_pre", "nat_pre"} {
		for _, c := range rec.comments(chain) {
			if strings.HasPrefix(c, "wgft:r_failed:") {
				t.Errorf("%s still has %q for the fail-closed rule", chain, c)
			}
		}
	}
	rec.row(t, "nat_pre", Comment("r_ok", "dnat"))
	rec.row(t, "filter_pre", Comment("r_ok", "src_flow"))
}
