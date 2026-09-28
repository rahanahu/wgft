package doctor

import (
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/adminapi"
)

func TestDataplaneDoesNotReportFullPublicationAfterForcedCommitFailure(t *testing.T) {
	desired, active, full, pending := uint64(11), uint64(11), uint64(10), true
	in := Input{Rules: &adminapi.BatchResponse{
		Generation: desired, DesiredGeneration: &desired, ActiveGeneration: &active,
		AgentStateGeneration: &full, AgentStatePending: &pending,
		ApplyError: "agent delivery projection differs from the data plane publication",
	}}
	c := DataplaneCheck(in)
	if c.Status != StatusUnknown || c.Reason != ReasonAgentStatePending ||
		strings.Contains(c.Detail, "rules are published") || !strings.Contains(c.Detail, "full agent State") {
		t.Fatalf("forced Commit failure was reported as complete: %+v", c)
	}
	if len(c.Internal) < 3 || c.Internal[2] != "full agent State at generation 10" {
		t.Fatalf("last full State token was not identified: %+v", c.Internal)
	}
}
