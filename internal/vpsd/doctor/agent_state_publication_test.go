package doctor

import (
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/adminapi"
	"github.com/rahanahu/wgft/proto"
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

func TestDataplaneReportsStoppedForwardingAlongsidePendingAgentState(t *testing.T) {
	generation, pending := uint64(11), true
	in := Input{Rules: &adminapi.BatchResponse{
		Generation: generation, DesiredGeneration: &generation, ActiveGeneration: &generation,
		AgentStatePending: &pending,
		IPForward:         &adminapi.IPForwardStatus{Value: "0"},
		Rules:             []proto.Rule{{ID: "active-rule", Enabled: true, VPSMode: proto.ModeKernel}},
		RuleStates:        map[string]adminapi.RuleApply{"active-rule": {ApplyState: adminapi.ApplyActive}},
	}}
	c := DataplaneCheck(in)
	if c.Status != StatusFailed || c.Reason != ReasonIPForwardOff ||
		!strings.Contains(c.Detail, "kernel forwards none") ||
		!strings.Contains(c.Detail, "full agent State publication") ||
		!strings.Contains(c.Next, "sysctl -w net.ipv4.ip_forward=1") {
		t.Fatalf("observed forwarding stop or pending State was hidden: %+v", c)
	}
}
