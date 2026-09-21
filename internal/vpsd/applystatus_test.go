//go:build linux

package vpsd

import (
	"testing"

	"github.com/rahanahu/wgft/internal/reconcile"
)

// TestNeverZero confirms the helper applyStatusToAdmin uses to build
// admin.RuleApply.ActiveGeneration (design.md 7a.11 節, item 2 of the 2026-09-21 JSON-contract
// fixes): 0 ("never published"; generation 0 is itself a real, reachable value, 9 節) becomes nil,
// any other generation becomes a pointer to itself.
func TestNeverZero(t *testing.T) {
	if got := neverZero(0); got != nil {
		t.Errorf("neverZero(0) = %v, want nil", got)
	}
	if got := neverZero(6); got == nil || *got != 6 {
		t.Errorf("neverZero(6) = %v, want a pointer to 6", got)
	}
}

// TestApplyStatusToAdminNeverPublishedRule confirms a rule the reconciler has never published
// (reconcile.RuleStatus.ActiveGeneration == 0, e.g. a rule added since the last successful
// transaction) comes out with a nil admin.RuleApply.ActiveGeneration, not a present 0.
func TestApplyStatusToAdminNeverPublishedRule(t *testing.T) {
	st := reconcile.Status{
		DesiredGeneration: 3, ActiveGeneration: 2,
		Rules: map[string]reconcile.RuleStatus{
			"r_new":  {State: reconcile.Active, ActiveGeneration: 0},
			"r_live": {State: reconcile.Active, ActiveGeneration: 2},
		},
	}
	got := applyStatusToAdmin(st)
	if got.Rules["r_new"].ActiveGeneration != nil {
		t.Errorf(`r_new.ActiveGeneration = %v, want nil ("never published")`, got.Rules["r_new"].ActiveGeneration)
	}
	if ag := got.Rules["r_live"].ActiveGeneration; ag == nil || *ag != 2 {
		t.Errorf("r_live.ActiveGeneration = %v, want a pointer to 2", ag)
	}
}
