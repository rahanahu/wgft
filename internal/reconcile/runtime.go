// Package reconcile holds the transaction skeleton shared by the server and the agent (design.md
// 7a.2, 7a.7 節): the frontend participant interface and the Runtime, which binds one frontend
// participant and one dataplane participant in a fixed order.
//
// It depends only on internal/planner (the Plan) and internal/dataplane (the participant
// interface), never on a concrete frontend or dataplane implementation. The control plane (vpsd,
// later the agent) assembles a Runtime from implementations at startup.
//
// Phase 2 scope (design.md 7a.8 節): the Runtime runs Prepare -> Commit for the Plan it is given.
// Observe, the diff against Active, generations and per-rule outcomes arrive with the Reconciler
// in Phase 4; until then the control plane calls Runtime.Apply directly with the whole Plan, as
// the pre-Runtime code applied the whole rule set on every change.
package reconcile

import (
	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/planner"
)

// Frontend is the frontend participant (design.md 7a.2 節): the listeners wgft itself opens in
// front of the dataplane, such as the Relay listeners.
type Frontend interface {
	// Prepare opens what the Plan newly needs (for Relay, new listeners) without starting to serve
	// them, and leaves everything it already has untouched. An error means nothing was kept open.
	Prepare(p planner.Plan) (FrontendPrepared, error)
}

// FrontendPrepared is one staged frontend change, finished by exactly one of Commit or Rollback.
type FrontendPrepared interface {
	// Listening is the set of ports that will be listening after Commit: the dataplane's
	// Desired.RelayListening (design.md 7a.2 節 step 2).
	Listening() map[uint16]bool
	// Commit starts serving what Prepare opened and closes what the Plan dropped. It runs after
	// the point of no return, so it must not fail, and calling it again changes nothing
	// (design.md 7a.2 節).
	Commit()
	// Rollback closes what Prepare opened and leaves the listeners that were already serving.
	Rollback()
}

// Runtime is the fixed-order composition of one frontend participant and one dataplane
// participant (design.md 7a.2 節). It is not a general two-phase commit: the participants and
// their order are fixed.
type Runtime struct {
	// Frontend is nil when the process has no frontend (design.md 7a.2 節: the agent's frontend is
	// empty or the userspace Relay listeners).
	Frontend  Frontend
	Dataplane dataplane.Participant
}

// Apply converges the frontend and the dataplane to p in the fixed order of design.md 7a.2 節:
//
//  1. Frontend.Prepare
//  2. its Listening() becomes the dataplane's Desired.RelayListening, and Dataplane.Prepare runs
//  3. the dataplane Commit (the point of no return)
//  4. the frontend Commit
//  5. on failure before the point of no return, what was prepared is rolled back in reverse order
//
// The dataplane's errors are returned unwrapped so the caller keeps the wording it reports.
func (r Runtime) Apply(p planner.Plan) error {
	var fp FrontendPrepared
	d := dataplane.Desired{Plan: p}
	if r.Frontend != nil {
		var err error
		if fp, err = r.Frontend.Prepare(p); err != nil {
			return err
		}
		d.RelayListening = fp.Listening()
	}
	dp, err := r.Dataplane.Prepare(d)
	if err != nil {
		if fp != nil {
			fp.Rollback()
		}
		return err
	}
	if err := dp.Commit(); err != nil {
		dp.Rollback()
		if fp != nil {
			fp.Rollback()
		}
		return err
	}
	if fp != nil {
		fp.Commit()
	}
	return nil
}
