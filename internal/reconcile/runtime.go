// Package reconcile holds the transaction skeleton shared by the server and the agent (design.md
// 7a.2, 7a.3, 7a.7 節): the frontend participant interface, the Runtime, which binds one frontend
// participant and one dataplane participant in a fixed order, and the Reconciler, which drives the
// Runtime and keeps the Active state and the generations.
//
// It depends only on internal/planner (the Plan), internal/policy and internal/dataplane (the
// participant interface), never on a concrete frontend or dataplane implementation. The control
// plane (vpsd, later the agent) assembles a Runtime from implementations at startup.
package reconcile

import (
	"sort"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/planner"
)

// Frontend is the frontend participant (design.md 7a.2 節): the listeners wgft itself opens in
// front of the dataplane, such as the Relay listeners.
type Frontend interface {
	// Prepare opens what the Plan newly needs (for Relay, new listeners) without starting to serve
	// them, and leaves everything it already has untouched. An error is a backend-wide failure and
	// means nothing was kept open. A failure confined to one rule (one listener that cannot bind)
	// is not an error but an entry of FrontendPrepared.Failed.
	Prepare(p planner.Plan) (FrontendPrepared, error)
}

// FrontendPrepared is one staged frontend change, finished by exactly one of Commit or Rollback.
type FrontendPrepared interface {
	// Listening is the set of ports that will be listening after Commit: the dataplane's
	// Desired.RelayListening (design.md 7a.2 節 step 2). Ports of failed rules are not in it.
	Listening() map[uint16]bool
	// Failed returns the rules whose Prepare failed, with the reason (design.md 7a.3 節).
	Failed() map[string]error
	// Commit starts serving what Prepare opened and closes what the Plan dropped. The listeners of
	// retiring rules are not closed: they stop accepting and keep the established connections
	// retiring allows (design.md 7a.3 節: StopAccepting and Retire). Commit runs after the point of
	// no return, so it must not fail, and calling it again changes nothing (design.md 7a.2 節).
	Commit(retiring []dataplane.Retiring)
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

// Tx is one transaction the Runtime applies.
type Tx struct {
	// Plan is the Desired value to publish.
	Plan planner.Plan
	// WG is the WireGuard declaration; nil leaves the peers alone.
	WG *dataplane.WGConfig
	// ActivePeers is the peer set the device has now (dataplane.Desired.ActivePeers).
	ActivePeers []dataplane.Peer
	// Previous is, per rule ID, the value each rule last had Active: what a rule whose Prepare fails
	// in this transaction retires to (design.md 7a.3 節).
	Previous map[string]planner.PortPlan
}

// Outcome is what a transaction did.
type Outcome struct {
	// Failed holds the rule-local failures of both participants, with the reason. None of these
	// rules is published (fail-closed).
	Failed map[string]error
	// Retiring holds the failed rules that had a previous Active value: their established flows
	// were kept where their new declaration still admits them.
	Retiring []dataplane.Retiring
	// Published is the Plan the dataplane published: Tx.Plan without the failed rules.
	Published planner.Plan
	// Committed is what the dataplane's Commit reported (drop counters, WireGuard changes,
	// convergence).
	Committed dataplane.Committed
}

// Apply runs one transaction in the fixed order of design.md 7a.2 節:
//
//  1. Frontend.Prepare. Rules it could not prepare are removed from the Plan the dataplane sees,
//     so no dispatch is published for them (design.md 7a.3 節: fail-closed)
//  2. its Listening() becomes the dataplane's Desired.RelayListening, and Dataplane.Prepare runs
//  3. the failed rules of both participants that had a previous Active value become Retiring
//  4. the dataplane Commit (the point of no return)
//  5. the frontend Commit
//  6. on failure before the point of no return, what was prepared is rolled back in reverse order
//
// An error is a backend-wide failure (design.md 7a.3 節): nothing was published. The dataplane's
// errors are returned unwrapped so the caller keeps the wording it reports.
func (r Runtime) Apply(tx Tx) (Outcome, error) {
	out := Outcome{Failed: map[string]error{}}
	var fp FrontendPrepared
	d := dataplane.Desired{Plan: tx.Plan, WG: tx.WG, ActivePeers: tx.ActivePeers}
	if r.Frontend != nil {
		var err error
		if fp, err = r.Frontend.Prepare(tx.Plan); err != nil {
			return Outcome{}, err
		}
		for id, e := range fp.Failed() {
			out.Failed[id] = e
		}
		d.Plan = tx.Plan.Without(ids(out.Failed))
		d.RelayListening = fp.Listening()
	}
	dp, err := r.Dataplane.Prepare(d)
	if err != nil {
		if fp != nil {
			fp.Rollback()
		}
		return Outcome{}, err
	}
	for id, e := range dp.Failed() {
		out.Failed[id] = e
	}
	out.Retiring = retiring(tx, out.Failed)
	committed, err := dp.Commit(out.Retiring)
	if err != nil {
		dp.Rollback()
		if fp != nil {
			fp.Rollback()
		}
		return Outcome{}, err
	}
	if fp != nil {
		fp.Commit(out.Retiring)
	}
	out.Published = tx.Plan.Without(ids(out.Failed))
	out.Committed = committed
	return out, nil
}

func ids(failed map[string]error) map[string]bool {
	out := make(map[string]bool, len(failed))
	for id := range failed {
		out[id] = true
	}
	return out
}

// retiring lists, in rule ID order, the failed rules that had a previous Active value, each with
// the source policy of its new declaration.
func retiring(tx Tx, failed map[string]error) []dataplane.Retiring {
	var out []dataplane.Retiring
	for id := range failed {
		prev, ok := tx.Previous[id]
		if !ok {
			continue
		}
		r := dataplane.Retiring{Previous: prev}
		if pp, ok := tx.Plan.Port(id); ok {
			r.Desired = pp.Policy
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Previous.RuleID < out[j].Previous.RuleID })
	return out
}
