package reconcile

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/proto"
)

// ApplyState is where one rule of the Desired set stands against what is Active (design.md 7a.3
// 節). Its values are the admin API's apply_state.
type ApplyState string

const (
	// Active: the rule's Desired value is the value being forwarded.
	Active ApplyState = "active"
	// Pending: the rule's Desired value is not Active yet because the last transaction failed as a
	// whole (a backend-wide failure). Whatever was Active before is still forwarding.
	Pending ApplyState = "pending"
	// NotActive: the rule is not forwarded, for the reason given: its Prepare failed (it is then
	// fail-closed), it is disabled, its agent is not registered, or its stored row is invalid.
	NotActive ApplyState = "not_active"
)

// RuleStatus is one rule's apply state (design.md 7a.3 節).
type RuleStatus struct {
	State  ApplyState
	Reason string
	// ActiveGeneration is the generation at which the rule's Active value was last published;
	// 0 when it never was.
	ActiveGeneration uint64
}

// Resource is one rule's forwarding resource as the drift report shows it.
type Resource struct {
	RuleID     string
	Proto      proto.Proto
	ListenPort proto.PortRange
	Forwarding string // "transparent" or "relay"
}

// Status is the Reconciler's view of Desired against Active (design.md 7a.3 節).
type Status struct {
	// DesiredGeneration is the generation of the Desired value last reconciled.
	DesiredGeneration uint64
	// ActiveGeneration is the generation of the last transaction that committed. It does not
	// advance on a backend-wide failure.
	ActiveGeneration uint64
	// Reconciled is false until the first transaction was attempted.
	Reconciled bool
	// Rules is the apply state of every rule of the Desired set, by rule ID.
	Rules map[string]RuleStatus
	// ActiveOnly lists what is Active but no longer Desired: rules deleted, disabled or of an
	// unregistered agent whose removal a backend-wide failure kept from being published.
	ActiveOnly []Resource
	// Retiring lists the previous Active values of fail-closed rules: they accept no new flows,
	// and the established flows they still admit are kept until they end.
	Retiring []Resource
	// LastError is the backend-wide failure of the last transaction, empty when it committed.
	// While a repair is pending (the transaction published, but a step after the publication
	// failed), it says so and names the failure; the rules stay active (design.md 7a.3 節: 戻れない
	// 地点の後の修復).
	LastError string
	// NeedsRetry is true while Desired is not fully Active for a reason a retry can fix: the last
	// transaction failed as a whole, or some rule's Prepare failed (design.md 7a.3 節: 再試行). The
	// control plane retries these on a timer, since what clears them (a port being freed, another
	// process releasing table inet wgft when it exits) sends no notification. Rules not forwarded on
	// purpose (disabled, agent not registered, invalid row) do not count.
	NeedsRetry bool
}

// Input is one reconcile request: the Desired value.
type Input struct {
	// Plan is what to forward; Plan.Generation is the Desired generation.
	Plan planner.Plan
	// WG is the WireGuard declaration, peers included; nil leaves the peers alone.
	WG *dataplane.WGConfig
	// Excluded is, by rule ID, every rule of the Desired set the Plan does not forward, with the
	// reason (disabled, agent not registered, invalid stored row). Rules in neither Plan nor
	// Excluded are not part of the Desired set.
	Excluded map[string]string
	// Retry marks a periodic retry: if it would publish exactly what the last committed
	// transaction published, nothing is committed (Outcome.NoOp). A change made by an operator is
	// always published, as before.
	Retry bool
}

// Reconciler drives a Runtime: Observe (once), diff against Active, Prepare, Commit (design.md
// 7a.2, 7a.3 節). It keeps Active and the generations for the control plane. Every transaction
// publishes the whole Plan (design.md 6.1 節: the nftables table is always replaced as a whole);
// the diff against Active decides what the transaction reports per rule and what a failed rule
// retires to, not which parts are published.
//
// A Reconciler is safe for concurrent use; transactions are serialized.
type Reconciler struct {
	rt Runtime

	mu          sync.Mutex
	observed    bool
	activePeers []dataplane.Peer
	// active is, by rule ID, the value each rule has Active now (published by a committed
	// transaction).
	active map[string]planner.PortPlan
	// activeGen is, by rule ID, the generation at which active[id] was published.
	activeGen map[string]uint64
	// retiring is, by rule ID, the previous Active value of each fail-closed rule.
	retiring map[string]dataplane.Retiring
	// published is what the last committed transaction published; nil before the first.
	published *Published
	// resync is set when an Observe after a Commit found drift (or could not read the state): the
	// next transaction republishes the whole Plan and converges the device as a whole, whatever
	// Retry says, and is cleared when it commits (design.md 7a.3 節: 実際の状態への収束).
	resync bool
	// repair is set while the last transaction published but left a repair pending
	// (dataplane.Committed.RepairPending; design.md 7a.3 節: 戻れない地点の後の修復). A retry then
	// runs the dataplane's Repair even when it would publish the same again.
	repair bool
	// last is the Desired value of the last Reconcile, for the status a failed Observe reports.
	last    Input
	hasLast bool
	status  Status
}

// New returns a Reconciler that drives rt. Nothing is Active until its first transaction commits.
func New(rt Runtime) *Reconciler {
	return &Reconciler{rt: rt, active: map[string]planner.PortPlan{}, activeGen: map[string]uint64{},
		retiring: map[string]dataplane.Retiring{}}
}

// Reconcile runs one transaction toward in (design.md 7a.3 節).
//
// A rule-local failure (one listener that cannot bind) is not an error: the rule is reported
// not_active with the reason, it publishes no dispatch (fail-closed), its established flows are
// kept as Retiring where its new declaration still admits them, and the other rules are published
// and the active generation advances. A backend-wide failure (the peers or the nftables
// transaction) is returned as the error: nothing is published, what was prepared is rolled back,
// the active generation stays, and the rules whose Desired value differs from Active are reported
// pending.
func (r *Reconciler) Reconcile(in Input) (Outcome, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.DesiredGeneration = in.Plan.Generation
	r.status.Reconciled = true
	r.last, r.hasLast = in, true
	if !r.observed {
		obs, err := r.rt.Dataplane.Observe()
		if err != nil {
			r.fail(in, err)
			return Outcome{}, err
		}
		r.activePeers = obs.Peers
		r.observed = true
	}
	previous := make(map[string]planner.PortPlan, len(r.active)+len(r.retiring))
	for id, rt := range r.retiring {
		previous[id] = rt.Previous
	}
	for id, pp := range r.active {
		previous[id] = pp
	}
	var drift []string
	if in.Retry && r.repair && !r.resync && r.published != nil {
		// 修復の再試行は、まず実際の状態を確かめる。食い違い(読み直せなかったテーブルを含む)が
		// あれば、修復の手順だけでなく公開し直す(design.md 7a.3 節: 戻れない地点の後の修復)
		obs, err := r.rt.Dataplane.Observe()
		if err != nil {
			r.resync = true
			r.fail(in, err)
			return Outcome{}, err
		}
		if len(obs.Drift) > 0 {
			drift = obs.Drift
			r.resync = true
			r.activePeers = obs.Peers
		}
	}
	tx := Tx{Plan: in.Plan, WG: in.WG, ActivePeers: r.activePeers, Previous: previous, Resync: r.resync}
	if in.Retry && !r.resync {
		tx.Unchanged = r.published
	}
	out, err := r.rt.Apply(tx)
	out.Drift = drift
	if err != nil {
		r.fail(in, err)
		return out, err
	}
	if out.NoOp && r.repair {
		// 公開は前回と同じなので差し替えず、残っている修復の手順だけを走らせる
		out.Committed = r.rt.Dataplane.Repair()
		out.Repaired = true
	}
	r.published = &Published{Plan: out.Published, Listening: out.Listening, Failed: ids(out.Failed)}
	gen := in.Plan.Generation
	active := make(map[string]planner.PortPlan, len(out.Published.Ports))
	for _, pp := range out.Published.Ports {
		active[pp.RuleID] = pp
		if old, ok := r.active[pp.RuleID]; !ok || !reflect.DeepEqual(old, pp) {
			r.activeGen[pp.RuleID] = gen
		}
	}
	r.active = active
	r.retiring = make(map[string]dataplane.Retiring, len(out.Retiring))
	for _, rt := range out.Retiring {
		r.retiring[rt.Previous.RuleID] = rt
	}
	// A rule no longer in Desired forgets its history, so that one created again with the same ID
	// does not report an old generation.
	for id := range r.activeGen {
		if _, ok := active[id]; !ok {
			if _, desired := in.Plan.Port(id); !desired {
				delete(r.activeGen, id)
			}
		}
	}
	if in.WG != nil {
		r.activePeers = in.WG.Peers
	}
	r.resync = false
	r.repair = out.Committed.RepairPending
	r.status.ActiveGeneration = gen
	r.status.LastError = ""
	if r.repair {
		r.status.LastError = repairError(gen, out.Committed.Errors)
	}
	r.status.NeedsRetry = len(out.Failed) > 0 || r.repair
	r.status.Rules = r.ruleStates(in, out.Failed, nil)
	r.status.ActiveOnly = r.activeOnly(in)
	r.status.Retiring = r.retiringResources()
	return out, nil
}

// repairError is the status's LastError while a repair is pending: the publication happened, but a
// step after it failed (design.md 7a.3 節: 戻れない地点の後の修復).
func repairError(gen uint64, errs []error) string {
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		msgs = append(msgs, e.Error())
	}
	if len(msgs) == 0 {
		msgs = append(msgs, "a repair is still pending")
	}
	return fmt.Sprintf("published generation %d, but a repair after the publication failed: %s", gen, strings.Join(msgs, "; "))
}

// Observe compares the actual state of the dataplane with what the last transaction committed
// (design.md 7a.3 節: 実際の状態への収束). The control plane calls it after the dataplane's change
// notifications and periodically as a safety net against missed ones.
//
// drift is what the dataplane reported drifted, returned only when it is newly found, for one log
// line. due tells whether a transaction should run now: the state drifted (now, or earlier and
// the republication has not committed yet), or the last transaction failed as a whole, which the
// change that caused the notification may have cleared. An
// Observe that finds nothing changed and no failure pending is not due, so nothing is prepared or
// committed and the nftables meters and ct count sets are kept.
//
// An error (the state could not be read, or a resource wgft converges is held by someone else) is
// recorded like a backend-wide failure, with every rule reported pending, and the next transaction
// republishes as after drift.
func (r *Reconciler) Observe() (drift []string, due bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.published == nil {
		// まだ何も commit していないので、比べる相手が無い。最初のトランザクションの失敗だけを試し直す
		return nil, r.status.LastError != "", nil
	}
	obs, err := r.rt.Dataplane.Observe()
	if err != nil {
		r.resync = true
		if r.hasLast {
			r.fail(r.last, err)
		}
		return nil, false, err
	}
	if len(obs.Drift) > 0 {
		if !r.resync {
			drift = obs.Drift
		}
		r.resync = true
		r.activePeers = obs.Peers
	}
	return drift, r.resync || r.status.LastError != "", nil
}

// fail records a backend-wide failure: Active, its generation and the retiring set are unchanged.
// While a drift is not republished yet (resync), every rule of the Plan is reported pending: what
// was Active may no longer be forwarding.
func (r *Reconciler) fail(in Input, err error) {
	r.status.LastError = err.Error()
	r.status.NeedsRetry = true
	r.status.Rules = r.ruleStates(in, nil, err)
	r.status.ActiveOnly = r.activeOnly(in)
	r.status.Retiring = r.retiringResources()
}

func (r *Reconciler) ruleStates(in Input, failed map[string]error, backendErr error) map[string]RuleStatus {
	out := make(map[string]RuleStatus, len(in.Plan.Ports)+len(in.Excluded))
	for id, reason := range in.Excluded {
		st := RuleStatus{State: NotActive, Reason: reason, ActiveGeneration: r.activeGen[id]}
		if _, still := r.active[id]; still && backendErr != nil {
			// 無効化などで転送をやめる宣言が、backend 全体の失敗でまだ公開されていない
			st.State, st.Reason = Pending, backendErr.Error()
		}
		out[id] = st
	}
	for _, pp := range in.Plan.Ports {
		st := RuleStatus{State: Active, ActiveGeneration: r.activeGen[pp.RuleID]}
		switch {
		case failed[pp.RuleID] != nil:
			st.State, st.Reason = NotActive, failed[pp.RuleID].Error()
		case backendErr != nil:
			if cur, ok := r.active[pp.RuleID]; r.resync || !ok || !reflect.DeepEqual(cur, pp) {
				st.State, st.Reason = Pending, backendErr.Error()
			}
		}
		out[pp.RuleID] = st
	}
	return out
}

func resourceOf(pp planner.PortPlan) Resource {
	return Resource{RuleID: pp.RuleID, Proto: pp.Proto, ListenPort: pp.ListenPort, Forwarding: pp.Forwarding.String()}
}

func (r *Reconciler) activeOnly(in Input) []Resource {
	var out []Resource
	for id, pp := range r.active {
		if _, ok := in.Plan.Port(id); !ok {
			out = append(out, resourceOf(pp))
		}
	}
	sortResources(out)
	return out
}

func (r *Reconciler) retiringResources() []Resource {
	var out []Resource
	for _, rt := range r.retiring {
		out = append(out, resourceOf(rt.Previous))
	}
	sortResources(out)
	return out
}

func sortResources(rs []Resource) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].RuleID < rs[j].RuleID })
}

// Status returns a copy of the current status.
func (r *Reconciler) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.status
	st.Rules = make(map[string]RuleStatus, len(r.status.Rules))
	for id, rs := range r.status.Rules {
		st.Rules[id] = rs
	}
	st.ActiveOnly = append([]Resource(nil), r.status.ActiveOnly...)
	st.Retiring = append([]Resource(nil), r.status.Retiring...)
	return st
}
