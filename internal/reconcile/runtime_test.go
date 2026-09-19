package reconcile

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

// recorder collects the calls both fake participants see, in order.
type recorder struct{ calls []string }

func (r *recorder) add(s string) { r.calls = append(r.calls, s) }

type fakeFrontend struct {
	rec        *recorder
	listening  map[uint16]bool
	failed     map[string]error
	prepareErr error
	gotPlan    planner.Plan
	retiring   []dataplane.Retiring
}

func (f *fakeFrontend) Prepare(p planner.Plan) (FrontendPrepared, error) {
	f.rec.add("frontend.Prepare")
	f.gotPlan = p
	if f.prepareErr != nil {
		return nil, f.prepareErr
	}
	return &fakeFrontendPrepared{f}, nil
}

type fakeFrontendPrepared struct{ f *fakeFrontend }

func (p *fakeFrontendPrepared) Listening() map[uint16]bool { return p.f.listening }
func (p *fakeFrontendPrepared) Failed() map[string]error   { return p.f.failed }
func (p *fakeFrontendPrepared) Commit(r []dataplane.Retiring) {
	p.f.rec.add("frontend.Commit")
	p.f.retiring = r
}
func (p *fakeFrontendPrepared) Rollback() { p.f.rec.add("frontend.Rollback") }

type fakeDataplane struct {
	rec        *recorder
	observed   []dataplane.Peer
	observeErr error
	got        dataplane.Desired
	failed     map[string]error
	prepareErr error
	commitErr  error
	committed  dataplane.Committed
	retiring   []dataplane.Retiring
	observes   int
	drift      []string            // what Observe reports drifted
	repaired   dataplane.Committed // what Repair returns
}

func (d *fakeDataplane) Repair() dataplane.Committed {
	d.rec.add("dataplane.Repair")
	return d.repaired
}

func (d *fakeDataplane) Observe() (dataplane.Observed, error) {
	d.observes++
	d.rec.add("dataplane.Observe")
	return dataplane.Observed{Peers: d.observed, Drift: d.drift}, d.observeErr
}

func (d *fakeDataplane) Prepare(in dataplane.Desired) (dataplane.Prepared, error) {
	d.rec.add("dataplane.Prepare")
	d.got = in
	if d.prepareErr != nil {
		return nil, d.prepareErr
	}
	return &fakeDataplanePrepared{d}, nil
}

type fakeDataplanePrepared struct{ d *fakeDataplane }

func (p *fakeDataplanePrepared) Failed() map[string]error { return p.d.failed }
func (p *fakeDataplanePrepared) Commit(r []dataplane.Retiring) (dataplane.Committed, error) {
	p.d.rec.add("dataplane.Commit")
	p.d.retiring = r
	if p.d.commitErr != nil {
		return dataplane.Committed{}, p.d.commitErr
	}
	return p.d.committed, nil
}
func (p *fakeDataplanePrepared) Rollback() { p.d.rec.add("dataplane.Rollback") }

func TestRuntimeApplyOrder(t *testing.T) {
	errPrepare := errors.New("prepare failed")
	errCommit := errors.New("commit failed")
	listening := map[uint16]bool{443: true}
	cases := []struct {
		name        string
		noFrontend  bool
		frontendErr error
		dpPrepErr   error
		dpCommitErr error
		wantErr     error
		want        []string
	}{
		{name: "success", want: []string{"frontend.Prepare", "dataplane.Prepare", "dataplane.Commit", "frontend.Commit"}},
		{name: "frontend prepare fails", frontendErr: errPrepare, wantErr: errPrepare,
			want: []string{"frontend.Prepare"}},
		{name: "dataplane prepare fails", dpPrepErr: errPrepare, wantErr: errPrepare,
			want: []string{"frontend.Prepare", "dataplane.Prepare", "frontend.Rollback"}},
		{name: "dataplane commit fails", dpCommitErr: errCommit, wantErr: errCommit,
			want: []string{"frontend.Prepare", "dataplane.Prepare", "dataplane.Commit", "dataplane.Rollback", "frontend.Rollback"}},
		{name: "no frontend", noFrontend: true, want: []string{"dataplane.Prepare", "dataplane.Commit"}},
		{name: "no frontend, commit fails", noFrontend: true, dpCommitErr: errCommit, wantErr: errCommit,
			want: []string{"dataplane.Prepare", "dataplane.Commit", "dataplane.Rollback"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			dp := &fakeDataplane{rec: rec, prepareErr: tc.dpPrepErr, commitErr: tc.dpCommitErr}
			rt := Runtime{Dataplane: dp}
			if !tc.noFrontend {
				rt.Frontend = &fakeFrontend{rec: rec, listening: listening, prepareErr: tc.frontendErr}
			}
			plan := planner.Plan{Generation: 7}
			_, err := rt.Apply(Tx{Plan: plan})
			if !errors.Is(err, tc.wantErr) || (err == nil) != (tc.wantErr == nil) {
				t.Fatalf("Apply error = %v, want %v", err, tc.wantErr)
			}
			if !reflect.DeepEqual(rec.calls, tc.want) {
				t.Fatalf("calls = %v, want %v", rec.calls, tc.want)
			}
			// The dataplane sees the Plan and, with a frontend, the frontend's listening set
			// (design.md 7a.2 節 step 2).
			if len(rec.calls) > 1 || tc.noFrontend {
				if dp.got.Plan.Generation != 7 {
					t.Fatalf("dataplane got Plan generation %d, want 7", dp.got.Plan.Generation)
				}
				var wantListening map[uint16]bool
				if !tc.noFrontend {
					wantListening = listening
				}
				if !reflect.DeepEqual(dp.got.RelayListening, wantListening) {
					t.Fatalf("dataplane got RelayListening %v, want %v", dp.got.RelayListening, wantListening)
				}
			}
		})
	}
}

// testPlan builds a Plan from rules for the agent "home" at 10.200.0.2.
func testPlan(t *testing.T, gen uint64, rules ...proto.Rule) planner.Plan {
	t.Helper()
	normalized, err := model.NormalizeRules(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	return planner.Build(planner.Input{Generation: gen, Rules: normalized,
		Agents: []planner.Agent{{Name: "home", Addr: netip.MustParseAddr("10.200.0.2")}}})
}

func tcpRule(id string, port uint16, mode proto.VPSMode, deny ...string) proto.Rule {
	r := proto.Rule{ID: id, Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: port, Hi: port},
		Target: "192.168.1.10:80", VPSMode: mode, Enabled: true}
	for _, d := range deny {
		r.SourceDeny = append(r.SourceDeny, netip.MustParsePrefix(d))
	}
	return r
}

// A rule the frontend could not prepare is fail-closed: the dataplane never sees it, it is not
// published, and when it had a previous Active value it retires to that value, judged together
// with its new source policy (design.md 7a.3 節).
func TestRuntimeFailClosed(t *testing.T) {
	rec := &recorder{}
	errBind := errors.New("bind failed: address in use")
	fe := &fakeFrontend{rec: rec, failed: map[string]error{"r_moved": errBind}}
	dp := &fakeDataplane{rec: rec}
	rt := Runtime{Frontend: fe, Dataplane: dp}

	old := testPlan(t, 1, tcpRule("r_moved", 8443, proto.ModeProxy), tcpRule("r_other", 25565, proto.ModeKernel))
	plan := testPlan(t, 2, tcpRule("r_moved", 9443, proto.ModeProxy, "203.0.113.0/24"), tcpRule("r_other", 25565, proto.ModeKernel))
	prev, _ := old.Port("r_moved")
	out, err := rt.Apply(Tx{Plan: plan, Previous: map[string]planner.PortPlan{"r_moved": prev}})
	if err != nil {
		t.Fatalf("a rule-local failure must not fail the transaction: %v", err)
	}
	if _, ok := dp.got.Plan.Port("r_moved"); ok {
		t.Error("the dataplane was given the failed rule; its dispatch must be left out of the published Plan")
	}
	for _, rp := range dp.got.Plan.Admission.Rules {
		if rp.RuleID == "r_moved" {
			t.Error("the failed rule's admission policy reached the dataplane")
		}
	}
	if _, ok := dp.got.Plan.Port("r_other"); !ok {
		t.Error("the other rule must still be published")
	}
	if !errors.Is(out.Failed["r_moved"], errBind) || len(out.Failed) != 1 {
		t.Errorf("Failed = %v, want only r_moved", out.Failed)
	}
	if _, ok := out.Published.Port("r_moved"); ok {
		t.Error("Outcome.Published contains the failed rule")
	}
	if len(out.Retiring) != 1 || out.Retiring[0].Previous.ListenPort.Lo != 8443 {
		t.Fatalf("Retiring = %+v, want r_moved's previous value on 8443", out.Retiring)
	}
	r := out.Retiring[0]
	if !reflect.DeepEqual(r.Desired.SourceDeny, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}) {
		t.Errorf("Retiring.Desired = %+v, want the new declaration's source policy", r.Desired)
	}
	if r.SourceAllowed(netip.MustParseAddr("203.0.113.5")) {
		t.Error("a source the new declaration denies must not be kept")
	}
	if !r.SourceAllowed(netip.MustParseAddr("198.51.100.5")) {
		t.Error("a source both values admit must be kept")
	}
	if !reflect.DeepEqual(fe.retiring, out.Retiring) || !reflect.DeepEqual(dp.retiring, out.Retiring) {
		t.Error("both participants' Commit must receive the retiring rules")
	}
}

// A rule the dataplane itself could not prepare also retires; a failed rule with no previous
// Active value (a new rule) has nothing to retire.
func TestRuntimeDataplaneFailureRetires(t *testing.T) {
	rec := &recorder{}
	dp := &fakeDataplane{rec: rec, failed: map[string]error{"r_new": errors.New("bind failed"), "r_changed": errors.New("bind failed")}}
	rt := Runtime{Dataplane: dp}
	old := testPlan(t, 1, tcpRule("r_changed", 8000, proto.ModeKernel))
	plan := testPlan(t, 2, tcpRule("r_changed", 8001, proto.ModeKernel), tcpRule("r_new", 9000, proto.ModeKernel))
	prev, _ := old.Port("r_changed")
	out, err := rt.Apply(Tx{Plan: plan, Previous: map[string]planner.PortPlan{"r_changed": prev}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Retiring) != 1 || out.Retiring[0].Previous.RuleID != "r_changed" {
		t.Errorf("Retiring = %+v, want only r_changed", out.Retiring)
	}
	if len(out.Published.Ports) != 0 {
		t.Errorf("Published = %+v, want neither failed rule", out.Published.Ports)
	}
}

func TestPolicySourceAllowed(t *testing.T) {
	rp := policy.RulePolicy{SourceAllow: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		SourceDeny: []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")}}
	for addr, want := range map[string]bool{"198.51.100.1": true, "198.51.100.7": false, "203.0.113.1": false} {
		if got := rp.SourceAllowed(netip.MustParseAddr(addr)); got != want {
			t.Errorf("SourceAllowed(%s) = %v, want %v", addr, got, want)
		}
	}
	if !(policy.RulePolicy{}).SourceAllowed(netip.MustParseAddr("192.0.2.1")) {
		t.Error("an empty policy admits every source")
	}
}
