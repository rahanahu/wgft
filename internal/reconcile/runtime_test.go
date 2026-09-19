package reconcile

import (
	"errors"
	"reflect"
	"testing"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/planner"
)

// recorder collects the calls both fake participants see, in order.
type recorder struct{ calls []string }

func (r *recorder) add(s string) { r.calls = append(r.calls, s) }

type fakeFrontend struct {
	rec        *recorder
	listening  map[uint16]bool
	prepareErr error
}

func (f *fakeFrontend) Prepare(planner.Plan) (FrontendPrepared, error) {
	f.rec.add("frontend.Prepare")
	if f.prepareErr != nil {
		return nil, f.prepareErr
	}
	return &fakeFrontendPrepared{f}, nil
}

type fakeFrontendPrepared struct{ f *fakeFrontend }

func (p *fakeFrontendPrepared) Listening() map[uint16]bool { return p.f.listening }
func (p *fakeFrontendPrepared) Commit()                    { p.f.rec.add("frontend.Commit") }
func (p *fakeFrontendPrepared) Rollback()                  { p.f.rec.add("frontend.Rollback") }

type fakeDataplane struct {
	rec        *recorder
	got        dataplane.Desired
	prepareErr error
	commitErr  error
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

func (p *fakeDataplanePrepared) Commit() error {
	p.d.rec.add("dataplane.Commit")
	return p.d.commitErr
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
			err := rt.Apply(plan)
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
