//go:build linux

package vpsd

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// gateParticipant is holdParticipant with drift that Observe reports, and a count of the
// transactions it was asked to prepare, split into the ones that failed and the ones that did not.
type gateParticipant struct {
	mu        sync.Mutex
	err       error
	drift     []string
	published int
	failed    int
}

func (p *gateParticipant) set(err error, drift []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err, p.drift = err, drift
}

// take returns and resets the counts.
func (p *gateParticipant) take() (published, failed int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	published, failed = p.published, p.failed
	p.published, p.failed = 0, 0
	return published, failed
}

func (p *gateParticipant) Observe() (dataplane.Observed, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return dataplane.Observed{Drift: p.drift}, nil
}

func (p *gateParticipant) Prepare(dataplane.Desired) (dataplane.Prepared, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		p.failed++
		return nil, p.err
	}
	p.published++
	return holdPrepared{}, nil
}

func (p *gateParticipant) Repair() dataplane.Committed { return dataplane.Committed{} }

// newGateDaemon returns a Daemon whose first transaction committed, with the retry gate on a clock
// the test moves.
func newGateDaemon(t *testing.T) (*Daemon, *gateParticipant, *store.Store, *time.Time) {
	t.Helper()
	st := openTestStore(t)
	addRule(t, st, "r_a")
	p := &gateParticipant{}
	d := newHoldDaemon(t, st, p, "127.0.0.1:0", "127.0.0.1:0")
	now := time.Unix(1_000_000, 0)
	d.retryGate.Now = func() time.Time { return now }
	d.mu.Lock()
	err := d.applyNFT(rulesOf(t, st))
	d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	p.take()
	return d, p, st, &now
}

// After a failed publication, the notifications that follow (the failed publication's own table
// replacement sends them) reapply only once retryGate opens, instead of every Debounce. The delay
// starts at 1 s and doubles with each failure in a row. Newly observed drift still reapplies at
// once, and a success opens the gate again (design.md 7a.3 節: 再試行).
func TestNotificationReapplyAfterFailureIsSpacedOut(t *testing.T) {
	d, p, st, now := newGateDaemon(t)
	observe := func() (published, failed int) { d.observeOnce(); return p.take() }
	expect := func(what string, wantPublished, wantFailed int) {
		t.Helper()
		if published, failed := observe(); published != wantPublished || failed != wantFailed {
			t.Fatalf("%s: %d published, %d failed; want %d and %d", what, published, failed, wantPublished, wantFailed)
		}
	}

	// An operator's change fails as a whole: the last error is the only reason to reapply.
	p.set(errors.New("table inet wgft was replaced, but it does not hold what was sent"), nil)
	d.mu.Lock()
	err := d.applyNFT(rulesOf(t, st))
	d.mu.Unlock()
	if err == nil {
		t.Fatal("the failing apply succeeded")
	}
	p.take()
	expect("a notification right after the failure", 0, 0)

	// Newly observed drift passes the closed gate.
	p.set(errors.New("table inet wgft was replaced, but it does not hold what was sent"), []string{"table inet wgft was changed"})
	expect("new drift while the gate is closed", 0, 1)
	// The same drift is no longer new. That was the second failure in a row, so the gate spaces the
	// next reapplies 2 s, then 4 s apart.
	*now = now.Add(1999 * time.Millisecond)
	expect("before the 2 s delay", 0, 0)
	*now = now.Add(time.Millisecond)
	expect("after 2 s", 0, 1)
	*now = now.Add(3999 * time.Millisecond)
	expect("before the 4 s delay", 0, 0)

	// The periodic retry does not ask the gate, and its success opens it. The drift is gone, so that
	// the last step below depends on the gate alone.
	p.set(nil, nil)
	d.retryOnce()
	if published, _ := p.take(); published != 1 {
		t.Fatalf("periodic retry while the gate is closed: %d published, want 1", published)
	}
	p.set(errors.New("netlink: no buffer space available"), nil)
	d.mu.Lock()
	_ = d.applyNFT(rulesOf(t, st))
	d.mu.Unlock()
	p.take()
	*now = now.Add(999 * time.Millisecond)
	expect("before the 1 s delay after a success", 0, 0)
	*now = now.Add(time.Millisecond)
	expect("1 s after the first failure following a success", 0, 1)
}

// A failure before the transaction, reading the server database, leaves the gate open: it does not
// set NeedsRetry, so no periodic retry would come, and closing the gate would leave the
// notifications without a way to try again.
func TestStoreFailureDoesNotCloseTheGate(t *testing.T) {
	d, _, st, _ := newGateDaemon(t)
	rules := rulesOf(t, st)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	err := d.applyNFT(rules)
	d.mu.Unlock()
	if err == nil {
		t.Fatal("applying with a closed server database succeeded")
	}
	if d.rec.Status().NeedsRetry {
		t.Fatal("the store failure scheduled a periodic retry; this test assumes it does not")
	}
	if !d.retryGate.Allow(false) {
		t.Error("a failure before the transaction closed the gate")
	}
}
