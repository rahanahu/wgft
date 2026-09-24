//go:build linux

package vpsd

import (
	"errors"
	"testing"
	"time"
)

// After a failed publication, the notifications that follow (the failed publication's own table
// replacement sends them) reapply only once retryGate opens, 1 s, 2 s, ... after each failure,
// instead of every Debounce. The delay doubles with each failure in a row. Newly observed drift still reapplies at once, and a success opens the
// gate again (design.md 7a.3 節: 再試行).
func TestNotificationReapplyAfterFailureIsSpacedOut(t *testing.T) {
	f := newDisableFixture(t)
	now := time.Unix(1_000_000, 0)
	f.d.retryGate.Now = func() time.Time { return now }
	observe := func() []string { f.d.observeOnce(); return f.log.take() }

	// An operator's change fails as a whole: the last error is the only reason to reapply.
	f.p.setErr(errors.New("table inet wgft was replaced, but it does not hold what was sent"))
	f.d.mu.Lock()
	err := f.d.applyNFT(rulesOf(t, f.st))
	f.d.mu.Unlock()
	if err == nil {
		t.Fatal("the failing apply succeeded")
	}
	f.log.take()
	if got := observe(); len(got) != 0 {
		t.Fatalf("a notification right after the failure reapplied: %v", got)
	}

	// Newly observed drift passes the closed gate.
	f.p.mu.Lock()
	f.p.drift = []string{"table inet wgft was changed"}
	f.p.mu.Unlock()
	if got := observe(); !sameEvents(got, "publish failed") {
		t.Fatalf("new drift while the gate is closed: %v, want an immediate reapply", got)
	}
	// The same drift is no longer new. That was the second failure in a row, so the gate spaces the
	// next reapplies 2 s, then 4 s apart.
	now = now.Add(1999 * time.Millisecond)
	if got := observe(); len(got) != 0 {
		t.Fatalf("reapplied %v before the 2 s delay passed", got)
	}
	now = now.Add(time.Millisecond)
	if got := observe(); !sameEvents(got, "publish failed") {
		t.Fatalf("after 2 s: %v, want one reapply", got)
	}
	now = now.Add(3999 * time.Millisecond)
	if got := observe(); len(got) != 0 {
		t.Fatalf("reapplied %v before the 4 s delay passed", got)
	}

	// The periodic retry does not ask the gate, and its success opens it. The drift is gone, so that
	// the last step below depends on the gate alone.
	f.p.mu.Lock()
	f.p.drift = nil
	f.p.mu.Unlock()
	f.p.setErr(nil)
	f.d.retryOnce()
	if got := f.log.take(); len(got) == 0 || got[0] != "publish r_a,r_c,r_o" {
		t.Fatalf("periodic retry while the gate is closed: %v, want a publication", got)
	}
	f.p.setErr(errors.New("netlink: no buffer space available"))
	f.d.mu.Lock()
	_ = f.d.applyNFT(rulesOf(t, f.st))
	f.d.mu.Unlock()
	f.log.take()
	now = now.Add(999 * time.Millisecond)
	if got := observe(); len(got) != 0 {
		t.Fatalf("reapplied %v before the 1 s delay after a success passed", got)
	}
	now = now.Add(time.Millisecond)
	if got := observe(); !sameEvents(got, "publish failed") {
		t.Fatalf("1 s after the first failure following a success: %v, want the delay to start over", got)
	}
}

// A failure before the transaction, reading the server database, leaves the gate open: it does not
// set NeedsRetry, so no periodic retry would come, and closing the gate would leave the
// notifications without a way to try again.
func TestStoreFailureDoesNotCloseTheGate(t *testing.T) {
	f := newDisableFixture(t)
	now := time.Unix(1_000_000, 0)
	f.d.retryGate.Now = func() time.Time { return now }
	rules := rulesOf(t, f.st)
	if err := f.st.Close(); err != nil {
		t.Fatal(err)
	}
	f.d.mu.Lock()
	err := f.d.applyNFT(rules)
	f.d.mu.Unlock()
	if err == nil {
		t.Fatal("applying with a closed server database succeeded")
	}
	if f.d.rec.Status().NeedsRetry {
		t.Fatal("the store failure scheduled a periodic retry; this test assumes it does not")
	}
	if !f.d.retryGate.Allow(false) {
		t.Error("a failure before the transaction closed the gate")
	}
}
