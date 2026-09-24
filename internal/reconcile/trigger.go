package reconcile

import (
	"context"
	"time"

	"github.com/rahanahu/wgft/internal/dataplane"
)

// Triggers decides when the control plane converges without an operator's change (design.md 7a.3
// 節: 実際の状態への収束、再試行): after change notifications, periodically as a safety net, and on
// the retry timer.
type Triggers struct {
	// Debounce is how long to wait after the first notification of a burst before observing, so
	// that one nftables transaction or `flush ruleset` with its follow-up leads to one Observe.
	Debounce time.Duration
	// SafetyNet is how often to observe even without a notification: WireGuard has no
	// notifications, and a subscription can lose them.
	SafetyNet time.Duration
	// Retry is how often to retry while Desired is not fully Active (Status.NeedsRetry): what
	// clears a failed Prepare or a backend-wide failure (a port freed, another process releasing
	// table inet wgft) sends no notification.
	Retry time.Duration
}

// DefaultTriggers are the intervals of design.md 7a.3 節.
var DefaultTriggers = Triggers{Debounce: 250 * time.Millisecond, SafetyNet: 5 * time.Minute, Retry: 30 * time.Second}

// Run calls observe after each burst of wakes (Debounce after its first wake) and every
// SafetyNet, and retry every Retry, until ctx is done. The calls are made one at a time from the
// calling goroutine. A wake that arrives while observe runs leads to one more observe.
func (t Triggers) Run(ctx context.Context, wake <-chan struct{}, observe, retry func()) {
	safety := time.NewTicker(t.SafetyNet)
	defer safety.Stop()
	retries := time.NewTicker(t.Retry)
	defer retries.Stop()
	var debounce <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
			if debounce == nil {
				debounce = time.After(t.Debounce)
			}
		case <-debounce:
			debounce = nil
			observe()
		case <-safety.C:
			observe()
		case <-retries.C:
			retry()
		}
	}
}

// Backoff is how long to wait before restarting a failed Watch: from Min, doubling up to Max.
type Backoff struct {
	Min, Max time.Duration
}

// DefaultBackoff restarts a failed Watch after 1 s, then 2 s, and so on up to 1 minute.
var DefaultBackoff = Backoff{Min: time.Second, Max: time.Minute}

// Watch keeps s.Watch running until ctx is done (design.md 7a.3 節: 実際の状態への収束). When it
// fails, Watch wakes the control plane (notifications may have been lost meanwhile), waits per
// backoff and subscribes again. logf reports the first failure of a run of failures only; a Watch
// that stayed up for at least backoff.Max ends the run.
func Watch(ctx context.Context, s dataplane.Sensor, wake func(), backoff Backoff, logf func(format string, args ...any)) {
	delay := backoff.Min
	failing := false
	for {
		started := time.Now()
		err := s.Watch(ctx, wake)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) >= backoff.Max {
			failing, delay = false, backoff.Min
		}
		if !failing {
			if err == nil {
				logf("watching the data plane for changes stopped; subscribing again")
			} else {
				logf("watching the data plane for changes failed: %v; subscribing again in %v, and the periodic check still runs as a backstop", err, delay)
			}
			failing = true
		}
		wake()
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay *= 2; delay > backoff.Max {
			delay = backoff.Max
		}
	}
}

// RetryGate spaces out the reapplies that change notifications ask for while the last transaction
// failed as a whole (design.md 7a.3 節: 実際の状態への収束、再試行). A failed publication can still
// replace the nftables table (ENOBUFS on the replies, or sets that do not hold what was sent,
// design.md 6.1 節), and that replacement sends notifications of its own. Without the gate each of
// them would lead to another reapply a Debounce later, which resets the meters and ct count sets a
// few times a second and never lets the failure rest.
//
// After a failure the gate stays closed for a delay that starts at Backoff.Min and doubles up to
// Backoff.Max; a success opens it again and starts the delay over. Drift that Observe newly reports
// passes the gate at once: the next publication must converge it. Such drift is either a change
// made outside wgft or the table a failed publication replaced (the baseline is still the last
// success), so each run of failures starts with one reapply the gate does not hold back; after that
// the Reconciler is resyncing and reports the same drift as not new. The periodic retry
// (Triggers.Retry) does not ask the gate.
type RetryGate struct {
	// Backoff bounds the delay. The zero value means DefaultRetryBackoff.
	Backoff Backoff
	// Now is the clock; nil means time.Now. Only unit tests set it.
	Now func() time.Time

	delay time.Duration // the last delay; 0 while nothing has failed
	until time.Time     // the gate is closed before this time
}

// DefaultRetryBackoff starts at 1 s and doubles up to the periodic retry's 30 s, so that a failure
// is retried after a notification no more often than the periodic retry does once it has settled.
var DefaultRetryBackoff = Backoff{Min: time.Second, Max: DefaultTriggers.Retry}

func (g *RetryGate) now() time.Time {
	if g.Now == nil {
		return time.Now()
	}
	return g.Now()
}

// Failed records a failed transaction and closes the gate for the next delay.
func (g *RetryGate) Failed() {
	b := g.Backoff
	if b == (Backoff{}) {
		b = DefaultRetryBackoff
	}
	switch {
	case g.delay == 0:
		g.delay = b.Min
	case g.delay*2 > b.Max:
		g.delay = b.Max
	default:
		g.delay *= 2
	}
	g.until = g.now().Add(g.delay)
}

// Succeeded records a successful transaction: the gate opens and the delay starts over.
func (g *RetryGate) Succeeded() {
	g.delay, g.until = 0, time.Time{}
}

// Allow reports whether a notification's reapply may run now. newDrift is whether Observe found
// drift it had not reported before.
func (g *RetryGate) Allow(newDrift bool) bool {
	return newDrift || !g.now().Before(g.until)
}
