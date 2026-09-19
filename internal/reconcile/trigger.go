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
				logf("watching the data plane for changes failed: %v; subscribing again, and checking every few minutes meanwhile", err)
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
