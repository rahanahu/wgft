package reconcile

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor polls cond for up to 2 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// A burst of wakes leads to one observe after the debounce, not one per wake.
//
// The burst has to end before the debounce does: a wake that comes later rightly opens a second
// window and leads to a second observe. The wakes are therefore handed over on an unbuffered
// channel with nothing in between, instead of with a short sleep before each; sleeps made the
// burst's length depend on the timer and the scheduler, and on a Windows CI runner ten of them
// once outlasted the window. An attempt that still sees an observe before its burst ends, because
// the test was descheduled for a whole window, did not produce a burst, and the burst is sent again,
// for at most three attempts in all.
func TestTriggersDebounce(t *testing.T) {
	tr := Triggers{Debounce: 50 * time.Millisecond, SafetyNet: time.Hour, Retry: time.Hour}
	for attempt := 1; !debounceOneBurst(t, tr); attempt++ {
		if attempt == 3 {
			t.Fatalf("in %d attempts, the burst never ended before the %v debounce did", attempt, tr.Debounce)
		}
	}
}

// debounceOneBurst runs tr on one burst of wakes and checks the observes it leads to. It reports
// false, having checked nothing more, when an observe ran after a whole window but before the burst
// could be checked.
func debounceOneBurst(t *testing.T, tr Triggers) bool {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	wake := make(chan struct{})
	var observed, retried atomic.Int32
	// start is taken before the first send, so the time from start to the first observe is never
	// shorter than the time from the first wake to it: an observe that comes less than one window
	// after start cannot be the debounce of the first wake.
	var firstObserve atomic.Int64 // nanoseconds after start, set by the first observe
	start := time.Now()
	tooEarly := func() bool {
		at := time.Duration(firstObserve.Load())
		if at < tr.Debounce {
			t.Errorf("observed %s after the burst started, before the %v debounce could have ended", at, tr.Debounce)
			return true
		}
		return false
	}
	done := make(chan struct{})
	go func() {
		tr.Run(ctx, wake, func() {
			firstObserve.CompareAndSwap(0, int64(time.Since(start)))
			observed.Add(1)
		}, func() { retried.Add(1) })
		close(done)
	}()
	defer func() { cancel(); <-done }()
	send := func() {
		select {
		case wake <- struct{}{}:
		case <-time.After(2 * time.Second):
			t.Fatal("Run did not take the wake")
		}
	}
	// A send returns once Run has taken the wake, and Run observes on its own goroutine between
	// takes, so seeing no observe here means every wake of the burst fell into the first window.
	for i := 0; i < 10; i++ {
		send()
	}
	if n := observed.Load(); n != 0 {
		// Too early is Run's fault; later than one window means the test was descheduled.
		if tooEarly() {
			return true
		}
		t.Logf("an observe ran after a whole window but before the burst could be checked; trying again")
		return false
	}
	waitFor(t, "the debounced observe", func() bool { return observed.Load() == 1 })
	// The window must last the whole Debounce, not merely end after the burst.
	tooEarly()
	time.Sleep(150 * time.Millisecond)
	if n := observed.Load(); n != 1 {
		t.Errorf("observed %d times after one burst, want 1", n)
	}
	send()
	waitFor(t, "the observe of the next burst", func() bool { return observed.Load() == 2 })
	if retried.Load() != 0 {
		t.Error("a wake must not retry")
	}
	return true
}

// Without any wake, the safety net observes on its interval, and the retry timer retries on its
// own (design.md 7a.3 節: the safety net is tested here with short intervals, not in the lab).
func TestTriggersSafetyNetAndRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var observed, retried atomic.Int32
	tr := Triggers{Debounce: time.Hour, SafetyNet: 20 * time.Millisecond, Retry: 30 * time.Millisecond}
	done := make(chan struct{})
	go func() {
		tr.Run(ctx, make(chan struct{}), func() { observed.Add(1) }, func() { retried.Add(1) })
		close(done)
	}()
	waitFor(t, "safety-net observes", func() bool { return observed.Load() >= 3 })
	waitFor(t, "retries", func() bool { return retried.Load() >= 2 })
	cancel()
	<-done
}

// fakeSensor fails its first watches, then blocks until ctx is done.
type fakeSensor struct {
	mu    sync.Mutex
	fails int
	calls int
}

func (s *fakeSensor) Watch(ctx context.Context, wake func()) error {
	s.mu.Lock()
	s.calls++
	n := s.calls
	s.mu.Unlock()
	if n <= s.fails {
		wake()
		return fmt.Errorf("receive: %w", errors.New("no buffer space available"))
	}
	<-ctx.Done()
	return nil
}

// A failing Watch is restarted with backoff, each failure wakes the control plane (notifications
// may have been lost), and the run of failures is logged once.
func TestWatchRestartsAndLogsOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &fakeSensor{fails: 3}
	var wakes atomic.Int32
	var mu sync.Mutex
	var logs []string
	done := make(chan struct{})
	go func() {
		Watch(ctx, s, func() { wakes.Add(1) }, Backoff{Min: time.Millisecond, Max: 10 * time.Millisecond},
			func(f string, a ...any) {
				mu.Lock()
				logs = append(logs, fmt.Sprintf(f, a...))
				mu.Unlock()
			})
		close(done)
	}()
	waitFor(t, "the fourth subscription", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.calls == 4
	})
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(logs) != 1 {
		t.Errorf("logged %d lines for one run of failures, want 1: %q", len(logs), logs)
	}
	if n := wakes.Load(); n < 6 {
		t.Errorf("woke %d times for 3 failures, want each failure to wake (sensor and restart)", n)
	}
}
