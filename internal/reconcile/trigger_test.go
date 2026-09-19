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
func TestTriggersDebounce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wake := make(chan struct{}, 1)
	var observed, retried atomic.Int32
	tr := Triggers{Debounce: 50 * time.Millisecond, SafetyNet: time.Hour, Retry: time.Hour}
	go tr.Run(ctx, wake, func() { observed.Add(1) }, func() { retried.Add(1) })
	for i := 0; i < 10; i++ {
		select {
		case wake <- struct{}{}:
		default:
		}
		time.Sleep(2 * time.Millisecond)
	}
	waitFor(t, "the debounced observe", func() bool { return observed.Load() == 1 })
	time.Sleep(150 * time.Millisecond)
	if n := observed.Load(); n != 1 {
		t.Errorf("observed %d times after one burst, want 1", n)
	}
	wake <- struct{}{}
	waitFor(t, "the observe of the next burst", func() bool { return observed.Load() == 2 })
	if retried.Load() != 0 {
		t.Error("a wake must not retry")
	}
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
