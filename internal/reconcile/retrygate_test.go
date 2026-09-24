package reconcile

import (
	"testing"
	"time"
)

// The gate closes after a failure for a delay that starts at Min and doubles up to Max, opens again
// once the delay has passed, and starts over after a success. Newly observed drift passes while it
// is closed (design.md 7a.3 節: 再試行).
func TestRetryGate(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	g := RetryGate{Backoff: Backoff{Min: time.Second, Max: 30 * time.Second}, Now: func() time.Time { return now }}
	if !g.Allow(false) {
		t.Fatal("the gate is closed before any failure")
	}
	for i, want := range []time.Duration{1, 2, 4, 8, 16, 30, 30} {
		want *= time.Second
		g.Failed()
		now = now.Add(want - time.Millisecond)
		if g.Allow(false) {
			t.Fatalf("failure %d: the gate is open %v after it, want closed for %v", i+1, want-time.Millisecond, want)
		}
		if !g.Allow(true) {
			t.Fatalf("failure %d: newly observed drift does not pass the closed gate", i+1)
		}
		now = now.Add(time.Millisecond)
		if !g.Allow(false) {
			t.Fatalf("failure %d: the gate is still closed %v after it", i+1, want)
		}
	}
	g.Succeeded()
	if !g.Allow(false) {
		t.Fatal("the gate is closed after a success")
	}
	g.Failed()
	now = now.Add(time.Second)
	if !g.Allow(false) {
		t.Error("after a success the delay did not start over at Min")
	}
}

// The zero Backoff is DefaultRetryBackoff: the delay settles at the periodic retry's interval.
func TestRetryGateDefault(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	g := RetryGate{Now: func() time.Time { return now }}
	for i := 0; i < 10; i++ {
		g.Failed()
	}
	if g.delay != DefaultTriggers.Retry || DefaultRetryBackoff.Min != time.Second {
		t.Errorf("settled delay %v, want %v from a %v start", g.delay, DefaultTriggers.Retry, DefaultRetryBackoff.Min)
	}
}
