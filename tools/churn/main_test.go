package main

import (
	"net"
	"strings"
	"testing"
)

func TestQuantile(t *testing.T) {
	v := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	for _, c := range []struct{ q, want float64 }{{0.5, 5}, {0.99, 10}, {1, 10}, {0, 1}} {
		if got := quantile(v, c.q); got != c.want {
			t.Errorf("quantile(%v) = %v, want %v", c.q, got, c.want)
		}
	}
	if got := quantile(nil, 0.5); got != -1 {
		t.Errorf("quantile of nothing = %v, want -1", got)
	}
}

func TestSummaryCountsEachOutcome(t *testing.T) {
	res := []result{
		{connect: 1, total: 2, out: okOutcome},
		{connect: 1500, total: 1600, out: okOutcome},
		{connect: -1, total: -1, out: refused},
		{connect: 3, total: -1, out: reset},
		{connect: -1, total: -1, out: skipped},
	}
	s := summary(res, 100, 0.05, 200, 3, 0.05, 1.7)
	for _, want := range []string{
		"received=800 ", "churn_planned=5 ", "churn_ok=2 ", "churn_refused=1 ", "churn_reset=1 ",
		"churn_skipped=1", "churn_ok_per_s=40.0 ", "churn_inflight_max=3 ", "churn_connect_over_1s=1 ",
		"churn_connect_p50_ms=3.000 ", "churn_rr_max_ms=1600.000",
	} {
		if !strings.Contains(s+" ", want) {
			t.Errorf("summary lacks %q: %s", want, s)
		}
	}
}

// TestRunAgainstServe opens connections at a low rate through the loopback, with each end closing
// first, and expects every one of them to complete.
func TestRunAgainstServe(t *testing.T) {
	for _, closeBy := range []string{"server", "client"} {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go serveOn(ln, 200, closeBy)
		var out strings.Builder
		if rc := run([]string{"-addr", ln.Addr().String(), "-rate", "200", "-seconds", "0.25", "-close", closeBy}, &out); rc != 0 {
			t.Errorf("close %s: run returned %d", closeBy, rc)
		}
		if !strings.Contains(out.String(), " churn_ok=50 ") {
			t.Errorf("close %s: not every connection completed: %s", closeBy, out.String())
		}
		ln.Close()
	}
}
