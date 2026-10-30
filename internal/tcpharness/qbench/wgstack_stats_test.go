//go:build qbench

package qbench

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rahanahu/wgft/internal/wgstack"
)

// setBoost sets the boost policy QBENCH_BOOST picks for wgstack: demand, the default, accept or
// never. The last two are the test switch of wgstack-performance.md's diagnosis.
func setBoost(cfg *wgstack.Config) {
	switch os.Getenv("QBENCH_BOOST") {
	case "accept":
		cfg.TestBoost = wgstack.BoostAtAccept
	case "never":
		cfg.TestBoost = wgstack.BoostNever
	default:
		cfg.TestBoost = wgstack.BoostOnDemand
	}
}

// wgstackStats formats the Device counters the performance stage's diagnosis reads for each run.
func wgstackStats(st wgstack.Stats) string {
	return fmt.Sprintf("boosted=%d boost_granted=%d boost_reclaimed=%d recv_trimmed=%d "+
		"rtos=%d rtos_backed_off=%d rtos_short_of_dupthresh=%d fast_recoveries=%d partial_acks=%d "+
		"retrans_fast=%d retrans_partial=%d retrans_rto=%d retrans_pmtu=%d "+
		"dupacks_in=%d acks_delayed=%d acks_immediate=%d retransmit_aborts=%d probe_aborts=%d",
		st.Boosted, st.BoostGranted, st.BoostReclaimed, st.RecvTrimmed,
		st.RTOs, st.RTOsBackedOff, st.RTOsShortOfDupThresh, st.FastRecoveries, st.PartialAcks,
		st.RetransFast, st.RetransPartial, st.RetransRTO, st.RetransPMTU,
		st.DupAcksIn, st.AcksDelayed, st.AcksImmediate, st.RetransmitAborts, st.ProbeAborts)
}

// traceRTO keeps the wall-clock time and the RTO, backoff included, of every TraceRTO event. The
// trace is called under the connection's lock, so record only copies and returns.
type traceRTO struct {
	mu  sync.Mutex
	rto []struct {
		at  time.Time
		rto time.Duration
	}
}

func (t *traceRTO) record(ev wgstack.TraceEvent) {
	if ev.Kind != wgstack.TraceRTO {
		return
	}
	t.mu.Lock()
	t.rto = append(t.rto, struct {
		at  time.Time
		rto time.Duration
	}{time.Now(), ev.RTO})
	t.mu.Unlock()
}

// rtoBefore is the RTO of the last TraceRTO before end, the RTO in use when the outage ended, or
// "-" when there was none or no outage.
func (t *traceRTO) rtoBefore(end time.Time) string {
	if end.IsZero() {
		return "-"
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := "-"
	for _, r := range t.rto {
		if r.at.Before(end) {
			out = r.rto.String()
		}
	}
	return out
}
