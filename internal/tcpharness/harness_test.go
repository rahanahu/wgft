package tcpharness

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestSegmentRoundTrip(t *testing.T) {
	mss := uint16(1380)
	s := Segment{
		Src: netip.MustParseAddrPort("10.200.0.1:40000"), Dst: netip.MustParseAddrPort("10.200.0.2:8000"),
		Seq: 0xfffffff0, Ack: 7, Flags: FlagACK | FlagPSH, Window: 512,
		Opts:    Options{MSS: &mss, WS: 7, SACKPermitted: true, TS: &Timestamps{1, 2}, SACK: []SACKBlock{{10, 20}}},
		Payload: []byte("hello"), TTL: 64, DF: true,
	}
	got, err := Parse(s.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, s) {
		t.Fatalf("round trip:\n got %v\nwant %v", got, s)
	}
	pkt := s.Marshal()
	pkt[len(pkt)-1] ^= 1
	if _, err := Parse(pkt); err == nil {
		t.Fatal("a corrupted payload passed the TCP checksum")
	}
	if _, err := Parse([]byte{0x60, 0, 0, 0}); err != ErrNotTCP {
		t.Fatalf("IPv6 packet: err=%v", err)
	}
}

// stubClocked is a ClockedDUT without TCP: it emits one prepared packet once its clock reaches
// at. It exercises the harness's fake-clock path that a wgft-owned stack will use.
type stubClocked struct {
	now, at time.Time
	pkt     []byte
	ready   [][]byte
}

func (s *stubClocked) Name() string                             { return "stub" }
func (s *stubClocked) Addr() netip.Addr                         { return DUTAddr }
func (s *stubClocked) MTU() int                                 { return MTU }
func (s *stubClocked) Inject([]byte) error                      { return nil }
func (s *stubClocked) Emitted() <-chan []byte                   { return nil }
func (s *stubClocked) Listen(uint16) (Listener, error)          { return nil, nil }
func (s *stubClocked) ListenUDP(uint16) (net.PacketConn, error) { return nil, nil }
func (s *stubClocked) Close() error                             { return nil }
func (s *stubClocked) Now() time.Time                           { return s.now }
func (s *stubClocked) Advance(d time.Duration) {
	s.now = s.now.Add(d)
	if s.pkt != nil && !s.now.Before(s.at) {
		s.ready = append(s.ready, s.pkt)
		s.pkt = nil
	}
}
func (s *stubClocked) Poll() ([]byte, bool) {
	if len(s.ready) == 0 {
		return nil, false
	}
	p := s.ready[0]
	s.ready = s.ready[1:]
	return p, true
}

func TestClockedNextSpendsNoRealTime(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	stub := &stubClocked{now: start, at: start.Add(3 * time.Second)}
	h := newH(t, Engine{Name: "stub"}, "clock", stub, 1)
	p := h.NewPeer(8000)
	stub.pkt = Segment{Src: p.Remote, Dst: p.Local, Flags: FlagACK, Seq: 1, Ack: 2}.Marshal()

	wall := time.Now()
	if s, ok := p.Next(time.Second); ok {
		t.Fatalf("a segment before its time: %v", s)
	}
	if got := h.Now().Sub(start); got != time.Second {
		t.Fatalf("the clock moved %v during a 1 s wait", got)
	}
	if h.Prompt() != 0 {
		t.Fatalf("Prompt on a ClockedDUT is %v, want 0", h.Prompt())
	}
	s, ok := p.Next(10 * time.Second)
	if !ok || s.Seq != 1 || len(s.Payload) != 0 {
		t.Fatalf("Next: %v %v", s, ok)
	}
	if got := h.Now().Sub(start); got != 3*time.Second {
		t.Fatalf("the segment was taken at %v, want 3s", got)
	}
	if spent := time.Since(wall); spent > 2*time.Second {
		t.Fatalf("a fake-clock wait of 3 s took %v of real time", spent)
	}
}

// TestSeedReplays checks that one seed gives a scenario the same ports, ISNs and timestamp bases.
func TestSeedReplays(t *testing.T) {
	peers := func(seed uint64) []Peer {
		h := newH(t, Engine{Name: "stub"}, "seed", &stubClocked{}, ScenarioSeed(seed, "seed"))
		var out []Peer
		for range 3 {
			p := h.NewPeer(8000)
			out = append(out, Peer{Local: p.Local, ISS: p.ISS, tsBase: p.tsBase})
		}
		return out
	}
	a, b, c := peers(42), peers(42), peers(43)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("seed 42 gave %v, then %v", a, b)
	}
	if reflect.DeepEqual(a, c) {
		t.Fatal("seeds 42 and 43 gave the same peers")
	}
	if ScenarioSeed(42, "x") == ScenarioSeed(42, "y") {
		t.Fatal("two scenarios got the same seed")
	}
}

// TestKnownDifferences checks how a check's outcome meets the expected-difference list.
func TestKnownDifferences(t *testing.T) {
	e := Engine{Name: "stub", New: func(testing.TB, uint64) DUT { return &stubClocked{} }, Known: map[string]Known{
		"s/known":      {Observed: "dropped", Reason: "on purpose"},
		"s/changed":    {Observed: "dropped", Reason: "on purpose"},
		"s/unexpected": {Observed: "dropped", Reason: "on purpose"},
		"s/required":   {Observed: "dropped", Reason: "on purpose"},
	}}
	s := Scenario{Name: "s", Run: func(h *H) {
		h.Check("pass", true, "ok", "ok")
		h.Check("pass", false, "ok", "bad the second time")
		h.Check("fail", false, "ok", "bad")
		h.Check("known", false, "answered", "dropped")
		h.Check("changed", false, "answered", "reset")
		h.Check("unexpected", true, "answered", "answered")
		h.Require("required", false, "answered", "dropped")
		h.Check("after-require", true, "never reached", "")
	}}
	got := Record(t, e, s, 1)
	want := map[string][]string{
		"s/pass": {OutcomePass, OutcomeFail}, "s/fail": {OutcomeFail}, "s/known": {OutcomeKnown}, "s/changed": {OutcomeChanged},
		"s/unexpected": {OutcomeUnexpected}, "s/required": {OutcomeKnown},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outcomes:\n got %v\nwant %v", got, want)
	}
}

// stubRealTime is stubClocked seen only through DUT, without its clock: a DUT on real time.
type stubRealTime struct{ DUT }

// TestSometimesKnown checks a difference listed as shown only on some runs: on real time both a
// pass and the listed difference are accepted, a changed difference still fails, and on a
// ClockedDUT the entry is an error either way.
func TestSometimesKnown(t *testing.T) {
	known := map[string]Known{
		"s/shown":     {Observed: "dropped", Reason: "timing", Sometimes: true},
		"s/not-shown": {Observed: "dropped", Reason: "timing", Sometimes: true},
		"s/changed":   {Observed: "dropped", Reason: "timing", Sometimes: true},
	}
	s := Scenario{Name: "s", Run: func(h *H) {
		h.Check("shown", false, "answered", "dropped")
		h.Check("not-shown", true, "answered", "answered")
		h.Check("changed", false, "answered", "reset")
	}}
	for _, c := range []struct {
		name string
		dut  func() DUT
		want map[string][]string
	}{
		{"real-time", func() DUT { return stubRealTime{&stubClocked{}} }, map[string][]string{
			"s/shown": {OutcomeKnown}, "s/not-shown": {OutcomePass}, "s/changed": {OutcomeChanged}}},
		{"clocked", func() DUT { return &stubClocked{} }, map[string][]string{
			"s/shown": {OutcomeChanged}, "s/not-shown": {OutcomeUnexpected}, "s/changed": {OutcomeChanged}}},
	} {
		e := Engine{Name: c.name, New: func(testing.TB, uint64) DUT { return c.dut() }, Known: known}
		if got := Record(t, e, s, 1); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s outcomes:\n got %v\nwant %v", c.name, got, c.want)
		}
	}
}

// TestRetryAfterStall checks Run's rule for a scenario that failed: it runs again only on real
// time, only after a stall, and at most scenarioAttempts times in all.
func TestRetryAfterStall(t *testing.T) {
	for _, c := range []struct {
		a    attemptResult
		n    int
		want bool
	}{
		{attemptResult{failed: true, stall: stallLimit}, 1, true},
		{attemptResult{failed: true, stall: stallLimit}, scenarioAttempts - 1, true},
		{attemptResult{failed: true, stall: stallLimit}, scenarioAttempts, false},
		{attemptResult{failed: true, stall: stallLimit - time.Millisecond}, 1, false},
		{attemptResult{failed: false, stall: time.Second}, 1, false},
		{attemptResult{failed: true, stall: time.Second, clocked: true}, 1, false},
	} {
		if got := c.a.retry(c.n); got != c.want {
			t.Errorf("retry(%+v, attempt %d) = %v, want %v", c.a, c.n, got, c.want)
		}
	}

	// A scenario on real time that fails its first attempt and passes its second passes, and the
	// DUT of the failed attempt is closed before the second starts.
	old := stallLimit
	stallLimit = 0 // every oversleep of the watch counts as a stall
	t.Cleanup(func() { stallLimit = old })
	attempts, open := 0, 0
	e := Engine{Name: "stub-real-time", New: func(tb testing.TB, _ uint64) DUT {
		open++
		tb.Cleanup(func() { open-- })
		return stubRealTime{&stubClocked{}}
	}}
	Run(t, e, []Scenario{{Name: "flaky", Run: func(h *H) {
		attempts++
		if open != 1 {
			h.T.Errorf("%d DUTs open in attempt %d", open, attempts)
		}
		time.Sleep(3 * time.Millisecond)
		h.Check("once", attempts > 1, "passes from the second attempt on", fmt.Sprintf("attempt %d", attempts))
	}}})
	if attempts != 2 {
		t.Errorf("the scenario ran %d times, want 2", attempts)
	}
}

// TestPerformanceScenarioBuildsWithNewPerformance checks that a Performance scenario gets the
// engine's NewPerformance DUT, that others get New, and that an engine without NewPerformance
// runs a Performance scenario on New.
func TestPerformanceScenarioBuildsWithNewPerformance(t *testing.T) {
	var built []string
	stub := func(name string) func(testing.TB, uint64) DUT {
		return func(testing.TB, uint64) DUT { built = append(built, name); return &stubClocked{} }
	}
	run := func(e Engine, perf bool) {
		Record(t, e, Scenario{Name: "s", Run: func(*H) {}, Performance: perf}, 1)
	}
	both := Engine{Name: "both", New: stub("new"), NewPerformance: stub("perf")}
	run(both, false)
	run(both, true)
	run(Engine{Name: "plain", New: stub("new")}, true)
	if want := []string{"new", "perf", "new"}; !reflect.DeepEqual(built, want) {
		t.Fatalf("DUTs built: %v, want %v", built, want)
	}
}
