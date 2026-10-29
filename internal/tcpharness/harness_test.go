package tcpharness

import (
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

func (s *stubClocked) Name() string                    { return "stub" }
func (s *stubClocked) Addr() netip.Addr                { return DUTAddr }
func (s *stubClocked) MTU() int                        { return MTU }
func (s *stubClocked) Inject([]byte) error             { return nil }
func (s *stubClocked) Emitted() <-chan []byte          { return nil }
func (s *stubClocked) Listen(uint16) (Listener, error) { return nil, nil }
func (s *stubClocked) Close() error                    { return nil }
func (s *stubClocked) Now() time.Time                  { return s.now }
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
