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
	out     chan []byte
}

func (s *stubClocked) Name() string                    { return "stub" }
func (s *stubClocked) Addr() netip.Addr                { return DUTAddr }
func (s *stubClocked) MTU() int                        { return MTU }
func (s *stubClocked) Inject([]byte) error             { return nil }
func (s *stubClocked) Emitted() <-chan []byte          { return s.out }
func (s *stubClocked) Listen(uint16) (Listener, error) { return nil, nil }
func (s *stubClocked) Close() error                    { return nil }
func (s *stubClocked) Now() time.Time                  { return s.now }
func (s *stubClocked) Advance(d time.Duration) {
	s.now = s.now.Add(d)
	if s.pkt != nil && !s.now.Before(s.at) {
		s.out <- s.pkt
		s.pkt = nil
	}
}

func TestClockedNextSpendsNoRealTime(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	stub := &stubClocked{now: start, at: start.Add(3 * time.Second), out: make(chan []byte, 1)}
	h := newH(t, Engine{Name: "stub"}, "clock", stub)
	p := h.NewPeer(8000)
	stub.pkt = Segment{Src: p.Remote, Dst: p.Local, Flags: FlagACK, Seq: 1, Ack: 2}.Marshal()

	wall := time.Now()
	if s, ok := p.Next(time.Second); ok {
		t.Fatalf("a segment before its time: %v", s)
	}
	if got := h.Now().Sub(start); got != time.Second {
		t.Fatalf("the clock moved %v during a 1 s wait", got)
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
