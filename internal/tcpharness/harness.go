package tcpharness

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sort"
	"testing"
	"time"
)

// The addresses and the MTU every DUT is built with. The MTU is wgft's default tunnel MTU
// (WGFT_MTU), so an MSS of 1380 is what the agent advertises in production.
var (
	DUTAddr  = netip.MustParseAddr("10.200.0.2")
	PeerAddr = netip.MustParseAddr("10.200.0.1")
)

const MTU = 1420

// Engine names one TCP engine and how to build a fresh DUT of it. Known is the engine's
// expected-difference list: the checks, as "scenario/check", that are known to fail on this
// engine, each with the reason. A listed check that passes is reported as an error, so the list
// cannot go stale silently.
type Engine struct {
	Name  string
	New   func(tb testing.TB) DUT
	Known map[string]string
}

// Scenario is one engine-neutral conformance scenario.
type Scenario struct {
	Name string
	// Refs names the RFC sections and the gVisor packetimpact tests the scenario follows.
	Refs string
	Run  func(h *H)
}

// Run runs every scenario as a subtest against a fresh DUT of e.
func Run(t *testing.T, e Engine, scenarios []Scenario) {
	seen := map[string]bool{}
	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			t.Logf("refs: %s", s.Refs)
			d := e.New(t)
			h := newH(t, e, s.Name, d)
			s.Run(h)
			for k := range h.checked {
				seen[k] = true
			}
		})
	}
	var stale []string
	for k := range e.Known {
		if !seen[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	for _, k := range stale {
		t.Logf("known difference %s was not exercised in this run", k)
	}
}

// H is the context of one scenario on one DUT.
type H struct {
	T        testing.TB
	DUT      DUT
	engine   Engine
	scenario string
	checked  map[string]bool
	nextPort uint16
}

func newH(t testing.TB, e Engine, scenario string, d DUT) *H {
	h := &H{T: t, DUT: d, engine: e, scenario: scenario, checked: map[string]bool{},
		nextPort: uint16(40000 + rand.IntN(20000))}
	return h
}

// Check records the outcome of one check against the engine's expected-difference list.
func (h *H) Check(id string, ok bool, format string, args ...any) bool {
	h.T.Helper()
	key := h.scenario + "/" + id
	h.checked[key] = true
	detail := fmt.Sprintf(format, args...)
	reason, known := h.engine.Known[key]
	switch {
	case ok && !known:
		h.T.Logf("PASS  %s: %s", key, detail)
	case ok && known:
		h.T.Errorf("UNEXPECTED PASS  %s on %s: %s; remove it from the expected-difference list (%s)", key, h.engine.Name, detail, reason)
	case !ok && known:
		h.T.Logf("KNOWN DIFFERENCE  %s on %s: %s (%s)", key, h.engine.Name, detail, reason)
	default:
		h.T.Errorf("FAIL  %s on %s: %s", key, h.engine.Name, detail)
	}
	return ok
}

// Require is Check, but the scenario stops when the check fails.
func (h *H) Require(id string, ok bool, format string, args ...any) {
	h.T.Helper()
	if !h.Check(id, ok, format, args...) {
		h.T.SkipNow() // a failure is already recorded; a known difference ends the scenario quietly
	}
}

// Measure reports a value for the comparison tables. It asserts nothing.
func (h *H) Measure(name string, v any) {
	h.T.Helper()
	h.T.Logf("MEASURE engine=%s %s/%s=%v", h.engine.Name, h.scenario, name, v)
}

// Listen opens a listener on the DUT and closes it at the end of the scenario.
func (h *H) Listen(port uint16) Listener {
	h.T.Helper()
	l, err := h.DUT.Listen(port)
	if err != nil {
		h.T.Fatalf("listen on %d: %v", port, err)
	}
	h.T.Cleanup(func() { l.Close() })
	return l
}

// Peer is the testbench's end of one connection. Sequence numbers are absolute.
type Peer struct {
	h      *H
	Local  netip.AddrPort
	Remote netip.AddrPort

	ISS    uint32 // the testbench's initial sequence number
	SndNxt uint32 // the testbench's next sequence number
	DutISS uint32
	RcvNxt uint32 // the next DUT sequence number the testbench expects

	WS     int    // the shift the testbench advertised; -1 for none
	Window uint16 // the window field the testbench sends
	DutWS  int    // the shift the DUT advertised; -1 for none
	SACK   bool   // SACK was negotiated
	TS     bool   // timestamps were negotiated

	tsStart  time.Time
	tsBase   uint32
	TSRecent uint32 // the latest TSval of the DUT
	SynTSVal uint32 // the TSval of the testbench's SYN
}

// NewPeer makes a testbench endpoint towards the DUT's port with a fresh source port and ISS.
func (h *H) NewPeer(dutPort uint16) *Peer {
	h.nextPort++
	return &Peer{
		h:       h,
		Local:   netip.AddrPortFrom(PeerAddr, h.nextPort),
		Remote:  netip.AddrPortFrom(h.DUT.Addr(), dutPort),
		ISS:     rand.Uint32(),
		WS:      -1,
		Window:  65535,
		DutWS:   -1,
		tsStart: h.Now(),
		tsBase:  rand.Uint32(),
	}
}

// TSVal is the testbench's timestamp clock, 1 ms per tick.
func (p *Peer) TSVal() uint32 { return p.tsBase + uint32(p.h.Now().Sub(p.tsStart)/time.Millisecond) }

// Segment builds a segment of this flow. The timestamps option is added when negotiated.
func (p *Peer) Segment(flags uint8, seq uint32, payload []byte) Segment {
	o := NoOptions()
	if p.TS {
		o.TS = &Timestamps{Val: p.TSVal(), Ecr: p.TSRecent}
	}
	return Segment{Src: p.Local, Dst: p.Remote, Seq: seq, Ack: p.RcvNxt, Flags: flags, Window: p.Window, Opts: o, Payload: payload}
}

// Send injects s into the DUT.
func (p *Peer) Send(s Segment) {
	p.h.T.Helper()
	if err := p.h.DUT.Inject(s.Marshal()); err != nil {
		p.h.T.Fatalf("inject %v: %v", s, err)
	}
}

// SendData sends payload at the testbench's current SndNxt with ACK|PSH and advances SndNxt.
func (p *Peer) SendData(payload []byte) {
	p.h.T.Helper()
	p.Send(p.Segment(FlagACK|FlagPSH, p.SndNxt, payload))
	p.SndNxt += uint32(len(payload))
}

// SendAck sends a pure ACK of RcvNxt.
func (p *Peer) SendAck() {
	p.h.T.Helper()
	p.Send(p.Segment(FlagACK, p.SndNxt, nil))
}

// Now is the scenario's clock: the engine's clock when the DUT is a ClockedDUT, else real time.
func (h *H) Now() time.Time {
	if c, ok := h.DUT.(ClockedDUT); ok {
		return c.Now()
	}
	return time.Now()
}

// clockStep is how far Next moves a ClockedDUT's clock between looks at its output.
const clockStep = time.Millisecond

// Next returns the next segment of this flow the DUT emits within d of the scenario's clock.
// Packets of other flows, and packets that are not well-formed IPv4 TCP, are logged and dropped.
// With a ClockedDUT, Next takes what the engine has already emitted and otherwise advances the
// engine's clock in steps of clockStep until d has passed, so no real time is spent waiting.
func (p *Peer) Next(d time.Duration) (Segment, bool) {
	clocked, isClocked := p.h.DUT.(ClockedDUT)
	var timeout <-chan time.Time
	var deadline time.Time
	if isClocked {
		deadline = clocked.Now().Add(d)
	} else {
		timer := time.NewTimer(d)
		defer timer.Stop()
		timeout = timer.C
	}
	for {
		var pkt []byte
		var ok bool
		if isClocked {
			select {
			case pkt, ok = <-p.h.DUT.Emitted():
			default:
				if !clocked.Now().Before(deadline) {
					return Segment{}, false
				}
				clocked.Advance(clockStep)
				continue
			}
		} else {
			select {
			case pkt, ok = <-p.h.DUT.Emitted():
			case <-timeout:
				return Segment{}, false
			}
		}
		if !ok {
			return Segment{}, false
		}
		s, err := Parse(pkt)
		if err != nil {
			p.h.T.Logf("emitted packet ignored: %v (% x)", err, pkt[:min(len(pkt), 40)])
			continue
		}
		if s.Src != p.Remote || s.Dst != p.Local {
			p.h.T.Logf("segment of another flow ignored: %v", s)
			continue
		}
		if s.Opts.TS != nil {
			p.TSRecent = s.Opts.TS.Val
		}
		p.h.T.Logf("<- %v", s)
		return s, true
	}
}

// Await returns the first segment of this flow within d that match accepts, logging the
// segments it passes over.
func (p *Peer) Await(d time.Duration, match func(Segment) bool) (Segment, bool) {
	deadline := p.h.Now().Add(d)
	for {
		left := deadline.Sub(p.h.Now())
		if left <= 0 {
			return Segment{}, false
		}
		s, ok := p.Next(left)
		if !ok {
			return Segment{}, false
		}
		if match(s) {
			return s, true
		}
	}
}

// Quiet reports whether the DUT emits nothing on this flow for d.
func (p *Peer) Quiet(d time.Duration) (Segment, bool) {
	s, ok := p.Next(d)
	return s, !ok
}

// Connect opens a connection to l from a new peer with the given SYN options and returns the
// peer, the SYN-ACK and the accepted connection. The final ACK carries window field win.
func (h *H) Connect(l Listener, port uint16, syn Options) (*Peer, Segment, Conn) {
	h.T.Helper()
	p := h.NewPeer(port)
	p.WS = syn.WS
	if syn.TS != nil {
		// the SYN's TSval comes from the peer's clock, so later segments pass PAWS (RFC 7323 5)
		syn.TS = &Timestamps{Val: p.TSVal(), Ecr: 0}
		p.SynTSVal = syn.TS.Val
	}
	s := Segment{Src: p.Local, Dst: p.Remote, Seq: p.ISS, Flags: FlagSYN, Window: 65535, Opts: syn}
	p.Send(s)
	synack, ok := p.Await(2*time.Second, func(s Segment) bool { return s.Has(FlagSYN | FlagACK) })
	h.Require("handshake.synack", ok && synack.Ack == p.ISS+1, "SYN-ACK acknowledging ISS+1 within 2 s: %v", synack)
	p.SndNxt = p.ISS + 1
	p.DutISS = synack.Seq
	p.RcvNxt = synack.Seq + 1
	p.DutWS = synack.Opts.WS
	p.SACK = syn.SACKPermitted && synack.Opts.SACKPermitted
	p.TS = syn.TS != nil && synack.Opts.TS != nil
	if p.WS < 0 || p.DutWS < 0 {
		p.WS, p.DutWS = -1, -1 // window scaling is used only when both sides offered it (RFC 7323 2.2)
	}
	if p.TS {
		p.TSRecent = synack.Opts.TS.Val
	}
	p.SendAck()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := l.Accept(ctx)
	h.Require("handshake.accept", err == nil, "accept within 2 s after the final ACK: err=%v", err)
	h.T.Cleanup(func() { c.Abort() })
	return p, synack, c
}

// StandardSYN is the SYN options a modern client sends: MSS for wgft's MTU, window scale 7,
// SACK-permitted and timestamps. Connect fills in the timestamp value.
func StandardSYN() Options {
	mss := uint16(MTU - 40)
	return Options{MSS: &mss, WS: 7, SACKPermitted: true, TS: &Timestamps{}}
}

// readFull reads n bytes from c within d of real time. Socket deadlines are real time on every
// engine; a ClockedDUT is expected to hand data to its sockets as soon as it is injected.
func readFull(c Conn, n int, d time.Duration) ([]byte, error) {
	c.SetReadDeadline(time.Now().Add(d))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, n)
	got := 0
	for got < n {
		k, err := c.Read(buf[got:])
		got += k
		if err != nil {
			return buf[:got], err
		}
	}
	return buf, nil
}

// errString formats an error for a check's detail.
func errString(err error) string {
	if err == nil {
		return "nil"
	}
	var ne interface{ Timeout() bool }
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return err.Error()
}
