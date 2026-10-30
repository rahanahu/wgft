package tcpharness

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"
)

// The addresses and the MTU every DUT is built with. The MTU is wgft's default tunnel MTU,
// WGFT_MTU, so an MSS of 1380 is what the agent advertises in production.
var (
	DUTAddr  = netip.MustParseAddr("10.200.0.2")
	PeerAddr = netip.MustParseAddr("10.200.0.1")
)

const MTU = 1420

// SeedEnv names the environment variable that fixes the run's seed, to replay a failure.
const SeedEnv = "WGFT_TEST_TCPHARNESS_SEED"

// Known is one entry of an engine's expected-difference list: what the engine is known to do
// instead, and why that is accepted. Observed must equal the failing check's observation, so a
// difference that changes shape fails the run instead of hiding behind the entry.
type Known struct {
	Observed string
	Reason   string
}

// Engine names one TCP engine and how to build a fresh DUT of it. New gets the scenario's seed;
// an engine that takes randomness, such as an ISN key, uses it so a run can be replayed. Known
// maps "scenario/check" to the engine's expected differences.
type Engine struct {
	Name  string
	New   func(tb testing.TB, seed uint64) DUT
	Known map[string]Known
	// Prepare, when set, runs before New for each scenario, so an engine can apply the scenario's
	// own settings: the Linux reference applies Scenario.Linux.
	Prepare func(tb testing.TB, s Scenario)
}

// Scenario is one engine-neutral conformance scenario.
type Scenario struct {
	Name string
	// Refs names the RFC sections and the gVisor packetimpact tests the scenario follows.
	Refs string
	Run  func(h *H)
	// Linux holds sysctls, as path and value under /proc/sys, that the reference Linux uses for
	// this scenario on top of its pinned configuration. A scenario family that checks a mechanism
	// the pinned configuration switches off, such as RACK-TLP, turns it back on here.
	Linux [][2]string
}

// runSeed is the run's seed: SeedEnv's value, or a random one that the run logs.
func runSeed(t testing.TB) uint64 {
	if v := os.Getenv(SeedEnv); v != "" {
		s, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			t.Fatalf("%s=%q is not an unsigned integer", SeedEnv, v)
		}
		return s
	}
	return rand.Uint64()
}

// ScenarioSeed derives a scenario's seed from the run's seed and the scenario's name, so a
// scenario run alone with -run gets the seed it had in the full run.
func ScenarioSeed(run uint64, scenario string) uint64 {
	f := fnv.New64a()
	f.Write([]byte(scenario))
	return run ^ f.Sum64()
}

// Run runs every scenario as a subtest against a fresh DUT of e. A listed difference that no
// check reached is an error when every scenario ran, and only logged when -run left some out.
func Run(t *testing.T, e Engine, scenarios []Scenario) {
	seed := runSeed(t)
	t.Logf("run seed: %d; replay with %s=%d", seed, SeedEnv, seed)
	seen := map[string]bool{}
	ran := 0
	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			ran++
			ss := ScenarioSeed(seed, s.Name)
			t.Logf("refs: %s", s.Refs)
			t.Logf("scenario seed: %d", ss)
			if e.Prepare != nil {
				e.Prepare(t, s)
			}
			h := newH(t, e, s.Name, e.New(t, ss), ss)
			// a deferred call also runs when Require ends the scenario through SkipNow or FailNow
			defer func() {
				for k := range h.outcome {
					seen[k] = true
				}
			}()
			s.Run(h)
		})
	}
	var unreached []string
	for k := range e.Known {
		if !seen[k] {
			unreached = append(unreached, k)
		}
	}
	sort.Strings(unreached)
	for _, k := range unreached {
		if ran == len(scenarios) {
			t.Errorf("known difference %s on %s: no check reached it; fix its key or remove it", k, e.Name)
		} else {
			t.Logf("known difference %s: not reached; -run left scenarios out", k)
		}
	}
}

// Outcome of one check.
const (
	OutcomePass       = "pass"
	OutcomeFail       = "fail"
	OutcomeKnown      = "known"
	OutcomeUnexpected = "unexpected-pass"
	OutcomeChanged    = "changed-difference"
)

// Record runs one scenario against a fresh DUT of e without failing t, and returns the outcomes
// of each check by key, one per time the scenario ran the check, in order. It lets the harness test itself: a scenario run against a deliberately wrong
// engine must fail the check meant to catch the fault.
func Record(t *testing.T, e Engine, s Scenario, seed uint64) map[string][]string {
	rec := &recorder{TB: t}
	var h *H
	done := make(chan struct{})
	go func() {
		defer close(done)
		if e.Prepare != nil {
			e.Prepare(rec, s)
		}
		h = newH(rec, e, s.Name, e.New(rec, seed), seed)
		s.Run(h)
	}()
	<-done
	if h == nil {
		t.Fatalf("scenario %s did not start: %v", s.Name, rec.msgs)
	}
	return h.outcome
}

// recorder is a testing.TB that logs failures instead of failing, and ends the scenario's
// goroutine where the real one would stop the test.
type recorder struct {
	testing.TB
	msgs []string
}

func (r *recorder) Errorf(format string, args ...any) {
	m := fmt.Sprintf(format, args...)
	r.msgs = append(r.msgs, m)
	r.TB.Logf("recorded: %s", m)
}
func (r *recorder) Error(args ...any) { r.Errorf("%s", fmt.Sprint(args...)) }
func (r *recorder) Fatalf(format string, args ...any) {
	r.Errorf(format, args...)
	runtime.Goexit()
}
func (r *recorder) Fatal(args ...any)                { r.Fatalf("%s", fmt.Sprint(args...)) }
func (r *recorder) Fail()                            {}
func (r *recorder) FailNow()                         { runtime.Goexit() }
func (r *recorder) SkipNow()                         { runtime.Goexit() }
func (r *recorder) Skipf(format string, args ...any) { r.TB.Logf(format, args...); runtime.Goexit() }
func (r *recorder) Skip(args ...any)                 { r.TB.Log(args...); runtime.Goexit() }

// H is the context of one scenario on one DUT.
type H struct {
	T        testing.TB
	DUT      DUT
	engine   Engine
	scenario string
	outcome  map[string][]string
	rng      *rand.Rand
	nextPort uint16
}

func newH(t testing.TB, e Engine, scenario string, d DUT, seed uint64) *H {
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	return &H{T: t, DUT: d, engine: e, scenario: scenario, outcome: map[string][]string{}, rng: rng,
		nextPort: uint16(40000 + rng.IntN(20000))}
}

// Check records one check against the engine's expected-difference list. what states the
// expectation. got is the observation; it is compared with a listed difference's Observed, so it
// names behaviour and leaves out values that change from run to run, such as sequence numbers.
func (h *H) Check(id string, ok bool, what, got string) bool {
	h.T.Helper()
	key := h.scenario + "/" + id
	k, known := h.engine.Known[key]
	switch {
	case ok && !known:
		h.outcome[key] = append(h.outcome[key], OutcomePass)
		h.T.Logf("PASS  %s: %s; got: %s", key, what, got)
	case ok && known:
		h.outcome[key] = append(h.outcome[key], OutcomeUnexpected)
		h.T.Errorf("UNEXPECTED PASS  %s on %s: %s; got: %s; the list says: %s; remove the entry", key, h.engine.Name, what, got, k.Observed)
	case !ok && known && got == k.Observed:
		h.outcome[key] = append(h.outcome[key], OutcomeKnown)
		h.T.Logf("KNOWN DIFFERENCE  %s on %s: %s; got: %s; reason: %s", key, h.engine.Name, what, got, k.Reason)
	case !ok && known:
		h.outcome[key] = append(h.outcome[key], OutcomeChanged)
		h.T.Errorf("CHANGED DIFFERENCE  %s on %s: %s; got: %s; the list says: %s", key, h.engine.Name, what, got, k.Observed)
	default:
		h.outcome[key] = append(h.outcome[key], OutcomeFail)
		h.T.Errorf("FAIL  %s on %s: %s; got: %s", key, h.engine.Name, what, got)
	}
	return ok
}

// Require is Check, but the scenario stops when the check fails. A known difference ends it as
// a skip; any other failure ends it as a failure.
func (h *H) Require(id string, ok bool, what, got string) {
	h.T.Helper()
	if h.Check(id, ok, what, got) {
		return
	}
	if o := h.outcome[h.scenario+"/"+id]; o[len(o)-1] == OutcomeKnown {
		h.T.SkipNow()
	}
	h.T.FailNow()
}

// Measure reports a value for the comparison tables. It asserts nothing.
func (h *H) Measure(name string, v any) {
	h.T.Helper()
	h.T.Logf("MEASURE engine=%s %s/%s=%v", h.engine.Name, h.scenario, name, v)
}

// Prompt is how soon the DUT must answer where the RFCs ask for an immediate segment, such as
// the duplicate ACK for an out-of-order segment. On real time it is far below the 200 ms floor of
// a delayed ACK and of the RTO, so a delayed answer fails. On a ClockedDUT it is zero: the answer
// must be ready before the clock moves.
func (h *H) Prompt() time.Duration {
	if _, ok := h.DUT.(ClockedDUT); ok {
		return 0
	}
	return 100 * time.Millisecond
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

	DutAck    uint32 // the latest acknowledgment number from the DUT
	DutWindow int    // the latest window the DUT advertised, in bytes

	lastTS uint32 // the TSval of the latest segment sent with timestamps
}

// NewPeer makes a testbench endpoint towards the DUT's port with a fresh source port and ISS
// from the scenario's seed.
func (h *H) NewPeer(dutPort uint16) *Peer {
	h.nextPort++
	return &Peer{
		h:       h,
		Local:   netip.AddrPortFrom(PeerAddr, h.nextPort),
		Remote:  netip.AddrPortFrom(h.DUT.Addr(), dutPort),
		ISS:     h.rng.Uint32(),
		WS:      -1,
		Window:  65535,
		DutWS:   -1,
		tsStart: h.Now(),
		tsBase:  h.rng.Uint32(),
	}
}

// Reincarnate makes a new peer on the same four-tuple as p, for a new connection after p's has
// closed, with the given ISS and a timestamp clock that continues p's 1000 ticks later.
func (p *Peer) Reincarnate(iss uint32) *Peer {
	return &Peer{h: p.h, Local: p.Local, Remote: p.Remote, ISS: iss, WS: -1, Window: 65535, DutWS: -1,
		tsStart: p.h.Now(), tsBase: p.TSVal() + 1000}
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
	if s.Opts.TS != nil {
		p.lastTS = s.Opts.TS.Val
	}
	p.h.T.Logf("-> %v", s)
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

// SendFIN sends a FIN, with payload if any, and advances SndNxt past it.
func (p *Peer) SendFIN(payload []byte) {
	p.h.T.Helper()
	p.Send(p.Segment(FlagFIN|FlagACK|FlagPSH, p.SndNxt, payload))
	p.SndNxt += uint32(len(payload)) + 1
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

// next returns the DUT's next packet within d of the scenario's clock.
func (h *H) next(d time.Duration) ([]byte, bool) {
	if c, ok := h.DUT.(ClockedDUT); ok {
		deadline := c.Now().Add(d)
		for {
			if pkt, ok := c.Poll(); ok {
				return pkt, true
			}
			if !c.Now().Before(deadline) {
				return nil, false
			}
			c.Advance(clockStep)
		}
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case pkt, ok := <-h.DUT.Emitted():
		return pkt, ok
	case <-timer.C:
		return nil, false
	}
}

// Next returns the next segment of this flow the DUT emits within d of the scenario's clock.
// Packets of other flows, and packets that are not well-formed IPv4 TCP, are logged and dropped.
// A packet larger than the MTU fails the scenario: the harness compares segments as TCP alone
// cut them, with no offload in between.
func (p *Peer) Next(d time.Duration) (Segment, bool) {
	deadline := p.h.Now().Add(d)
	for {
		pkt, ok := p.h.next(max(deadline.Sub(p.h.Now()), 0))
		if !ok {
			return Segment{}, false
		}
		if len(pkt) > p.h.DUT.MTU() {
			p.h.T.Errorf("FAIL  emitted packet on %s: at most the MTU of %d bytes; got: %d bytes", p.h.engine.Name, p.h.DUT.MTU(), len(pkt))
		}
		s, err := Parse(pkt)
		if err != nil {
			p.h.T.Logf("emitted packet ignored: %v: % x", err, pkt[:min(len(pkt), 40)])
			continue
		}
		if s.Src != p.Remote || s.Dst != p.Local {
			p.h.T.Logf("segment of another flow ignored: %v", s)
			continue
		}
		if s.Opts.TS != nil {
			p.TSRecent = s.Opts.TS.Val
		}
		if s.Has(FlagACK) {
			p.DutAck = s.Ack
			p.DutWindow = int(s.Window)
			if p.DutWS >= 0 && !s.Has(FlagSYN) {
				p.DutWindow <<= p.DutWS
			}
		}
		p.h.T.Logf("<- %v", s)
		return s, true
	}
}

// Collect returns every well-formed TCP segment the DUT emits within d, of any flow, so a
// scenario can watch several flows at once without Next dropping the others.
func (h *H) Collect(d time.Duration) []Segment {
	var out []Segment
	deadline := h.Now().Add(d)
	for {
		pkt, ok := h.next(max(deadline.Sub(h.Now()), 0))
		if !ok {
			return out
		}
		if s, err := Parse(pkt); err == nil {
			h.T.Logf("<- %v", s)
			out = append(out, s)
		}
	}
}

// Await returns the first segment of this flow within d that match accepts, logging the
// segments it passes over.
func (p *Peer) Await(d time.Duration, match func(Segment) bool) (Segment, bool) {
	deadline := p.h.Now().Add(d)
	for {
		s, ok := p.Next(max(deadline.Sub(p.h.Now()), 0))
		if !ok {
			return Segment{}, false
		}
		if match(s) {
			return s, true
		}
	}
}

// SendFreshAck sends a pure ACK whose TSval is above every TSval sent before, waiting for the
// timestamp clock to tick when it must, and returns that TSval. A segment the DUT sent before it
// had this ACK echoes an older TSval, which QuietSince tells apart.
func (p *Peer) SendFreshAck() uint32 {
	p.h.T.Helper()
	for p.TS && int32(p.TSVal()-p.lastTS) <= 0 {
		if c, ok := p.h.DUT.(ClockedDUT); ok {
			c.Advance(time.Millisecond)
		} else {
			time.Sleep(time.Millisecond)
		}
	}
	p.SendAck()
	return p.lastTS
}

// QuietSince is Quiet, but it passes over segments whose TSecr is older than ts: segments the DUT
// sent before it had the segment that carried ts, such as a tail loss probe that a slow testbench
// let fire before its ACK arrived. It returns how many it passed over.
func (p *Peer) QuietSince(d time.Duration, ts uint32) (Segment, bool, int) {
	stale := 0
	deadline := p.h.Now().Add(d)
	for {
		s, ok := p.Next(max(deadline.Sub(p.h.Now()), 0))
		if !ok {
			return Segment{}, true, stale
		}
		if p.TS && s.Opts.TS != nil && int32(s.Opts.TS.Ecr-ts) < 0 {
			p.h.T.Logf("sent before the DUT had the testbench's latest segment, passed over: %v", s)
			stale++
			continue
		}
		return s, false, stale
	}
}

// Quiet reports whether the DUT emits nothing on this flow for d.
func (p *Peer) Quiet(d time.Duration) (Segment, bool) {
	s, ok := p.Next(d)
	return s, !ok
}

// Dial describes the testbench's side of a handshake.
type Dial struct {
	SYN Options
	// Window is the window field of every segment after the SYN; zero means 65535.
	Window uint16
	// SynWindow is the SYN's window field, which is never scaled; zero means Window.
	SynWindow uint16
	// AckDelay holds the final ACK of the handshake back, so the DUT's first RTT sample, and
	// with RTT the RACK and TLP timers, has a path delay to work with.
	AckDelay time.Duration
}

// Handshake runs a three-way handshake from a new peer to port and returns the peer and the
// SYN-ACK. It does not accept the connection.
func (h *H) Handshake(port uint16, d Dial) (*Peer, Segment) {
	h.T.Helper()
	p := h.NewPeer(port)
	return p, h.HandshakeFrom(p, d)
}

// HandshakeFrom runs a three-way handshake from p, which may be a reincarnated peer.
func (h *H) HandshakeFrom(p *Peer, d Dial) Segment {
	h.T.Helper()
	p.Window = 65535
	if d.Window != 0 {
		p.Window = d.Window
	}
	synWin := p.Window
	if d.SynWindow != 0 {
		synWin = d.SynWindow
	}
	p.WS = d.SYN.WS
	syn := d.SYN
	if syn.TS != nil {
		// the SYN's TSval comes from the peer's clock, so later segments pass PAWS
		syn.TS = &Timestamps{Val: p.TSVal(), Ecr: 0}
		p.SynTSVal = syn.TS.Val
	}
	p.Send(Segment{Src: p.Local, Dst: p.Remote, Seq: p.ISS, Flags: FlagSYN, Window: synWin, Opts: syn})
	synack, ok := p.Await(2*time.Second, func(s Segment) bool { return s.Has(FlagSYN | FlagACK) })
	h.Require("handshake.synack", ok && synack.Ack == p.ISS+1, "a SYN-ACK acknowledging ISS+1 within 2 s", synackString(p, synack, ok))
	p.adopt(syn, synack)
	if d.AckDelay > 0 {
		p.Quiet(d.AckDelay)
	}
	p.SendAck()
	return synack
}

// adopt takes the connection's parameters from the SYN the peer sent and the SYN-ACK.
func (p *Peer) adopt(syn Options, synack Segment) {
	p.SndNxt = p.ISS + 1
	p.DutISS = synack.Seq
	p.RcvNxt = synack.Seq + 1
	p.DutWS = synack.Opts.WS
	p.SACK = syn.SACKPermitted && synack.Opts.SACKPermitted
	p.TS = syn.TS != nil && synack.Opts.TS != nil
	if p.WS < 0 || p.DutWS < 0 {
		p.WS, p.DutWS = -1, -1 // window scaling is used only when both sides offered it, RFC 7323 2.2
	}
	if p.TS {
		p.TSRecent = synack.Opts.TS.Val
	}
}

func synackString(p *Peer, s Segment, ok bool) string {
	switch {
	case !ok:
		return "no SYN-ACK"
	case s.Ack != p.ISS+1:
		return "a SYN-ACK acknowledging another number"
	}
	return "a SYN-ACK acknowledging ISS+1"
}

// Connect opens a connection to l from a new peer with the given SYN options and returns the
// peer, the SYN-ACK and the accepted connection.
func (h *H) Connect(l Listener, port uint16, syn Options) (*Peer, Segment, Conn) {
	h.T.Helper()
	return h.ConnectWith(l, port, Dial{SYN: syn})
}

// ConnectWith is Connect with the whole Dial.
func (h *H) ConnectWith(l Listener, port uint16, d Dial) (*Peer, Segment, Conn) {
	h.T.Helper()
	p, synack := h.Handshake(port, d)
	return p, synack, h.Accept(l)
}

// Accept accepts the next connection within 2 s and aborts it at the end of the scenario.
func (h *H) Accept(l Listener) Conn {
	h.T.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := l.Accept(ctx)
	h.Require("handshake.accept", err == nil, "accept within 2 s after the final ACK", "error "+errString(err))
	h.T.Cleanup(func() { c.Abort() })
	return c
}

// StandardSYN is the SYN options a modern client sends: MSS for wgft's MTU, window scale 7,
// SACK-permitted and timestamps. Handshake fills in the timestamp value.
func StandardSYN() Options {
	mss := uint16(MTU - 40)
	return Options{MSS: &mss, WS: 7, SACKPermitted: true, TS: &Timestamps{}}
}

// NoSACKSYN is StandardSYN without SACK-permitted, for the loss-recovery scenarios: both ends
// then recover as NewReno.
func NoSACKSYN() Options {
	o := StandardSYN()
	o.SACKPermitted = false
	return o
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

// errString names an error for a check's observation: nil, timeout, EOF or the error's text.
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
