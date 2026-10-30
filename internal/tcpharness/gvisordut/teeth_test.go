package gvisordut

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/tcpharness"
)

// The tests in this file run a scenario against a deliberately wrong engine, gVisor behind a
// wrapper that injects one fault, and require the check meant to catch that fault to fail. They
// keep the harness's bounds from loosening until a fault passes.

func scenario(t *testing.T, name string) tcpharness.Scenario {
	for _, s := range tcpharness.Scenarios {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no scenario %s", name)
	return tcpharness.Scenario{}
}

func mutant(name string, wrap func(tcpharness.DUT) tcpharness.DUT) tcpharness.Engine {
	base := Engine(nil)
	return tcpharness.Engine{Name: name, New: func(tb testing.TB, seed uint64) tcpharness.DUT {
		return wrap(base.New(tb, seed))
	}}
}

func wantOutcome(t *testing.T, got map[string][]string, key, want string) {
	t.Helper()
	o := got[key]
	bad := len(o) == 0
	for _, v := range o {
		bad = bad || v != want
	}
	if bad {
		t.Errorf("%s: outcome %q, want %q; all outcomes: %v", key, got[key], want, got)
	}
}

// delayedACKs holds every pure ACK the engine emits for delay before passing it on, the way a
// receiver that delays the ACK of an out-of-order segment would.
type delayedACKs struct {
	tcpharness.DUT
	out chan []byte
}

func (d *delayedACKs) Emitted() <-chan []byte { return d.out }

func delayACKs(delay time.Duration) func(tcpharness.DUT) tcpharness.DUT {
	return func(inner tcpharness.DUT) tcpharness.DUT {
		d := &delayedACKs{DUT: inner, out: make(chan []byte, 1024)}
		go func() {
			defer close(d.out)
			for pkt := range inner.Emitted() {
				if s, err := tcpharness.Parse(pkt); err == nil && s.Flags == tcpharness.FlagACK && len(s.Payload) == 0 {
					time.Sleep(delay)
				}
				d.out <- pkt
			}
		}()
		return d
	}
}

func TestHarnessCatchesDelayedDuplicateACK(t *testing.T) {
	t.Parallel() // independent Devices; the package then takes about as long as its longest test
	got := tcpharness.Record(t, mutant("gvisor-delayed-ack", delayACKs(300*time.Millisecond)), scenario(t, "ooo-sack"), 1)
	wantOutcome(t, got, "ooo-sack/dupack1", tcpharness.OutcomeFail)
}

// corruptMSS536 breaks the TCP checksum of every SYN that offers an MSS of 536, so the engine
// drops the SYN for a reason that has nothing to do with the MSS floor.
type corruptMSS536 struct{ tcpharness.DUT }

func (d corruptMSS536) Inject(pkt []byte) error {
	if s, err := tcpharness.Parse(pkt); err == nil && s.Flags == tcpharness.FlagSYN && s.Opts.MSS != nil && *s.Opts.MSS == 536 {
		pkt = append([]byte(nil), pkt...)
		sum := binary.BigEndian.Uint16(pkt[36:])
		binary.BigEndian.PutUint16(pkt[36:], sum^0xffff^1)
	}
	return d.DUT.Inject(pkt)
}

func TestHarnessCatchesMSSFloorDropForAnotherReason(t *testing.T) {
	t.Parallel() // independent Devices; the package then takes about as long as its longest test
	e := mutant("gvisor-bad-checksum", func(d tcpharness.DUT) tcpharness.DUT { return corruptMSS536{d} })
	got := tcpharness.Record(t, e, scenario(t, "handshake-mss-floor"), 1)
	wantOutcome(t, got, "handshake-mss-floor/mss536.synack", tcpharness.OutcomeFail)
}

// unscaledReceiver drops every injected data segment that starts more than 64 KiB past the
// latest acknowledgment the engine sent, as a receiver that read its own window unscaled would.
type unscaledReceiver struct {
	tcpharness.DUT
	out chan []byte
	mu  sync.Mutex
	ack map[uint16]uint32 // by the testbench's port
}

func (d *unscaledReceiver) Emitted() <-chan []byte { return d.out }

func (d *unscaledReceiver) Inject(pkt []byte) error {
	if s, err := tcpharness.Parse(pkt); err == nil && len(s.Payload) > 0 {
		d.mu.Lock()
		ack, ok := d.ack[s.Src.Port()]
		d.mu.Unlock()
		if ok && int32(s.Seq-ack) > 65535 {
			return nil
		}
	}
	return d.DUT.Inject(pkt)
}

func dropBeyond64K(inner tcpharness.DUT) tcpharness.DUT {
	d := &unscaledReceiver{DUT: inner, out: make(chan []byte, 1024), ack: map[uint16]uint32{}}
	go func() {
		defer close(d.out)
		for pkt := range inner.Emitted() {
			if s, err := tcpharness.Parse(pkt); err == nil && s.Has(tcpharness.FlagACK) {
				d.mu.Lock()
				if a, ok := d.ack[s.Dst.Port()]; !ok || int32(s.Ack-a) > 0 {
					d.ack[s.Dst.Port()] = s.Ack
				}
				d.mu.Unlock()
			}
			d.out <- pkt
		}
	}()
	return d
}

func TestHarnessCatchesUnscaledReceiveWindow(t *testing.T) {
	t.Parallel() // independent Devices; the package then takes about as long as its longest test
	got := tcpharness.Record(t, mutant("gvisor-unscaled-receiver", dropBeyond64K), scenario(t, "window-scale"), 1)
	wantOutcome(t, got, "window-scale/own-scale.span-held", tcpharness.OutcomeFail)
}

// rewritten passes every emitted packet through f on its way to the testbench.
type rewritten struct {
	tcpharness.DUT
	out chan []byte
}

func (d *rewritten) Emitted() <-chan []byte { return d.out }

func rewrite(f func([]byte) []byte) func(tcpharness.DUT) tcpharness.DUT {
	return func(inner tcpharness.DUT) tcpharness.DUT {
		d := &rewritten{DUT: inner, out: make(chan []byte, 1024)}
		go func() {
			defer close(d.out)
			for pkt := range inner.Emitted() {
				d.out <- f(pkt)
			}
		}()
		return d
	}
}

// zeroUDPChecksum clears the checksum of every UDP datagram the engine sends, in its first
// fragment when it is fragmented: a valid datagram that no longer carries a checksum.
func zeroUDPChecksum(pkt []byte) []byte {
	p, err := tcpharness.ParseIPv4(pkt)
	if err != nil || p.Proto != tcpharness.ProtoUDP || p.Offset != 0 {
		return pkt
	}
	pkt = append([]byte(nil), pkt...)
	ihl := int(pkt[0]&0x0f) * 4
	pkt[ihl+6], pkt[ihl+7] = 0, 0
	return pkt
}

func TestHarnessCatchesUDPReplyWithoutChecksum(t *testing.T) {
	t.Parallel()
	e := mutant("gvisor-no-udp-checksum", rewrite(zeroUDPChecksum))
	got := tcpharness.Record(t, e, scenario(t, "udp-datagram"), 1)
	wantOutcome(t, got, "udp-datagram/reply", tcpharness.OutcomeFail)
	got = tcpharness.Record(t, e, scenario(t, "udp-large"), 1)
	wantOutcome(t, got, "udp-large/reply.reassembles", tcpharness.OutcomeFail)
}

// earlyTimeExceeded answers the first fragment of the timeout scenario's datagram with Time
// Exceeded after 5 s, as a reassembly table with a 5 s lifetime would.
type earlyTimeExceeded struct {
	*rewritten
	once sync.Once
}

func (d *earlyTimeExceeded) Inject(pkt []byte) error {
	if p, err := tcpharness.ParseIPv4(pkt); err == nil && p.Proto == tcpharness.ProtoUDP && p.MF && p.Offset == 0 && p.ID == 401 {
		quote := append([]byte(nil), pkt[:28]...)
		d.once.Do(func() {
			time.AfterFunc(5*time.Second, func() {
				te := tcpharness.ICMPPacket(p.Dst, p.Src, 1, tcpharness.ICMP{Type: tcpharness.ICMPTimeExceeded, Code: tcpharness.CodeReassemblyTime, Body: quote})
				d.out <- te.Marshal()
			})
		})
	}
	return d.rewritten.Inject(pkt)
}

func TestHarnessCatchesEarlyReassemblyTimeout(t *testing.T) {
	t.Parallel()
	e := mutant("gvisor-5s-reassembly", func(inner tcpharness.DUT) tcpharness.DUT {
		return &earlyTimeExceeded{rewritten: rewrite(func(p []byte) []byte { return p })(inner).(*rewritten)}
	})
	got := tcpharness.Record(t, e, scenario(t, "udp-reassembly-timeout"), 1)
	wantOutcome(t, got, "udp-reassembly-timeout/time-exceeded.not-early", tcpharness.OutcomeFail)
}

// finAfterAck sends the engine's FIN once more 100 ms after it left, echoing the latest TSval
// the testbench sent, as an engine that resends after the testbench's ACK arrived would.
type finAfterAck struct {
	tcpharness.DUT
	stale bool // keep the FIN's own TSecr, as a probe sent before the ACK arrived
	// change, when set, alters the resent copy: data instead of the FIN, or another number
	change func(*tcpharness.Segment)
	after  time.Duration // how long after the FIN the copy goes; 100 ms when zero
	out    chan []byte
	mu     sync.Mutex
	tsval  uint32
	wg     sync.WaitGroup
	resent bool
}

func (d *finAfterAck) Emitted() <-chan []byte { return d.out }

func (d *finAfterAck) Inject(pkt []byte) error {
	if s, err := tcpharness.Parse(pkt); err == nil && s.Opts.TS != nil {
		d.mu.Lock()
		d.tsval = s.Opts.TS.Val
		d.mu.Unlock()
	}
	return d.DUT.Inject(pkt)
}

func resendFINAfterAck(inner tcpharness.DUT) tcpharness.DUT { return resendFIN(inner, false) }

func resendFIN(inner tcpharness.DUT, stale bool) tcpharness.DUT {
	return resendChanged(inner, stale, nil)
}

func resendChanged(inner tcpharness.DUT, stale bool, change func(*tcpharness.Segment)) tcpharness.DUT {
	d := &finAfterAck{DUT: inner, stale: stale, change: change, out: make(chan []byte, 1024)}
	go func() {
		for pkt := range inner.Emitted() {
			if s, err := tcpharness.Parse(pkt); err == nil && s.Has(tcpharness.FlagFIN) && s.Opts.TS != nil && !d.resent {
				d.resent = true
				d.wg.Add(1)
				after := d.after
				if after == 0 {
					after = 100 * time.Millisecond
				}
				time.AfterFunc(after, func() {
					defer d.wg.Done()
					if d.change != nil && d.after > 0 {
						// the copy's TSval says when the engine would have sent it
						s.Opts.TS.Val += uint32(after / time.Millisecond)
					}
					if !d.stale {
						d.mu.Lock()
						s.Opts.TS.Ecr = d.tsval
						d.mu.Unlock()
					}
					if d.change != nil {
						d.change(&s)
					}
					d.out <- s.Marshal()
				})
			}
			d.out <- pkt
		}
		d.wg.Wait()
		close(d.out)
	}()
	return d
}

func TestHarnessCatchesFINAfterTheAck(t *testing.T) {
	t.Parallel()
	got := tcpharness.Record(t, mutant("gvisor-fin-after-ack", resendFINAfterAck), scenario(t, "fin-passive-close"), 1)
	wantOutcome(t, got, "fin-passive-close/closed.quiet", tcpharness.OutcomeFail)
}

// A FIN resent with the TSecr it had, which the DUT sent before it had the testbench's ACK, is
// the tail loss probe a loaded machine lets fire; the scenario passes over it.
func TestHarnessPassesOverAFINSentBeforeTheAck(t *testing.T) {
	t.Parallel()
	e := mutant("gvisor-fin-probe", func(d tcpharness.DUT) tcpharness.DUT { return resendFIN(d, true) })
	got := tcpharness.Record(t, e, scenario(t, "fin-passive-close"), 1)
	wantOutcome(t, got, "fin-passive-close/closed.quiet", tcpharness.OutcomePass)
}

// dropFinalAck drops the testbench's pure ACK of the engine's FIN, so the engine stays in LAST-ACK
// and resends its FIN, each time echoing the TSval it had before.
type dropFinalAck struct {
	tcpharness.DUT
	mu   sync.Mutex
	fin  uint32 // the sequence number after the engine's FIN, once it has sent one
	seen bool
	out  chan []byte
}

func (d *dropFinalAck) Emitted() <-chan []byte { return d.out }

func (d *dropFinalAck) Inject(pkt []byte) error {
	if s, err := tcpharness.Parse(pkt); err == nil && s.Flags == tcpharness.FlagACK && len(s.Payload) == 0 {
		d.mu.Lock()
		drop := d.seen && s.Ack == d.fin
		d.mu.Unlock()
		if drop {
			return nil
		}
	}
	return d.DUT.Inject(pkt)
}

func dropAckOfFIN(inner tcpharness.DUT) tcpharness.DUT {
	d := &dropFinalAck{DUT: inner, out: make(chan []byte, 1024)}
	go func() {
		defer close(d.out)
		for pkt := range inner.Emitted() {
			if s, err := tcpharness.Parse(pkt); err == nil && s.Has(tcpharness.FlagFIN) {
				d.mu.Lock()
				d.fin, d.seen = s.Seq+s.Len(), true
				d.mu.Unlock()
			}
			d.out <- pkt
		}
	}()
	return d
}

func TestHarnessCatchesFINResentAfterADroppedAck(t *testing.T) {
	t.Parallel()
	got := tcpharness.Record(t, mutant("gvisor-drops-final-ack", dropAckOfFIN), scenario(t, "fin-passive-close"), 1)
	wantOutcome(t, got, "fin-passive-close/closed.quiet", tcpharness.OutcomeFail)
}

// earlyResend resends the engine's lowest unacknowledged data segment the moment the n-th
// duplicate ACK with SACK blocks reaches it, echoing that ACK's TSval, as a sender that counted n
// duplicate ACKs as the threshold, or that ran RACK with no reorder window, would.
type earlyResend struct {
	tcpharness.DUT
	n int
	// stale keeps the segment's own TSecr, as a probe the engine sent before the ACK arrived
	stale bool
	out   chan []byte
	mu    sync.Mutex
	// by the testbench's port: the data segments sent, by sequence number, and the duplicate
	// ACKs counted for the latest acknowledgment number
	sent   map[uint16]map[uint32]tcpharness.Segment
	ack    map[uint16]uint32
	dups   map[uint16]int
	closed bool
}

func (d *earlyResend) Emitted() <-chan []byte { return d.out }

func (d *earlyResend) Inject(pkt []byte) error {
	err := d.DUT.Inject(pkt)
	s, perr := tcpharness.Parse(pkt)
	if perr != nil || s.Flags != tcpharness.FlagACK || len(s.Payload) > 0 || len(s.Opts.SACK) == 0 {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	port := s.Src.Port()
	if a, ok := d.ack[port]; !ok || a != s.Ack {
		d.ack[port], d.dups[port] = s.Ack, 0
	}
	d.dups[port]++
	if seg, ok := d.sent[port][s.Ack]; ok && d.dups[port] == d.n && !d.closed {
		if seg.Opts.TS != nil && s.Opts.TS != nil && !d.stale {
			ts := *seg.Opts.TS
			ts.Ecr = s.Opts.TS.Val
			seg.Opts.TS = &ts
		}
		d.out <- seg.Marshal()
	}
	return err
}

func resendAtDupack(n int) func(tcpharness.DUT) tcpharness.DUT { return resendAt(n, false) }

func resendAt(n int, stale bool) func(tcpharness.DUT) tcpharness.DUT {
	return func(inner tcpharness.DUT) tcpharness.DUT {
		d := &earlyResend{DUT: inner, n: n, stale: stale, out: make(chan []byte, 1024),
			sent: map[uint16]map[uint32]tcpharness.Segment{}, ack: map[uint16]uint32{}, dups: map[uint16]int{}}
		go func() {
			for pkt := range inner.Emitted() {
				if s, err := tcpharness.Parse(pkt); err == nil && len(s.Payload) > 0 {
					d.mu.Lock()
					if d.sent[s.Dst.Port()] == nil {
						d.sent[s.Dst.Port()] = map[uint32]tcpharness.Segment{}
					}
					if _, ok := d.sent[s.Dst.Port()][s.Seq]; !ok {
						d.sent[s.Dst.Port()][s.Seq] = s
					}
					d.mu.Unlock()
				}
				d.out <- pkt
			}
			d.mu.Lock()
			d.closed = true
			close(d.out)
			d.mu.Unlock()
		}()
		return d
	}
}

// On limited-transmit-rack's path, RACK's reorder window outlasts the checks, so a resend at
// the first or the second duplicate ACK is one no correct sender makes.
func TestHarnessCatchesResendAtFirstDupack(t *testing.T) {
	got := tcpharness.Record(t, mutant("gvisor-dupthresh-1", resendAtDupack(1)), scenario(t, "limited-transmit-rack"), 1)
	wantOutcome(t, got, "limited-transmit-rack/no-retransmit-before-third", tcpharness.OutcomeFail)
}

// A resend that echoes a TSecr older than the first duplicate ACK left before that ACK arrived,
// as a probe on a loaded machine does; it answers no duplicate ACK and does not fail the check.
func TestHarnessPassesOverAResendBeforeTheDupack(t *testing.T) {
	got := tcpharness.Record(t, mutant("gvisor-stale-probe", resendAt(1, true)), scenario(t, "limited-transmit-rack"), 1)
	wantOutcome(t, got, "limited-transmit-rack/no-retransmit-before-third", tcpharness.OutcomePass)
}

func TestHarnessCatchesResendAtSecondDupack(t *testing.T) {
	got := tcpharness.Record(t, mutant("gvisor-dupthresh-2", resendAtDupack(2)), scenario(t, "limited-transmit-rack"), 1)
	wantOutcome(t, got, "limited-transmit-rack/no-retransmit-before-third", tcpharness.OutcomeFail)
}

// A sender with no reorder window resends the late segment at the first SACK.
func TestHarnessCatchesResendWithinTheReorderWindow(t *testing.T) {
	got := tcpharness.Record(t, mutant("gvisor-no-reorder-window", resendAtDupack(1)), scenario(t, "rack-reorder"), 1)
	wantOutcome(t, got, "rack-reorder/within-window.no-retransmit", tcpharness.OutcomeFail)
}

// delayResends holds every data segment that repeats a sequence number already sent for delay,
// as a sender that resends a lost segment only on its probe or its RTO would be late.
func delayResends(delay time.Duration) func(tcpharness.DUT) tcpharness.DUT {
	return func(inner tcpharness.DUT) tcpharness.DUT {
		d := &delayedACKs{DUT: inner, out: make(chan []byte, 1024)}
		go func() {
			defer close(d.out)
			sent := map[uint32]bool{}
			for pkt := range inner.Emitted() {
				if s, err := tcpharness.Parse(pkt); err == nil && len(s.Payload) > 0 {
					if sent[s.Seq] {
						time.Sleep(delay)
					}
					sent[s.Seq] = true
				}
				d.out <- pkt
			}
		}()
		return d
	}
}

func TestHarnessCatchesLateRACKResend(t *testing.T) {
	got := tcpharness.Record(t, mutant("gvisor-late-resend", delayResends(150*time.Millisecond)), scenario(t, "rack-reorder"), 1)
	wantOutcome(t, got, "rack-reorder/beyond-window.resent-early", tcpharness.OutcomeFail)
}

// A probe held back 400 ms comes after the RTO could, and fails tlp-tail-loss's probe check even
// when a stalled testbench widens its bound.
func TestHarnessCatchesLateTailLossProbe(t *testing.T) {
	got := tcpharness.Record(t, mutant("gvisor-late-probe", delayResends(400*time.Millisecond)), scenario(t, "tlp-tail-loss"), 1)
	wantOutcome(t, got, "tlp-tail-loss/probe-at-2srtt", tcpharness.OutcomeFail)
}

// Only an unchanged resend of the FIN is passed over: a stale-TSecr segment that carries data, or
// a FIN at another sequence number, still fails the check.
func TestHarnessCatchesStaleSegmentsOtherThanTheFIN(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*tcpharness.Segment){
		"data": func(s *tcpharness.Segment) {
			s.Flags, s.Payload = tcpharness.FlagACK|tcpharness.FlagPSH, []byte("x")
		},
		"another-seq": func(s *tcpharness.Segment) { s.Seq++ },
	} {
		e := mutant("gvisor-stale-"+name, func(d tcpharness.DUT) tcpharness.DUT { return resendChanged(d, true, change) })
		got := tcpharness.Record(t, e, scenario(t, "fin-passive-close"), 1)
		wantOutcome(t, got, "fin-passive-close/closed.quiet", tcpharness.OutcomeFail)
	}
}

// A FIN resent 300 ms after the first, past the 250 ms in which a tail loss probe comes, is not
// passed over even with its stale TSecr: it is what a DUT that never had the ACK sends at its RTO.
func TestHarnessCatchesStaleFINPastTheProbeWindow(t *testing.T) {
	t.Parallel()
	e := mutant("gvisor-stale-fin-300ms", func(inner tcpharness.DUT) tcpharness.DUT {
		d := resendChanged(inner, true, func(*tcpharness.Segment) {}).(*finAfterAck)
		d.after = 300 * time.Millisecond
		return d
	})
	got := tcpharness.Record(t, e, scenario(t, "fin-passive-close"), 1)
	wantOutcome(t, got, "fin-passive-close/closed.quiet", tcpharness.OutcomeFail)
}
