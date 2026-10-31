package gvisordut

import (
	"encoding/binary"
	"strings"
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
// It runs alone, not in the parallel group: it needs a PASS from one attempt with a resend 100 ms
// after the FIN on real time, which a loaded neighbour could delay.
func TestHarnessPassesOverAFINSentBeforeTheAck(t *testing.T) {
	e := mutant("gvisor-fin-probe", func(d tcpharness.DUT) tcpharness.DUT { return resendFIN(d, true) })
	got := tcpharness.Record(t, e, scenario(t, "fin-passive-close"), 1)
	wantOutcome(t, got, "fin-passive-close/closed.quiet", tcpharness.OutcomePass)
}

// dropFinalAck drops the testbench's pure ACK of the engine's FIN, so the engine stays in LAST-ACK
// and resends its FIN, each time echoing the TSval it had before. From the engine's first resend
// after a drop on, it also repeats that resend every repeatEvery, as an engine that keeps resending
// without the ACK does: gVisor's own next resend can come seconds later on a loaded runner (over
// 3.5 s once on the Windows runner), and the tests below need a resend to judge. With holdData set,
// it also holds the testbench's pure ACK of the engine's last data segment that long before the
// engine sees it, as a loaded machine that processes the ACK late does: the FIN then goes out with
// that data still unacknowledged, and its first resend is a probe that comes at once.
type dropFinalAck struct {
	tcpharness.DUT
	holdData    time.Duration
	repeatEvery time.Duration
	mu          sync.Mutex
	fin         uint32 // the sequence number after the engine's FIN, once it has sent one
	seen        bool
	dropped     bool   // an ACK of the FIN was dropped
	repeating   bool   // the engine's first resend after a drop is being repeated
	closed      bool   // out is closed
	dataEnd     uint32 // the sequence number after the engine's latest data segment
	out         chan []byte
}

func (d *dropFinalAck) Emitted() <-chan []byte { return d.out }

func (d *dropFinalAck) Inject(pkt []byte) error {
	if s, err := tcpharness.Parse(pkt); err == nil && s.Flags == tcpharness.FlagACK && len(s.Payload) == 0 {
		d.mu.Lock()
		drop := d.seen && s.Ack == d.fin
		d.dropped = d.dropped || drop
		hold := d.holdData > 0 && !d.seen && d.dataEnd != 0 && s.Ack == d.dataEnd
		d.mu.Unlock()
		if drop {
			return nil
		}
		if hold {
			time.AfterFunc(d.holdData, func() { d.DUT.Inject(pkt) })
			return nil
		}
	}
	return d.DUT.Inject(pkt)
}

// repeat sends pkt every repeatEvery until out closes.
func (d *dropFinalAck) repeat(pkt []byte) {
	for {
		time.Sleep(d.repeatEvery)
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			return
		}
		select {
		case d.out <- pkt:
		default:
		}
		d.mu.Unlock()
	}
}

func dropAckOfFIN(inner tcpharness.DUT) tcpharness.DUT {
	return dropAckOfFINHolding(inner, 0, 100*time.Millisecond)
}

func dropAckOfFINHolding(inner tcpharness.DUT, holdData, repeatEvery time.Duration) tcpharness.DUT {
	d := &dropFinalAck{DUT: inner, holdData: holdData, repeatEvery: repeatEvery, out: make(chan []byte, 1024)}
	go func() {
		defer func() {
			d.mu.Lock()
			d.closed = true
			close(d.out)
			d.mu.Unlock()
		}()
		for pkt := range inner.Emitted() {
			if s, err := tcpharness.Parse(pkt); err == nil {
				d.mu.Lock()
				if len(s.Payload) > 0 {
					d.dataEnd = s.Seq + uint32(len(s.Payload))
				}
				if s.Has(tcpharness.FlagFIN) {
					if d.dropped && !d.repeating && d.fin == s.Seq+s.Len() {
						d.repeating = true
						go d.repeat(append([]byte(nil), pkt...))
					}
					d.fin, d.seen = s.Seq+s.Len(), true
				}
				d.mu.Unlock()
			}
			d.out <- pkt
		}
	}()
	return d
}

// The two tests below need closed.quiet to fail on a resend, not on the end of the wait for
// Delivered, which a DUT that lost the ACK reaches whatever it sends.
func TestHarnessCatchesFINResentAfterADroppedAck(t *testing.T) {
	t.Parallel()
	got, failures := tcpharness.RecordFailures(t, mutant("gvisor-drops-final-ack", dropAckOfFIN), scenario(t, "fin-passive-close"), 1)
	wantOutcome(t, got, "fin-passive-close/closed.quiet", tcpharness.OutcomeFail)
	wantObserved(t, failures, "fin-passive-close/closed.quiet", "got: FIN|ACK")
}

// The engine has the ACK of the CLOSE-WAIT data only 100 ms after its FIN went out, and drops the
// ACK of the FIN. Its first resend is a probe sent before it had the ACK, which the scenario
// passes over; gVisor's own next resend comes about 520 ms after that, and the repeat 700 ms
// after it, both past the 500 ms quiet interval. The scenario catches the resend because it
// waits for the engine to report the ACK before the interval starts, and a resend in that wait
// fails the check; the observation must be that resend, not the end of the wait.
func TestHarnessCatchesFINResentAfterADroppedAckWhenTheDataAckIsLate(t *testing.T) {
	t.Parallel()
	late := func(d tcpharness.DUT) tcpharness.DUT {
		return dropAckOfFINHolding(d, 100*time.Millisecond, 700*time.Millisecond)
	}
	got, failures := tcpharness.RecordFailures(t, mutant("gvisor-late-data-ack-drops-final-ack", late), scenario(t, "fin-passive-close"), 1)
	wantOutcome(t, got, "fin-passive-close/closed.quiet", tcpharness.OutcomeFail)
	wantObserved(t, failures, "fin-passive-close/closed.quiet", "got: FIN|ACK")
}

// wantObserved requires the recorded failure of check key to name the observation want.
func wantObserved(t *testing.T, failures []string, key, want string) {
	t.Helper()
	for _, f := range failures {
		if strings.Contains(f, " "+key+" ") || strings.Contains(f, " "+key+":") {
			if !strings.Contains(f, want) {
				t.Errorf("%s failed for another reason: %q, want an observation %q", key, f, want)
			}
			return
		}
	}
	t.Errorf("%s: no recorded failure; failures: %q", key, failures)
}

// earlyResend resends the engine's lowest unacknowledged data segment the moment the n-th
// duplicate ACK with SACK blocks reaches it, echoing that ACK's TSval, as a sender that counted n
// duplicate ACKs as the threshold, or that ran RACK with no reorder window, would.
type earlyResend struct {
	tcpharness.DUT
	n int
	// stale keeps the segment's own TSecr, as a probe the engine sent before the ACK arrived
	stale bool
	// delay, when set, holds the resend that long after the n-th duplicate ACK
	delay time.Duration
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
		if d.delay == 0 {
			d.out <- seg.Marshal()
		} else {
			pkt := seg.Marshal()
			time.AfterFunc(d.delay, func() {
				d.mu.Lock()
				defer d.mu.Unlock()
				if !d.closed {
					d.out <- pkt
				}
			})
		}
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

// A probe held back 110 ms comes after 195 ms, where the bound stops however late the testbench
// was, so a sender whose first resend comes at RTO-like times cannot pass under load.
func TestHarnessCatchesProbeAtTheRTOFloor(t *testing.T) {
	got := tcpharness.Record(t, mutant("gvisor-probe-at-rto", delayResends(110*time.Millisecond)), scenario(t, "tlp-tail-loss"), 1)
	wantOutcome(t, got, "tlp-tail-loss/probe-at-2srtt", tcpharness.OutcomeFail)
}

// dropFirstResend drops the first segment the engine sends again, so its tail loss probe is lost
// and the next resend is the RTO's, from SND.UNA.
func dropFirstResend(inner tcpharness.DUT) tcpharness.DUT {
	d := &delayedACKs{DUT: inner, out: make(chan []byte, 1024)}
	go func() {
		defer close(d.out)
		sent := map[uint32]bool{}
		dropped := false
		for pkt := range inner.Emitted() {
			if s, err := tcpharness.Parse(pkt); err == nil && len(s.Payload) > 0 {
				if sent[s.Seq] && !dropped {
					dropped = true
					continue
				}
				sent[s.Seq] = true
			}
			d.out <- pkt
		}
	}()
	return d
}

// With the probe lost, the first resend the testbench sees is the RTO's of the first tail segment,
// which the probe check tells apart by its sequence number, not by its time.
func TestHarnessCatchesRTOInPlaceOfAProbe(t *testing.T) {
	got := tcpharness.Record(t, mutant("gvisor-no-probe", dropFirstResend), scenario(t, "tlp-tail-loss"), 1)
	wantOutcome(t, got, "tlp-tail-loss/probe-at-2srtt", tcpharness.OutcomeFail)
}

// On limited-transmit-rack's path, a resend 25 ms after the second duplicate ACK still comes
// inside RACK's reorder window, where the watch now runs; with the old 20 ms watch it went
// unseen. The resend must come after that old watch and reach the testbench before the window
// ends, about 97 ms after the first duplicate ACK. 25 ms leaves 5 ms past the old watch and about
// 50 ms before the window ends when the duplicate ACKs are 20 ms apart. With 38 ms the Windows
// runner once counted the resend past the window: its 15.6 ms clock tick stretched the gap between
// the duplicate ACKs to 32 ms and can delay the resend's timer and the testbench's reading of the
// clock by a tick each.
func TestHarnessCatchesResendAfterTheSecondDupack(t *testing.T) {
	e := mutant("gvisor-resend-25ms-after-dupack2", func(inner tcpharness.DUT) tcpharness.DUT {
		d := resendAt(2, false)(inner).(*earlyResend)
		d.delay = 25 * time.Millisecond
		return d
	})
	got := tcpharness.Record(t, e, scenario(t, "limited-transmit-rack"), 1)
	wantOutcome(t, got, "limited-transmit-rack/no-retransmit-before-third", tcpharness.OutcomeFail)
}

// emitFilter passes every emitted packet through f, which returns the packets to send in its
// place: none drops it, more adds copies, each optionally after a delay.
type emitFilter struct {
	tcpharness.DUT
	out chan []byte
	wg  sync.WaitGroup
}

func (d *emitFilter) Emitted() <-chan []byte { return d.out }

type delayed struct {
	pkt   []byte
	after time.Duration
}

func filterEmitted(f func(pkt []byte) []delayed) func(tcpharness.DUT) tcpharness.DUT {
	return func(inner tcpharness.DUT) tcpharness.DUT {
		d := &emitFilter{DUT: inner, out: make(chan []byte, 1024)}
		go func() {
			for pkt := range inner.Emitted() {
				for _, e := range f(pkt) {
					if e.after == 0 {
						d.out <- e.pkt
						continue
					}
					d.wg.Add(1)
					time.AfterFunc(e.after, func() { defer d.wg.Done(); d.out <- e.pkt })
				}
			}
			d.wg.Wait()
			close(d.out)
		}()
		return d
	}
}

func rfc2525Record(t *testing.T, name string, f func(pkt []byte) []delayed, scen, key string) {
	t.Helper()
	got := tcpharness.Record(t, mutant(name, filterEmitted(f)), scenario(t, scen), 1)
	wantOutcome(t, got, key, tcpharness.OutcomeFail)
}

// Stamping the initial window's last five segments 6 ms later makes them a second window, which
// the initial-window check must not let pass as a probe.
func TestHarnessCatchesASecondInitialWindow(t *testing.T) {
	var mu sync.Mutex
	n := map[uint16]int{}
	rfc2525Record(t, "gvisor-split-window", func(pkt []byte) []delayed {
		s, err := tcpharness.Parse(pkt)
		if err != nil || len(s.Payload) == 0 || s.Opts.TS == nil {
			return []delayed{{pkt, 0}}
		}
		mu.Lock()
		n[s.Dst.Port()]++
		k := n[s.Dst.Port()]
		mu.Unlock()
		if k > 5 {
			s.Opts.TS.Val += 6
			pkt = s.Marshal()
		}
		return []delayed{{pkt, 0}}
	}, "rfc2525-initial-window", "rfc2525-initial-window/mss1380.one-probe-at-most")
}

// A resend that brings a second segment with it fails the RTO's one-segment check.
func TestHarnessCatchesAnRTOOfTwoSegments(t *testing.T) {
	var mu sync.Mutex
	sent := map[uint32]tcpharness.Segment{}
	var order []uint32
	rfc2525Record(t, "gvisor-rto-two", func(pkt []byte) []delayed {
		s, err := tcpharness.Parse(pkt)
		if err != nil || len(s.Payload) == 0 {
			return []delayed{{pkt, 0}}
		}
		mu.Lock()
		defer mu.Unlock()
		if _, seen := sent[s.Seq]; !seen {
			sent[s.Seq] = s
			order = append(order, s.Seq)
			return []delayed{{pkt, 0}}
		}
		for i, q := range order {
			if q == s.Seq && i+1 < len(order) {
				return []delayed{{pkt, 0}, {sent[order[i+1]].Marshal(), 0}}
			}
		}
		return []delayed{{pkt, 0}}
	}, "rfc2525-rto-slow-start", "rfc2525-rto-slow-start/one-segment")
}

// A SYN-ACK resent after 300 ms is below the initial RTO of 1 s.
func TestHarnessCatchesAnEarlySynAckResend(t *testing.T) {
	rfc2525Record(t, "gvisor-synack-300ms", func(pkt []byte) []delayed {
		s, err := tcpharness.Parse(pkt)
		if err == nil && s.Has(tcpharness.FlagSYN|tcpharness.FlagACK) {
			return []delayed{{pkt, 0}, {pkt, 300 * time.Millisecond}}
		}
		return []delayed{{pkt, 0}}
	}, "rfc2525-synack-rto", "rfc2525-synack-rto/initial-rto")
}

// Dropping two of every three pure ACKs makes one ACK cover three segments.
func TestHarnessCatchesStretchACKs(t *testing.T) {
	var mu sync.Mutex
	n := 0
	rfc2525Record(t, "gvisor-stretch-ack", func(pkt []byte) []delayed {
		s, err := tcpharness.Parse(pkt)
		if err == nil && s.Flags == tcpharness.FlagACK && len(s.Payload) == 0 {
			mu.Lock()
			n++
			keep := n%3 == 0
			mu.Unlock()
			if !keep {
				return nil
			}
		}
		return []delayed{{pkt, 0}}
	}, "rfc2525-stretch-ack", "rfc2525-stretch-ack/every-second-segment")
}

// A FIN held back 300 ms is not prompt.
func TestHarnessCatchesALateFIN(t *testing.T) {
	rfc2525Record(t, "gvisor-late-fin", func(pkt []byte) []delayed {
		s, err := tcpharness.Parse(pkt)
		if err == nil && s.Has(tcpharness.FlagFIN) {
			return []delayed{{pkt, 300 * time.Millisecond}}
		}
		return []delayed{{pkt, 0}}
	}, "rfc2525-close-fin", "rfc2525-close-fin/fin-prompt")
}

// A lost RST, and a RST with another sequence number, fail the data-after-close checks.
func TestHarnessCatchesNoOrWrongRSTAfterClose(t *testing.T) {
	rfc2525Record(t, "gvisor-no-rst", func(pkt []byte) []delayed {
		if s, err := tcpharness.Parse(pkt); err == nil && s.Has(tcpharness.FlagRST) {
			return nil
		}
		return []delayed{{pkt, 0}}
	}, "rfc2525-data-after-close", "rfc2525-data-after-close/rst")
	rfc2525Record(t, "gvisor-rst-off-by-one", func(pkt []byte) []delayed {
		if s, err := tcpharness.Parse(pkt); err == nil && s.Has(tcpharness.FlagRST) {
			s.Seq++
			return []delayed{{s.Marshal(), 0}}
		}
		return []delayed{{pkt, 0}}
	}, "rfc2525-data-after-close", "rfc2525-data-after-close/rst.seq")
}
