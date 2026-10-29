package gvisordut

import (
	"encoding/binary"
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

func wantOutcome(t *testing.T, got map[string]string, key, want string) {
	t.Helper()
	if got[key] != want {
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
	e := mutant("gvisor-bad-checksum", func(d tcpharness.DUT) tcpharness.DUT { return corruptMSS536{d} })
	got := tcpharness.Record(t, e, scenario(t, "handshake-mss-floor"), 1)
	wantOutcome(t, got, "handshake-mss-floor/mss536.synack", tcpharness.OutcomeFail)
}
