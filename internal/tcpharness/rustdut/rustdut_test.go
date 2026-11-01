package rustdut

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/dutproto"
	"github.com/rahanahu/wgft/internal/tcpharness"
	"github.com/rahanahu/wgft/internal/tcpharness/wgstackdut"
)

// TestSeedIsWgstackdutsSource checks that HELLO's seed is the first 64 bytes of the random source
// wgstackdut gives the Go wgstack, for several seeds.
func TestSeedIsWgstackdutsSource(t *testing.T) {
	for _, seed := range []uint64{0, 1, 5, 1 << 63, 0x0123456789abcdef} {
		want := make([]byte, dutproto.SeedLen)
		if _, err := io.ReadFull(wgstackdut.RandSource(seed), want); err != nil {
			t.Fatal(err)
		}
		if got := Seed(seed); !bytes.Equal(got[:], want) {
			t.Errorf("seed %d: Seed = %x, wgstackdut's source starts %x", seed, got, want)
		}
	}
}

// TestClassify checks the table of requests that change state and requests that only ask.
func TestClassify(t *testing.T) {
	wb := &dutproto.WouldBlock{}
	cases := []struct {
		req, resp dutproto.Msg
		want      class
	}{
		{&dutproto.Now{}, &dutproto.Time{}, query},
		{&dutproto.Delivered{}, &dutproto.Bool{}, query},
		{&dutproto.Stats{}, &dutproto.Text{}, query},
		{&dutproto.Bound{}, &dutproto.Text{}, query},
		{&dutproto.Held{}, &dutproto.Text{}, query},
		{&dutproto.Accept{}, wb, query},
		{&dutproto.Accept{}, &dutproto.Accepted{}, changes},
		{&dutproto.Read{}, wb, query},
		{&dutproto.Read{}, &dutproto.Data{Data: dutproto.Bytes{}}, query},
		{&dutproto.Read{}, &dutproto.Data{Data: dutproto.Bytes("x")}, changes},
		{&dutproto.Read{}, &dutproto.Error{Err: dutproto.ErrEOF}, changes},
		{&dutproto.Write{}, &dutproto.Wrote{N: 0}, query},
		{&dutproto.Write{}, &dutproto.Wrote{N: 1}, changes},
		{&dutproto.UDPRecv{}, wb, query},
		{&dutproto.UDPRecv{}, &dutproto.Datagram{}, changes},
		{&dutproto.UDPSend{}, wb, query},
		{&dutproto.UDPSend{}, &dutproto.OK{}, changes},
		{&dutproto.PingRecv{}, wb, query},
		{&dutproto.Inject{}, &dutproto.OK{}, changes},
		{&dutproto.Poll{}, &dutproto.Packets{}, changes},
		{&dutproto.Advance{}, &dutproto.Time{}, changes},
		{&dutproto.Events{}, &dutproto.EventList{}, changes},
		{&dutproto.BoostPolicy{}, &dutproto.Bool{}, changes},
	}
	for _, c := range cases {
		if got := classify(c.req, c.resp); got != c.want {
			t.Errorf("%s answered %s: class %d, want %d", c.req.Kind(), c.resp.Kind(), got, c.want)
		}
	}
}

// TestRemoteErrors checks that an engine's error comes back with its message and with what
// errKind and errString of tcpharness read from it.
func TestRemoteErrors(t *testing.T) {
	msg := "read tcp 10.200.0.2:80->10.200.0.1:40001: connection reset by peer"
	err := respErr(&dutproto.Error{Err: dutproto.ErrReset, Msg: msg}, "read")
	if err.Error() != msg || !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("reset: %v", err)
	}
	if err := respErr(&dutproto.Error{Err: dutproto.ErrEOF, Msg: "EOF"}, "read"); err != io.EOF {
		t.Errorf("EOF: %v", err)
	}
	if err := respErr(&dutproto.Error{Err: dutproto.ErrClosed, Msg: net.ErrClosed.Error()}, "read"); !errors.Is(err, net.ErrClosed) {
		t.Errorf("closed: %v", err)
	}
	var ne net.Error
	if err := respErr(&dutproto.Error{Err: dutproto.ErrTimeout, Msg: "i/o timeout"}, "read"); !errors.As(err, &ne) || !ne.Timeout() {
		t.Errorf("timeout: %v", err)
	}
}

// dutBin returns BinEnv's binary or skips.
func dutBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv(BinEnv)
	if bin == "" {
		t.Skipf("set %s to a DUT binary to run", BinEnv)
	}
	return bin
}

// requireDutserve skips unless BinEnv names the Go wgstack's dutserve.
func requireDutserve(t *testing.T) string {
	t.Helper()
	bin := dutBin(t)
	d, err := New(Config{Bin: bin, Log: t.Logf}, tcpharness.DUTAddr, tcpharness.MTU, 1)
	if err != nil {
		t.Fatal(err)
	}
	name := d.Name()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if name != "wgstack" {
		t.Skipf("%s names the engine %q; this test compares with the Go wgstack's dutserve", BinEnv, name)
	}
	return bin
}

// runSeed is the run's seed from tcpharness.SeedEnv, or a random one that the test logs.
func runSeed(t *testing.T) uint64 {
	t.Helper()
	if v := os.Getenv(tcpharness.SeedEnv); v != "" {
		s, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			t.Fatalf("%s=%q is not an unsigned integer", tcpharness.SeedEnv, v)
		}
		return s
	}
	s := rand.Uint64()
	t.Logf("run seed: %d; replay with %s=%d", s, tcpharness.SeedEnv, s)
	return s
}

// TestSameAsWgstackdut checks rustdut itself (test-tooling.md section 3): every scenario run on
// the Go wgstack through rustdut and dutserve gives the same checks, outcomes, observations and
// measurements as the same scenario run on the Go wgstack in this process through wgstackdut, from
// the same seed. Both engines get the same name and no expected-difference list, so a known
// difference is a failure on both and the failure messages compare too. A scenario
// that reads or writes from a goroutine of its own compares without its measurements, which
// depend on when that goroutine runs (test-tooling.md section 2).
func TestSameAsWgstackdut(t *testing.T) {
	requireDutserve(t)
	run := runSeed(t)
	direct, remote := wgstackdut.Engine(nil), Engine(nil)
	direct.Name, remote.Name = "go-wgstack", "go-wgstack"
	for _, scenarios := range [][]tcpharness.Scenario{tcpharness.Scenarios, tcpharness.CongestionScenarios} {
		for _, s := range scenarios {
			t.Run(s.Name, func(t *testing.T) {
				seed := tcpharness.ScenarioSeed(run, s.Name)
				want := tcpharness.RecordChecks(t, direct, s, seed)
				got := tcpharness.RecordChecks(t, remote, s, seed)
				if concurrentScenarios[s.Name] {
					want.Checks, got.Checks = withoutMeasures(want.Checks), withoutMeasures(got.Checks)
				}
				if d := traceDiff(want, got); d != "" {
					t.Errorf("scenario seed %d: rustdut over dutserve differs from wgstackdut:\n%s", seed, d)
				}
				if len(want.Checks) == 0 && !want.Skipped {
					t.Errorf("wgstackdut ran no check; the comparison shows nothing")
				}
			})
		}
	}
}

func withoutMeasures(cs []tcpharness.CheckRecord) []tcpharness.CheckRecord {
	var out []tcpharness.CheckRecord
	for _, c := range cs {
		if c.Outcome != "measure" {
			out = append(out, c)
		}
	}
	return out
}

// traceDiff describes where two traces first differ, or returns "".
func traceDiff(want, got tcpharness.CheckTrace) string {
	var b strings.Builder
	for i := range max(len(want.Checks), len(got.Checks)) {
		var w, g tcpharness.CheckRecord
		if i < len(want.Checks) {
			w = want.Checks[i]
		}
		if i < len(got.Checks) {
			g = got.Checks[i]
		}
		if w != g {
			fmt.Fprintf(&b, "check %d: wgstackdut %+v\n             rustdut    %+v\n", i, w, g)
			break
		}
	}
	for i := range max(len(want.Failures), len(got.Failures)) {
		var w, g string
		if i < len(want.Failures) {
			w = want.Failures[i]
		}
		if i < len(got.Failures) {
			g = got.Failures[i]
		}
		if w != g {
			fmt.Fprintf(&b, "failure %d: wgstackdut %q\n               rustdut    %q\n", i, w, g)
			break
		}
	}
	if want.Failed != got.Failed || want.Skipped != got.Skipped {
		fmt.Fprintf(&b, "wgstackdut failed=%v skipped=%v; rustdut failed=%v skipped=%v\n", want.Failed, want.Skipped, got.Failed, got.Skipped)
	}
	return b.String()
}

// TestTranscriptRepeats checks the rule that keeps a transcript independent of the wall clock: a
// scenario run twice from the same seed sends the same requests and gets the same responses,
// byte for byte, although its reads and writes wait on deadlines in real time. A scenario that
// reads or writes from a goroutine of its own may order its requests differently from run to
// run; those are listed and logged, not failed.
func TestTranscriptRepeats(t *testing.T) {
	bin := requireDutserve(t)
	run := runSeed(t)
	for _, s := range tcpharness.Scenarios {
		t.Run(s.Name, func(t *testing.T) {
			seed := tcpharness.ScenarioSeed(run, s.Name)
			var sums [2]uint64
			var lens [2]int
			for i := range 2 {
				var tr bytes.Buffer
				e := transcriptEngine(bin, &tr)
				tcpharness.RecordChecks(t, e, s, seed)
				h := fnv.New64a()
				h.Write(tr.Bytes())
				sums[i], lens[i] = h.Sum64(), tr.Len()
			}
			switch {
			case sums[0] == sums[1]:
				t.Logf("transcript of %d bytes repeats", lens[0])
			case concurrentScenarios[s.Name]:
				t.Logf("transcripts differ, %d and %d bytes; the scenario reads or writes from a goroutine of its own", lens[0], lens[1])
			default:
				t.Errorf("scenario seed %d: transcripts differ, %d and %d bytes", seed, lens[0], lens[1])
			}
		})
	}
}

// concurrentScenarios read or write from a goroutine of their own while the scenario's goroutine
// drives the clock, so the order of their requests and their measurements depend on the scheduler
// (test-tooling.md section 2 asks only for equal checks from them). A scenario added with such a
// goroutine fails TestTranscriptRepeats until it is listed here.
var concurrentScenarios = map[string]bool{
	// ownScale's reader
	"window-scale": true,
	// bulkOpen's writer
	"chained-recovery": true, "reorder-wait-recovery": true, "rto-after-burst": true,
	// the reader of the overflow and pacing scenarios
	"rcv-overflow-hold": true, "rcv-overflow-read-half": true, "rcv-overflow-read-all": true,
	"rcv-overflow-hold-perf": true, "rcv-overflow-read-half-perf": true,
	"rcv-window-pacing": true, "rcv-window-pacing-fixed": true,
	// ccOpen's writer
	"cubic-after-loss": true, "cubic-fast-convergence": true, "hystart-css": true, "hystart-css-back": true,
	"hystart-css-ack-burst": true, "cubic-ack-burst": true,
}

// TestConcurrentScenariosExist keeps concurrentScenarios to scenario names.
func TestConcurrentScenariosExist(t *testing.T) {
	names := map[string]bool{}
	for _, s := range append(append([]tcpharness.Scenario{}, tcpharness.Scenarios...), tcpharness.CongestionScenarios...) {
		names[s.Name] = true
	}
	for n := range concurrentScenarios {
		if !names[n] {
			t.Errorf("concurrentScenarios names %q, which is not a scenario", n)
		}
	}
}

// transcriptEngine is Engine with every DUT's transcript written to w.
func transcriptEngine(bin string, w io.Writer) tcpharness.Engine {
	e := Engine(nil)
	build := func(boost dutproto.Boost) func(tb testing.TB, seed uint64) tcpharness.DUT {
		return func(tb testing.TB, seed uint64) tcpharness.DUT {
			d, err := New(Config{Bin: bin, Boost: boost, Log: tb.Logf, Transcript: w}, tcpharness.DUTAddr, tcpharness.MTU, seed)
			if err != nil {
				tb.Fatalf("rustdut: %v", err)
			}
			tb.Cleanup(func() { d.Close() })
			return d
		}
	}
	e.New, e.NewPerformance = build(dutproto.BoostOnDemand), build(dutproto.BoostAtAccept)
	return e
}

// errorScenario drives the error paths where rustdut answers without the engine's operation:
// a deadline that has already passed, an oversized datagram, and Accept after its context ended.
// Each check records the error's message and what errors.Is and Timeout find in it.
var errorScenario = tcpharness.Scenario{Name: "rustdut-errors", Refs: "rustdut's error paths", Run: func(h *tcpharness.H) {
	const port = 9101
	past := time.Unix(1, 0)
	desc := func(err error) string {
		var ne net.Error
		return fmt.Sprintf("%v; closed %v, EPIPE %v, EMSGSIZE %v, EOF %v, timeout %v", err, errors.Is(err, net.ErrClosed),
			errors.Is(err, syscall.EPIPE), errors.Is(err, syscall.EMSGSIZE), errors.Is(err, io.EOF), errors.As(err, &ne) && ne.Timeout())
	}
	check := func(id string, err error, want func(error) bool, what string) {
		h.Check(id, want(err), what, desc(err))
	}
	isTimeout := func(err error) bool {
		var ne net.Error
		return errors.As(err, &ne) && ne.Timeout()
	}
	l := h.Listen(port)

	_, _, c := h.Connect(l, port, tcpharness.StandardSYN())
	c.Abort()
	c.SetReadDeadline(past)
	_, err := c.Read(make([]byte, 10))
	check("read-after-abort", err, func(err error) bool { return errors.Is(err, net.ErrClosed) }, "Read after Abort with a passed deadline is closed")

	_, _, c = h.Connect(l, port, tcpharness.StandardSYN())
	c.CloseWrite()
	c.SetWriteDeadline(past)
	_, err = c.Write([]byte("x"))
	check("write-after-close-write", err, func(err error) bool { return errors.Is(err, syscall.EPIPE) }, "Write after CloseWrite with a passed deadline is EPIPE")

	_, _, c = h.Connect(l, port, tcpharness.StandardSYN())
	c.SetWriteDeadline(past)
	_, err = c.Write([]byte("x"))
	check("write-deadline", err, isTimeout, "Write on a writable connection with a passed deadline times out")
	c.SetReadDeadline(past)
	_, err = c.Read(make([]byte, 10))
	check("read-deadline", err, isTimeout, "Read on an open connection with a passed deadline times out")

	u, err := h.DUT.ListenUDP(port)
	if err != nil {
		h.T.Fatalf("ListenUDP: %v", err)
	}
	to := net.UDPAddrFromAddrPort(netip.AddrPortFrom(tcpharness.PeerAddr, 7))
	u.SetWriteDeadline(past)
	_, err = u.WriteTo(make([]byte, 65508), to)
	check("udp-oversize", err, func(err error) bool { return errors.Is(err, syscall.EMSGSIZE) }, "an oversized WriteTo with a passed deadline is EMSGSIZE")
	_, err = u.WriteTo([]byte("x"), to)
	check("udp-write-deadline", err, isTimeout, "WriteTo with a passed deadline times out")
	u.Close()
	u.SetReadDeadline(past)
	_, _, err = u.ReadFrom(make([]byte, 10))
	check("udp-read-after-close", err, func(err error) bool { return errors.Is(err, net.ErrClosed) }, "ReadFrom after Close with a passed deadline is closed")

	l2, err := h.DUT.Listen(port + 1)
	if err != nil {
		h.T.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err = l2.Accept(ctx)
	cancel()
	check("accept-context", err, func(err error) bool { return errors.Is(err, context.DeadlineExceeded) }, "Accept returns its context's error")
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	_, err = l2.Accept(ctx)
	cancel()
	check("accept-after-context", err, func(err error) bool { return errors.Is(err, net.ErrClosed) }, "a later Accept finds the listener closed")
}}

// TestErrorsAsWgstackdut checks that rustdut's error paths give the errors the Go wgstack gives
// in-process: every check passes on both and the two traces are the same.
func TestErrorsAsWgstackdut(t *testing.T) {
	requireDutserve(t)
	direct, remote := wgstackdut.Engine(nil), Engine(nil)
	direct.Name, remote.Name = "go-wgstack", "go-wgstack"
	want := tcpharness.RecordChecks(t, direct, errorScenario, 1)
	got := tcpharness.RecordChecks(t, remote, errorScenario, 1)
	for _, tr := range []tcpharness.CheckTrace{want, got} {
		if tr.Failed || len(tr.Failures) > 0 {
			t.Errorf("the error scenario failed: %v", tr.Failures)
		}
	}
	if d := traceDiff(want, got); d != "" {
		t.Errorf("rustdut over dutserve differs from wgstackdut:\n%s", d)
	}
	if len(want.Checks) < 9 {
		t.Errorf("the error scenario ran %d checks; it stopped early", len(want.Checks))
	}
}
