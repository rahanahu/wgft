//go:build linux

package vpsd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/internal/startup"
	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/proxyrelay"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// TestWaitForApplyRetriesUntilTheApplySucceeds confirms the hold's loop keeps retrying on the
// timer and leaves as soon as an apply succeeds (design.md 11b 節: 出る条件). The interval is a
// parameter so this runs without the real 30 seconds; Run passes reconcile.DefaultTriggers.Retry.
//
// The loop itself must log nothing: what a retry says about its failure is retryHold's decision,
// which stays quiet while the reason does not change (design.md 11b 節: ログ). A line printed here
// instead would be printed on every retry, which is what the suppression exists to prevent.
func TestWaitForApplyRetriesUntilTheApplySucceeds(t *testing.T) {
	applied := make(chan struct{})
	calls := 0
	retry := func() {
		calls++
		if calls == 3 {
			close(applied)
		}
	}
	buf := captureLog(t)
	if err := waitForApply(context.Background(), applied, nil, time.Millisecond, retry); err != nil {
		t.Fatalf("waitForApply = %v, want nil once the apply succeeded", err)
	}
	if calls != 3 {
		t.Errorf("retry called %d times, want exactly 3: the loop must stop at the successful apply", calls)
	}
	if buf.String() != "" {
		t.Errorf("the hold loop logged %q; a line here would be printed on every retry", buf.String())
	}
}

// TestWaitForApplyLeavesWithoutWaitingForTheTimer is the admin batch case of design.md 11b 節: the
// operator makes the declaration smaller, Daemon.Batch applies it itself, and the hold must end
// there instead of at the next 30-second retry. The interval here is longer than the test could
// ever wait, so only the channel Batch closes can end it.
func TestWaitForApplyLeavesWithoutWaitingForTheTimer(t *testing.T) {
	applied := make(chan struct{})
	retried := false
	go func() {
		time.Sleep(5 * time.Millisecond)
		close(applied) // stands in for the apply inside Daemon.Batch
	}()
	start := time.Now()
	if err := waitForApply(context.Background(), applied, nil, time.Hour, func() { retried = true }); err != nil {
		t.Fatalf("waitForApply = %v, want nil", err)
	}
	if took := time.Since(start); took > 30*time.Second {
		t.Errorf("waitForApply took %s; it must not wait for the retry timer", took)
	}
	if retried {
		t.Error("the retry timer must not have fired")
	}
}

// TestWaitForApplyStopsWhenTheContextIsDone confirms SIGTERM during the hold ends it (design.md
// 11b 節: 終了コードを持たない). errHoldStopped is what tells serve to shut down quietly instead of
// reporting a startup failure.
func TestWaitForApplyStopsWhenTheContextIsDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := waitForApply(ctx, make(chan struct{}), nil, time.Hour, func() { t.Error("no retry expected") })
	if !errors.Is(err, errHoldStopped) {
		t.Errorf("waitForApply = %v, want it to wrap errHoldStopped", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("waitForApply = %v, want it to keep the context's own cause", err)
	}
}

// TestWaitForApplyReturnsTheAdminServeFailure confirms the one listener the hold opens is still
// watched: if serving the admin API stops, the hold ends with that failure, which cmd/wgft maps to
// exit code 1 (design.md 11b 節: 管理用 API の待ち受けそのものが失敗した場合).
func TestWaitForApplyReturnsTheAdminServeFailure(t *testing.T) {
	serveErr := make(chan error, 1)
	want := errors.New("admin API: closed")
	serveErr <- want
	err := waitForApply(context.Background(), make(chan struct{}), serveErr, time.Hour, func() {})
	if !errors.Is(err, want) {
		t.Errorf("waitForApply = %v, want %v", err, want)
	}
}

// TestHoldFailsWhenTheAdminAPICannotListen covers two rules of design.md 11b 節 that only the hold
// itself can show.
//
// The first is the exit code: the hold opens exactly one listener, and if that listener cannot be
// opened there is nothing left for the operator to reach, so the failure is returned and cmd/wgft
// exits 1. Swallowing it would leave a hold nobody can end, retrying forever in silence.
//
// The second is the order: the channel that tells the hold an apply succeeded must exist before the
// admin API answers its first request. Daemon.Batch applies the rules itself, so a batch served in
// that window would apply successfully with nothing listening for it, and the hold would wait for
// the next retry instead of ending at once.
func TestHoldFailsWhenTheAdminAPICannotListen(t *testing.T) {
	st := openTestStore(t)
	d := &Daemon{st: st, dp: holdDataplane{p: newHoldParticipant(errors.New("boom"))},
		opts: Options{Mode: modeUserspace}}
	buf := captureLog(t)

	// A deadline so that a hold which ignores the failure ends the test instead of hanging until
	// the package timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	listenFailed := errors.New("admin API: listen: address already in use")
	signalReady := false
	err := d.hold(ctx, errors.New("failed to apply the userspace dataplane: boom"), func() error {
		d.mu.Lock()
		signalReady = d.applied != nil
		d.mu.Unlock()
		return listenFailed
	}, nil)

	if !errors.Is(err, listenFailed) {
		t.Errorf("hold = %v, want the admin listen failure back so cmd/wgft exits 1", err)
	}
	if !signalReady {
		t.Error("the apply signal must exist before the admin API answers, or a batch applied in that window is missed")
	}
	// Nothing listens, so nothing may claim it does. The line announcing the hold belongs after the
	// listener is open, and the failure the startup was about to hold for goes into the error
	// instead, which is the only thing the operator gets.
	if strings.Contains(buf.String(), "startup hold:") {
		t.Errorf("a hold that could not open its listener must not announce itself, got %q", buf.String())
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("the error must carry the apply failure the startup was about to hold for, got %q", err)
	}
}

// TestRetryHoldLogsOnlyWhenTheReasonChanges pins the log rule of design.md 11b 節: one line entering
// the hold, one leaving it, nothing while the same failure repeats, and one more line when the
// reason changes. The line entering the hold already carries the reason, so repeating it every 30
// seconds would only fill the journal, while a reason that changed is news the operator needs.
func TestRetryHoldLogsOnlyWhenTheReasonChanges(t *testing.T) {
	st := openTestStore(t)
	p := newHoldParticipant(errors.New("no buffer space available"))
	d := &Daemon{st: st, dp: holdDataplane{p: p}, opts: Options{Mode: modeUserspace}}
	// The hold was entered with the failure the dataplane keeps returning.
	d.beginHold(errors.New("failed to apply the userspace dataplane: no buffer space available"))

	buf := captureLog(t)
	for i := 0; i < 3; i++ {
		d.retryHold()
	}
	if buf.String() != "" {
		t.Errorf("a retry that failed the same way logged %q, want nothing", buf.String())
	}

	p.fail(errors.New("operation not permitted"))
	d.retryHold()
	first := buf.String()
	if n := strings.Count(first, "startup hold:"); n != 1 {
		t.Fatalf("a changed reason must log exactly 1 line, got %d:\n%s", n, first)
	}
	if !strings.Contains(first, "operation not permitted") {
		t.Errorf("the line must carry the new reason, got %q", first)
	}
	// The same shape as the line entering the hold: the reason first, then the way out.
	if !strings.Contains(first, "wgft rule rm") || !strings.Contains(first, "wgft status") {
		t.Errorf("the line must keep the shape of the line entering the hold, got %q", first)
	}

	d.retryHold()
	d.retryHold()
	if buf.String() != first {
		t.Errorf("the new reason must be logged once, got:\n%s", buf.String())
	}
}

// TestRetryHoldDoesNotAdviseARuleChangeWhenTheDatabaseCannotBeRead: the way out the hold offers is
// a smaller declaration, which is an answer to an apply that fails. A retry that cannot read the
// declaration at all is a different failure, and wgft rule rm does not fix a server database that
// cannot be read, so the line carries the reason without that advice.
func TestRetryHoldDoesNotAdviseARuleChangeWhenTheDatabaseCannotBeRead(t *testing.T) {
	st := openTestStore(t)
	d := &Daemon{st: st, dp: holdDataplane{p: newHoldParticipant(errors.New("boom"))},
		opts: Options{Mode: modeUserspace}}
	d.beginHold(errors.New("failed to apply the userspace dataplane: boom"))
	st.Close() // every read of the declaration now fails

	buf := captureLog(t)
	d.retryHold()
	line := buf.String()
	if !strings.Contains(line, "reading the rules again") {
		t.Fatalf("the line must name the failed read, got %q", line)
	}
	if strings.Contains(line, "wgft rule rm") || strings.Contains(line, "wgft rule disable") {
		t.Errorf("a database that cannot be read is not fixed by a smaller declaration, got %q", line)
	}
	if !strings.Contains(line, "startup hold:") || !strings.Contains(line, "the reason changed") {
		t.Errorf("the line must keep the shape of the other hold lines, got %q", line)
	}

	d.retryHold()
	if buf.String() != line {
		t.Errorf("the same failed read must be logged once, got:\n%s", buf.String())
	}
}

// TestServeStartsWithoutAHoldWhenTheFirstApplyWorks is the ordinary startup, which the hold must
// leave untouched (design.md 11b 節: 以後の挙動は保留を経ていない起動と変わらない): the first apply
// succeeds, so no hold line is logged, nothing waits for the retry timer, and both APIs listen.
// This path opens the admin API once, so it says nothing about opening it twice; that is the hold's
// path, and TestServeHoldsTheStartupUntilTheRulesApply is where it is checked.
func TestServeStartsWithoutAHoldWhenTheFirstApplyWorks(t *testing.T) {
	st := openTestStore(t)
	addrs := freeAddrs(t, 2)
	adminAddr, agentAddr := addrs[0], addrs[1]
	d := newHoldDaemon(t, st, newHoldParticipant(nil), adminAddr, agentAddr)

	buf := newSyncBuffer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- d.serve(ctx, rulesOf(t, st)) }()

	// Whichever line comes first decides: an apply that works has nothing to hold for.
	waitFor(t, "the startup to report where it went", func() bool {
		s := buf.String()
		return strings.Contains(s, "server started") || strings.Contains(s, "startup hold")
	})
	if strings.Contains(buf.String(), "startup hold") {
		t.Fatalf("an apply that works must not enter the hold, got:\n%s", buf.String())
	}
	waitForStartup(t, buf, done)
	if took := time.Since(start); took > 25*time.Second {
		t.Errorf("the startup took %s; an apply that works must not wait for the hold's retry timer", took)
	}
	if !agentAPIAnswers(d, agentAddr) {
		t.Error("the agent API must be listening after an ordinary startup")
	}
	if code, err := adminGet(adminAddr, "/api/v1/rules"); err != nil || code != 200 {
		t.Errorf("the admin API must answer after an ordinary startup; got %d, %v", code, err)
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("serve = %v, want nil on shutdown", err)
	}
}

// TestServeHoldsTheStartupUntilTheRulesApply is the whole of design.md 11b 節's 起動の保留 in one
// run of serve, with a dataplane whose first apply fails.
//
//   - serve does not return, only the admin API listens and answers, the agent API does not, and
//     the server started line waits
//   - a batch whose apply fails does not end the hold: the way out is a successful apply and
//     nothing else, so a failed one must leave the startup exactly where it was
//   - a batch whose apply succeeds ends it at once, without the 30-second retry: Daemon.Batch
//     applies the rules itself, so the hold has to notice an apply it did not run
//   - the server started line then counts the declaration as the operator left it
//   - an apply after the hold is over is an ordinary apply and must not disturb anything
func TestServeHoldsTheStartupUntilTheRulesApply(t *testing.T) {
	st := openTestStore(t)
	addRule(t, st, "r_big")
	addRule(t, st, "r_small")

	addrs := freeAddrs(t, 2)
	adminAddr, agentAddr := addrs[0], addrs[1]
	p := newHoldParticipant(errors.New("no buffer space available"))
	d := newHoldDaemon(t, st, p, adminAddr, agentAddr)

	buf := newSyncBuffer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.serve(ctx, rulesOf(t, st)) }()

	waitFor(t, "the hold to be reported", func() bool { return strings.Contains(buf.String(), "startup hold:") })
	select {
	case err := <-done:
		t.Fatalf("serve returned %v; a first apply that fails must hold the startup, not end it", err)
	case <-time.After(50 * time.Millisecond):
	}
	if code, err := adminGet(adminAddr, "/api/v1/rules"); err != nil || code != 200 {
		t.Errorf("the admin API must answer during the hold: it is the operator's only way back; got %d, %v", code, err)
	}
	if agentAPIAnswers(d, agentAddr) {
		t.Errorf("the agent API must not listen during the hold; %s answered", agentAddr)
	}
	if strings.Contains(buf.String(), "server started") {
		t.Errorf("the server started line must wait for the apply, got %q", buf.String())
	}
	if line := buf.String(); !strings.Contains(line, "wgft status") ||
		!strings.Contains(line, "wgft rule rm") || !strings.Contains(line, "wgft rule disable") {
		t.Errorf("the hold line must show how to read the state and how to make the declaration smaller, got %q", line)
	}
	// The hold stops publication, not forwarding: a restart leaves the previous table and peers in
	// the kernel, and kernel-mode transparent rules keep carrying traffic under the old declaration
	// (design.md 11b 節: 転送). The line must not tell the operator otherwise.
	if strings.Contains(buf.String(), "nothing is forwarded") {
		t.Errorf("the hold line must not claim forwarding stopped, got %q", buf.String())
	}
	// Read after the table is applied, so during the hold there is nothing to report yet
	// (design.md 11b 節: 保留の間の conntrack の UDP タイムアウト 2 値).
	if got := d.udpTimeouts(); got != (linux.UDPTimeouts{}) {
		t.Errorf("udpTimeouts during the hold = %+v, want the zero value", got)
	}

	// A first attempt that still cannot be applied: the store keeps the change, as it does while
	// the server runs, but the startup stays held.
	if _, err := d.Batch(admin.BatchRequest{Op: "cli rule rm", Delete: []string{"r_big"}}); err == nil {
		t.Fatal("Batch must report the failed apply")
	}
	if stillHeld := !appearsWithin(buf, "server started", 300*time.Millisecond); !stillHeld {
		t.Fatalf("an apply that failed must not end the hold; log:\n%s", buf.String())
	}
	if agentAPIAnswers(d, agentAddr) {
		t.Error("the agent API must still not listen after a batch whose apply failed")
	}

	// Reading the conntrack timeouts happens when the hold ends, while the admin API is already
	// answering. Readers across that moment show the race detector both sides of that value.
	stopReaders := readTimeoutsConcurrently(d)

	p.succeed()
	if _, err := d.Batch(admin.BatchRequest{Op: "cli rule rm", Delete: []string{"r_small"}}); err != nil {
		t.Fatalf("Batch: %v", err)
	}
	waitForStartup(t, buf, done)
	stopReaders()

	if !agentAPIAnswers(d, agentAddr) {
		t.Error("the agent API must be listening once the hold is over")
	}
	// The hold ending is what makes the conntrack read happen, so the values the dataplane returns
	// must be in place from then on: they go into the global state the agent API hands out, and the
	// agent API opens right after (design.md 11b 節: 出る条件).
	if got := d.udpTimeouts(); got != heldTimeouts {
		t.Errorf("udpTimeouts after the hold = %+v, want %+v", got, heldTimeouts)
	}
	if n := strings.Count(buf.String(), "startup hold:"); n != 1 {
		t.Errorf("the log has %d lines entering the hold, want exactly 1", n)
	}
	if n := strings.Count(buf.String(), "startup hold over"); n != 1 {
		t.Errorf("the log has %d lines leaving the hold, want exactly 1", n)
	}
	// The started line itself, not any other line that mentions rules: it must count the
	// declaration as it is now that the operator has removed both rules.
	started := startedLine(t, buf)
	if !strings.Contains(started, "0 rules") {
		t.Errorf("the started line must count the rules the operator left, got %q", started)
	}

	// The hold is over; an ordinary apply must not trip over what the hold left behind.
	if _, err := d.Batch(admin.BatchRequest{Op: "api"}); err != nil {
		t.Errorf("an apply after the hold = %v, want success", err)
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("serve = %v, want nil on shutdown", err)
	}
}

// TestServeDoesNotHoldOnAStartupRefusal pins the entry condition of design.md 11b 節: a startup
// refusal keeps exiting 3 wherever it is raised, hold or no hold. Waiting with the admin API open
// would be pointless for a failure nothing but the operator's own hand can clear, and it would
// turn RestartPreventExitStatus=3 into a process that stays up forwarding nothing.
func TestServeDoesNotHoldOnAStartupRefusal(t *testing.T) {
	st := openTestStore(t)
	refusal := startup.Prerequisite("CAP_NET_ADMIN", "kernel mode needs CAP_NET_ADMIN")
	addrs := freeAddrs(t, 2)
	adminAddr := addrs[0]
	d := newHoldDaemon(t, st, newHoldParticipant(refusal), adminAddr, addrs[1])

	buf := newSyncBuffer(t)
	// A deadline so that a refusal which is held by mistake ends the test with the assertion below
	// instead of hanging until the package timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := d.serve(ctx, nil)
	if !startup.IsRefusal(err) {
		t.Fatalf("serve = %v, want the refusal back so cmd/wgft exits 3", err)
	}
	if strings.Contains(buf.String(), "startup hold") {
		t.Errorf("a refusal must not enter the hold, got %q", buf.String())
	}
	if code, err := adminGet(adminAddr, "/api/v1/rules"); err == nil && code == 200 {
		t.Error("a refusal must not leave the admin API listening")
	}
}

// TestServeShutsDownDuringTheStartupHold confirms SIGTERM during the hold ends the process the
// quiet way (design.md 11b 節: 起動の保留は終了しないので終了コードを持たない): serve returns nil,
// so cmd/wgft exits 0, and the server started line is never printed.
func TestServeShutsDownDuringTheStartupHold(t *testing.T) {
	st := openTestStore(t)
	shutAddrs := freeAddrs(t, 2)
	d := newHoldDaemon(t, st, newHoldParticipant(errors.New("no buffer space available")), shutAddrs[0], shutAddrs[1])

	buf := newSyncBuffer(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.serve(ctx, nil) }()
	waitFor(t, "the hold to be reported", func() bool { return strings.Contains(buf.String(), "startup hold:") })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve = %v, want nil: a hold that is interrupted is not a startup failure", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after the context was cancelled")
	}
	if strings.Contains(buf.String(), "server started") {
		t.Errorf("the server started line must not be printed, got %q", buf.String())
	}
}

// holdParticipant is a dataplane.Participant whose Prepare fails with whatever error it is given,
// standing in for a declaration the kernel refuses as a whole, a transaction too large for the
// netlink socket for instance, which is what the startup hold exists for. A nil error makes it an
// ordinary working dataplane.
type holdParticipant struct {
	mu  sync.Mutex
	err error
}

func newHoldParticipant(err error) *holdParticipant { return &holdParticipant{err: err} }

func (p *holdParticipant) succeed() { p.fail(nil) }

func (p *holdParticipant) fail(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err = err
}

func (p *holdParticipant) Observe() (dataplane.Observed, error) { return dataplane.Observed{}, nil }

func (p *holdParticipant) Prepare(dataplane.Desired) (dataplane.Prepared, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return nil, p.err
	}
	return holdPrepared{}, nil
}

func (p *holdParticipant) Repair() dataplane.Committed { return dataplane.Committed{} }

type holdPrepared struct{}

func (holdPrepared) Failed() map[string]error { return nil }
func (holdPrepared) Commit([]dataplane.Retiring) (dataplane.Committed, error) {
	return dataplane.Committed{}, nil
}
func (holdPrepared) Rollback() {}

// heldTimeouts are the conntrack UDP timeouts this package's fake dataplane reports. They are not
// the kernel defaults, so a test can tell the value that was actually read from a zero value that
// was never read at all.
var heldTimeouts = linux.UDPTimeouts{Timeout: 31, TimeoutStream: 121}

// holdDataplane is stubDataplane with a participant of its own and conntrack timeouts that can be
// recognised.
type holdDataplane struct {
	stubDataplane
	p dataplane.Participant
}

func (d holdDataplane) participant() dataplane.Participant { return d.p }

func (d holdDataplane) ReadUDPTimeouts() (linux.UDPTimeouts, error) { return heldTimeouts, nil }

// newHoldDaemon builds the Daemon serve expects from Run: the store and the dataplane are up, the
// wg key and the address range are decided, and the relay manager exists.
//
// The admin API is a TCP address on purpose, although the shipped default is a Unix socket: opening
// a TCP listener twice fails with EADDRINUSE, which is how these tests see a startup that forgets
// it already opened the admin API. admin.Listen removes the socket file before it binds, so the
// same mistake on a Unix socket succeeds and quietly orphans the first listener, and the test would
// pass while the bug shipped. Keep these addresses on TCP.
func newHoldDaemon(t *testing.T, st *store.Store, p dataplane.Participant, adminAddr, agentAddr string) *Daemon {
	t.Helper()
	return &Daemon{
		st: st, dp: holdDataplane{p: p}, serverKey: testKey(t),
		network: netip.MustParsePrefix("10.200.0.0/24"),
		proxy:   proxyrelay.New(proxyrelay.Options{Pool: resource.NewPool(16)}),
		opts: Options{Mode: modeUserspace, WGInterface: "wgft0", Version: "test",
			AdminAddr: adminAddr, AgentAPIAddr: agentAddr},
	}
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func addRule(t *testing.T, st *store.Store, id string) {
	t.Helper()
	port := uint16(40000 + len(id))
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, proto.Rule{ID: id, Agent: "home", Proto: proto.TCP,
			ListenPort: proto.PortRange{Lo: port, Hi: port}, Target: "192.168.1.30:443",
			VPSMode: proto.ModeKernel, Enabled: false}), nil
	}); err != nil {
		t.Fatal(err)
	}
}

func rulesOf(t *testing.T, st *store.Store) []proto.Rule {
	t.Helper()
	rules, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func testKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// freeAddrs returns n distinct loopback host:port addresses nothing is listening on, so that the
// test can tell a listener that is open from one that is not. All the reservations are held open
// until the last one is made: a closed listening socket has no TIME_WAIT, so reserving one port at
// a time can hand out the same port twice, and two APIs of one test would then share an address.
func freeAddrs(t *testing.T, n int) []string {
	t.Helper()
	lns := make([]net.Listener, 0, n)
	addrs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		lns = append(lns, ln)
		addrs = append(addrs, ln.Addr().String())
	}
	for _, ln := range lns {
		ln.Close()
	}
	return addrs
}

// agentAPIAnswers reports whether the agent API itself is listening at addr, by completing a TLS
// handshake and comparing the certificate with the one this server holds. A bare TCP dial would
// also succeed if any other process on the host had taken the port, which would turn "the agent
// API must not listen during the hold" into a test that fails for someone else's reason.
func agentAPIAnswers(d *Daemon, addr string) bool {
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		return false
	}
	defer c.Close()
	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return false
	}
	want := d.agentAPI.Fingerprint()
	return sha256.Sum256(certs[0].Raw) == want
}

// adminGet calls the admin API the way the CLI does.
func adminGet(addr, path string) (int, error) {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + addr + path)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// waitForStartup waits for the server started line, and fails at once if serve returns first, so
// that a startup which ends in an error does not have to wait out the whole deadline.
func waitForStartup(t *testing.T, buf *syncBuffer, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("serve returned %v before the server started line; log:\n%s", err, buf.String())
		default:
		}
		if strings.Contains(buf.String(), "server started") {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for the server started line; log:\n%s", buf.String())
}

// appearsWithin reports whether want shows up in the log within d. It is for the cases where the
// answer must stay no: a startup that is held cannot log the started line, whatever the timing.
func appearsWithin(buf *syncBuffer, want string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), want) {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// startedLine returns the server started line itself, so an assertion about it cannot pass on some
// other line that happens to mention the same words.
func startedLine(t *testing.T, buf *syncBuffer) string {
	t.Helper()
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, "server started") {
			return l
		}
	}
	t.Fatalf("no server started line in:\n%s", buf.String())
	return ""
}

// readTimeoutsConcurrently keeps reading the conntrack timeouts until the returned function is
// called. serve writes them once, when the hold ends, while the admin API is already answering
// requests that report them, so this is the pair of accesses the race detector has to see.
func readTimeoutsConcurrently(d *Daemon) func() {
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = d.udpTimeouts()
			}
		}()
	}
	return func() { close(stop); wg.Wait() }
}

// syncBuffer collects the log while serve runs in another goroutine; captureLog's plain
// bytes.Buffer would be read and written at the same time.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func newSyncBuffer(t *testing.T) *syncBuffer {
	t.Helper()
	b := &syncBuffer{}
	prev := log.Writer()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(prev) })
	return b
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
