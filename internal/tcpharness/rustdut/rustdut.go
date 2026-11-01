// Package rustdut is the tcpharness DUT for an engine in another process that speaks the frame
// protocol of internal/dutproto on its standard input and output, as docs/design/v2/test-tooling.md
// section 3 defines: the Rust wgstack's wgstack-dut, and, to check this adapter and the Rust
// runner, the Go wgstack's dutserve. It is a ClockedDUT: the requests drive the engine's fake
// clock, and only the application's read and write deadlines and Accept's context wait on the
// wall clock, as with wgstackdut.
//
// The engine answers every request without waiting: an operation that would have to wait answers
// WOULD_BLOCK, or WROTE 0 for a write, and changes nothing. A waiting operation here sends its
// request again only after some request that changes the engine's state, so the requests the
// adapter sends do not depend on how long the wall-clock waits last: an answer that cannot have
// changed is not asked again. The table of requests that change state and requests that only ask
// is the design's; classify below is its code.
package rustdut

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/dutproto"
	"github.com/rahanahu/wgft/internal/tcpharness"
)

// BinEnv names the DUT binary: the Rust wgstack-dut, or the Go wgstack's test binary built with
// `go test -c -o wgstack-dutserve.test ./internal/wgstack`. Without it the tests that need a DUT
// skip, so go test ./... passes where there is no cargo.
const BinEnv = "WGFT_TEST_WGSTACK_DUT"

// dutserveEnv makes the Go wgstack's test binary serve as a DUT. The Rust binary ignores it.
const dutserveEnv = "WGFT_WGSTACK_DUTSERVE"

// epoch is where the harness's view of the engine's clock starts, the same as wgstackdut's.
var epoch = time.Unix(1_000_000_000, 0)

// Config is how to start one DUT process.
type Config struct {
	// Bin is the DUT binary.
	Bin string
	// Boost and Congestion are HELLO's test choices.
	Boost      dutproto.Boost
	Congestion dutproto.Congestion
	// Log receives the process's standard error, a line at a time, and the adapter's own notes.
	Log func(format string, args ...any)
	// Transcript, when set, receives every request frame and its response frame as they pass,
	// in order: the transcript of test-tooling.md section 2 and the recordings of section 4.
	Transcript io.Writer
}

// Seed is HELLO's 64-byte seed for a scenario's seed: the first 64 bytes of the random source
// wgstackdut gives the Go wgstack, a ChaCha8 keyed from the seed. The Go wgstack reads exactly 64
// bytes from it when it builds a Device, so wgstackdut, dutserve and the Rust wgstack get the
// same bytes from the same scenario seed.
func Seed(seed uint64) [dutproto.SeedLen]byte {
	var key [32]byte
	for i := range 4 {
		v := seed ^ uint64(i)*0x9e3779b97f4a7c15
		for j := range 8 {
			key[i*8+j] = byte(v >> (8 * j))
		}
	}
	var out [dutproto.SeedLen]byte
	rand.NewChaCha8(key).Read(out[:])
	return out
}

// DUT is one DUT process.
type DUT struct {
	cfg    Config
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	conn   *dutproto.Conn
	errLog chan struct{} // closed when the standard error reader ends
	name   string
	addr   netip.Addr
	mtu    int

	mu      sync.Mutex
	changed chan struct{} // closed by the next request that changes the engine's state
	cache   map[string]dutproto.Msg
	now     time.Duration
	nowSet  bool
	broken  error
	closed  bool
}

// New starts the DUT binary and builds its engine at addr with the given MTU and seed.
func New(cfg Config, addr netip.Addr, mtu int, seed uint64) (*DUT, error) {
	if cfg.Log == nil {
		cfg.Log = func(string, ...any) {}
	}
	cmd := exec.Command(cfg.Bin, "--clock", "fake")
	cmd.Env = append(os.Environ(), dutserveEnv+"=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting the DUT %s: %w", cfg.Bin, err)
	}
	d := &DUT{cfg: cfg, cmd: cmd, stdin: stdin, conn: dutproto.NewConn(stdout, stdin), errLog: make(chan struct{}),
		addr: addr, mtu: mtu, changed: make(chan struct{}), cache: map[string]dutproto.Msg{}}
	go func() {
		defer close(d.errLog)
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			cfg.Log("dut: %s", sc.Text())
		}
	}()
	s := Seed(seed)
	resp, err := d.do(&dutproto.Hello{Version: dutproto.Version, Clock: dutproto.ClockFake, Addr: addr, MTU: uint32(mtu),
		Seed: s[:], Limits: []dutproto.Limit{}, Boost: cfg.Boost, Congestion: cfg.Congestion})
	if err == nil {
		switch r := resp.(type) {
		case *dutproto.HelloOK:
			d.name = r.Engine
		case *dutproto.Error:
			err = fmt.Errorf("HELLO refused: %s", r.Msg)
		default:
			err = fmt.Errorf("HELLO answered %s", dutproto.Format(r))
		}
	}
	if err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// Engine is the harness's description of the DUT that BinEnv names. Its Name is "rustdut"; the
// DUT's Name is the engine the process reports, such as wgstack for dutserve.
func Engine(known map[string]tcpharness.Known) tcpharness.Engine {
	return tcpharness.Engine{
		Name:           "rustdut",
		New:            newFor(dutproto.BoostOnDemand),
		NewPerformance: newFor(dutproto.BoostAtAccept),
		Known:          known,
	}
}

func newFor(boost dutproto.Boost) func(tb testing.TB, seed uint64) tcpharness.DUT {
	return func(tb testing.TB, seed uint64) tcpharness.DUT {
		bin := os.Getenv(BinEnv)
		if bin == "" {
			tb.Skipf("set %s to a DUT binary to run", BinEnv)
		}
		d, err := New(Config{Bin: bin, Boost: boost, Log: tb.Logf}, tcpharness.DUTAddr, tcpharness.MTU, seed)
		if err != nil {
			tb.Fatalf("rustdut: %v", err)
		}
		tb.Cleanup(func() {
			if err := d.Close(); err != nil {
				tb.Errorf("rustdut: %v", err)
			}
		})
		return d
	}
}

// class is how a request counts for the rule that a waiting operation does not ask again.
type class int

const (
	changes class = iota // the request changes the engine's state: earlier answers no longer hold
	query                // the request only asks: its answer holds until a request that changes
)

// classify is the design's table. A request that can answer that it would have to wait is a
// query when it does so, and changes state when it returns a result.
func classify(req, resp dutproto.Msg) class {
	switch req.Kind() {
	case dutproto.KindNow, dutproto.KindDelivered, dutproto.KindStats, dutproto.KindBound, dutproto.KindHeld:
		return query
	case dutproto.KindAccept, dutproto.KindUDPRecv, dutproto.KindUDPSend, dutproto.KindPingRecv:
		if resp.Kind() == dutproto.KindWouldBlock {
			return query
		}
	case dutproto.KindRead:
		if resp.Kind() == dutproto.KindWouldBlock {
			return query
		}
		if r, ok := resp.(*dutproto.Data); ok && len(r.Data) == 0 {
			return query
		}
	case dutproto.KindWrite:
		if r, ok := resp.(*dutproto.Wrote); ok && r.N == 0 {
			return query
		}
	}
	return changes
}

// errDUTClosed is what an operation returns after the DUT was closed or broke.
var errDUTClosed = errors.New("rustdut: the DUT process is closed")

// do sends one request and returns its response. A query whose answer still holds is answered
// from the cache without sending. The returned channel is closed by the next request that changes
// the engine's state; an operation that has to wait waits on it.
func (d *DUT) do(req dutproto.Msg) (dutproto.Msg, error) {
	resp, _, err := d.ask(req)
	return resp, err
}

func (d *DUT) ask(req dutproto.Msg) (dutproto.Msg, <-chan struct{}, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.broken != nil {
		return nil, d.changed, d.broken
	}
	if d.closed {
		return nil, d.changed, errDUTClosed
	}
	frame := dutproto.AppendFrame(nil, req)
	if req.Kind() == dutproto.KindNow && d.nowSet {
		return &dutproto.Time{Now: d.now}, d.changed, nil
	}
	key := string(frame)
	if r, ok := d.cache[key]; ok {
		return r, d.changed, nil
	}
	resp, err := d.roundTrip(frame)
	if err != nil {
		d.broken = fmt.Errorf("rustdut: %s: %w", req.Kind(), err)
		d.cfg.Log("%v", d.broken)
		close(d.changed)
		return nil, d.changed, d.broken
	}
	if t, ok := resp.(*dutproto.Time); ok {
		d.now, d.nowSet = t.Now, true
	}
	if req.Kind() == dutproto.KindHello {
		return resp, d.changed, nil
	}
	if classify(req, resp) == query {
		d.cache[key] = resp
		return resp, d.changed, nil
	}
	clear(d.cache)
	close(d.changed)
	d.changed = make(chan struct{})
	return resp, d.changed, nil
}

// roundTrip writes one frame and reads the response frame. d.mu is held.
func (d *DUT) roundTrip(frame []byte) (dutproto.Msg, error) {
	if err := d.conn.SendRaw(frame); err != nil {
		return nil, err
	}
	k, body, err := d.conn.ReadRaw()
	if err != nil {
		return nil, err
	}
	if k.IsRequest() {
		return nil, fmt.Errorf("the DUT answered with a request frame %s", k)
	}
	if d.cfg.Transcript != nil {
		d.cfg.Transcript.Write(frame)
		hdr := binary.LittleEndian.AppendUint32(nil, uint32(1+len(body)))
		d.cfg.Transcript.Write(append(append(hdr, byte(k)), body...))
	}
	return dutproto.Decode(k, body)
}

// Close ends the process: it closes the standard input, which the DUT takes as the end, and waits
// for the process and its standard error. A process that exits with an error is reported.
func (d *DUT) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	if d.broken == nil {
		close(d.changed)
	}
	d.mu.Unlock()
	d.stdin.Close()
	exited := make(chan error, 1)
	go func() {
		<-d.errLog
		exited <- d.cmd.Wait()
	}()
	select {
	case err := <-exited:
		if err != nil {
			return fmt.Errorf("the DUT process %s ended with %v", d.cfg.Bin, err)
		}
	case <-time.After(10 * time.Second):
		d.cmd.Process.Kill()
		<-exited
		return fmt.Errorf("the DUT process %s did not end within 10 s of its standard input closing; killed", d.cfg.Bin)
	}
	return nil
}

func (d *DUT) Name() string           { return d.name }
func (d *DUT) Addr() netip.Addr       { return d.addr }
func (d *DUT) MTU() int               { return d.mtu }
func (d *DUT) Emitted() <-chan []byte { return nil }

// Inject hands one packet to the engine.
func (d *DUT) Inject(pkt []byte) error {
	resp, err := d.do(&dutproto.Inject{Packets: []dutproto.Bytes{pkt}})
	if err != nil {
		return err
	}
	return respErr(resp, "inject")
}

// Now is the engine's clock as a time for the harness.
func (d *DUT) Now() time.Time {
	resp, err := d.do(&dutproto.Now{})
	if t, ok := resp.(*dutproto.Time); ok && err == nil {
		return epoch.Add(t.Now)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return epoch.Add(d.now)
}

// Advance moves the engine's clock and runs the timers that fall due.
func (d *DUT) Advance(dt time.Duration) { d.do(&dutproto.Advance{D: dt}) }

// Poll takes the next packet the engine sends now. It asks for one packet at a time, as
// ClockedDUT.Poll takes one.
func (d *DUT) Poll() ([]byte, bool) {
	resp, err := d.do(&dutproto.Poll{Max: 1})
	if p, ok := resp.(*dutproto.Packets); ok && err == nil && len(p.Packets) > 0 {
		return p.Packets[0], true
	}
	return nil, false
}

func (d *DUT) Listen(port uint16) (tcpharness.Listener, error) {
	h, err := d.handle(&dutproto.TCPListen{Port: port}, "listen")
	if err != nil {
		return nil, err
	}
	return &listener{d: d, h: h, addr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(d.addr, port))}, nil
}

func (d *DUT) ListenUDP(port uint16) (net.PacketConn, error) {
	h, err := d.handle(&dutproto.UDPListen{Port: port}, "listen")
	if err != nil {
		return nil, err
	}
	return &udpConn{d: d, h: h, laddr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(d.addr, port))}, nil
}

func (d *DUT) handle(req dutproto.Msg, op string) (dutproto.Handle, error) {
	resp, err := d.do(req)
	if err != nil {
		return 0, err
	}
	if h, ok := resp.(*dutproto.HandleResp); ok {
		return h.H, nil
	}
	return 0, respErr(resp, op)
}

// remoteError is an error the engine returned, rebuilt with the engine's message and with the
// standard error it stands for, so errors.Is, a Timeout method and errKind read it as they read
// the engine's own error.
type remoteError struct {
	kind dutproto.ErrKind
	msg  string
}

func (e *remoteError) Error() string { return e.msg }
func (e *remoteError) Timeout() bool { return e.kind == dutproto.ErrTimeout }
func (e *remoteError) Unwrap() error {
	switch e.kind {
	case dutproto.ErrTimeout:
		return os.ErrDeadlineExceeded
	case dutproto.ErrEOF:
		return io.EOF
	case dutproto.ErrClosed:
		return net.ErrClosed
	case dutproto.ErrReset:
		return syscall.ECONNRESET
	case dutproto.ErrBrokenPipe:
		return syscall.EPIPE
	}
	return nil
}

// respErr turns a response that is not a success into an error; OK is nil.
func respErr(resp dutproto.Msg, op string) error {
	switch r := resp.(type) {
	case *dutproto.OK:
		return nil
	case *dutproto.Error:
		if r.Err == dutproto.ErrEOF {
			return io.EOF
		}
		return &remoteError{kind: r.Err, msg: r.Msg}
	}
	return fmt.Errorf("rustdut: %s answered %s", op, dutproto.Format(resp))
}

// waitFor waits until changed is closed, the deadline passes or done is closed, and reports
// whether the operation may ask again.
func waitFor(changed <-chan struct{}, deadline time.Time, done <-chan struct{}) bool {
	var timer <-chan time.Time
	if !deadline.IsZero() {
		t := time.NewTimer(time.Until(deadline))
		defer t.Stop()
		timer = t.C
	}
	select {
	case <-changed:
		return true
	case <-timer:
		return true
	case <-done:
		return false
	}
}

// expired reports whether a deadline is set and has passed.
func expired(dl time.Time) bool { return !dl.IsZero() && !time.Now().Before(dl) }

type listener struct {
	d    *DUT
	h    dutproto.Handle
	addr *net.TCPAddr
}

func (l *listener) Close() error {
	resp, err := l.d.do(&dutproto.Close{H: l.h})
	if err != nil {
		return err
	}
	return respErr(resp, "close")
}

// Accept takes the next connection. While the engine has none it waits for a request that
// changes the engine's state or for ctx; when ctx ends it closes the listener, as wgstackdut does.
func (l *listener) Accept(ctx context.Context) (tcpharness.Conn, error) {
	for {
		resp, changed, err := l.d.ask(&dutproto.Accept{H: l.h})
		if err != nil {
			return nil, err
		}
		switch r := resp.(type) {
		case *dutproto.Accepted:
			return &conn{d: l.d, h: r.H, laddr: l.addr, raddr: net.TCPAddrFromAddrPort(r.Remote)}, nil
		case *dutproto.WouldBlock:
			if !waitFor(changed, time.Time{}, ctx.Done()) {
				l.Close()
				return nil, ctx.Err()
			}
		default:
			return nil, respErr(resp, "accept")
		}
	}
}

// conn is an accepted connection. Its deadlines are the application's, on the wall clock.
type conn struct {
	d            *DUT
	h            dutproto.Handle
	laddr, raddr *net.TCPAddr

	mu       sync.Mutex
	rdl, wdl time.Time
}

func (c *conn) deadlines() (r, w time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rdl, c.wdl
}

func (c *conn) opErr(op string, err error) error {
	return &net.OpError{Op: op, Net: "tcp", Source: c.laddr, Addr: c.raddr, Err: err}
}

// Read reads what the engine has. While it has nothing it waits for a request that changes the
// engine's state or for the read deadline. With the deadline passed it returns the error the
// engine checks first, a closed connection's, or else the timeout, as wgstack's Read does: a read
// of 0 bytes asks the engine for the first without changing anything.
func (c *conn) Read(b []byte) (int, error) {
	b = b[:min(len(b), maxRead)]
	for {
		rdl, _ := c.deadlines()
		if expired(rdl) {
			resp, err := c.d.do(&dutproto.Read{H: c.h, Max: 0})
			if err != nil {
				return 0, err
			}
			if _, ok := resp.(*dutproto.Data); !ok {
				return 0, respErr(resp, "read")
			}
			return 0, c.opErr("read", os.ErrDeadlineExceeded)
		}
		resp, changed, err := c.d.ask(&dutproto.Read{H: c.h, Max: uint32(len(b))})
		if err != nil {
			return 0, err
		}
		switch r := resp.(type) {
		case *dutproto.Data:
			return copy(b, r.Data), nil
		case *dutproto.WouldBlock:
			if !waitFor(changed, rdl, nil) {
				return 0, errDUTClosed
			}
		default:
			return 0, respErr(resp, "read")
		}
	}
}

// maxRead bounds one READ's size so the answer fits in a frame.
const maxRead = 1 << 20

// Write hands b to the engine as it takes it. While the engine takes nothing it waits for a
// request that changes the engine's state or for the write deadline. With the deadline passed it
// returns the error the engine checks first, or else the timeout: a write of 0 bytes asks the
// engine for the first without changing anything.
func (c *conn) Write(b []byte) (int, error) {
	total := 0
	for {
		_, wdl := c.deadlines()
		if expired(wdl) {
			resp, err := c.d.do(&dutproto.Write{H: c.h, Data: dutproto.Bytes{}})
			if err != nil {
				return total, err
			}
			if _, ok := resp.(*dutproto.Wrote); !ok {
				return total, respErr(resp, "write")
			}
			return total, c.opErr("write", os.ErrDeadlineExceeded)
		}
		chunk := b[total:]
		chunk = chunk[:min(len(chunk), maxRead)]
		resp, changed, err := c.d.ask(&dutproto.Write{H: c.h, Data: chunk})
		if err != nil {
			return total, err
		}
		r, ok := resp.(*dutproto.Wrote)
		switch {
		case !ok:
			return total, respErr(resp, "write")
		case r.N > 0:
			total += int(r.N)
			if total == len(b) {
				return total, nil
			}
		case len(b) == 0:
			return 0, nil
		default:
			if !waitFor(changed, wdl, nil) {
				return total, errDUTClosed
			}
		}
	}
}

func (c *conn) simple(req dutproto.Msg, op string) error {
	resp, err := c.d.do(req)
	if err != nil {
		return err
	}
	return respErr(resp, op)
}

func (c *conn) Close() error            { return c.simple(&dutproto.Close{H: c.h}, "close") }
func (c *conn) CloseWrite() error       { return c.simple(&dutproto.CloseWrite{H: c.h}, "close") }
func (c *conn) Abort() error            { return c.simple(&dutproto.Abort{H: c.h}, "abort") }
func (c *conn) CloseForDelivery() error { return c.simple(&dutproto.CloseForDelivery{H: c.h}, "close") }

func (c *conn) Delivered() bool {
	resp, err := c.d.do(&dutproto.Delivered{H: c.h})
	r, ok := resp.(*dutproto.Bool)
	return err == nil && ok && r.V
}

// OnBoost registers a hook that lets the connection return to its floor buffers, which is what
// the engine does without one, and tells f the state at registration. Later changes, which the
// DUT keeps for EVENTS, do not reach f: no scenario registers a hook, and asking EVENTS after every
// request would add a request to every step of the transcript.
func (c *conn) OnBoost(f func(boosted bool) bool) {
	resp, err := c.d.do(&dutproto.BoostPolicy{H: c.h, Floor: true})
	if r, ok := resp.(*dutproto.Bool); ok && err == nil {
		f(r.V)
		return
	}
	f(false)
}

func (c *conn) LocalAddr() net.Addr  { return c.laddr }
func (c *conn) RemoteAddr() net.Addr { return c.raddr }

func (c *conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rdl, c.wdl = t, t
	return nil
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rdl = t
	return nil
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wdl = t
	return nil
}

// udpConn is an unconnected UDP socket of the engine.
type udpConn struct {
	d     *DUT
	h     dutproto.Handle
	laddr *net.UDPAddr

	mu       sync.Mutex
	rdl, wdl time.Time
	closed   bool
}

func (u *udpConn) state() (rdl, wdl time.Time, closed bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.rdl, u.wdl, u.closed
}

func (u *udpConn) opErr(op string, addr net.Addr, err error) error {
	return &net.OpError{Op: op, Net: "udp", Source: u.laddr, Addr: addr, Err: err}
}

// ReadFrom takes the next datagram. With the read deadline passed it returns the error wgstack
// checks first, a closed socket's, from its own record of Close, or else the timeout.
func (u *udpConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		rdl, _, closed := u.state()
		if expired(rdl) {
			if closed {
				return 0, nil, net.ErrClosed
			}
			return 0, nil, u.opErr("read", nil, os.ErrDeadlineExceeded)
		}
		resp, changed, err := u.d.ask(&dutproto.UDPRecv{H: u.h, Max: uint32(min(len(b), maxRead))})
		if err != nil {
			return 0, nil, err
		}
		switch r := resp.(type) {
		case *dutproto.Datagram:
			return copy(b, r.Data), net.UDPAddrFromAddrPort(r.From), nil
		case *dutproto.WouldBlock:
			if !waitFor(changed, rdl, nil) {
				return 0, nil, errDUTClosed
			}
		default:
			return 0, nil, respErr(resp, "read")
		}
	}
}

// udpMaxPayload is the largest UDP payload in an IPv4 packet; WriteTo checks it before the
// deadline, as wgstack does.
const udpMaxPayload = 65535 - 20 - 8

// WriteTo sends one datagram. With the write deadline passed it returns the error wgstack checks
// first, from the address, the size or its own record of Close, or else the timeout.
func (u *udpConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok || ua.Port <= 0 || ua.Port > 65535 || ua.IP.To4() == nil {
		return 0, u.opErr("write", addr, errors.New("invalid UDP address"))
	}
	to := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ua.IP.To4())), uint16(ua.Port))
	for {
		_, wdl, closed := u.state()
		if expired(wdl) && len(b) <= udpMaxPayload {
			if closed {
				return 0, net.ErrClosed
			}
			return 0, u.opErr("write", addr, os.ErrDeadlineExceeded)
		}
		resp, changed, err := u.d.ask(&dutproto.UDPSend{H: u.h, To: to, Data: b})
		if err != nil {
			return 0, err
		}
		if _, ok := resp.(*dutproto.WouldBlock); ok {
			if !waitFor(changed, wdl, nil) {
				return 0, errDUTClosed
			}
			continue
		}
		if err := respErr(resp, "write"); err != nil {
			return 0, err
		}
		return len(b), nil
	}
}

func (u *udpConn) Close() error {
	u.mu.Lock()
	u.closed = true
	u.mu.Unlock()
	resp, err := u.d.do(&dutproto.Close{H: u.h})
	if err != nil {
		return err
	}
	return respErr(resp, "close")
}

func (u *udpConn) LocalAddr() net.Addr { return u.laddr }

func (u *udpConn) SetDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.rdl, u.wdl = t, t
	return nil
}

func (u *udpConn) SetReadDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.rdl = t
	return nil
}

func (u *udpConn) SetWriteDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.wdl = t
	return nil
}

// The adapter meets the harness's interfaces, including the optional methods the relay looks up
// by type assertion.
var (
	_ tcpharness.ClockedDUT     = (*DUT)(nil)
	_ tcpharness.Listener       = (*listener)(nil)
	_ tcpharness.Conn           = (*conn)(nil)
	_ tcpharness.Deliverer      = (*conn)(nil)
	_ tcpharness.DeliveryCloser = (*conn)(nil)
	_ tcpharness.Booster        = (*conn)(nil)
	_ net.PacketConn            = (*udpConn)(nil)
)
