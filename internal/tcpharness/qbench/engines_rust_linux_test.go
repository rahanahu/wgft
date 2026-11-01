//go:build qbench && linux

package qbench

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/rahanahu/wgft/internal/dutproto"
)

// rsProc is one wgstack-dut process on the real clock: the frame protocol on its standard input
// and output, packets on a SOCK_SEQPACKET socketpair whose other end is the process's fd 3, and
// each accepted connection's bytes on a Unix socket of its own.
type rsProc struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	ctl     *dutproto.Conn
	dev     *seqpacketDev
	dir     string
	created time.Time // when HELLO built the engine, the start of RTO_AT's clock

	mu     sync.Mutex // one request at a time
	broken error

	closeOnce sync.Once
}

// newWgstackRS is the Rust wgstack in wgstack-dut, as a DUT of the rig.
func newWgstackRS() (*DUT, error) {
	bin := os.Getenv(wgstackRSEnv)
	if bin == "" {
		return nil, fmt.Errorf("the wgstack-rs engine needs %s, the wgstack-dut binary", wgstackRSEnv)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socketpair: %w", err)
	}
	mine, theirs := os.NewFile(uintptr(fds[0]), "qbench-packets"), os.NewFile(uintptr(fds[1]), "wgstack-dut-packets")
	defer theirs.Close()
	fc, err := net.FileConn(mine)
	mine.Close()
	if err != nil {
		return nil, fmt.Errorf("the packet socket: %w", err)
	}
	dir, err := os.MkdirTemp("", "qbench-rs-")
	if err != nil {
		fc.Close()
		return nil, err
	}
	p := &rsProc{dev: &seqpacketDev{c: fc.(*net.UnixConn), events: make(chan tun.Event, 1)}, dir: dir}
	p.dev.events <- tun.EventUp
	p.cmd = exec.Command(bin, "--clock", "real")
	p.cmd.ExtraFiles = []*os.File{theirs} // fd 3
	p.cmd.Stderr = os.Stderr              // the DUT prefixes its own lines
	if p.stdin, err = p.cmd.StdinPipe(); err != nil {
		p.close()
		return nil, err
	}
	stdout, err := p.cmd.StdoutPipe()
	if err != nil {
		p.close()
		return nil, err
	}
	if err := p.cmd.Start(); err != nil {
		p.close()
		return nil, fmt.Errorf("starting %s: %w", bin, err)
	}
	p.ctl = dutproto.NewConn(stdout, p.stdin)
	var seed [dutproto.SeedLen]byte
	rand.Read(seed[:])
	boost := dutproto.BoostOnDemand
	switch os.Getenv("QBENCH_BOOST") {
	case "accept":
		boost = dutproto.BoostAtAccept
	case "never":
		boost = dutproto.BoostNever
	}
	p.created = time.Now()
	resp, err := p.do(&dutproto.Hello{Version: dutproto.Version, Clock: dutproto.ClockReal, Addr: dutAddr, MTU: mtu,
		Seed: seed[:], Limits: []dutproto.Limit{}, Boost: boost, Congestion: dutproto.CongestionCubic})
	if err == nil {
		if e, ok := resp.(*dutproto.Error); ok {
			err = fmt.Errorf("HELLO refused: %s", e.Msg)
		} else if _, ok := resp.(*dutproto.HelloOK); !ok {
			err = fmt.Errorf("HELLO answered %s", dutproto.Format(resp))
		}
	}
	if err != nil {
		p.close()
		return nil, err
	}
	var accepted atomic.Pointer[rsConn]
	return &DUT{Name: "wgstack-rs", Dev: p.dev,
		Listen: p.listen,
		Close:  p.close,
		Stats: func(time.Time) string {
			s := "-"
			if r, err := p.do(&dutproto.Stats{}); err == nil {
				if t, ok := r.(*dutproto.Text); ok {
					s = t.S
				}
			}
			return s
		},
		CPU: p.cpu,
		OnAccept: func(c net.Conn) error {
			if rc, ok := c.(*rsConn); ok {
				accepted.Store(rc)
			}
			return nil
		},
		RTOAt: func(at time.Time) time.Duration {
			c := accepted.Load()
			if c == nil {
				return -1
			}
			r, err := p.do(&dutproto.RTOAt{H: c.h, At: max(at.Sub(p.created), 0)})
			if rto, ok := r.(*dutproto.RTO); err == nil && ok && rto.Known {
				return rto.RTO
			}
			return -1 // the core does not report its RTO: the judgment uses Linux's alone
		},
	}, nil
}

// do sends one request and reads its response.
func (p *rsProc) do(req dutproto.Msg) (dutproto.Msg, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken != nil {
		return nil, p.broken
	}
	if err := p.ctl.Send(req); err != nil {
		p.broken = fmt.Errorf("wgstack-dut: %s: %w", req.Kind(), err)
		return nil, p.broken
	}
	resp, err := p.ctl.Recv()
	if err != nil {
		p.broken = fmt.Errorf("wgstack-dut: %s: %w", req.Kind(), err)
		return nil, p.broken
	}
	return resp, nil
}

// cpu is the CPU time the process's threads have run, from the scheduler's nanosecond counters,
// or -1 when they cannot be read.
func (p *rsProc) cpu() time.Duration {
	if p.cmd.Process == nil {
		return -1
	}
	tasks, err := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/schedstat", p.cmd.Process.Pid))
	if err != nil || len(tasks) == 0 {
		return -1
	}
	var sum time.Duration
	for _, t := range tasks {
		b, err := os.ReadFile(t)
		if err != nil {
			continue // a thread that ended meanwhile
		}
		f := strings.Fields(string(b))
		if len(f) == 0 {
			continue
		}
		ns, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			return -1
		}
		sum += time.Duration(ns)
	}
	return sum
}

// close ends the process: its standard input closes, the packet socket closes, and the process
// gets 5 s to exit before it is killed.
func (p *rsProc) close() {
	p.closeOnce.Do(func() {
		if p.stdin != nil {
			p.stdin.Close()
		}
		p.dev.Close()
		if p.cmd != nil && p.cmd.Process != nil {
			done := make(chan struct{})
			go func() { p.cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				p.cmd.Process.Kill()
				<-done
			}
		}
		os.RemoveAll(p.dir)
	})
}

func (p *rsProc) listen(port uint16) (Listener, error) {
	resp, err := p.do(&dutproto.TCPListen{Port: port})
	if err != nil {
		return nil, err
	}
	switch r := resp.(type) {
	case *dutproto.HandleResp:
		return &rsListener{p: p, h: r.H, done: make(chan struct{})}, nil
	case *dutproto.Error:
		return nil, errors.New(r.Msg)
	}
	return nil, fmt.Errorf("TCP_LISTEN answered %s", dutproto.Format(resp))
}

// rsListener asks ACCEPT every millisecond until a connection is there: the DUT answers without
// waiting, and the rig's dial is in flight meanwhile.
type rsListener struct {
	p    *rsProc
	h    dutproto.Handle
	once sync.Once
	done chan struct{}
}

func (l *rsListener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.done:
			return nil, net.ErrClosed
		default:
		}
		resp, err := l.p.do(&dutproto.Accept{H: l.h})
		if err != nil {
			return nil, err
		}
		switch r := resp.(type) {
		case *dutproto.WouldBlock:
			select {
			case <-l.done:
				return nil, net.ErrClosed
			case <-time.After(time.Millisecond):
			}
		case *dutproto.Accepted:
			return l.p.relay(r.H)
		case *dutproto.Error:
			return nil, errors.New(r.Msg)
		default:
			return nil, fmt.Errorf("ACCEPT answered %s", dutproto.Format(resp))
		}
	}
}

func (l *rsListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.p.do(&dutproto.Close{H: l.h})
	})
	return nil
}

// relay has the DUT connect connection h to a Unix socket of its own and returns this end.
func (p *rsProc) relay(h dutproto.Handle) (net.Conn, error) {
	path := filepath.Join(p.dir, fmt.Sprintf("c%d", h))
	ul, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer ul.Close()
	resp, err := p.do(&dutproto.ConnSocket{H: h, Path: path})
	if err != nil {
		return nil, err
	}
	if e, ok := resp.(*dutproto.Error); ok {
		return nil, fmt.Errorf("CONN_SOCKET: %s", e.Msg)
	}
	ul.SetDeadline(time.Now().Add(5 * time.Second))
	c, err := ul.AcceptUnix()
	if err != nil {
		return nil, err
	}
	return &rsConn{UnixConn: c, p: p, h: h}, nil
}

// rsConn is the Go end of a relayed connection. Abort resets the engine's connection, as Abort
// does on the Go wgstack's; Close and CloseWrite act on the Unix socket, which the DUT relays
// as the product's relay does: the end of one direction closes the other side's sending
// direction.
type rsConn struct {
	*net.UnixConn
	p *rsProc
	h dutproto.Handle
}

func (c *rsConn) Abort() error {
	_, err := c.p.do(&dutproto.Abort{H: c.h})
	c.UnixConn.Close()
	return err
}

// seqpacketDev is the rig's end of the packet socketpair as a tun.Device: one message is one
// packet.
type seqpacketDev struct {
	c      *net.UnixConn
	events chan tun.Event
	once   sync.Once
}

func (d *seqpacketDev) File() *os.File           { return nil }
func (d *seqpacketDev) MTU() (int, error)        { return mtu, nil }
func (d *seqpacketDev) Name() (string, error)    { return "wgstack-rs", nil }
func (d *seqpacketDev) Events() <-chan tun.Event { return d.events }
func (d *seqpacketDev) BatchSize() int           { return 1 }

func (d *seqpacketDev) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := d.c.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.EOF // the DUT closed its end
	}
	sizes[0] = n
	return 1, nil
}

func (d *seqpacketDev) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		if _, err := d.c.Write(b[offset:]); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

func (d *seqpacketDev) Close() error {
	var err error
	d.once.Do(func() { err = d.c.Close() })
	return err
}
