//go:build qbench && linux

package qbench

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/rahanahu/wgft/internal/tcpharness"
	"github.com/rahanahu/wgft/internal/tcpharness/linuxdut"
)

// newLinux is the reference Linux DUT: a TUN device in the test's network namespace, which must
// be one the process can configure, with the kernel's TCP on its sockets. TestQBenchGate and
// TestQBenchRoutine re-run themselves in such a namespace when the linux engine is asked for.
func newLinux() (*DUT, error) {
	d, err := linuxdut.NewPerformance(dutAddr, mtu)
	if err != nil {
		return nil, err
	}
	rs := &rtoSampler{}
	return &DUT{Name: "linux", Dev: newTunAdapter(d),
		Listen: func(p uint16) (Listener, error) {
			l, err := d.Listen(p)
			if err != nil {
				return nil, err
			}
			return linuxListener{l}, nil
		},
		Close:    func() { rs.stop(); d.Close() },
		OnAccept: rs.start,
		RTOAt:    rs.at,
		RTOErr:   rs.lastErr,
	}, nil
}

type linuxListener struct{ l tcpharness.Listener }

func (l linuxListener) Accept() (net.Conn, error) { return l.l.Accept(context.Background()) }
func (l linuxListener) Close() error              { return l.l.Close() }

// rtoSampler reads the accepted socket's TCP_INFO every 10 ms and keeps the RTO samples, so the
// RTO in use at the end of an outage, tcpi_rto with its backoff, can be read afterwards.
type rtoSampler struct {
	mu      sync.Mutex
	err     error // the last TCP_INFO error, if any
	samples []struct {
		at  time.Time
		rto time.Duration
	}
	done chan struct{}
	once sync.Once
}

func (r *rtoSampler) start(c net.Conn) error {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return fmt.Errorf("the accepted %T has no file descriptor for TCP_INFO", c)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return fmt.Errorf("TCP_INFO: %w", err)
	}
	r.done = make(chan struct{})
	go func() {
		t := time.NewTicker(10 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-r.done:
				return
			case <-t.C:
			}
			var info *unix.TCPInfo
			var gerr error
			raw.Control(func(fd uintptr) { info, gerr = unix.GetsockoptTCPInfo(int(fd), unix.SOL_TCP, unix.TCP_INFO) })
			if info == nil || info.Rto == 0 {
				if gerr == nil {
					gerr = errors.New("TCP_INFO reports an RTO of 0")
				}
				r.mu.Lock()
				r.err = gerr
				r.mu.Unlock()
				continue
			}
			r.mu.Lock()
			r.samples = append(r.samples, struct {
				at  time.Time
				rto time.Duration
			}{time.Now(), time.Duration(info.Rto) * time.Microsecond})
			r.mu.Unlock()
		}
	}()
	return nil
}

func (r *rtoSampler) stop() {
	r.once.Do(func() {
		if r.done != nil {
			close(r.done)
		}
	})
}

// lastErr is the last error a TCP_INFO read gave, or nil.
func (r *rtoSampler) lastErr() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

func (r *rtoSampler) at(t time.Time) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := time.Duration(-1)
	for _, s := range r.samples {
		if s.at.Before(t) {
			out = s.rto
		}
	}
	return out
}

// tunAdapter shows a linuxdut DUT as the tun.Device the rig's link pumps packets through.
type tunAdapter struct {
	d      *linuxdut.DUT
	events chan tun.Event
}

func newTunAdapter(d *linuxdut.DUT) *tunAdapter {
	a := &tunAdapter{d: d, events: make(chan tun.Event, 1)}
	a.events <- tun.EventUp
	return a
}

func (a *tunAdapter) File() *os.File           { return nil }
func (a *tunAdapter) MTU() (int, error)        { return a.d.MTU(), nil }
func (a *tunAdapter) Name() (string, error)    { return linuxdut.IfName, nil }
func (a *tunAdapter) Events() <-chan tun.Event { return a.events }
func (a *tunAdapter) BatchSize() int           { return 1 }
func (a *tunAdapter) Close() error             { return a.d.Close() }

func (a *tunAdapter) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt, ok := <-a.d.Emitted()
	if !ok {
		return 0, os.ErrClosed
	}
	sizes[0] = copy(bufs[0][offset:], pkt)
	return 1, nil
}

func (a *tunAdapter) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		if err := a.d.Inject(b[offset:]); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

// pinLinux pins the performance sysctls when the linux engine runs, and returns where the run
// happens: the kernel's release and the values, which the plan records with the results.
func pinLinux(t *testing.T, engines []string) string {
	var u unix.Utsname
	unix.Uname(&u)
	release := strings.TrimRight(string(u.Release[:]), "\x00")
	where := "linux " + release
	if !has(engines, "linux") {
		fmt.Printf("QBENCH-META where=%q\n", where)
		return where
	}
	if err := linuxdut.PinPerformance(); err != nil {
		t.Fatalf("pinning the performance sysctls: %v", err)
	}
	// record the values as the kernel reads them back, not as written
	var vals []string
	for _, kv := range linuxdut.PerformanceSysctls {
		b, err := os.ReadFile("/proc/sys/" + kv[0])
		if err != nil {
			t.Fatalf("reading %s back: %v", kv[0], err)
		}
		vals = append(vals, kv[0]+"="+strings.Join(strings.Fields(string(b)), " "))
	}
	where += "; " + strings.Join(vals, ", ")
	fmt.Printf("QBENCH-META where=%q\n", where)
	return where
}

// inNetns re-runs the test in a new user and network namespace where the linux engine can work,
// and reports whether the caller is that re-run.
func inNetns(t *testing.T) bool {
	if os.Getenv("WGFT_TEST_IN_NETNS") == "1" {
		return true
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v", "-test.timeout=0")
	cmd.Env = append(os.Environ(), "WGFT_TEST_IN_NETNS=1")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("the run in a new user and network namespace failed: %v", err)
	}
	return false
}
