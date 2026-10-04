//go:build linux && lab

package nettun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The relay must reset a kernel socket with out-of-order receive memory before returning its
// flow and per-source slots. Run only in the disposable lab VM; the test creates its own network
// namespace and changes tcp_fin_timeout there so plain Close cannot hide retained memory.
func TestRelayHoldOutOfOrderKernelData(t *testing.T) {
	if os.Getenv("WGFT_TEST_IN_NETNS") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRelayHoldOutOfOrderKernelData$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), "WGFT_TEST_IN_NETNS=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		}
		out, err := cmd.CombinedOutput()
		t.Logf("in a new user and network namespace:\n%s", out)
		var pe *os.PathError
		if errors.As(err, &pe) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL) {
			t.Skipf("cannot create an unprivileged user and network namespace here: %v", err)
		}
		if err != nil {
			t.Fatalf("the test failed in the namespace: %v", err)
		}
		return
	}
	setupNetns(t)
	established(t, func(t *testing.T) error { return oooScene(t) })
}

func setupNetns(t *testing.T) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		t.Fatal(err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		t.Fatalf("bringing lo up: %v", err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/tcp_fin_timeout", []byte("120"), 0); err != nil {
		t.Fatalf("setting tcp_fin_timeout in the test's namespace: %v", err)
	}
}

func sockOpt(c *net.TCPConn, f func(fd int) (int, error)) int {
	rc, err := c.SyscallConn()
	if err != nil {
		return -1
	}
	v := -1
	if rc.Control(func(fd uintptr) {
		if n, err := f(int(fd)); err == nil {
			v = n
		}
	}) != nil {
		return -1
	}
	return v
}

func inq(c *net.TCPConn) int {
	return sockOpt(c, func(fd int) (int, error) { return unix.IoctlGetInt(fd, unix.SIOCINQ) })
}

// rmemAlloc is SO_MEMINFO's SK_MEMINFO_RMEM_ALLOC of c, or -1.
func rmemAlloc(c *net.TCPConn) int {
	return sockOpt(c, func(fd int) (int, error) {
		var m [9]uint32
		l := uint32(36)
		_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_MEMINFO,
			uintptr(unsafe.Pointer(&m[0])), uintptr(unsafe.Pointer(&l)), 0)
		if e != 0 {
			return 0, e
		}
		return int(m[0]), nil
	})
}

// seqs reads c's next send sequence number and next expected receive sequence number with
// TCP_REPAIR, then leaves repair mode.
func seqs(t *testing.T, c *net.TCPConn) (snd, rcv uint32) {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ferr error
	rc.Control(func(fd uintptr) {
		f := int(fd)
		if ferr = unix.SetsockoptInt(f, unix.IPPROTO_TCP, unix.TCP_REPAIR, 1); ferr != nil {
			return
		}
		defer unix.SetsockoptInt(f, unix.IPPROTO_TCP, unix.TCP_REPAIR, -1)
		const sendQueue, recvQueue = 2, 1
		unix.SetsockoptInt(f, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, sendQueue)
		s, err := unix.GetsockoptInt(f, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
		if err != nil {
			ferr = err
			return
		}
		unix.SetsockoptInt(f, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, recvQueue)
		r, err := unix.GetsockoptInt(f, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
		if err != nil {
			ferr = err
			return
		}
		snd, rcv = uint32(s), uint32(r)
	})
	if ferr != nil {
		t.Fatalf("TCP_REPAIR: %v", ferr)
	}
	return snd, rcv
}

func csum(b []byte, sum uint32) uint16 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// sendOutOfOrder sends one TCP segment of n bytes from the loopback port sport to dport, starting
// gap bytes beyond seq, with a raw socket.
func sendOutOfOrder(t *testing.T, sport, dport uint16, seq, ack uint32, gap, n int) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		t.Fatalf("raw socket: %v", err)
	}
	defer unix.Close(fd)
	tcp := make([]byte, 20+n)
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq+uint32(gap))
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = 5 << 4
	tcp[13] = 0x18 // PSH ACK
	binary.BigEndian.PutUint16(tcp[14:], 512)
	for i := 0; i < n; i++ {
		tcp[20+i] = 'x'
	}
	pseudo := []byte{127, 0, 0, 1, 127, 0, 0, 1, 0, 6, byte(len(tcp) >> 8), byte(len(tcp))}
	var s uint32
	for i := 0; i < len(pseudo); i += 2 {
		s += uint32(binary.BigEndian.Uint16(pseudo[i:]))
	}
	binary.BigEndian.PutUint16(tcp[16:], csum(tcp, s))
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:], []byte{127, 0, 0, 1})
	copy(ip[16:], []byte{127, 0, 0, 1})
	binary.BigEndian.PutUint16(ip[10:], csum(ip, 0))
	if err := unix.Sendto(fd, append(ip, tcp...), 0, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("sending the out-of-order segment: %v", err)
	}
}

var skmemR = regexp.MustCompile(`skmem:\(r(\d+),`)

// pairMemory returns the receive memory (ss skmem r) of every socket whose local port is lport and
// whose peer port is pport.
func pairMemory(t *testing.T, lport, pport uint16) []int {
	t.Helper()
	out, err := exec.Command("ss", "-tmnaH", fmt.Sprintf("( sport = :%d and dport = :%d )", lport, pport)).CombinedOutput()
	if err != nil {
		t.Fatalf("ss: %v: %s", err, out)
	}
	var rs []int
	for _, m := range skmemR.FindAllStringSubmatch(string(out), -1) {
		n, _ := strconv.Atoi(m[1])
		rs = append(rs, n)
	}
	if len(rs) == 0 && strings.TrimSpace(string(out)) != "" {
		t.Fatalf("cannot read skmem from ss: %s", out)
	}
	return rs
}

func oooScene(t *testing.T) error {
	e := newHoldEnv(t, false, 8, "r1")
	pr := e.open("r1")
	if pr == nil {
		t.Fatal("refused")
	}
	pr.kend.SetReadBuffer(4096)
	lport := uint16(pr.relayK.LocalAddr().(*net.TCPAddr).Port)
	pport := uint16(pr.kend.LocalAddr().(*net.TCPAddr).Port)
	snd, rcv := seqs(t, pr.kend)
	sendOutOfOrder(t, pport, lport, snd, rcv, 1000, 500)
	if _, err := holdWait(time.Second, func() bool { return rmemAlloc(pr.relayK) > 0 }); err != nil {
		return fmt.Errorf("the out-of-order segment did not reach the relay's socket: rmem %d", rmemAlloc(pr.relayK))
	}
	if q, m := inq(pr.relayK), rmemAlloc(pr.relayK); q != 0 || m <= 0 {
		return fmt.Errorf("SIOCINQ %d, RMEM_ALLOC %d; want 0 and above 0", q, m)
	}
	t.Logf("before the end: SIOCINQ %d, RMEM_ALLOC %d", inq(pr.relayK), rmemAlloc(pr.relayK))
	// the agent's peer sends a tail that fits in the relay socket's send buffer, then resets, which
	// ends the relay on the error path
	if _, err := pr.peer.Write(holdData(8 << 10)); err != nil {
		t.Fatal(err)
	}
	if _, err := holdWait(time.Second, func() bool { return inq(pr.kend) >= 8<<10 }); err != nil {
		return fmt.Errorf("the peer's tail did not reach the client's receive queue: %v", err)
	}
	pr.peer.(interface{ Abort() }).Abort()
	if err := e.waitEnded(pr, 5*time.Second); err != nil {
		return err
	}
	// the client reads whatever comes
	readEnd := make(chan error, 1)
	go func() {
		pr.kend.SetReadDeadline(time.Now().Add(15 * time.Second))
		_, err := io.Copy(io.Discard, pr.kend)
		readEnd <- err
	}()
	if _, err := holdWait(10*time.Second, func() bool { return e.pool.InUse() == 0 && e.srcInUse.Load() == 0 }); err != nil {
		t.Fatalf("slots not returned: K %d, per-source %d", e.pool.InUse(), e.srcInUse.Load())
	}
	mem := pairMemory(t, lport, pport)
	rerr := <-readEnd
	reset := errors.Is(rerr, unix.ECONNRESET)
	t.Logf("after K returned: the client's read ended with %v; sockets of the pair hold receive memory %v", rerr, mem)
	for _, m := range mem {
		if m > 0 {
			t.Fatalf("a socket of the pair still holds %d bytes of receive memory after K was returned (reset seen by the client: %v)", m, reset)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if e.releases.Load() != 1 || e.doubles.Load() != 0 || e.pool.Ledger().DoubleReleases != 0 {
		t.Fatalf("per-source releases %d (doubles %d), pool double releases %d; want 1, 0, 0",
			e.releases.Load(), e.doubles.Load(), e.pool.Ledger().DoubleReleases)
	}
	return nil
}
