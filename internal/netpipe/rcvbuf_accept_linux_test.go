//go:build linux

package netpipe

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// replaceSeam は試験の間だけ *p を v に差し替える。
func replaceSeam[T any](t *testing.T, p *T, v T) {
	t.Helper()
	saved := *p
	*p = v
	t.Cleanup(func() { *p = saved })
}

// holdAboveFloor は、accept したソケットに floor を超える受信のメモリを持たせる。固定していない
// ソケットが accept の前に受信のバッファを広げた状態を、通常の setsockopt と loopback の順序内の
// データで作る。
func holdAboveFloor(t *testing.T, dialed, accepted *net.TCPConn) {
	t.Helper()
	rc, err := accepted.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Control(func(fd uintptr) { fix(int(fd), true) }); err != nil {
		t.Fatal(err)
	}
	go dialed.Write(make([]byte, 1<<20))
	deadline := time.Now().Add(5 * time.Second)
	for rmemOf(t, accepted) <= kernelFloorBytes {
		if time.Now().After(deadline) {
			t.Fatalf("receive memory stayed at %d, never above the floor %d", rmemOf(t, accepted), kernelFloorBytes)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// accept したばかりのソケットは、受信のバッファを floor に固定され、窓の上限を KernelBoostWindow に
// 置かれて通る。
func TestFixAtAcceptLocksTheFloor(t *testing.T) {
	_, accepted := tcpPairLoopback(t, &net.Dialer{Timeout: 5 * time.Second})
	if !FixAtAccept(accepted) {
		t.Fatalf("refused a fresh connection; receive memory %d", rmemOf(t, accepted))
	}
	if got := rcvBuf(t, accepted); got != floorEffective {
		t.Fatalf("SO_RCVBUF after FixAtAccept = %d, want %d", got, floorEffective)
	}
	if got := sockInt(t, accepted, unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP); got != KernelBoostWindow {
		t.Fatalf("TCP_WINDOW_CLAMP after FixAtAccept = %d, want %d", got, KernelBoostWindow)
	}
}

// 受信のメモリは、受信のバッファを floor に固定した後に読む。読む時点のソケットはすでに floor に
// 固定されている。
func TestFixAtAcceptLocksBeforeMeasuring(t *testing.T) {
	_, accepted := tcpPairLoopback(t, &net.Dialer{Timeout: 5 * time.Second})
	var events []string
	set, measure := setRecvBuf, sockMemInfo
	replaceSeam(t, &setRecvBuf, func(fd, n int) error {
		events = append(events, "lock")
		return set(fd, n)
	})
	replaceSeam(t, &sockMemInfo, func(fd int) (int, int, bool) {
		n, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
		if err != nil || n != floorEffective {
			t.Errorf("SO_RCVBUF when the receive memory was read = %d, %v; want %d", n, err, floorEffective)
		}
		events = append(events, "measure")
		return measure(fd)
	})
	if !FixAtAccept(accepted) {
		t.Fatal("refused a fresh connection")
	}
	if len(events) != 2 || events[0] != "lock" || events[1] != "measure" {
		t.Fatalf("events = %v, want [lock measure]", events)
	}
}

// 固定する前に floor を超える受信のデータを持っていたソケットは通さない。固定しても、すでに持つ
// データは解放されないためである。
func TestFixAtAcceptRefusesHeldData(t *testing.T) {
	dialed, accepted := tcpPairLoopback(t, &net.Dialer{Timeout: 5 * time.Second})
	holdAboveFloor(t, dialed, accepted)
	if FixAtAccept(accepted) {
		t.Fatalf("passed a connection holding %d bytes of receive memory, above the floor %d", rmemOf(t, accepted), kernelFloorBytes)
	}
	if got := rcvBuf(t, accepted); got != floorEffective {
		t.Fatalf("SO_RCVBUF after the refusal = %d, want the floor %d", got, floorEffective)
	}
}

// 受信のバッファを固定できなければ、受信のメモリを読まずに通さない。固定できないソケットは Linux が
// 受信のバッファを広げうるためである。
func TestFixAtAcceptRefusesWhenNotLocked(t *testing.T) {
	_, accepted := tcpPairLoopback(t, &net.Dialer{Timeout: 5 * time.Second})
	measured := false
	replaceSeam(t, &setRecvBuf, func(int, int) error { return errors.New("injected") })
	measure := sockMemInfo
	replaceSeam(t, &sockMemInfo, func(fd int) (int, int, bool) {
		measured = true
		return measure(fd)
	})
	if FixAtAccept(accepted) {
		t.Fatal("passed a connection whose receive buffer could not be locked")
	}
	if measured {
		t.Fatal("read the receive memory after the lock failed")
	}
}

// 受信のメモリを読めなければ通さない。
func TestFixAtAcceptRefusesWhenUnmeasured(t *testing.T) {
	_, accepted := tcpPairLoopback(t, &net.Dialer{Timeout: 5 * time.Second})
	replaceSeam(t, &sockMemInfo, func(int) (int, int, bool) { return 0, 0, false })
	if FixAtAccept(accepted) {
		t.Fatal("passed a connection whose receive memory could not be read")
	}
}

// 読んだ受信のメモリか受信のバッファが floor を 1 byte でも超えれば通さず、floor ちょうどなら通す。
func TestFixAtAcceptComparesWithTheFloor(t *testing.T) {
	for _, c := range []struct {
		name         string
		rmem, rcvbuf int
		want         bool
	}{
		{"both at the floor", kernelFloorBytes, kernelFloorBytes, true},
		{"memory above the floor", kernelFloorBytes + 1, kernelFloorBytes, false},
		{"buffer above the floor", 0, kernelFloorBytes + 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, accepted := tcpPairLoopback(t, &net.Dialer{Timeout: 5 * time.Second})
			replaceSeam(t, &sockMemInfo, func(int) (int, int, bool) { return c.rmem, c.rcvbuf, true })
			if got := FixAtAccept(accepted); got != c.want {
				t.Fatalf("FixAtAccept with rmem %d and rcvbuf %d = %v, want %v", c.rmem, c.rcvbuf, got, c.want)
			}
		})
	}
}

// カーネルの TCP の接続でなければ、何もせずに通す。
func TestFixAtAcceptPassesOtherConns(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if !FixAtAccept(a) {
		t.Fatal("refused a connection that is not a kernel TCP socket")
	}
}
