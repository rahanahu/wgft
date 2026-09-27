//go:build linux

package sockbuf

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// listenSized は、受信と送信のバッファを要求した UDP ソケットを開く。wireguard-go と同じく
// SO_RCVBUF と SO_SNDBUF で要求する。
func listenSized(t *testing.T, network, addr string, size int) *net.UDPConn {
	t.Helper()
	c, err := tryListenSized(network, addr, size)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func tryListenSized(network, addr string, size int) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, size)
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, size)
		})
	}}
	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// Measure は自分のプロセスの記述子から、その port の UDP ソケットだけを見つけ、最も小さい値を返す。
// 要求した値の 2 倍が返るのは Linux の規則である(socket(7))。
func TestMeasureFindsOwnSocketsOnThePort(t *testing.T) {
	a := listenSized(t, "udp4", "127.0.0.1:0", 65536)
	port := uint16(a.LocalAddr().(*net.UDPAddr).Port)
	// 同じ port の別のファミリーのソケットと、別の port のソケットを並べる
	b, err := tryListenSized("udp6", net.JoinHostPort("::1", strconv.Itoa(int(port))), 32768)
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	defer b.Close()
	listenSized(t, "udp4", "127.0.0.1:0", 16384)
	r := Measure(port)
	if !r.Supported || r.Err != nil {
		t.Fatalf("Measure = %+v", r)
	}
	if r.Sockets != 2 {
		t.Errorf("Sockets = %d, want the two sockets on port %d", r.Sockets, port)
	}
	if r.Recv != 65536 || r.Send != 65536 {
		t.Errorf("Recv %d Send %d, want the smaller socket's 2 x 32768", r.Recv, r.Send)
	}
	if r.Met() {
		t.Error("a 64 KiB buffer meets the requirement")
	}
}

func TestMeasureWithoutSocket(t *testing.T) {
	a := listenSized(t, "udp4", "127.0.0.1:0", 65536)
	port := a.LocalAddr().(*net.UDPAddr).Port
	a.Close()
	r := Measure(uint16(port))
	if r.Err == nil || r.Measured() {
		t.Errorf("Measure of a closed port = %+v, want an error", r)
	}
}

func TestMeasureDevice(t *testing.T) {
	a := listenSized(t, "udp4", "127.0.0.1:0", 65536)
	port := a.LocalAddr().(*net.UDPAddr).Port
	r := MeasureDevice(func() (string, error) {
		return "private_key=00\nlisten_port=" + strconv.Itoa(port) + "\n", nil
	})
	if !r.Measured() || int(r.Port) != port || r.Recv != 131072 {
		t.Errorf("MeasureDevice = %+v", r)
	}
}

func TestReadLimits(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "rmem_max"), []byte("212992\n"), 0o644)
	old := sysctlDir
	sysctlDir = dir
	t.Cleanup(func() { sysctlDir = old })
	l := ReadLimits()
	if l.RmemMax != 212992 || l.RmemErr != nil {
		t.Errorf("rmem_max = %d, %v", l.RmemMax, l.RmemErr)
	}
	// 分けた network namespace ではファイルが無いカーネルがある(設計文書 6.1 節)
	if l.WmemErr == nil {
		t.Error("a missing wmem_max must be an error")
	}
}

// 試しのソケットは FORCE を使わないので、呼び出し元の権限によらず、権限を持たないプロセスの値を
// 返す。値は 2 x min(Requested, rmem_max) である。
func TestPlainProbe(t *testing.T) {
	p := PlainProbe()
	if p.Err != nil {
		t.Fatal(p.Err)
	}
	l := ReadLimits()
	if l.RmemErr != nil || l.WmemErr != nil {
		t.Skipf("the sysctls cannot be read here: %v %v", l.RmemErr, l.WmemErr)
	}
	if want := 2 * min(Requested, l.RmemMax); p.Recv != want {
		t.Errorf("Recv = %d, want %d from rmem_max %d", p.Recv, want, l.RmemMax)
	}
	if want := 2 * min(Requested, l.WmemMax); p.Send != want {
		t.Errorf("Send = %d, want %d from wmem_max %d", p.Send, want, l.WmemMax)
	}
}
