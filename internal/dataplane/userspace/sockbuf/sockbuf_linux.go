//go:build linux

package sockbuf

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// supported は、この OS で測る手段を持つかどうかである。
const supported = true

// fdDir は自分のプロセスのファイル記述子の一覧である。値は /proc/self/fd で、テストだけが差し替える。
var fdDir = "/proc/self/fd"

// Measure は、自分のプロセスのファイル記述子のうち、port に bind した UDP ソケットの実効の受信と
// 送信のバッファを読む。wireguard-go のソケットを読むだけで、値は変えない。
//
// 権限は要らない。自分のファイル記述子に getsockopt をかけるだけだからである。systemd の unit の
// 砂箱と Docker の中でも同じく読める。一覧を読む間に閉じられて番号が使い回された記述子は、型と
// port で外れるので、読み違えない。
func Measure(port uint16) Reading {
	r := Reading{Supported: true, Port: port}
	ents, err := os.ReadDir(fdDir)
	if err != nil {
		r.Err = fmt.Errorf("list this process's file descriptors: %w", err)
		return r
	}
	for _, e := range ents {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		recv, send, ok, err := readSocket(fd, port)
		if err != nil {
			r.Err = err
			return r
		}
		if !ok {
			continue
		}
		if r.Sockets == 0 || recv < r.Recv {
			r.Recv = recv
		}
		if r.Sockets == 0 || send < r.Send {
			r.Send = send
		}
		r.Sockets++
	}
	if r.Sockets == 0 {
		r.Err = fmt.Errorf("no UDP socket bound to port %d was found in this process", port)
	}
	return r
}

// readSocket は、fd が port に bind した UDP ソケットなら、その実効のバッファを返す。そうでなければ
// ok が偽である。対象のソケットで getsockopt が失敗したときだけ誤りを返す。
func readSocket(fd int, port uint16) (recv, send int, ok bool, err error) {
	typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || typ != unix.SOCK_DGRAM {
		return 0, 0, false, nil
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return 0, 0, false, nil
	}
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		ok = a.Port == int(port)
	case *unix.SockaddrInet6:
		ok = a.Port == int(port)
	}
	if !ok {
		return 0, 0, false, nil
	}
	if recv, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF); err != nil {
		return 0, 0, false, fmt.Errorf("read SO_RCVBUF of the socket on port %d: %w", port, err)
	}
	if send, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF); err != nil {
		return 0, 0, false, fmt.Errorf("read SO_SNDBUF of the socket on port %d: %w", port, err)
	}
	return recv, send, true, nil
}

// sysctlDir は net.core の sysctl のファイルがある場所である。値は /proc/sys/net/core で、テストだけが
// 差し替える。
var sysctlDir = "/proc/sys/net/core"

// ReadLimits は net.core.rmem_max と net.core.wmem_max を読む。値は初期の network namespace の
// ものだけで、分けた namespace ではカーネルによってファイルが無いか、読み取りだけの写しになる
// (設計文書 6.1 節)。
func ReadLimits() Limits {
	var l Limits
	l.RmemMax, l.RmemErr = readInt(sysctlDir + "/rmem_max")
	l.WmemMax, l.WmemErr = readInt(sysctlDir + "/wmem_max")
	return l
}

func readInt(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, fmt.Errorf("%s is not an integer: %w", path, err)
	}
	return n, nil
}

// PlainProbe は、CAP_NET_ADMIN を持たないプロセスが得る実効のバッファを試しのソケットで確かめる。
// SO_RCVBUF と SO_SNDBUF で Requested を要求し、読み返してすぐ閉じる。FORCE を使わないので、
// root で実行しても結果は権限を持たないプロセスのものになる。
func PlainProbe() Probe {
	var p Probe
	var setErr error
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			if setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, Requested); setErr != nil {
				return
			}
			if setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, Requested); setErr != nil {
				return
			}
			p.Recv, setErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
			if setErr != nil {
				return
			}
			p.Send, setErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
		})
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		return Probe{Err: fmt.Errorf("open a trial UDP socket: %w", err)}
	}
	pc.Close()
	if setErr != nil {
		return Probe{Err: fmt.Errorf("size a trial UDP socket: %w", setErr)}
	}
	return p
}
