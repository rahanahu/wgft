// Package sockbuf は、ユーザー空間モードの動作条件である WireGuard の UDP ソケットのバッファ
// (設計文書 7 節の「ソケットのバッファの条件」)を、そのソケットを持つプロセス自身が測る。
//
// wireguard-go は UDP ソケットを開くときに受信と送信のバッファを要求するが、得られた値を報告しない。
// このパッケージは wireguard-go の Bind を置き換えず、自分のプロセスのファイル記述子のうち
// WireGuard の listen port に bind した UDP ソケットを探し、getsockopt で実効の値を読むだけである。
// 測る手段を持つのは Linux だけであり、他の OS では測らない(設計文書 7 節)。
//
// エージェント(internal/dataplane/userspace/tunnel)とユーザー空間モードの server
// (internal/dataplane/userspace/utun)は、トンネルを立てるたびに Measure で測り、条件に届かなければ
// Warn で 1 行の警告を出す。wgft はこの値を決める sysctl を書き換えない。
package sockbuf

import (
	"fmt"

	"github.com/rahanahu/wgft/internal/dataplane/userspace/wgipc"
	"github.com/rahanahu/wgft/internal/lograte"
)

// Requested は、wireguard-go が UDP ソケットに要求する受信と送信のバッファである。単位はバイト。
// golang.zx2c4.com/wireguard の conn/controlfns.go の socketBufferSize と同じ値である。
const Requested = 7 << 20

// Required は、Linux で条件を満たすソケットが得る実効の受信と送信のバッファである。単位はバイト。
// Linux は要求の 2 倍をソケットに割り当て、getsockopt もその値を返す(socket(7))。
const Required = 2 * Requested

// Reading は、WireGuard の UDP ソケットを 1 回測った結果である。
type Reading struct {
	// Supported は、この OS で測る手段を持つかどうかである。Linux だけが真である。偽のとき、
	// 他の項目は意味を持たない
	Supported bool
	// Port は測った WireGuard の listen port である
	Port uint16
	// Sockets は、この port に bind した自分の UDP ソケットのうち測れたものの数である。
	// IPv4 と IPv6 で 1 つずつ開くので、ふつうは 2 である
	Sockets int
	// Recv と Send は、測ったソケットのうち最も小さい実効の受信と送信のバッファである。単位はバイト
	Recv, Send int
	// Err は、測れなかった理由である。値があるとき、Sockets、Recv、Send は意味を持たない
	Err error
}

// Measured は、実効の値を読めたかどうかである。
func (r Reading) Measured() bool {
	return r.Supported && r.Err == nil && r.Sockets > 0
}

// Met は、測った値が条件を満たすかどうかである。受信と送信の両方が Required 以上であることを
// 条件とする(設計文書 7 節)。
func (r Reading) Met() bool {
	return r.Measured() && r.Recv >= Required && r.Send >= Required
}

// MeasureDevice は、wireguard-go の device の IpcGet から listen port を読み、そのポートの
// ソケットを Measure で測る。ipcGet には device.Device の IpcGet を渡す。
func MeasureDevice(ipcGet func() (string, error)) Reading {
	if !supported {
		return Reading{}
	}
	out, err := ipcGet()
	if err != nil {
		return Reading{Supported: true, Err: fmt.Errorf("read the listen port: %w", err)}
	}
	port, err := wgipc.ListenPort(out)
	if err != nil {
		return Reading{Supported: true, Err: err}
	}
	return Measure(port)
}

// warnGate は Warn の警告を 1 分に 1 回までに絞る門である。1 つのプロセスは 1 つのトンネルしか
// 持たないので、プロセスに 1 つでよい。
var warnGate lograte.Gate

// Warn は、測った値が条件に届かないか測れなかったときに、英語の 1 行を logf に出す。条件を満たす
// 場合と、測る手段の無い OS では何も出さない。トンネルを続けて作り直しても行が並ばないように、
// 1 分に 1 回までに絞る。
func Warn(r Reading, logf func(format string, args ...any)) {
	warn(&warnGate, r, logf)
}

func warn(g *lograte.Gate, r Reading, logf func(format string, args ...any)) {
	msg := WarningText(r)
	if msg == "" || !g.Allow() {
		return
	}
	logf("%s", msg)
}

// WarningText は Warn が出す 1 行である。出すものが無ければ空を返す。
func WarningText(r Reading) string {
	switch {
	case !r.Supported || r.Met():
		return ""
	case !r.Measured():
		err := r.Err
		if err == nil {
			err = fmt.Errorf("no UDP socket bound to port %d was found in this process", r.Port)
		}
		return fmt.Sprintf("warning: cannot measure the WireGuard UDP socket buffers: %v; userspace mode requires %d bytes each for receive and send", err, Required)
	}
	return fmt.Sprintf("warning: the WireGuard UDP sockets on port %d got a receive buffer of %d bytes and a send buffer of %d bytes; "+
		"userspace mode requires %d bytes each. Set net.core.rmem_max and net.core.wmem_max to %d or more on this host, "+
		"or on the container host for a container, then restart; wgft never changes these sysctls",
		r.Port, r.Recv, r.Send, Required, Requested)
}

// Limits は、得られるバッファの上限を決める 2 つの sysctl の値である。
type Limits struct {
	// RmemMax と WmemMax は net.core.rmem_max と net.core.wmem_max の値である。読めなければ
	// RmemErr と WmemErr に理由が入る
	RmemMax, WmemMax int
	RmemErr, WmemErr error
}

// Probe は、CAP_NET_ADMIN を持たないプロセスが WireGuard のソケットで得る実効のバッファである。
// 呼び出し元の権限によらない。FORCE を使わず、SO_RCVBUF と SO_SNDBUF だけで Requested を要求して
// 読み返すためである(設計文書 7 節)。
type Probe struct {
	Recv, Send int
	Err        error
}
