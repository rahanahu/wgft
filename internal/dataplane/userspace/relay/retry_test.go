package relay

import (
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rahanahu/wgft/proto"
)

// callScript は Accept か ReadFrom の呼び出しを数え、決めた回の呼び出しを誤りにする。呼び出しの
// 時刻も控える。
type callScript struct {
	mu    sync.Mutex
	fail  func(call int) bool // call は 1 から数える
	times []time.Time
}

func (s *callScript) next() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.times = append(s.times, time.Now())
	return s.fail(len(s.times))
}

func (s *callScript) calls() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.times...)
}

// waitCalls は、呼び出しが n 回を超えるまで待ち、その時刻を返す。
func (s *callScript) waitCalls(t *testing.T, n int) []time.Time {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if c := s.calls(); len(c) >= n {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d calls, want %d", len(s.calls()), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// failFirst は最初の n 回を誤りにする。
func failFirst(n int) func(int) bool { return func(call int) bool { return call <= n } }

// scriptedNet は loopback の待ち受けとソケットを、script が決めた回に誤りを返すものに包む。TCP は
// ファイル記述子が尽きたときの accept4 の EMFILE を、UDP は管理者がソケットを破棄したとき
// (ss -K)の recvfrom の ECONNABORTED を模す。
type scriptedNet struct {
	*loopback
	script *callScript
}

func (n *scriptedNet) ListenTCP(port uint16) (net.Listener, error) {
	ln, err := n.loopback.ListenTCP(port)
	if err != nil {
		return nil, err
	}
	return &scriptedListener{Listener: ln, script: n.script}, nil
}

func (n *scriptedNet) ListenUDP(port uint16) (net.PacketConn, error) {
	pc, err := n.loopback.ListenUDP(port)
	if err != nil {
		return nil, err
	}
	return &scriptedPacketConn{PacketConn: pc, script: n.script}, nil
}

type scriptedListener struct {
	net.Listener
	script *callScript
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	if l.script.next() {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Addr: l.Addr(), Err: os.NewSyscallError("accept4", syscall.EMFILE)}
	}
	return l.Listener.Accept()
}

type scriptedPacketConn struct {
	net.PacketConn
	script *callScript
}

func (c *scriptedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if c.script.next() {
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Addr: c.LocalAddr(), Err: os.NewSyscallError("recvfrom", syscall.ECONNABORTED)}
	}
	return c.PacketConn.ReadFrom(b)
}

// logBuffer は Manager のログの書式を控える。
type logBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuffer) logf(f string, _ ...any) {
	l.mu.Lock()
	l.b.WriteString(f + "\n")
	l.mu.Unlock()
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// echoTCP は中継の port を通して 1 往復する。
func echoTCP(t *testing.T, port uint16, msg string) {
	t.Helper()
	c, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo through the relay = %q, %v", buf, err)
	}
}

// echoUDP は中継の port を通して 1 往復する。
func echoUDP(t *testing.T, port uint16, msg string) {
	t.Helper()
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != msg {
		t.Fatalf("echo through the relay = %q, %v", buf[:n], err)
	}
}

// TCP の accept と UDP の読み取りが、待ち受けを閉じた以外の理由で失敗しても、待ち受けは開いたまま
// 試し直して中継を続け、失敗は 1 分に 1 回までログに出す。ループが抜けると、ソケットは bind された
// まま中継しない状態で残る。
func TestServeRetriesAfterAFailure(t *testing.T) {
	for _, p := range []proto.Proto{proto.TCP, proto.UDP} {
		t.Run(string(p), func(t *testing.T) {
			n := &scriptedNet{loopback: &loopback{}, script: &callScript{fail: failFirst(3)}}
			var port uint16
			var target string
			if p == proto.TCP {
				port, target = reserveTCP(t, n.loopback), tcpEcho(t)
			} else {
				port = reserveUDP(t, n.loopback)
				target, _ = udpEcho(t)
			}
			logs := &logBuffer{}
			m := New(n, Options{Logf: logs.logf})
			defer m.Close()
			m.Apply(map[Key]Desired{{p, port}: {target, "r1"}})
			n.script.waitCalls(t, 4)
			if p == proto.TCP {
				echoTCP(t, port, "ping")
			} else {
				echoUDP(t, port, "ping")
			}
			failed := "accept failed"
			if p == proto.UDP {
				failed = "read failed"
			}
			if c := strings.Count(logs.String(), failed); c != 1 {
				t.Errorf("%s logged %d times, want once a minute:\n%s", failed, c, logs)
			}
		})
	}
}

// 失敗が続く間は試し直しの間隔を倍々に広げ、成功したら最初の間隔に戻す。間を置かずに試し直すと、
// 失敗が続く間 CPU を使い続ける。成功の後も広げたままにすると、次の 1 回の失敗から戻るまでに、
// 前に続いた失敗の分だけ待たされる。
func TestServeRetryBacksOffAndResets(t *testing.T) {
	for _, p := range []proto.Proto{proto.TCP, proto.UDP} {
		t.Run(string(p), func(t *testing.T) {
			// 1 から 6 回目と 8 回目の呼び出しが失敗する。6 回の失敗の後の待ちは 5 ms から倍々に
			// 160 ms まで広がる。7 回目の成功で戻らなければ、8 回目の失敗の後に 320 ms 待つ
			script := &callScript{fail: func(call int) bool { return call <= 6 || call == 8 }}
			n := &scriptedNet{loopback: &loopback{}, script: script}
			var port uint16
			var target string
			if p == proto.TCP {
				port, target = reserveTCP(t, n.loopback), tcpEcho(t)
			} else {
				port = reserveUDP(t, n.loopback)
				target, _ = udpEcho(t)
			}
			m := New(n, Options{Logf: func(string, ...any) {}})
			defer m.Close()
			m.Apply(map[Key]Desired{{p, port}: {target, "r1"}})
			calls := script.waitCalls(t, 7)
			if gap := calls[6].Sub(calls[0]); gap < 250*time.Millisecond {
				t.Errorf("6 failures took %v; want the retries to back off from 5ms, about 315ms in all", gap)
			}
			// 7 回目の呼び出しを成功させる
			if p == proto.TCP {
				echoTCP(t, port, "ping")
			} else {
				echoUDP(t, port, "ping")
			}
			calls = script.waitCalls(t, 9)
			if gap := calls[8].Sub(calls[7]); gap > 150*time.Millisecond {
				t.Errorf("the retry after a success waited %v; want the backoff reset to 5ms", gap)
			}
		})
	}
}

// 失敗が止まらないときの試し直しの回数は、後退の上限に従う。
func TestServeRetryDoesNotSpin(t *testing.T) {
	for _, p := range []proto.Proto{proto.TCP, proto.UDP} {
		t.Run(string(p), func(t *testing.T) {
			script := &callScript{fail: func(int) bool { return true }}
			n := &scriptedNet{loopback: &loopback{}, script: script}
			var port uint16
			if p == proto.TCP {
				port = reserveTCP(t, n.loopback)
			} else {
				port = reserveUDP(t, n.loopback)
			}
			m := New(n, Options{Logf: func(string, ...any) {}})
			m.Apply(map[Key]Desired{{p, port}: {"127.0.0.1:9", "r1"}})
			time.Sleep(200 * time.Millisecond)
			m.Close()
			// 5、10、20、40、80 ms と待つので、200 ms の間の呼び出しは 6 回ほどである
			if c := len(script.calls()); c > 20 {
				t.Errorf("%d calls in 200ms of failures, want the retries to back off", c)
			}
		})
	}
}

// 待ち受けを閉じたことによる失敗は、試し直さず、失敗としてログにも出さない。
func TestServeCloseIsNotAFailure(t *testing.T) {
	for _, p := range []proto.Proto{proto.TCP, proto.UDP} {
		t.Run(string(p), func(t *testing.T) {
			lb := &loopback{}
			var port uint16
			if p == proto.TCP {
				port = reserveTCP(t, lb)
			} else {
				port = reserveUDP(t, lb)
			}
			logs := &logBuffer{}
			m := New(lb, Options{Logf: logs.logf})
			m.Apply(map[Key]Desired{{p, port}: {"127.0.0.1:9", "r1"}})
			m.Close()
			time.Sleep(100 * time.Millisecond)
			if got := logs.String(); strings.Contains(got, "failed") {
				t.Errorf("closing the listener logged a failure:\n%s", got)
			}
		})
	}
}
