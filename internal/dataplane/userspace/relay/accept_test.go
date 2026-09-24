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

// failingAcceptNet は loopback の TCP の待ち受けを、最初の fails 回の Accept が誤りを返すものに
// 包む。ホストのソケットでファイル記述子が尽きたときの accept4 の EMFILE を模す。
type failingAcceptNet struct {
	*loopback
	fails int
	ln    *failingListener
}

func (n *failingAcceptNet) ListenTCP(port uint16) (net.Listener, error) {
	ln, err := n.loopback.ListenTCP(port)
	if err != nil {
		return nil, err
	}
	n.ln = &failingListener{Listener: ln, fails: n.fails}
	return n.ln, nil
}

type failingListener struct {
	net.Listener
	mu    sync.Mutex
	fails int
	calls int
}

func (l *failingListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.calls++
	fail := l.fails > 0
	if fail {
		l.fails--
	}
	l.mu.Unlock()
	if fail {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Addr: l.Addr(), Err: os.NewSyscallError("accept4", syscall.EMFILE)}
	}
	return l.Listener.Accept()
}

// TCP の accept が待ち受けを閉じた以外の理由で失敗しても、待ち受けは開いたまま試し直して中継を
// 続け、失敗は 1 分に 1 回までログに出す。accept のループが抜けると、ソケットは bind されたまま
// 中継しない状態で残る。
func TestTCPAcceptFailureKeepsTheListener(t *testing.T) {
	srv, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()
	n := &failingAcceptNet{loopback: &loopback{}, fails: 3}
	port := reserveTCP(t, n.loopback)
	var logs strings.Builder
	var logMu sync.Mutex
	m := New(n, Options{Logf: func(f string, a ...any) {
		t.Logf(f, a...)
		logMu.Lock()
		logs.WriteString(f + "\n")
		logMu.Unlock()
	}})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.TCP, port}: {srv.Addr().String(), "r1"}})

	c, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo through the relay after failed accepts = %q, %v", buf, err)
	}

	logMu.Lock()
	got := logs.String()
	logMu.Unlock()
	if c := strings.Count(got, "accept failed"); c != 1 {
		t.Errorf("accept failure logged %d times, want once a minute:\n%s", c, got)
	}
}

// 待ち受けを閉じたことによる accept の失敗は、試し直さず、失敗としてログにも出さない。
func TestTCPListenerCloseIsNotAnAcceptFailure(t *testing.T) {
	lb := &loopback{}
	port := reserveTCP(t, lb)
	var logs strings.Builder
	var logMu sync.Mutex
	m := New(lb, Options{Logf: func(f string, a ...any) {
		logMu.Lock()
		logs.WriteString(f + "\n")
		logMu.Unlock()
	}})
	m.Apply(map[Key]Desired{{proto.TCP, port}: {"127.0.0.1:9", "r1"}})
	m.Close()
	time.Sleep(100 * time.Millisecond)
	logMu.Lock()
	got := logs.String()
	logMu.Unlock()
	if strings.Contains(got, "accept failed") {
		t.Errorf("closing the listener logged an accept failure:\n%s", got)
	}
}

// accept の失敗が続く間は、試し直しの間隔を倍々に広げる。間を置かずに試し直すと、失敗が続く間
// accept の呼び出しが CPU を使い続ける。
func TestTCPAcceptFailureBacksOff(t *testing.T) {
	n := &failingAcceptNet{loopback: &loopback{}, fails: 1 << 30}
	port := reserveTCP(t, n.loopback)
	m := New(n, Options{Logf: func(string, ...any) {}})
	m.Apply(map[Key]Desired{{proto.TCP, port}: {"127.0.0.1:9", "r1"}})
	time.Sleep(200 * time.Millisecond)
	m.Close()
	n.ln.mu.Lock()
	calls := n.ln.calls
	n.ln.mu.Unlock()
	// 5、10、20、40、80 ms と待つので、200 ms の間の呼び出しは 6 回ほどである
	if calls > 20 {
		t.Errorf("%d accept calls in 200ms of failures, want the retries to back off", calls)
	}
}
