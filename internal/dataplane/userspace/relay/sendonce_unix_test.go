//go:build unix

package relay

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rahanahu/wgft/proto"
)

// sendtoScript は sendto の syscall を差し替え、呼び出しごとに決めた誤りを返してから本物を呼ぶ。
// 誤りが nil の回は本物だけを呼ぶ。台本が尽きたら本物を呼ぶ。
type sendtoScript struct {
	mu    sync.Mutex
	errs  []error
	calls int
}

func (s *sendtoScript) sendto(fd int, p []byte, flags int, to syscall.Sockaddr) error {
	s.mu.Lock()
	var err error
	if s.calls < len(s.errs) {
		err = s.errs[s.calls]
	}
	s.calls++
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return syscall.Sendto(fd, p, flags, to)
}

func installSendto(t *testing.T, errs ...error) *sendtoScript {
	t.Helper()
	s := &sendtoScript{errs: errs}
	prev := sendto
	sendto = s.sendto
	t.Cleanup(func() { sendto = prev })
	return s
}

// 公開側のカーネルのソケットの送信バッファが満杯(EAGAIN)なら、その応答を捨てて数え、1 分に
// 1 回までログに出し、セッションは続ける。EINTR はやり直す。それ以外の誤りはセッションを閉じる。
func TestUDPReplyDroppedWhenThePublicSendBufferIsFull(t *testing.T) {
	echoAddr, _ := udpEcho(t)
	lb := &loopback{}
	port := reserveUDP(t, lb)
	var (
		mu    sync.Mutex
		lines []string
	)
	logf := func(format string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, a...))
	}
	m := New(lb, Options{Logf: logf})
	defer m.Close()
	m.replies = newReplyPool(1)
	m.Apply(map[Key]Desired{{proto.UDP, port}: {echoAddr, "r1"}})
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	roundtrip := func(msg string) (string, error) {
		c.Write([]byte(msg))
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		b := make([]byte, 16)
		n, err := c.Read(b)
		return string(b[:n]), err
	}
	// 1 回目の応答は満杯で捨てる。2 回目は EINTR の後に届く。3 回目と 4 回目は満杯で捨てる
	script := installSendto(t, syscall.EAGAIN, syscall.EINTR, nil, syscall.EAGAIN, syscall.EAGAIN)
	if got, err := roundtrip("a"); err == nil {
		t.Fatalf("the reply to a should have been dropped, got %q", got)
	}
	if got, err := roundtrip("b"); err != nil || got != "b" {
		t.Fatalf("the reply to b after EINTR: %q %v", got, err)
	}
	for _, msg := range []string{"c", "d"} {
		if got, err := roundtrip(msg); err == nil {
			t.Fatalf("the reply to %s should have been dropped, got %q", msg, got)
		}
	}
	if got := m.replyDrops.drops.Load(); got != 3 {
		t.Errorf("drops = %d, want 3", got)
	}
	if n := m.Status()[0].Sessions; n != 1 {
		t.Errorf("sessions = %d, want the same session to survive the drops", n)
	}
	if got := m.replies.free(); got != 1 {
		t.Errorf("free slots after the drops = %d, want 1; a dropped reply must return its slot", got)
	}
	mu.Lock()
	var logged int
	for _, l := range lines {
		if strings.Contains(l, "send buffer of the public socket is full") {
			logged++
			if !strings.Contains(l, "dropped a reply of 1 bytes") || !strings.Contains(l, "1 replies dropped this way") {
				t.Errorf("first drop log line = %q", l)
			}
			// l.key already formats as "udp/<port>"; the line must not repeat "udp" in front of it.
			if strings.Contains(l, "udp udp/") {
				t.Errorf("log line doubles the protocol prefix: %q", l)
			}
		}
	}
	mu.Unlock()
	if logged != 1 {
		t.Errorf("drop logged %d times for 3 drops, want 1", logged)
	}
	// それ以外の誤りは従来どおりセッションを閉じる
	script.mu.Lock()
	script.errs = append(script.errs, syscall.EPERM)
	script.mu.Unlock()
	if got, err := roundtrip("e"); err == nil {
		t.Fatalf("the reply to e should have failed, got %q", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for m.Status()[0].Sessions != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := m.Status()[0].Sessions; n != 0 {
		t.Errorf("sessions after a send error = %d, want 0", n)
	}
	if got := m.replyDrops.drops.Load(); got != 3 {
		t.Errorf("drops after a send error = %d, want still 3", got)
	}
	// 閉じた後も同じ送信元からは新しいセッションになり、届く
	if got, err := roundtrip("f"); err != nil || got != "f" {
		t.Errorf("new session after the error: %q %v", got, err)
	}
}

// 公開側がカーネルの UDP ソケットで送信元が IPv4 なら 1 回だけ送る形を、そうでなければ WriteTo を選ぶ。
func TestNewReplySenderPicksTheOnceSenderForKernelSockets(t *testing.T) {
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	to := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	if _, ok := newReplySender(uc, to).(onceSender); !ok {
		t.Error("a kernel UDP socket with an IPv4 peer must get the once sender")
	}
	if _, ok := newReplySender(uc, &net.UDPAddr{IP: net.IPv6loopback, Port: 9}).(waitingSender); !ok {
		t.Error("an IPv6 peer must fall back to WriteTo")
	}
	if _, ok := newReplySender(&gatedPacketConn{PacketConn: uc}, to).(waitingSender); !ok {
		t.Error("a PacketConn that is not a kernel socket must get WriteTo")
	}
}
