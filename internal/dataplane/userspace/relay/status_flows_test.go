package relay

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// dialAndEcho は中継の公開側へ 1 本つなぎ、往復を済ませて返す。往復が済んだ時点で、公開側と
// 宛先側の両方が中継の表に入っている。
func dialAndEcho(t *testing.T, port uint16) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	if err != nil {
		t.Fatalf("dial %d: %v", port, err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("write to %d: %v", port, err)
	}
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatalf("read from %d: %v", port, err)
	}
	return c
}

// Status.Flows はフロー予算の上限の対象と同じ量である。TCP では公開側の接続 1 本につき 1 で、
// 公開側と宛先側の両方を数える Sessions とは一致しない(設計文書 10.2c 節の relay.sessions)。
// 本数の違う 2 本のルールを同じ Manager に立てるのは、待ち受けごとの数を、ルールごとの数や
// プロセス全体の数と取り違えても気づけるようにするためである。
func TestStatusFlowsMatchTheQuantityTheCapApplies(t *testing.T) {
	target := tcpEcho(t)
	lb := &loopback{}
	first := reserveTCP(t, lb)
	second := reserveTCP(t, lb)
	pool := resource.NewPool(32)
	m := New(lb, Options{TCPPool: pool, Logf: t.Logf})
	defer m.Close()
	m.Apply(map[Key]Desired{
		{proto.TCP, first}:  {target, "r1"},
		{proto.TCP, second}: {target, "r2"},
	})

	const onFirst, onSecond = 3, 2
	for i := 0; i < onFirst; i++ {
		dialAndEcho(t, first)
	}
	for i := 0; i < onSecond; i++ {
		dialAndEcho(t, second)
	}

	st1 := statusOf(t, m, Key{proto.TCP, first})
	st2 := statusOf(t, m, Key{proto.TCP, second})
	// 待ち受け 1 つが持つ数であり、両方の待ち受けを合わせた数ではない
	if st1.Flows != onFirst || st2.Flows != onSecond {
		t.Errorf("Flows = %d and %d, want %d and %d: each listener holds its own flows",
			st1.Flows, st2.Flows, onFirst, onSecond)
	}
	// 上限の判定を行う帳簿そのものと一致する
	if got := pool.RuleFlows("r1"); got != st1.Flows {
		t.Errorf("Flows = %d but the pool counts %d flows for rule r1", st1.Flows, got)
	}
	if got := pool.RuleFlows("r2"); got != st2.Flows {
		t.Errorf("Flows = %d but the pool counts %d flows for rule r2", st2.Flows, got)
	}
	if got, want := pool.InUse(), onFirst+onSecond; got != want {
		t.Errorf("the pool holds %d flows in total, want %d", got, want)
	}
	// Sessions は宛先側も数えるので上限の対象の 2 倍になる。この 2 つを取り違えないための番人
	if st1.Sessions != 2*onFirst || st2.Sessions != 2*onSecond {
		t.Errorf("Sessions = %d and %d, want %d and %d: they count both the public and the target side",
			st1.Sessions, st2.Sessions, 2*onFirst, 2*onSecond)
	}
}

// UDP はセッション 1 つが上限の対象の 1 つなので、Flows と Sessions が同じ量になる。TCP との
// 違いは、宛先側の接続を中継の表に別に持つかどうかだけである。
func TestStatusFlowsCountUDPSessions(t *testing.T) {
	echoAddr, _ := udpEcho(t)
	lb := &loopback{}
	port := reserveUDP(t, lb)
	pool := resource.NewPool(8)
	m := New(lb, Options{UDPIdleTimeout: 10 * time.Second, UDPPool: pool, Logf: t.Logf})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.UDP, port}: {echoAddr, "r1"}})

	const sessions = 3
	for i := 0; i < sessions; i++ {
		c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		msg := fmt.Sprint("m", i)
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		b := make([]byte, 100)
		if n, err := c.Read(b); err != nil || string(b[:n]) != msg {
			t.Fatalf("session %d: %q %v", i, string(b[:n]), err)
		}
	}

	st := statusOf(t, m, Key{proto.UDP, port})
	if st.Flows != sessions {
		t.Errorf("Flows = %d, want %d: one session takes one place in the budget", st.Flows, sessions)
	}
	if st.Sessions != sessions {
		t.Errorf("Sessions = %d, want %d", st.Sessions, sessions)
	}
	if got := pool.RuleFlows("r1"); got != sessions {
		t.Errorf("the pool counts %d flows for rule r1, want %d", got, sessions)
	}
}
