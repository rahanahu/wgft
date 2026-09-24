package relay

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/proto"
)

// blackhole は、1 つの宛先へのすべての dial を、テストが放すまで返さない Dial を作る。
// 黙ってパケットを捨てる LAN の target の代わりである。実際の dial は Options.Dial の期限
// (既定で 10 秒)まで返らないので、到達確認がその待ちを錠の中で行うかどうかがここで分かる。
type blackhole struct {
	addr    string
	entered chan struct{} // 止まる dial に入ったことの通知
	release chan struct{} // 閉じると、止まっていた dial が返る
	once    sync.Once
}

func newBlackhole(t *testing.T, addr string) *blackhole {
	b := &blackhole{addr: addr, entered: make(chan struct{}, 64), release: make(chan struct{})}
	t.Cleanup(b.free)
	return b
}

func (b *blackhole) free() { b.once.Do(func() { close(b.release) }) }

func (b *blackhole) dial(network, addr string) (net.Conn, error) {
	if addr != b.addr {
		return net.Dial(network, addr)
	}
	b.entered <- struct{}{}
	<-b.release
	return nil, errors.New("blackhole")
}

// waitEntered は、止まる dial に確認が入るまで待つ。
func waitEntered(t *testing.T, b *blackhole) {
	t.Helper()
	select {
	case <-b.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the probe never reached the blocked dial")
	}
}

// waitDone は Retry が戻るまで待つ。戻らなければ、確認が錠を持ったままである。
func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Retry did not return")
	}
}

// roundTrip は中継を通して 1 往復する。accept されただけでは足りない。錠を持ったまま確認していた版
// では accept そのものは成功し、処理の goroutine が ruleOf と targetOf で止まっていた。
func roundTrip(t *testing.T, port uint16) {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	c, err := net.DialTimeout("tcp4", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial the relay: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write through the relay: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read back through the relay: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("read %q through the relay, want %q", buf, "ping")
	}
}

// 黙って捨てる target への到達確認が走っている間も、健全なルールを通る接続は最後まで中継される
// (設計文書 5.2 節)。確認が Manager の錠を持っていた版では、accept した接続が ruleOf と targetOf で
// 止まり、黙って捨てる target 1 つにつき dial の期限だけ中継が進まなかった。
func TestProbeDoesNotStallRelayingDuringASweep(t *testing.T) {
	bh := newBlackhole(t, "127.0.0.1:9")
	echo := tcpEcho(t)
	lb := &loopback{}
	healthy := reserveTCP(t, lb)
	dead := reserveTCP(t, lb)
	m := New(lb, Options{Logf: t.Logf, Dial: bh.dial})
	m.probeTimeout = time.Second
	defer m.Close()

	m.Apply(map[Key]Desired{
		{proto.TCP, healthy}: {echo, "r_ok"},
		{proto.TCP, dead}:    {bh.addr, "r_dead"},
	})
	waitEntered(t, bh) // 適用のときの確認も同じ target を試す

	done := make(chan struct{})
	go func() { m.Retry(); close(done) }()
	waitEntered(t, bh) // 30 秒ごとの確認が、止まる dial の中に入った

	start := time.Now()
	roundTrip(t, healthy)
	if d := time.Since(start); d > m.probeTimeout/2 {
		t.Errorf("a round trip through a healthy rule took %v while a sweep was running", d)
	}
	waitDone(t, done)
}

// 適用も同じ作りである。黙って捨てる target を持つルールを適用している間も、既に開いている健全な
// ルールは中継を続ける。
func TestApplyDoesNotStallRelayingWhileItProbes(t *testing.T) {
	bh := newBlackhole(t, "127.0.0.1:9")
	echo := tcpEcho(t)
	lb := &loopback{}
	healthy := reserveTCP(t, lb)
	dead := reserveTCP(t, lb)
	m := New(lb, Options{Logf: t.Logf, Dial: bh.dial})
	m.probeTimeout = time.Second
	defer m.Close()

	first := map[Key]Desired{{proto.TCP, healthy}: {echo, "r_ok"}}
	m.Apply(first)
	roundTrip(t, healthy)

	applied := make(chan struct{})
	go func() {
		second := map[Key]Desired{{proto.TCP, healthy}: {echo, "r_ok"}, {proto.TCP, dead}: {bh.addr, "r_dead"}}
		m.Apply(second)
		close(applied)
	}()
	waitEntered(t, bh)
	start := time.Now()
	roundTrip(t, healthy)
	if d := time.Since(start); d > m.probeTimeout/2 {
		t.Errorf("a round trip through a healthy rule took %v while an apply was probing", d)
	}
	waitDone(t, applied)
	// 適用は確認の結果を待ってから戻るので、最初のハートビートにルールの状態が載る
	for _, s := range m.Status() {
		if s.RuleID == "r_dead" && s.Err == nil {
			t.Error("the rule with an unreachable target must be error as soon as Apply returns")
		}
	}
}

// 錠を放している競合可能期間に閉じた待ち受けは、確認の結果で戻らない(設計文書 5.2 節)。
func TestProbeResultIsDiscardedWhenTheListenerIsClosed(t *testing.T) {
	bh := newBlackhole(t, "127.0.0.1:9")
	lb := &loopback{}
	port := reserveTCP(t, lb)
	m := New(lb, Options{Logf: t.Logf, Dial: bh.dial})
	m.probeTimeout = time.Second
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.TCP, port}: {bh.addr, "r1"}})
	waitEntered(t, bh)

	done := make(chan struct{})
	go func() { m.Retry(); close(done) }()
	waitEntered(t, bh)
	m.Apply(nil) // 宣言が空になり、待ち受けは閉じる
	waitDone(t, done)
	if st := m.Status(); len(st) != 0 {
		t.Errorf("status = %+v, want no listener: a listener closed during the probe must not come back", st)
	}
}

// 錠を放している競合可能期間に宛先が変わった待ち受けは、前の宛先の結果を受け取らない
// (設計文書 5.2 節)。Prepare/Commit の経路の宛先の差し替えは待ち受けを開き直さないので、
// 待ち受けそのものの同一性だけでは見分けられない。
func TestProbeResultIsDiscardedWhenTheTargetChanged(t *testing.T) {
	const oldTarget = "127.0.0.1:9"
	newTarget := tcpEcho(t)
	var calls atomic.Int32
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	t.Cleanup(free)
	dial := func(network, addr string) (net.Conn, error) {
		if addr != oldTarget {
			return net.Dial(network, addr)
		}
		if calls.Add(1) == 1 {
			return nil, errors.New("connection refused")
		}
		// 2 回目は止まってから成功する。宛先が変わった待ち受けは、この成功を受け取ってはならない
		entered <- struct{}{}
		<-release
		c, _ := net.Pipe()
		return c, nil
	}
	lb := &loopback{}
	port := reserveTCP(t, lb)
	m := New(lb, Options{Logf: t.Logf, Dial: dial})
	m.probeTimeout = 5 * time.Second
	defer m.Close()

	m.Prepare(map[Key]Desired{{proto.TCP, port}: {oldTarget, "r1"}}).Commit(nil)
	if st := m.Status(); len(st) != 1 || st[0].Err == nil {
		t.Fatalf("status = %+v, want error: the first probe is refused", st)
	}

	done := make(chan struct{})
	go func() { m.Retry(); close(done) }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the second probe never reached the blocked dial")
	}
	// 待ち受けは同じまま、宛先だけが変わる
	m.Prepare(map[Key]Desired{{proto.TCP, port}: {newTarget, "r1"}}).Commit(nil)
	free()
	waitDone(t, done)

	st := m.Status()
	if len(st) != 1 || st[0].Target != newTarget {
		t.Fatalf("status = %+v, want the listener retargeted to %s", st, newTarget)
	}
	if st[0].Err == nil {
		t.Error("the listener took the old target's result: its state must stay until the new target is probed")
	}
	// 次の確認は新しい宛先を試すので、状態はそこで追いつく
	m.Retry()
	if st := m.Status(); st[0].Err != nil {
		t.Errorf("after the next sweep: %v, want ok for the reachable new target", st[0].Err)
	}
}

// 到達性が変わったときだけログを 1 行出す。周期ごとには出さない(設計文書 5.2 節)。
func TestTargetReachabilityIsLoggedOnChangeOnly(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	count := func(sub string) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, l := range lines {
			if strings.Contains(l, sub) {
				n++
			}
		}
		return n
	}
	targetPort := freePort(t) // まだ誰も listen していないので接続は拒まれる
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(targetPort)))
	lb := &loopback{}
	port := reserveTCP(t, lb)
	m := New(lb, Options{Logf: func(f string, a ...any) {
		mu.Lock()
		lines = append(lines, fmt.Sprintf(f, a...))
		mu.Unlock()
	}})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.TCP, port}: {target, "r1"}})
	for i := 0; i < 3; i++ {
		m.Retry()
	}
	if n := count("cannot connect to target"); n != 1 {
		t.Errorf("unreachable logged %d times over an apply and 3 sweeps, want 1; log: %v", n, lines)
	}

	srv, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(targetPort)})
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
			c.Close()
		}
	}()
	for i := 0; i < 3; i++ {
		m.Retry()
	}
	if n := count("is reachable again"); n != 1 {
		t.Errorf("recovery logged %d times over 3 sweeps, want 1; log: %v", n, lines)
	}
	if n := count("cannot connect to target"); n != 1 {
		t.Errorf("unreachable logged %d times in total, want 1; log: %v", n, lines)
	}
}

// 名前を引けない宛先の確認の誤りは、問い合わせごとに送信元のポートが変わっても同じ文面になる。文面は
// ハートビートのルールの理由になり、エージェントは理由の変化でログを出すので、変わると 30 秒ごとに全ルールの
// 行が出る。
func TestProbeErrorOfAFailedLookupKeepsItsText(t *testing.T) {
	var n atomic.Int32
	lb := &loopback{}
	port := reserveTCP(t, lb)
	m := New(lb, Options{Logf: func(string, ...any) {}, Dial: func(network, addr string) (net.Conn, error) {
		src := 40000 + n.Add(1)
		return nil, &net.OpError{Op: "dial", Net: network, Err: &net.DNSError{Name: "game.lan", Server: "192.168.1.1:53",
			Err: fmt.Sprintf("read udp 192.168.1.10:%d->192.168.1.1:53: read: connection refused", src)}}
	}})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.TCP, port}: {"game.lan:80", "r1"}})
	errText := func() string {
		for _, s := range m.Status() {
			if s.Key.Port == port && s.Err != nil {
				return s.Err.Error()
			}
		}
		return ""
	}
	first := errText()
	m.Retry()
	second := errText()
	if n.Load() < 2 {
		t.Fatalf("the target was dialled %d times, want a probe on apply and one on Retry", n.Load())
	}
	if first == "" || first != second {
		t.Errorf("the probe error changed between sweeps: %q, then %q", first, second)
	}
	if strings.Contains(second, "->") {
		t.Errorf("the probe error keeps the socket pair: %q", second)
	}
}
