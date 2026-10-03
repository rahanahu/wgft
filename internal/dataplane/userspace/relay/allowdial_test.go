package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/proto"
)

// 許可一覧があるときの接続の試し方(設計文書 7 節)の試験。期限の値には十分なゆとりを持たせ、
// 期限までに終わらなければ失敗にする。

// acceptingTCP は、接続を受け付けるだけの宛先を 127.0.0.1 に開き、そのポートを返す。
func acceptingTCP(t *testing.T) string {
	t.Helper()
	srv, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return strconv.Itoa(srv.Addr().(*net.TCPAddr).Port)
}

// silentDial は、silent のアドレスへの接続を黙って捨てられた接続のように止め、それ以外は本当に
// 接続する Options.Dial を返す。止めた接続は試験の終わりに誤りで返る。接続したアドレスを順に記録する。
type silentDial struct {
	silent  map[string]bool
	release chan struct{}
	mu      sync.Mutex
	dialed  []string
}

func newSilentDial(t *testing.T, silent ...string) *silentDial {
	d := &silentDial{silent: map[string]bool{}, release: make(chan struct{})}
	for _, s := range silent {
		d.silent[s] = true
	}
	t.Cleanup(func() { close(d.release) })
	return d
}

func (d *silentDial) dial(network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, addr)
	d.mu.Unlock()
	if d.silent[addr] {
		<-d.release
		return nil, errors.New("i/o timeout")
	}
	return (&net.Dialer{Timeout: time.Second}).Dial(network, addr)
}

func (d *silentDial) addrs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialed...)
}

// dialWithin は dialTarget を別の goroutine で呼び、limit までに戻らなければ試験を失敗にする。
func dialWithin(t *testing.T, m *Manager, network, target string, limit time.Duration) (net.Conn, time.Duration, error) {
	t.Helper()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	start := time.Now()
	go func() {
		c, err := m.dialTarget(network, target)
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		return r.c, time.Since(start), r.err
	case <-time.After(limit):
		t.Fatalf("dial %s did not return within %s", target, limit)
		return nil, 0, nil
	}
}

func lookupFixed(addrs ...string) func(context.Context, string) ([]netip.Addr, error) {
	return func(context.Context, string) ([]netip.Addr, error) {
		out := make([]netip.Addr, len(addrs))
		for i, a := range addrs {
			out[i] = netip.MustParseAddr(a)
		}
		return out, nil
	}
}

// 黙って捨てる IPv6 のアドレスが先に並ぶ名前でも、許可一覧があるときの TCP の接続は、少し待って
// IPv4 のアドレスを並行して試し、期限の 10 秒を待たずに繋がる。
func TestAllowListDialFallsBackToOtherFamily(t *testing.T) {
	port := acceptingTCP(t)
	v6, v4 := "[2001:db8::1]:"+port, "127.0.0.1:"+port
	d := newSilentDial(t, v6)
	m := New(&loopback{}, Options{
		Logf:              testLogf(t),
		AllowTarget:       allowList("[2001:db8::1]:"+port, v4),
		AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
		LookupTarget:      lookupFixed("2001:db8::1", "127.0.0.1"),
		Dial:              d.dial,
	})
	defer m.Close()
	c, took, err := dialWithin(t, m, "tcp", "dual.lan:"+port, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	if got := c.RemoteAddr().String(); got != v4 {
		t.Errorf("connected to %s, want %s", got, v4)
	}
	// IPv6 のアドレスを先に試し、待ってから IPv4 のアドレスへ進む
	if got := d.addrs(); len(got) != 2 || got[0] != v6 || got[1] != v4 {
		t.Errorf("dialed %v, want %s then %s", got, v6, v4)
	}
	if took < targetFallbackDelay*2/3 {
		t.Errorf("connected after %s, want the other family to start after about %s", took, targetFallbackDelay)
	}
}

// 先に試す族のアドレスがすべてすぐに失敗すれば、待たずにもう一方の族を試す。
func TestAllowListDialSkipsWaitWhenFirstFamilyFails(t *testing.T) {
	port := acceptingTCP(t)
	m := New(&loopback{}, Options{
		Logf:              testLogf(t),
		AllowTarget:       allowList("[2001:db8::1]:"+port, "127.0.0.1:"+port),
		AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
		LookupTarget:      lookupFixed("2001:db8::1", "127.0.0.1"),
		Dial: func(network, addr string) (net.Conn, error) {
			if addr == "127.0.0.1:"+port {
				return (&net.Dialer{Timeout: time.Second}).Dial(network, addr)
			}
			return nil, errors.New("network is unreachable")
		},
	})
	defer m.Close()
	c, took, err := dialWithin(t, m, "tcp", "dual.lan:"+port, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	if took >= targetFallbackDelay*2/3 {
		t.Errorf("connected after %s, want the other family to start at once", took)
	}
}

// 同じ名前のルールの適用のときの接続確認(2 秒)も、黙って捨てる先頭のアドレスで error にならない。
func TestAllowListProbeOKWithSilentFirstAddress(t *testing.T) {
	port := acceptingTCP(t)
	d := newSilentDial(t, "[2001:db8::1]:"+port)
	lb := &loopback{}
	m := New(lb, Options{
		Logf:              testLogf(t),
		AllowTarget:       allowList("[2001:db8::1]:"+port, "127.0.0.1:"+port),
		AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
		LookupTarget:      lookupFixed("2001:db8::1", "127.0.0.1"),
		Dial:              d.dial,
	})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.TCP, reserveTCP(t, lb)}: {"dual.lan:" + port, "r1"}})
	if st := m.Status(); len(st) != 1 || st[0].Err != nil {
		t.Fatalf("status = %+v, want the rule to be ok", st)
	}
}

// 同じ族のアドレスは順に試し、期限をまだ試していないアドレスの数で分ける。1 つの持ち分は 2 秒を
// 下回らない。
func TestAllowListDialSharesDeadline(t *testing.T) {
	for _, tc := range []struct {
		name  string
		addrs []string
		total time.Duration
		first time.Duration // 先頭のアドレスに与える期限
	}{
		{"split", []string{"127.0.0.2", "127.0.0.1"}, 6 * time.Second, 3 * time.Second},
		{"floor", []string{"127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.1"}, 6 * time.Second, minAddrDialTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var allowed []string
			for _, a := range tc.addrs {
				allowed = append(allowed, a+":80")
			}
			m := New(&loopback{}, Options{
				Logf:              testLogf(t),
				AllowTarget:       allowList(allowed...),
				AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
				LookupTarget:      lookupFixed(tc.addrs...),
			})
			defer m.Close()
			m.dialTimeout = tc.total
			var mu sync.Mutex
			left := map[string]time.Duration{}
			m.dialCtx = func(ctx context.Context, network, addr string) (net.Conn, error) {
				dl, ok := ctx.Deadline()
				if !ok {
					t.Errorf("dial %s without a deadline", addr)
				}
				mu.Lock()
				left[addr] = time.Until(dl)
				mu.Unlock()
				if addr == "127.0.0.1:80" {
					a, b := net.Pipe()
					b.Close()
					return a, nil
				}
				return nil, errors.New("i/o timeout")
			}
			c, _, err := dialWithin(t, m, "tcp", "v4.lan:80", 5*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			c.Close()
			mu.Lock()
			defer mu.Unlock()
			if len(left) != len(tc.addrs) {
				t.Fatalf("dialed %v, want every address in turn", left)
			}
			got := left[allowed[0]]
			if got > tc.first || got < tc.first-300*time.Millisecond {
				t.Errorf("first address deadline in %s, want about %s", got, tc.first)
			}
			// 最後のアドレスは残りをすべて受け取る
			if got := left["127.0.0.1:80"]; got < tc.total-tc.first-time.Second {
				t.Errorf("last address deadline in %s, want the rest of %s", got, tc.total)
			}
		})
	}
}

// 許可一覧の外のアドレスへは一度も接続しない。全アドレスが一覧の外なら、理由は今までと同じ文言である。
func TestAllowListDialSkipsDeniedAddresses(t *testing.T) {
	port := acceptingTCP(t)
	d := newSilentDial(t)
	m := New(&loopback{}, Options{
		Logf:              testLogf(t),
		AllowTarget:       allowList("127.0.0.1:" + port),
		AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
		LookupTarget: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "denied.lan" {
				return lookupFixed("2001:db8::9", "10.0.0.9")(context.Background(), host)
			}
			return lookupFixed("2001:db8::9", "10.0.0.9", "127.0.0.1", "10.0.0.8")(context.Background(), host)
		},
		Dial: d.dial,
	})
	defer m.Close()
	c, _, err := dialWithin(t, m, "tcp", "mixed.lan:"+port, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	if got := d.addrs(); len(got) != 1 || got[0] != "127.0.0.1:"+port {
		t.Errorf("dialed %v, want only the allowed address", got)
	}

	for _, network := range []string{"tcp", "udp"} {
		_, _, err = dialWithin(t, m, network, "denied.lan:"+port, 5*time.Second)
		if want := "target [2001:db8::9]:" + port + " is not in WGFT_AGENT_ALLOW_TARGETS"; err == nil || err.Error() != want {
			t.Errorf("%s: err = %v, want %q", network, err, want)
		}
		if !errors.Is(err, ErrTargetNotAllowed) {
			t.Errorf("%s: err %v does not wrap ErrTargetNotAllowed", network, err)
		}
	}
	if got := d.addrs(); len(got) != 1 {
		t.Errorf("dialed %v, want no dial when every address is denied", got)
	}
}

// 通したアドレスへの接続がすべて失敗すれば、解決の結果の順で最後に試したアドレスの誤りを返す。
// 一覧の拒否より接続の失敗を返すので、ルールは許可一覧の拒否として報告されない。
func TestAllowListDialReturnsLastAttemptError(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var dialed atomic.Int64
			m := New(&loopback{}, Options{
				Logf:              testLogf(t),
				AllowTarget:       allowList("[2001:db8::1]:80", "192.0.2.1:80", "192.0.2.2:80"),
				AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
				LookupTarget:      lookupFixed("10.0.0.9", "192.0.2.1", "2001:db8::1", "192.0.2.2", "10.0.0.8"),
				Dial: func(network, addr string) (net.Conn, error) {
					dialed.Add(1)
					return nil, errors.New("refused " + addr)
				},
			})
			defer m.Close()
			_, _, err := dialWithin(t, m, network, "mixed.lan:80", 5*time.Second)
			if err == nil || err.Error() != "refused 192.0.2.2:80" {
				t.Errorf("err = %v, want the error of the last address tried", err)
			}
			if errors.Is(err, ErrTargetNotAllowed) {
				t.Errorf("err %v is an allow list refusal, want the dial failure", err)
			}
			if n := dialed.Load(); n != 3 {
				t.Errorf("dialed %d addresses, want the 3 allowed ones", n)
			}
		})
	}
}

// 競争に負けた族の接続が後から繋がれば、その接続を閉じる。
func TestAllowListDialClosesLateConnection(t *testing.T) {
	late := make(chan *closeTrackConn, 1)
	m := New(&loopback{}, Options{
		Logf:              testLogf(t),
		AllowTarget:       allowList("[2001:db8::1]:80", "192.0.2.1:80"),
		AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
		LookupTarget:      lookupFixed("2001:db8::1", "192.0.2.1"),
		Dial: func(network, addr string) (net.Conn, error) {
			a, b := net.Pipe()
			b.Close()
			c := &closeTrackConn{Conn: a}
			if addr == "[2001:db8::1]:80" {
				time.Sleep(2 * targetFallbackDelay)
				late <- c
			}
			return c, nil
		},
	})
	defer m.Close()
	c, _, err := dialWithin(t, m, "tcp", "dual.lan:80", 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	var l *closeTrackConn
	select {
	case l = <-late:
	case <-time.After(5 * time.Second):
		t.Fatal("the first family's dial did not return")
	}
	if l == c {
		t.Fatal("the late connection won the race")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !l.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the late connection was not closed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type closeTrackConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// 先頭のアドレスの族が先に試される族である。IPv4 が先に並ぶ名前では、黙って捨てる IPv6 の
// アドレスがあっても、IPv4 を先に試し、もう一方の族を待たずに繋がる。
func TestAllowListDialTriesFirstAddressFamilyFirst(t *testing.T) {
	port := acceptingTCP(t)
	v4, v6 := "127.0.0.1:"+port, "[2001:db8::1]:"+port
	d := newSilentDial(t, v6)
	m := New(&loopback{}, Options{
		Logf:              testLogf(t),
		AllowTarget:       allowList(v4, v6),
		AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
		LookupTarget:      lookupFixed("127.0.0.1", "2001:db8::1"),
		Dial:              d.dial,
	})
	defer m.Close()
	c, took, err := dialWithin(t, m, "tcp", "dual.lan:"+port, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	if got := d.addrs(); len(got) == 0 || got[0] != v4 {
		t.Errorf("dialed %v, want %s first", got, v4)
	}
	if took >= targetFallbackDelay*2/3 {
		t.Errorf("connected after %s, want the first family to connect without waiting for the other", took)
	}
}

// 既定の Dial から作る dialCtx は、ctx の期限と取り消しに従う。アドレスごとの期限の分割と、負けた族の
// 打ち切りは、この性質に依る。
func TestDefaultDialContextFollowsContext(t *testing.T) {
	port := acceptingTCP(t)
	m := New(&loopback{}, Options{Logf: testLogf(t)})
	defer m.Close()
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	canceled, cancel2 := context.WithCancel(context.Background())
	cancel2()
	for name, ctx := range map[string]context.Context{"expired": expired, "canceled": canceled} {
		c, err := m.dialCtx(ctx, "tcp", "127.0.0.1:"+port)
		if err == nil {
			c.Close()
			t.Errorf("%s context: dial to a listening address succeeded, want the context to stop it", name)
		}
	}
	// 同じ宛先へ、生きた ctx なら繋がる(上の失敗が宛先のせいでないことの確認)
	c, err := m.dialCtx(context.Background(), "tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("dial with a live context: %v", err)
	}
	c.Close()
}

// 勝ちが決まったら、負けた族の試行の ctx を取り消す(期限まで走らせない)。
func TestAllowListDialCancelsLosingFamily(t *testing.T) {
	m := New(&loopback{}, Options{
		Logf:              testLogf(t),
		AllowTarget:       allowList("[2001:db8::1]:80", "192.0.2.1:80"),
		AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
		LookupTarget:      lookupFixed("2001:db8::1", "192.0.2.1"),
	})
	defer m.Close()
	loser := make(chan error, 1)
	m.dialCtx = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == "[2001:db8::1]:80" {
			<-ctx.Done()
			loser <- ctx.Err()
			return nil, ctx.Err()
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	c, _, err := dialWithin(t, m, "tcp", "dual.lan:80", 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	select {
	case err := <-loser:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("losing dial ended with %v, want it canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the losing family's dial was not canceled after the other family won")
	}
}
