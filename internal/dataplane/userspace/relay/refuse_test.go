package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// refuseAddrs はテスト用の Options.RefuseTarget。実際の判定は internal/agent/allowtargets の Unicast が
// 持つ。列挙したアドレスを、そのアドレスを名指す理由で拒む。
func refuseAddrs(addrs ...string) func(netip.Addr) string {
	return func(a netip.Addr) string {
		for _, s := range addrs {
			if a == netip.MustParseAddr(s) {
				return "target " + s + " is refused for the test"
			}
		}
		return ""
	}
}

// RefuseTarget が拒む IP リテラルの宛先は、許可一覧が無くても待ち受けを開かず、RefuseTarget の文言を
// そのまま理由とする error として見える(設計文書 7 節)。許可一覧による拒否と同じく ErrTargetNotAllowed を包む。
func TestApplyRefusesLiteralTarget(t *testing.T) {
	var netw neverListen
	pool := resource.NewPool(10)
	m := New(&netw, Options{
		Logf:         testLogf(t),
		UDPPool:      pool,
		RefuseTarget: refuseAddrs("239.1.2.3"),
		Dial:         func(network, addr string) (net.Conn, error) { t.Errorf("dialed %s", addr); return nil, nil },
	})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.UDP, 39973}: {"239.1.2.3:5000", "r1"}})
	if got := pool.Rules(); got != 0 {
		t.Errorf("accepting rules for a refused target = %d, want 0", got)
	}
	st := m.Status()
	if len(st) != 1 || st[0].Err == nil {
		t.Fatalf("status = %+v, want an error", st)
	}
	if want := "target 239.1.2.3 is refused for the test"; st[0].Err.Error() != want {
		t.Errorf("reason = %q, want %q", st[0].Err, want)
	}
	if !errors.Is(st[0].Err, ErrTargetNotAllowed) {
		t.Errorf("reason %v does not wrap ErrTargetNotAllowed", st[0].Err)
	}
	m.Retry()
	if n := netw.opened.Load(); n != 0 {
		t.Errorf("tried to open a listener %d times, want 0 for a refused target", n)
	}
	// IPv4 を写した IPv6 の書き方でも同じく拒む
	m.Apply(map[Key]Desired{{proto.UDP, 39973}: {"[::ffff:239.1.2.3]:5000", "r1"}})
	if st := m.Status(); len(st) != 1 || st[0].Err == nil || st[0].Err.Error() != "target 239.1.2.3 is refused for the test" {
		t.Errorf("mapped form: status = %+v", st)
	}
}

// 許可一覧に入っている宛先も、RefuseTarget が拒めば拒む。理由は RefuseTarget の文言である。
// 許可一覧に加えても通らない宛先なので、許可一覧の外という理由を示さない。
func TestRefuseTargetComesBeforeAllowList(t *testing.T) {
	var netw neverListen
	for _, allow := range []func(netip.AddrPort) bool{allowList("192.168.50.255:9"), allowList()} {
		m := New(&netw, Options{
			Logf:              testLogf(t),
			AllowTarget:       allow,
			AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
			RefuseTarget:      refuseAddrs("192.168.50.255"),
		})
		m.Apply(map[Key]Desired{{proto.UDP, 39974}: {"192.168.50.255:9", "r1"}})
		st := m.Status()
		if len(st) != 1 || st[0].Err == nil || st[0].Err.Error() != "target 192.168.50.255 is refused for the test" {
			t.Errorf("status = %+v, want the RefuseTarget reason", st)
		}
		m.Close()
	}
}

// RefuseTarget があれば、許可一覧が無くてもホスト名の宛先を自分で解決し、解決したアドレスで判定する。
// 拒むアドレスへは接続せず、残りのアドレスへ接続する(設計文書 7 節)。
func TestRefuseTargetResolvesHostNameWithoutAllowList(t *testing.T) {
	echoAddr, packets := udpEcho(t)
	_, portStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	var lookups atomic.Int64
	var dialed atomic.Value
	lb := &loopback{}
	m := New(lb, Options{
		Logf:         testLogf(t),
		RefuseTarget: refuseAddrs("127.0.0.9"),
		LookupTarget: func(ctx context.Context, host string) ([]netip.Addr, error) {
			lookups.Add(1)
			// 拒むアドレスを先に返す。それを飛ばして次へ接続すること
			return []netip.Addr{netip.MustParseAddr("127.0.0.9"), netip.MustParseAddr("127.0.0.1")}, nil
		},
		Dial: func(network, addr string) (net.Conn, error) {
			dialed.Store(addr)
			return net.Dial(network, addr)
		},
	})
	defer m.Close()
	listenPort := reserveUDP(t, lb)
	m.Apply(map[Key]Desired{{proto.UDP, listenPort}: {"mixed.lan:" + portStr, "r1"}})
	c, err := net.Dial("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(listenPort))))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && packets.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if packets.Load() == 0 {
		t.Fatal("the datagram did not reach the unicast address")
	}
	if lookups.Load() == 0 {
		t.Error("the relay must resolve the host name itself when RefuseTarget is set")
	}
	if got := dialed.Load(); got != "127.0.0.1:"+portStr {
		t.Errorf("dialed %v, want only the address RefuseTarget lets through", got)
	}
	if st := m.Status(); st[0].Err != nil {
		t.Errorf("status err = %v, want none while one address is usable", st[0].Err)
	}
}

// ホスト名が拒むアドレスだけに解決されたら、UDP のデータグラムを捨て、RefuseTarget の文言を状態に載せる。
// 名前が使えるアドレスに戻れば、状態の拒否は消える。
func TestUDPHostNameResolvingOnlyToRefusedAddress(t *testing.T) {
	echoAddr, packets := udpEcho(t)
	_, portStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	var resolved atomic.Value
	resolved.Store("192.168.50.255")
	lb := &loopback{}
	m := New(lb, Options{
		Logf:         testLogf(t),
		RefuseTarget: refuseAddrs("192.168.50.255"),
		LookupTarget: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(resolved.Load().(string))}, nil
		},
		Dial: func(network, addr string) (net.Conn, error) {
			if addr != "127.0.0.1:"+portStr {
				t.Errorf("dialed %s", addr)
			}
			return net.Dial(network, addr)
		},
	})
	defer m.Close()
	listenPort := reserveUDP(t, lb)
	m.Apply(map[Key]Desired{{proto.UDP, listenPort}: {"bc.lan:" + portStr, "r1"}})
	if st := m.Status(); st[0].Err != nil {
		t.Fatalf("a hostname target must open its listener: %v", st[0].Err)
	}
	send := func(src string) {
		t.Helper()
		c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(src)}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(listenPort)})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write([]byte("hi")); err != nil {
			t.Fatal(err)
		}
	}
	send("127.0.0.1")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && m.Status()[0].Err == nil {
		time.Sleep(10 * time.Millisecond)
	}
	st := m.Status()
	if st[0].Err == nil || st[0].Err.Error() != "target 192.168.50.255 is refused for the test" || !errors.Is(st[0].Err, ErrTargetNotAllowed) {
		t.Fatalf("status err = %v, want the RefuseTarget reason", st[0].Err)
	}
	if st[0].Sessions != 0 || packets.Load() != 0 {
		t.Errorf("sessions = %d, target datagrams = %d; want 0 and 0", st[0].Sessions, packets.Load())
	}
	// 名前が使えるアドレスに戻った。新しいセッションは届き、状態の拒否は消える
	resolved.Store("127.0.0.1")
	send("127.0.0.2")
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && packets.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if packets.Load() == 0 {
		t.Fatal("the datagram did not arrive after the name pointed back to a unicast address")
	}
	if st := m.Status(); st[0].Err != nil {
		t.Errorf("status err = %v after the name pointed back, want none", st[0].Err)
	}
}
