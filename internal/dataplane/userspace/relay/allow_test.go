package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// allowList はテスト用の許可一覧。実際の一覧は internal/agent/allowtargets が持つ。
func allowList(entries ...string) func(netip.AddrPort) bool {
	return func(ap netip.AddrPort) bool {
		for _, e := range entries {
			if e == ap.String() {
				return true
			}
		}
		return false
	}
}

// neverListen は、待ち受けを開こうとしたことを数える Network。許可一覧が拒んだ宛先で待ち受けを
// 開かないことを、ポートの取り合いに左右されずに確かめる。
type neverListen struct{ opened atomic.Int64 }

func (n *neverListen) ListenUDP(uint16) (net.PacketConn, error) {
	n.opened.Add(1)
	return nil, errors.New("listener must not be opened")
}

func (n *neverListen) ListenTCP(uint16) (net.Listener, error) {
	n.opened.Add(1)
	return nil, errors.New("listener must not be opened")
}

// 許可一覧を渡さなければ、名前解決も判定もせず、宛先の文字列そのままで接続する(導入前と同じ挙動)。
func TestNoAllowListDialsTargetAsIs(t *testing.T) {
	lb := &loopback{}
	var got atomic.Value
	m := New(lb, Options{
		Logf: t.Logf,
		Dial: func(network, addr string) (net.Conn, error) { got.Store(addr); return nil, errors.New("refused") },
		LookupTarget: func(ctx context.Context, host string) ([]netip.Addr, error) {
			t.Error("LookupTarget must not be called without an allow list")
			return nil, errors.New("unexpected")
		},
	})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.TCP, reserveTCP(t, lb)}: {"nas.lan:25565", "r1"}})
	if got.Load() != "nas.lan:25565" {
		t.Errorf("dialed %v, want the target as it is", got.Load())
	}
}

// 許可一覧の外にある IP リテラルの宛先は、待ち受けを開かず、理由付きの error として見える(仕様 5.2、7 節)。
func TestApplyDeniesLiteralTargetOutsideList(t *testing.T) {
	var netw neverListen
	pool := resource.NewPool(10)
	m := New(&netw, Options{
		Logf:              t.Logf,
		TCPPool:           pool,
		AllowTarget:       allowList("192.168.1.20:25565"),
		AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
		Dial:              func(network, addr string) (net.Conn, error) { t.Errorf("dialed %s", addr); return nil, nil },
	})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.TCP, 39972}: {"192.168.1.1:22", "r1"}})
	// 待ち受けを開かないルールは、受け付けているルールの集合 A に入らない(設計文書 7a.10 節)
	if got := pool.Rules(); got != 0 {
		t.Errorf("accepting rules for a denied target = %d, want 0", got)
	}
	st := m.Status()
	if len(st) != 1 || st[0].Err == nil {
		t.Fatalf("status = %+v, want an error", st)
	}
	if want := "target 192.168.1.1:22 is not in WGFT_AGENT_ALLOW_TARGETS"; st[0].Err.Error() != want {
		t.Errorf("reason = %q, want %q", st[0].Err, want)
	}
	if !errors.Is(st[0].Err, ErrTargetNotAllowed) {
		t.Errorf("reason %v does not wrap ErrTargetNotAllowed", st[0].Err)
	}
	// 30 秒ごとの再試行でも開かない
	m.Retry()
	if st := m.Status(); st[0].Err == nil {
		t.Error("after Retry the denied target must still be an error")
	}
	if n := netw.opened.Load(); n != 0 {
		t.Errorf("tried to open a listener %d times, want 0 for a denied target", n)
	}
	if got := pool.Rules(); got != 0 {
		t.Errorf("accepting rules for a denied target after Retry = %d, want 0", got)
	}
}

// ポートの範囲のうち 1 つだけが一覧の外にあるときは、そのポートの待ち受けだけを開かない(仕様 7 節)。
func TestApplyDeniesOnePortOfRange(t *testing.T) {
	echoAddr, _ := udpEcho(t)
	host, portStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	// 同じルールの 2 つのポート。実効宛先は echo のポートと、その次のポート。次だけを一覧から外す
	next := strconv.Itoa(mustPort(t, portStr) + 1)
	lb := &loopback{}
	m := New(lb, Options{Logf: t.Logf, AllowTarget: allowList(echoAddr), AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS"})
	defer m.Close()
	allowed, denied := reserveUDP(t, lb), freePort(t)
	m.Apply(map[Key]Desired{
		{proto.UDP, allowed}: {echoAddr, "r1"},
		{proto.UDP, denied}:  {net.JoinHostPort(host, next), "r1"},
	})
	st := m.Status()
	if len(st) != 2 {
		t.Fatalf("status = %+v, want 2 listeners", st)
	}
	for _, s := range st {
		switch s.Key.Port {
		case allowed:
			if s.Err != nil {
				t.Errorf("allowed port: %v", s.Err)
			}
		case denied:
			if s.Err == nil || !strings.Contains(s.Err.Error(), "is not in WGFT_AGENT_ALLOW_TARGETS") {
				t.Errorf("denied port: err = %v", s.Err)
			}
		}
	}
}

func mustPort(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// ホスト名の宛先は、待ち受けを開いてから接続のときに判定する。同じ名前が後で一覧の外の
// アドレスに解決されたら、その接続を拒み、理由をルールの状態に載せる(仕様 7 節)。
func TestDialTimeCheckFollowsDNS(t *testing.T) {
	// 宛先の実体。接続を受け付けるだけ
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
			c.Close()
		}
	}()
	targetPort := srv.Addr().(*net.TCPAddr).Port
	target := "nas.lan:" + strconv.Itoa(targetPort)

	var resolved atomic.Value // 名前解決の結果(後で差し替える)
	resolved.Store("127.0.0.1")
	var dialed atomic.Value
	lb := &loopback{}
	m := New(lb, Options{
		Logf:              t.Logf,
		AllowTarget:       allowList("127.0.0.1:" + strconv.Itoa(targetPort)),
		AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
		LookupTarget: func(ctx context.Context, host string) ([]netip.Addr, error) {
			if host != "nas.lan" {
				return nil, errors.New("unexpected host " + host)
			}
			return []netip.Addr{netip.MustParseAddr(resolved.Load().(string))}, nil
		},
		Dial: func(network, addr string) (net.Conn, error) {
			dialed.Store(addr)
			d := net.Dialer{Timeout: time.Second}
			return d.Dial(network, addr)
		},
	})
	defer m.Close()
	listenPort := reserveTCP(t, lb)
	m.Apply(map[Key]Desired{{proto.TCP, listenPort}: {target, "r1"}})
	// 許されるアドレスに解決される間は ok で、解決したアドレスへ接続している
	if st := m.Status(); st[0].Err != nil {
		t.Fatalf("allowed address: %v", st[0].Err)
	}
	if got := dialed.Load(); got != "127.0.0.1:"+strconv.Itoa(targetPort) {
		t.Errorf("dialed %v, want the resolved address", got)
	}

	// DNS が一覧の外のアドレスを返すようになったら、接続を拒む
	resolved.Store("127.0.0.2")
	dialed.Store("")
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(listenPort))), time.Second)
	if err != nil {
		// 拒否は RST なので、connect が返る前に届くこともある(relay_test.go の同じ扱い)
		if !isReset(err) {
			t.Fatal(err)
		}
	} else {
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := c.Read(make([]byte, 1)); err == nil {
			t.Errorf("read %d bytes, want the refused connection to be closed", n)
		}
	}
	if got := dialed.Load(); got != "" {
		t.Errorf("dialed %v, want no dial to a denied address", got)
	}
	// 拒否はルールの状態にも出る。Retry の宛先確認も同じ一覧に従うので error のまま
	if st := m.Status(); st[0].Err == nil || !errors.Is(st[0].Err, ErrTargetNotAllowed) {
		t.Errorf("status err = %v, want the allow list refusal", st[0].Err)
	}
	m.Retry()
	if st := m.Status(); st[0].Err == nil {
		t.Error("Retry must not clear the refusal while DNS points outside the list")
	}
	// 元のアドレスに戻れば、次の確認で ok に戻る
	resolved.Store("127.0.0.1")
	m.Retry()
	if st := m.Status(); st[0].Err != nil {
		t.Errorf("after DNS points back into the list: %v", st[0].Err)
	}
}

// UDP は、一覧の外のアドレスに解決されたセッションのデータグラムを捨て、理由を状態に載せる(仕様 7 節)。
func TestUDPDialTimeCheckDropsDatagrams(t *testing.T) {
	echoAddr, packets := udpEcho(t)
	_, portStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	lb := &loopback{}
	m := New(lb, Options{
		Logf:              t.Logf,
		AllowTarget:       allowList("127.0.0.9:" + portStr), // echo の 127.0.0.1 は許さない
		AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
		LookupTarget: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
	})
	defer m.Close()
	listenPort := reserveUDP(t, lb)
	m.Apply(map[Key]Desired{{proto.UDP, listenPort}: {"nas.lan:" + portStr, "r1"}})
	if st := m.Status(); st[0].Err != nil {
		t.Fatalf("a hostname target must open its listener: %v", st[0].Err)
	}
	c, err := net.Dial("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(listenPort))))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st := m.Status(); st[0].Err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := packets.Load(); got != 0 {
		t.Errorf("target received %d datagrams, want 0", got)
	}
	st := m.Status()
	if st[0].Err == nil || !errors.Is(st[0].Err, ErrTargetNotAllowed) {
		t.Errorf("status err = %v, want the allow list refusal", st[0].Err)
	}
	if st[0].Sessions != 0 {
		t.Errorf("sessions = %d, want 0", st[0].Sessions)
	}
}
