package relay

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// UDP の待ち受けの読み取りのループが新しい送信元のデータグラムを読み、受け付けの印を確かめた後で、
// 適用が待ち受けを Retiring(fail-closed)にしても、その送信元のセッションは作られず、応答も
// 返らない。Retiring の待ち受けは新しい送信元のデータグラムを捨てる(設計文書 7a.3 節)。
// 読み取りのループの先頭の確認だけでは、Admission Policy の判定や宛先への dial の間に Retiring に
// なった場合を捨てられない。
//
// 試験は、その窓を Admission Policy の判定(枠を取る前)と宛先への dial(枠を取った後)で止めて
// 再現する。Retiring の待ち受けは、成立済みのセッションが無ければ同じ Commit で閉じるので、
// keeper のセッションを 1 つ置く。keeper は Retiring の後も中継を続けなければならない。
func TestUDPNewSourceWhileListenerRetiresIsDropped(t *testing.T) {
	for _, tc := range []struct {
		name string
		// pauseInAdmit が真なら Admit で、偽なら Dial で読み取りのループを止める
		pauseInAdmit bool
	}{
		{"paused before the flow slot", true},
		{"paused after the flow slot", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			echoAddr, echoPackets := udpEcho(t)
			var (
				armed    atomic.Bool
				entered  = make(chan struct{})
				proceed  = make(chan struct{})
				pause    = func() { close(entered); <-proceed }
				releases atomic.Int32
				connMu   sync.Mutex
				dialed   []*closeTrackedConn
			)
			t.Cleanup(func() {
				// 失敗したときに止めたままの goroutine と、残ったソケットを片付ける
				select {
				case <-proceed:
				default:
					close(proceed)
				}
				connMu.Lock()
				defer connMu.Unlock()
				for _, c := range dialed {
					c.Close()
				}
			})
			pool := resource.NewPool(8)
			lb := &loopback{}
			port := reserveUDP(t, lb)
			// fail-closed にするため、ルールを bind できないポートへ移す
			blocker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Close()
			blocked := uint16(blocker.LocalAddr().(*net.UDPAddr).Port)
			m := New(lb, Options{
				UDPIdleTimeout: time.Hour,
				UDPPool:        pool,
				Logf:           testLogf(t),
				Admit: func(ruleID string, src netip.Addr, size int) (func(), bool) {
					if tc.pauseInAdmit && armed.CompareAndSwap(true, false) {
						pause()
					}
					return func() { releases.Add(1) }, true
				},
				Dial: func(network, addr string) (net.Conn, error) {
					if !tc.pauseInAdmit && armed.CompareAndSwap(true, false) {
						pause()
					}
					ua, err := net.ResolveUDPAddr(network, addr)
					if err != nil {
						return nil, err
					}
					uc, err := net.DialUDP(network, nil, ua)
					if err != nil {
						return nil, err
					}
					c := &closeTrackedConn{UDPConn: uc}
					connMu.Lock()
					dialed = append(dialed, c)
					connMu.Unlock()
					return c, nil
				},
			})
			defer m.Close()
			key := Key{proto.UDP, port}
			m.Prepare(map[Key]Desired{key: {echoAddr, "r1"}}).Commit(nil)

			dial := func() *net.UDPConn {
				c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			roundtrip := func(c *net.UDPConn, msg string, wait time.Duration) (string, error) {
				c.SetDeadline(time.Now().Add(wait))
				if _, err := c.Write([]byte(msg)); err != nil {
					return "", err
				}
				b := make([]byte, 100)
				n, err := c.Read(b)
				return string(b[:n]), err
			}
			keeper := dial()
			defer keeper.Close()
			if got, err := roundtrip(keeper, "keep", 2*time.Second); err != nil || got != "keep" {
				t.Fatalf("keeper roundtrip = %q, %v", got, err)
			}
			packetsBefore := echoPackets.Load()

			armed.Store(true)
			fresh := dial()
			defer fresh.Close()
			if _, err := fresh.Write([]byte("fresh")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("the read loop did not reach the pause point")
			}
			// 読み取りのループが止まっている間に、ルールを fail-closed にして待ち受けを Retiring にする
			s := m.Prepare(map[Key]Desired{{proto.UDP, blocked}: {echoAddr, "r1"}})
			if s.Failed()["r1"] == nil {
				t.Fatal("want r1 to fail")
			}
			s.Commit(map[string]func(netip.Addr) bool{"r1": func(netip.Addr) bool { return true }})
			if got := m.Retiring(); len(got) != 1 || got[0] != key {
				t.Fatalf("Retiring = %v, want [%s]", got, key)
			}
			m.mu.Lock()
			l := m.retiring[key]
			m.mu.Unlock()
			close(proceed)

			// 新しい送信元の送信元ごとの枠が返ったことを、捨てる処理が終わった印として待つ。
			// keeper の枠はセッションが続く間は返らない
			wantDials := 2
			if tc.pauseInAdmit {
				// 枠を取る前に止めた場合は、宛先へ dial もしない
				wantDials = 1
			}
			state := func() (ok bool, desc string) {
				connMu.Lock()
				defer connMu.Unlock()
				discarded := len(dialed) == wantDials
				if !tc.pauseInAdmit {
					discarded = discarded && dialed[1].closed.Load()
				}
				desc = fmt.Sprintf("dialed %d, sessions %d, pool in use %d, per-source releases %d",
					len(dialed), l.sessions(), pool.InUse(), releases.Load())
				return discarded && releases.Load() == 1 && l.sessions() == 1 && pool.InUse() == 1, desc
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				ok, desc := state()
				if ok {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("a retiring listener created a session for a new source: %s", desc)
				}
				time.Sleep(5 * time.Millisecond)
			}
			// 新しい送信元には応答が届かず、そのデータグラムは宛先へ送られない
			fresh.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if n, err := fresh.Read(make([]byte, 100)); err == nil {
				t.Errorf("a new source got a %d byte reply from a retiring listener", n)
			}
			if got := echoPackets.Load() - packetsBefore; got != 0 {
				t.Errorf("target received %d datagrams from a new source of a retiring listener", got)
			}
			// keeper のセッションは中継を続ける
			if got, err := roundtrip(keeper, "still", 2*time.Second); err != nil || got != "still" {
				t.Errorf("the established session did not survive: %q, %v", got, err)
			}
			// 片付けが 1 回だけであること。枠を返しすぎていないかを、少し待ってから確かめる
			time.Sleep(50 * time.Millisecond)
			if got := releases.Load(); got != 1 {
				t.Errorf("per-source release called %d times, want 1", got)
			}
			if got := pool.InUse(); got != 1 {
				t.Errorf("pool in use = %d, want 1 for the keeper", got)
			}
			if got := l.sessions(); got != 1 {
				t.Errorf("sessions = %d, want 1 for the keeper", got)
			}
		})
	}
}

// 登録の確認は、セッションの錠を取ってから受け付けの印を読む。錠を取る前に読むと、読んでから錠を
// 取るまでの間に待ち受けが Retiring になった場合に、印が下りた後の新しい送信元のセッションを登録する。
// Retiring の sweep はそのセッションを接続元制限で判定するだけなので、セッションは残る。
// 試験は、読み取りのループが錠を取った直後で止まっている間に、別の goroutine で待ち受けを Retiring
// にし、印が下りたのを見てから進める。Retiring の sweep は錠を待つので、印を下ろした後で止まっている。
func TestUDPRegistrationChecksRetiringUnderSessionLock(t *testing.T) {
	echoAddr, echoPackets := udpEcho(t)
	var (
		armed    atomic.Bool
		hookIn   = make(chan struct{})
		hookGo   = make(chan struct{})
		releases atomic.Int32
		connMu   sync.Mutex
		dialed   []*closeTrackedConn
	)
	t.Cleanup(func() {
		select {
		case <-hookGo:
		default:
			close(hookGo)
		}
		connMu.Lock()
		defer connMu.Unlock()
		for _, c := range dialed {
			c.Close()
		}
	})
	pool := resource.NewPool(8)
	lb := &loopback{}
	port := reserveUDP(t, lb)
	blocker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	blocked := uint16(blocker.LocalAddr().(*net.UDPAddr).Port)
	m := New(lb, Options{
		UDPIdleTimeout: time.Hour,
		UDPPool:        pool,
		Logf:           testLogf(t),
		Admit: func(ruleID string, src netip.Addr, size int) (func(), bool) {
			return func() { releases.Add(1) }, true
		},
		Dial: func(network, addr string) (net.Conn, error) {
			ua, err := net.ResolveUDPAddr(network, addr)
			if err != nil {
				return nil, err
			}
			uc, err := net.DialUDP(network, nil, ua)
			if err != nil {
				return nil, err
			}
			c := &closeTrackedConn{UDPConn: uc}
			connMu.Lock()
			dialed = append(dialed, c)
			connMu.Unlock()
			return c, nil
		},
	})
	defer m.Close()
	// 中継を始める前に設定する。止めるのは armed を立てた後の 1 回だけ
	m.testUDPRegistering = func() {
		if armed.CompareAndSwap(true, false) {
			close(hookIn)
			<-hookGo
		}
	}
	key := Key{proto.UDP, port}
	m.Prepare(map[Key]Desired{key: {echoAddr, "r1"}}).Commit(nil)
	m.mu.Lock()
	l := m.listeners[key]
	m.mu.Unlock()

	to := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}
	roundtrip := func(c *net.UDPConn, msg string) (string, error) {
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte(msg)); err != nil {
			return "", err
		}
		b := make([]byte, 100)
		n, err := c.Read(b)
		return string(b[:n]), err
	}
	keeper, err := net.DialUDP("udp4", nil, to)
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	if got, err := roundtrip(keeper, "keep"); err != nil || got != "keep" {
		t.Fatalf("keeper roundtrip = %q, %v", got, err)
	}
	packetsBefore := echoPackets.Load()

	armed.Store(true)
	fresh, err := net.DialUDP("udp4", nil, to)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if _, err := fresh.Write([]byte("fresh")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-hookIn:
	case <-time.After(5 * time.Second):
		t.Fatal("the read loop did not reach the registration")
	}
	// 読み取りのループはセッションの錠を持って止まっている。別の goroutine で Retiring にする
	retired := make(chan struct{})
	go func() {
		defer close(retired)
		s := m.Prepare(map[Key]Desired{{proto.UDP, blocked}: {echoAddr, "r1"}})
		s.Commit(map[string]func(netip.Addr) bool{"r1": func(netip.Addr) bool { return true }})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for l.accepting.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the listener did not stop accepting")
		}
		time.Sleep(time.Millisecond)
	}
	close(hookGo)
	select {
	case <-retired:
	case <-time.After(5 * time.Second):
		t.Fatal("the retiring Commit did not finish")
	}
	if got := m.Retiring(); len(got) != 1 || got[0] != key {
		t.Fatalf("Retiring = %v, want [%s]", got, key)
	}

	// 捨てる処理は宛先への接続を閉じ、フロー予算の枠と送信元ごとの枠を返す。錠を放した後に行うので、
	// 終わるのを待つ
	state := func() (ok bool, desc string) {
		connMu.Lock()
		defer connMu.Unlock()
		desc = fmt.Sprintf("dialed %d, sessions %d, pool in use %d, per-source releases %d",
			len(dialed), l.sessions(), pool.InUse(), releases.Load())
		return len(dialed) == 2 && dialed[1].closed.Load() && releases.Load() == 1 &&
			l.sessions() == 1 && pool.InUse() == 1, desc
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		ok, desc := state()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a retiring listener registered a session for a new source: %s", desc)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// 片付けが 1 回だけであること
	time.Sleep(50 * time.Millisecond)
	if got := releases.Load(); got != 1 {
		t.Errorf("per-source release called %d times, want 1", got)
	}
	if got := pool.InUse(); got != 1 {
		t.Errorf("pool in use = %d, want 1 for the keeper", got)
	}
	if got := l.sessions(); got != 1 {
		t.Errorf("sessions = %d, want 1 for the keeper", got)
	}
	fresh.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, err := fresh.Read(make([]byte, 100)); err == nil {
		t.Errorf("a new source got a %d byte reply from a retiring listener", n)
	}
	if got := echoPackets.Load() - packetsBefore; got != 0 {
		t.Errorf("target received %d datagrams from a new source of a retiring listener", got)
	}
	if got, err := roundtrip(keeper, "still"); err != nil || got != "still" {
		t.Errorf("the established session did not survive: %q, %v", got, err)
	}
}
