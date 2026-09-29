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

// closeTrackedConn は、中継が宛先へ開いた接続を閉じたかを記録する。*net.UDPConn を埋め込むので、
// 中継はカーネルのソケットとして到着を待てる(readWaiterOf)。
type closeTrackedConn struct {
	*net.UDPConn
	closed atomic.Bool
}

func (c *closeTrackedConn) Close() error {
	c.closed.Store(true)
	return c.UDPConn.Close()
}

// UDP の待ち受けの読み取りのループが新しい送信元のデータグラムを読んだ直後に、適用が待ち受けを
// 閉じても、そのデータグラムのセッションは残らない。closeF は done を閉じてからセッションの表を
// 空にし、無通信のセッションを閉じる goroutine も done で戻るので、閉じた後に表へ入ったセッションは
// 誰にも閉じられない。宛先が黙っていれば、フローの予算の枠、送信元ごとの枠、宛先へのソケット、
// 応答を待つ goroutine が残り続ける。
//
// 読み取りのループは、ルール ID を読むとき(ruleOf)と宛先を読むとき(targetOf)に Manager の錠を
// 待つので、錠を持って待ち受けを閉じる適用とこの順序で交差する。試験は、その 2 つの窓を
// Admission Policy の判定(枠を取る前)と宛先への dial(枠を取った後)で止めて再現する。
func TestUDPSessionCreatedWhileListenerClosesIsNotLeaked(t *testing.T) {
	for _, tc := range []struct {
		name string
		// pauseInAdmit が真なら Admit で、偽なら Dial で読み取りのループを止める
		pauseInAdmit bool
	}{
		{"paused before the flow slot", true},
		{"paused after the flow slot", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// 黙っている宛先。読まず、応答も返さない
			silent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { silent.Close() })

			var (
				entered  = make(chan struct{})
				proceed  = make(chan struct{})
				once     sync.Once
				pause    = func() { once.Do(func() { close(entered); <-proceed }) }
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
			m := New(lb, Options{
				UDPIdleTimeout: time.Hour,
				UDPPool:        pool,
				Logf:           testLogf(t),
				Admit: func(ruleID string, src netip.Addr, size int) (func(), bool) {
					if tc.pauseInAdmit {
						pause()
					}
					return func() { releases.Add(1) }, true
				},
				Dial: func(network, addr string) (net.Conn, error) {
					if !tc.pauseInAdmit {
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
			m.Apply(map[Key]Desired{key: {silent.LocalAddr().String(), "r1"}})
			m.mu.Lock()
			l := m.listeners[key]
			m.mu.Unlock()
			if l == nil || l.bindErr != nil {
				t.Fatalf("listener %s did not open", key)
			}

			client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err := client.Write([]byte("first")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("the read loop did not reach the pause point")
			}
			// 読み取りのループが止まっている間に、ルールを宣言から外して待ち受けを閉じる
			m.Apply(map[Key]Desired{})
			close(proceed)

			state := func() (ok bool, desc string) {
				connMu.Lock()
				defer connMu.Unlock()
				closed := len(dialed) == 1 && dialed[0].closed.Load()
				desc = fmt.Sprintf("dialed %d, upstream closed %v, sessions %d, pool in use %d, per-source releases %d",
					len(dialed), closed, l.sessions(), pool.InUse(), releases.Load())
				return closed && l.sessions() == 0 && pool.InUse() == 0 && releases.Load() == 1, desc
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				ok, desc := state()
				if ok {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("the session created after the listener closed was not discarded: %s", desc)
				}
				time.Sleep(5 * time.Millisecond)
			}
			// 片付けが 1 回だけであること。枠を返しすぎていないかを、少し待ってから確かめる
			time.Sleep(50 * time.Millisecond)
			if got := releases.Load(); got != 1 {
				t.Errorf("per-source release called %d times, want 1", got)
			}
			if got := pool.InUse(); got != 0 {
				t.Errorf("pool in use = %d, want 0", got)
			}
			if got := l.sessions(); got != 0 {
				t.Errorf("sessions after close = %d, want 0", got)
			}
			// 閉じた待ち受けのデータグラムは宛先へ送らない
			silent.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			if n, _, err := silent.ReadFrom(make([]byte, 64)); err == nil {
				t.Errorf("target received %d bytes from a listener that was already closed", n)
			}
		})
	}
}
