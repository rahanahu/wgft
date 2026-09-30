package relay

import (
	"errors"
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

// closeTrackedTCP は、中継が宛先へ開いた接続を閉じたかを記録する。*net.TCPConn を埋め込むので、
// netpipe はハーフクローズ(CloseWrite)を使える。
type closeTrackedTCP struct {
	*net.TCPConn
	closed atomic.Bool
}

func (c *closeTrackedTCP) Close() error {
	c.closed.Store(true)
	return c.TCPConn.Close()
}

// halfOpenEcho は、受け取ったものを送り返し、相手の FIN(EOF)を読んでも自分の側を閉じない宛先を
// 開く。受け取ったバイト数の合計を返す。自分の側を閉じないので、中継が宛先への接続を切らなければ、
// その接続は試験の後片付けまで残る。
func halfOpenEcho(t *testing.T) (addr string, received *atomic.Int64) {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	received = &atomic.Int64{}
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func() {
				b := make([]byte, 512)
				for {
					n, err := c.Read(b)
					if n > 0 {
						received.Add(int64(n))
						c.Write(b[:n])
					}
					if err != nil {
						return // 閉じない
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), received
}

// TCP の待ち受けが accept した接続の宛先への dial の最中に、待ち受けを閉じても、宛先への接続は
// 残らない。公開側の接続は accept のループが done を確かめて登録するので closeF が切るが、宛先への
// 接続は dial の後に登録する。closeF の後に登録すると closeF には切られない。接続の goroutine は
// 登録せずに宛先への接続を切り、フローの予算の枠、送信元ごとの枠、宛先への接続、中継の goroutine を
// 残さない。
//
// 試験は宛先への dial(Options.Dial)で接続の goroutine を止め、その間に待ち受けを閉じてから
// 再開する。Retiring にする操作(stopAccept)も done を閉じるが、成立済みの接続を残す(設計文書
// 7a.3 節)。dial の最中の接続も残り、中継を続けることを最後の場合で確かめる。
func TestTCPTargetDialedWhileListenerClosesIsCut(t *testing.T) {
	for _, tc := range []struct {
		name string
		// staged が真なら待ち受けを Prepare と Commit で開き、偽なら Apply で開く
		staged bool
		// closeListener は、dial で止まっている間に待ち受けを閉じる(または Retiring にする)
		closeListener func(t *testing.T, m *Manager)
		// retiring が真なら、接続は切れずに中継を続けることを確かめる
		retiring bool
	}{
		{name: "rule removed by Apply", closeListener: func(t *testing.T, m *Manager) {
			m.Apply(map[Key]Desired{})
		}},
		{name: "Manager.Close", closeListener: func(t *testing.T, m *Manager) {
			m.Close()
		}},
		{name: "rule removed by Commit", staged: true, closeListener: func(t *testing.T, m *Manager) {
			m.Prepare(map[Key]Desired{}).Commit(nil)
		}},
		{name: "rule retiring keeps the connection", staged: true, retiring: true, closeListener: func(t *testing.T, m *Manager) {
			// ルールを bind できないポートへ移し、fail-closed にして元の待ち受けを Retiring にする
			blocker, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Close()
			blocked := uint16(blocker.Addr().(*net.TCPAddr).Port)
			s := m.Prepare(map[Key]Desired{{proto.TCP, blocked}: {"127.0.0.1:1", "r1"}})
			if s.Failed()["r1"] == nil {
				t.Fatal("want r1 to fail")
			}
			s.Commit(map[string]func(netip.Addr) bool{"r1": func(netip.Addr) bool { return true }})
			if got := m.Retiring(); len(got) != 1 {
				t.Fatalf("Retiring = %v, want one listener", got)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, received := halfOpenEcho(t)
			var (
				armed    atomic.Bool
				entered  = make(chan struct{})
				proceed  = make(chan struct{})
				releases atomic.Int32
				connMu   sync.Mutex
				dialed   []*closeTrackedTCP
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
			port := reserveTCP(t, lb)
			m := New(lb, Options{
				TCPPool: pool,
				Logf:    testLogf(t),
				Admit: func(ruleID string, src netip.Addr, size int) (func(), bool) {
					return func() { releases.Add(1) }, true
				},
				Dial: func(network, addr string) (net.Conn, error) {
					// 待ち受けを開くときの到達確認の dial は止めない。止めるのは中継の dial だけ
					if armed.CompareAndSwap(true, false) {
						close(entered)
						<-proceed
					}
					c, err := net.Dial(network, addr)
					if err != nil {
						return nil, err
					}
					tracked := &closeTrackedTCP{TCPConn: c.(*net.TCPConn)}
					connMu.Lock()
					dialed = append(dialed, tracked)
					connMu.Unlock()
					return tracked, nil
				},
			})
			defer m.Close()
			key := Key{proto.TCP, port}
			desired := map[Key]Desired{key: {target, "r1"}}
			if tc.staged {
				m.Prepare(desired).Commit(nil)
			} else {
				m.Apply(desired)
			}
			m.mu.Lock()
			l := m.listeners[key]
			m.mu.Unlock()
			if l == nil || l.bindErr != nil {
				t.Fatalf("listener %s did not open", key)
			}
			connMu.Lock()
			probes := len(dialed)
			connMu.Unlock()

			armed.Store(true)
			client, err := dialLoopback(port)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			// 閉じた待ち受けの接続のデータは宛先へ届かない。Retiring の場合は後で送り返しを確かめる
			if !tc.retiring {
				if _, err := client.Write([]byte("first")); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("the connection goroutine did not reach the target dial")
			}
			tc.closeListener(t, m)
			close(proceed)

			if tc.retiring {
				if got, err := echoLine(client, "hi"); err != nil || got != "hi\n" {
					t.Fatalf("a connection accepted before the listener stopped accepting was not relayed: %q, %v", got, err)
				}
				if got := pool.InUse(); got != 1 {
					t.Errorf("pool in use = %d, want 1 for the retained connection", got)
				}
				return
			}

			// 公開側の接続は切れる。EOF でも RST による誤りでもよい
			client.SetReadDeadline(time.Now().Add(5 * time.Second))
			var ne net.Error
			if _, err := client.Read(make([]byte, 1)); err == nil || (errors.As(err, &ne) && ne.Timeout()) {
				t.Errorf("the client connection was not cut after its listener closed: read err = %v", err)
			}

			state := func() (ok bool, desc string) {
				connMu.Lock()
				defer connMu.Unlock()
				relayed := dialed[probes:]
				closed := len(relayed) == 1 && relayed[0].closed.Load()
				desc = fmt.Sprintf("dialed %d, target conn closed %v, sessions %d, pool in use %d, per-source releases %d",
					len(relayed), closed, l.sessions(), pool.InUse(), releases.Load())
				return closed && l.sessions() == 0 && pool.InUse() == 0 && releases.Load() == 1, desc
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				ok, desc := state()
				if ok {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("the target connection dialed after the listener closed was not cut: %s", desc)
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
			if got := received.Load(); got != 0 {
				t.Errorf("target received %d bytes from a listener that was already closed", got)
			}
		})
	}
}
