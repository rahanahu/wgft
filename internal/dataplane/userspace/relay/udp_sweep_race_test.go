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

// UDP の読み取りのループが新しい送信元のセッションを作る間(Admission Policy の判定から登録まで)に、
// 宛先の付け替え(Commit の retarget)か接続元制限の変更(CloseSessions)の sweep が走っても、
// その sweep が閉じるはずのセッションは登録されない(設計文書 7 節、6.2 節)。セッションは dial の後に
// 表へ入るので、sweep はまだ表に無いセッションを見ない。登録すれば、付け替えでは旧い宛先へ、
// 接続元制限では拒むようになった送信元のまま中継を続け、送り続ける送信元のセッションは無通信の
// 期限でも閉じない。
//
// 試験は、読み取りのループを Admit(判定を済ませた後)か Dial(宛先を読んだ後)で止め、その間に
// sweep を走らせてから進める。sweep がこの送信元を残す場合は、登録して中継を続けなければならない。
func TestUDPNewSourceAcrossSweep(t *testing.T) {
	for _, tc := range []struct {
		name string
		// pauseInAdmit が真なら Admit で、偽なら Dial で読み取りのループを止める
		pauseInAdmit bool
		// sweep は止めている間に走らせる操作。retargeted は宛先を B へ付け替えたことを表す
		sweep func(r *sweepUDPRig, t *testing.T) (retargeted bool)
		// dropped は sweep がこの送信元のセッションを閉じる場合に真
		dropped bool
	}{
		{"retarget while dialing", false, (*sweepUDPRig).retarget, true},
		{"source filter change while admitting", true, (*sweepUDPRig).denySource, true},
		{"source filter change while dialing", false, (*sweepUDPRig).denySource, true},
		{"sweep that keeps the source while dialing", false, (*sweepUDPRig).keepAll, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newSweepUDPRig(t, tc.pauseInAdmit)
			fresh := r.client(t)
			r.armed.Store(true)
			if _, err := fresh.Write([]byte("first")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-r.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("the read loop did not reach the pause point")
			}
			retargeted := tc.sweep(r, t)
			r.resume()

			if !tc.dropped {
				fresh.SetReadDeadline(time.Now().Add(2 * time.Second))
				b := make([]byte, 100)
				n, err := fresh.Read(b)
				if err != nil || string(b[:n]) != "first" {
					t.Fatalf("a source the sweep keeps was not relayed: %q, %v", b[:n], err)
				}
				if got := r.l().sessions(); got != 1 {
					t.Errorf("sessions = %d, want 1", got)
				}
				if got := r.releases.Load(); got != 0 {
					t.Errorf("per-source release called %d times while the session lives", got)
				}
				checkPool(t, r.pool)
				return
			}

			// 捨てる処理は宛先への接続を閉じ、フロー予算の枠と送信元ごとの枠を返す
			state := func() (bool, string) {
				r.connMu.Lock()
				defer r.connMu.Unlock()
				desc := fmt.Sprintf("dialed %d, sessions %d, pool in use %d, per-source releases %d, A got %d",
					len(r.dialed), r.l().sessions(), r.pool.InUse(), r.releases.Load(), r.packetsA.Load())
				return len(r.dialed) == 1 && r.dialed[0].closed.Load() && r.releases.Load() == 1 &&
					r.l().sessions() == 0 && r.pool.InUse() == 0, desc
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				ok, desc := state()
				if ok {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("a session the sweep cut was registered: %s", desc)
				}
				time.Sleep(5 * time.Millisecond)
			}
			fresh.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if n, err := fresh.Read(make([]byte, 100)); err == nil {
				t.Errorf("the source got a %d byte reply through a session the sweep cut", n)
			}
			if got := r.packetsA.Load(); got != 0 {
				t.Errorf("target A received %d datagrams through a session the sweep cut", got)
			}
			// 片付けが 1 回だけであること
			time.Sleep(50 * time.Millisecond)
			if got := r.releases.Load(); got != 1 {
				t.Errorf("per-source release called %d times, want 1", got)
			}
			if lg := checkPool(t, r.pool); lg.InUse != 0 {
				t.Errorf("pool in use = %d, want 0", lg.InUse)
			}

			// 次のデータグラムは今の宣言で判定される。付け替えなら新しい宛先 B へ届き、接続元制限なら拒まれる
			wait := 300 * time.Millisecond
			if retargeted {
				wait = 2 * time.Second
			}
			fresh.SetReadDeadline(time.Now().Add(wait))
			if _, err := fresh.Write([]byte("second")); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 100)
			n, err := fresh.Read(b)
			if retargeted {
				if err != nil || string(b[:n]) != "second" || r.packetsB.Load() != 1 || r.packetsA.Load() != 0 {
					t.Errorf("after the retarget: reply %q, %v; A got %d, B got %d; want the reply from B", b[:n], err, r.packetsA.Load(), r.packetsB.Load())
				}
			} else if err == nil {
				t.Errorf("a source the new policy refuses got a %d byte reply", n)
			}
		})
	}
}

type sweepUDPRig struct {
	m                  *Manager
	pool               *resource.Pool
	key                Key
	targetA, targetB   string
	packetsA, packetsB *atomic.Int64
	armed              atomic.Bool
	deny               atomic.Bool
	releases           atomic.Int32
	entered, proceed   chan struct{}
	proceedOnce        sync.Once
	connMu             sync.Mutex
	dialed             []*closeTrackedConn
}

func newSweepUDPRig(t *testing.T, pauseInAdmit bool) *sweepUDPRig {
	t.Helper()
	r := &sweepUDPRig{pool: resource.NewPool(8), entered: make(chan struct{}), proceed: make(chan struct{})}
	r.targetA, r.packetsA = udpEcho(t)
	r.targetB, r.packetsB = udpEcho(t)
	pause := func() { close(r.entered); <-r.proceed }
	t.Cleanup(func() {
		r.resume()
		r.connMu.Lock()
		defer r.connMu.Unlock()
		for _, c := range r.dialed {
			c.Close()
		}
	})
	lb := &loopback{}
	r.key = Key{proto.UDP, reserveUDP(t, lb)}
	r.m = New(lb, Options{
		UDPIdleTimeout: time.Hour,
		UDPPool:        r.pool,
		Logf:           testLogf(t),
		Admit: func(ruleID string, src netip.Addr, size int) (func(), bool) {
			// 判定を済ませてから止める。止めている間に方針が変わっても、この判定は古い方針のもの
			ok := !r.deny.Load()
			if pauseInAdmit && r.armed.CompareAndSwap(true, false) {
				pause()
			}
			if !ok {
				return nil, false
			}
			return func() { r.releases.Add(1) }, true
		},
		Dial: func(network, addr string) (net.Conn, error) {
			// 宛先は読み取りのループが読んだ後なので、止めている間に付け替えても addr は古い宛先
			if !pauseInAdmit && r.armed.CompareAndSwap(true, false) {
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
			r.connMu.Lock()
			r.dialed = append(r.dialed, c)
			r.connMu.Unlock()
			return c, nil
		},
	})
	t.Cleanup(r.m.Close)
	r.m.Prepare(map[Key]Desired{r.key: {r.targetA, "r1"}}).Commit(nil)
	return r
}

func (r *sweepUDPRig) resume() { r.proceedOnce.Do(func() { close(r.proceed) }) }

func (r *sweepUDPRig) l() *listener {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	return r.m.listeners[r.key]
}

func (r *sweepUDPRig) client(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(r.key.Port)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// retarget は待ち受けを開き直さずに宛先を B へ付け替える(Staged の retarget)。
func (r *sweepUDPRig) retarget(t *testing.T) bool {
	t.Helper()
	r.m.Prepare(map[Key]Desired{r.key: {r.targetB, "r1"}}).Commit(nil)
	if got := r.targetOfKey(); got != r.targetB {
		t.Fatalf("target = %s after the retarget, want %s", got, r.targetB)
	}
	return true
}

// denySource は方針を変えて送信元を拒み、ユーザー空間モードの Commit と同じく CloseSessions で
// 拒むようになった送信元のセッションを閉じる。
func (r *sweepUDPRig) denySource(t *testing.T) bool {
	t.Helper()
	r.deny.Store(true)
	r.m.CloseSessions(func(string, netip.Addr) bool { return !r.deny.Load() })
	return false
}

// keepAll はすべての送信元を残す CloseSessions を走らせる。
func (r *sweepUDPRig) keepAll(t *testing.T) bool {
	t.Helper()
	if n := r.m.CloseSessions(func(string, netip.Addr) bool { return true }); n != 0 {
		t.Fatalf("CloseSessions = %d, want 0", n)
	}
	return false
}

func (r *sweepUDPRig) targetOfKey() string {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	return r.m.listeners[r.key].target
}
