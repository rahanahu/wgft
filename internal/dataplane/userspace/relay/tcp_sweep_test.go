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

// sweepRig は、FIN を受けても自分の側を閉じない宛先(halfOpenEcho)へ中継する TCP の待ち受けを 1 つ
// Prepare と Commit で開き、中継が宛先へ開いた接続と、送信元ごとの枠を返した回数を記録する。
type sweepRig struct {
	m        *Manager
	pool     *resource.Pool
	key      Key
	l        *listener
	target   string // 待ち受けを開いたときの宛先
	target2  string // 宛先の差し替えに使う 2 つ目の宛先
	releases atomic.Int32
	armed    atomic.Bool
	entered  chan struct{}
	proceed  chan struct{}
	connMu   sync.Mutex
	dialed   []*closeTrackedTCP
	probes   int // 待ち受けを開くときの到達確認の dial の数
}

func newSweepRig(t *testing.T) *sweepRig {
	t.Helper()
	r := &sweepRig{pool: resource.NewPool(8), entered: make(chan struct{}), proceed: make(chan struct{})}
	r.target, _ = halfOpenEcho(t)
	r.target2, _ = halfOpenEcho(t)
	t.Cleanup(func() {
		// 失敗したときに止めたままの goroutine と、残ったソケットを片付ける
		r.resume()
		r.connMu.Lock()
		defer r.connMu.Unlock()
		for _, c := range r.dialed {
			c.Close()
		}
	})
	lb := &loopback{}
	port := reserveTCP(t, lb)
	r.m = New(lb, Options{
		TCPPool: r.pool,
		Logf:    testLogf(t),
		Admit: func(ruleID string, src netip.Addr, size int) (func(), bool) {
			return func() { r.releases.Add(1) }, true
		},
		Dial: func(network, addr string) (net.Conn, error) {
			// 待ち受けを開くときの到達確認の dial は止めない。止めるのは arm の後の中継の dial だけ
			if r.armed.CompareAndSwap(true, false) {
				close(r.entered)
				<-r.proceed
			}
			c, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			tracked := &closeTrackedTCP{TCPConn: c.(*net.TCPConn)}
			r.connMu.Lock()
			r.dialed = append(r.dialed, tracked)
			r.connMu.Unlock()
			return tracked, nil
		},
	})
	t.Cleanup(r.m.Close)
	r.key = Key{proto.TCP, port}
	r.m.Prepare(map[Key]Desired{r.key: {r.target, "r1"}}).Commit(nil)
	r.m.mu.Lock()
	r.l = r.m.listeners[r.key]
	r.m.mu.Unlock()
	if r.l == nil || r.l.bindErr != nil {
		t.Fatalf("listener %s did not open", r.key)
	}
	r.connMu.Lock()
	r.probes = len(r.dialed)
	r.connMu.Unlock()
	return r
}

func (r *sweepRig) resume() {
	select {
	case <-r.proceed:
	default:
		close(r.proceed)
	}
}

// connect は公開側へ接続する。dialing が真なら、中継の宛先への dial で止まるまで待って返す。
// 偽なら、宛先まで中継が通ったことを確かめて返す。
func (r *sweepRig) connect(t *testing.T, dialing bool) net.Conn {
	t.Helper()
	r.armed.Store(dialing)
	c, err := dialLoopback(r.key.Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if dialing {
		select {
		case <-r.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("the connection goroutine did not reach the target dial")
		}
		return c
	}
	if got, err := echoLine(c, "hi"); err != nil || got != "hi\n" {
		t.Fatalf("no relay before the change: %q, %v", got, err)
	}
	return c
}

// retire は宛先をそのままにルールを bind できないポートへ移し、fail-closed にして元の待ち受けを
// Retiring にする。keep は成立済みの接続を残すかの判定である。
func (r *sweepRig) retire(t *testing.T, keep bool) {
	t.Helper()
	blocker, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	blocked := uint16(blocker.Addr().(*net.TCPAddr).Port)
	s := r.m.Prepare(map[Key]Desired{{proto.TCP, blocked}: {r.target, "r1"}})
	if s.Failed()["r1"] == nil {
		t.Fatal("want r1 to fail")
	}
	s.Commit(map[string]func(netip.Addr) bool{"r1": func(netip.Addr) bool { return keep }})
}

// waitCut は、中継の両側が切れ、枠がすべて戻り、送信元ごとの枠が 1 回だけ返ったことを確かめる。
func (r *sweepRig) waitCut(t *testing.T, client net.Conn) {
	t.Helper()
	// 公開側の接続は切れる。EOF でも RST による誤りでもよい
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ne net.Error
	if _, err := client.Read(make([]byte, 1)); err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Errorf("the client connection was not cut: read err = %v", err)
	}
	state := func() (ok bool, desc string) {
		r.connMu.Lock()
		defer r.connMu.Unlock()
		relayed := r.dialed[r.probes:]
		closed := len(relayed) == 1 && relayed[0].closed.Load()
		desc = fmt.Sprintf("dialed %d, target conn closed %v, sessions %d, pool in use %d, per-source releases %d",
			len(relayed), closed, r.l.sessions(), r.pool.InUse(), r.releases.Load())
		return closed && r.l.sessions() == 0 && r.pool.InUse() == 0 && r.releases.Load() == 1, desc
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		ok, desc := state()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the relay was not cut on both sides: %s", desc)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// 片付けが 1 回だけであること。枠を返しすぎていないかを、少し待ってから確かめる
	time.Sleep(50 * time.Millisecond)
	if got := r.releases.Load(); got != 1 {
		t.Errorf("per-source release called %d times, want 1", got)
	}
	if got := r.pool.InUse(); got != 0 {
		t.Errorf("pool in use = %d, want 0", got)
	}
}

// 中継中の接続を切る操作(宛先の差し替え、接続元制限の変更、Retiring の待ち受けの判定のし直し)は、
// 公開側の接続と宛先への接続の組を両方とも切る(設計文書 6.2 節の「進行中の中継を閉じる契機」、
// 7a.3 節の Retire)。公開側だけを切ると、netpipe は宛先へ FIN を送った後も宛先からの読み取りを
// 続けるので、FIN を受けても自分の側を閉じない宛先では、宛先への接続、フローの予算の枠、送信元
// ごとの枠が、宛先が閉じるか待ち受けが閉じるまで残る。宛先への dial の最中に切った場合は、
// 宛先への接続を登録せずに切る。
func TestTCPSweepCutsBothSides(t *testing.T) {
	for _, tc := range []struct {
		name string
		// dialing が真なら、接続の goroutine を宛先への dial で止めたまま cut を走らせる
		dialing bool
		cut     func(t *testing.T, r *sweepRig)
	}{
		{name: "retarget by Commit", cut: func(t *testing.T, r *sweepRig) {
			r.m.Prepare(map[Key]Desired{r.key: {r.target2, "r1"}}).Commit(nil)
		}},
		{name: "retarget by Commit while dialing", dialing: true, cut: func(t *testing.T, r *sweepRig) {
			r.m.Prepare(map[Key]Desired{r.key: {r.target2, "r1"}}).Commit(nil)
		}},
		{name: "CloseSessions", cut: func(t *testing.T, r *sweepRig) {
			if n := r.m.CloseSessions(func(string, netip.Addr) bool { return false }); n != 1 {
				t.Errorf("CloseSessions = %d, want 1", n)
			}
		}},
		{name: "CloseSessions while dialing", dialing: true, cut: func(t *testing.T, r *sweepRig) {
			if n := r.m.CloseSessions(func(string, netip.Addr) bool { return false }); n != 1 {
				t.Errorf("CloseSessions = %d, want 1", n)
			}
		}},
		{name: "retire refuses the source", cut: func(t *testing.T, r *sweepRig) {
			r.retire(t, false)
		}},
		{name: "retiring re-check refuses the source", cut: func(t *testing.T, r *sweepRig) {
			// 1 回目は接続を残す。2 回目の Commit で判定し直すと、接続元が拒まれる
			r.retire(t, true)
			if got := r.m.Retiring(); len(got) != 1 {
				t.Fatalf("Retiring = %v, want one listener", got)
			}
			r.retire(t, false)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newSweepRig(t)
			client := r.connect(t, tc.dialing)
			tc.cut(t, r)
			r.resume()
			r.waitCut(t, client)
			if got := r.m.Retiring(); len(got) != 0 {
				// Retiring の待ち受けは、判定のし直しで中継が残っていなければ閉じる(設計文書 7a.3 節)
				t.Errorf("Retiring = %v, want none once no flow is left", got)
			}
		})
	}
}

// Retiring の待ち受けの判定のし直しで残してよい接続は、切らずに中継を続ける。
func TestTCPRetiringKeepsAdmittedPair(t *testing.T) {
	r := newSweepRig(t)
	client := r.connect(t, false)
	r.retire(t, true)
	r.retire(t, true)
	if got, err := echoLine(client, "again"); err != nil || got != "again\n" {
		t.Errorf("a retained connection stopped relaying: %q, %v", got, err)
	}
	if got := r.m.Retiring(); len(got) != 1 {
		t.Errorf("Retiring = %v, want the listener kept for its flow", got)
	}
	if got := r.pool.InUse(); got != 1 {
		t.Errorf("pool in use = %d, want 1", got)
	}
	if got := r.l.sessions(); got != 2 {
		t.Errorf("sessions = %d, want 2 for the public and the target side", got)
	}
}
