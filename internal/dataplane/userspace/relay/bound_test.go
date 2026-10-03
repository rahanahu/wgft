package relay

import (
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// bind に失敗した待ち受け(bound が偽)は sweep と stopAccept を持たず、ソケットも持たない。
// sweep と stopAccept を呼ぶ箇所と、ソケットのある待ち受けだけを扱う箇所が bound で分けていることを
// 確かめる。sweep と stopAccept の前で分け忘れると、nil の関数を呼んで panic する。

// blockedUDP は、ホストで先に bind しておいて Manager が bind できない UDP のポートを返す。
func blockedUDP(t *testing.T) uint16 {
	t.Helper()
	blocker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { blocker.Close() })
	return uint16(blocker.LocalAddr().(*net.UDPAddr).Port)
}

// CloseSessions は bind に失敗した待ち受けを飛ばす。本番では CloseSessions を呼ぶ vpsd が Apply の
// 経路を使わないので、表に bind に失敗した待ち受けは入らないが、入っていても panic しない。
func TestCloseSessionsSkipsAnUnboundListener(t *testing.T) {
	m := New(&loopback{}, Options{Logf: testLogf(t)})
	defer m.Close()
	k := Key{proto.UDP, blockedUDP(t)}
	m.Apply(map[Key]Desired{k: {"127.0.0.1:9", "r1"}})
	if st := m.Status(); len(st) != 1 || st[0].Listening {
		t.Fatalf("setup: status = %+v, want one listener that failed to bind", st)
	}
	if n := m.CloseSessions(func(string, netip.Addr) bool { return false }); n != 0 {
		t.Errorf("CloseSessions = %d, want 0", n)
	}
}

// retireLocked は bind に失敗した待ち受けの stopAccept と sweep を呼ばず、Prepare はそれを再開の
// 対象にせず bind し直す。本番では Apply と Prepare の経路を混ぜないのでこの状態に至らないが、
// 試験は Apply で作った待ち受けを直接 Retiring にして、その分岐を確かめる。
func TestRetireAndPrepareSkipAnUnboundListener(t *testing.T) {
	r := newTransitionRig(t)
	k := Key{proto.UDP, blockedUDP(t)}
	r.m.Apply(map[Key]Desired{k: {"127.0.0.1:9", "r_x"}})
	// 錠は defer で放す。retireLocked が panic しても、後片付けの Close が錠を待ち続けない
	func() {
		r.m.mu.Lock()
		defer r.m.mu.Unlock()
		l := r.m.listeners[k]
		if l == nil || l.bindErr == nil {
			t.Fatalf("setup: the listener must have failed to bind: %+v", l)
		}
		r.m.retireLocked(k, l, func(netip.Addr) bool { return false })
	}()
	if !r.logged("listener " + k.String() + " stopped accepting: rule r_x is not active; closed 0 flows") {
		t.Error("retireLocked did not log the retired unbound listener with 0 closed flows")
	}

	s := r.m.Prepare(map[Key]Desired{k: {"127.0.0.1:9", "r_x"}})
	defer s.Rollback()
	if s.revived[k] {
		t.Error("Prepare revived an unbound retiring listener instead of binding the port again")
	}
	if _, failed := s.Failed()["r_x"]; !failed {
		t.Errorf("failed = %v; Prepare did not try to bind the blocked port", s.Failed())
	}
	r.check()
}

// bind に失敗した TCP の待ち受けには、Apply も Retry も到達確認をしない。確認すれば、待ち受けの無い
// ルールのために宛先へ接続し、届かない宛先なら targetErr を書く。
func TestProbeSkipsAnUnboundListener(t *testing.T) {
	blocker, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	k := Key{proto.TCP, uint16(blocker.Addr().(*net.TCPAddr).Port)}
	ip, port := closedTarget(t)
	target := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	var dials atomic.Int64
	m := New(&loopback{}, Options{Logf: testLogf(t), Dial: func(network, addr string) (net.Conn, error) {
		dials.Add(1)
		return net.Dial(network, addr)
	}})
	defer m.Close()

	m.Apply(map[Key]Desired{k: {target, "r1"}})
	m.Retry() // ポートはふさがったままなので、開き直しもまた失敗する
	if n := dials.Load(); n != 0 {
		t.Errorf("dialed the target %d times for a listener that never bound, want 0", n)
	}
	m.mu.Lock()
	l := m.listeners[k]
	var bindErr, targetErr error
	if l != nil {
		bindErr, targetErr = l.bindErr, l.targetErr
	}
	m.mu.Unlock()
	if bindErr == nil {
		t.Fatal("setup: the listener must have failed to bind")
	}
	if targetErr != nil {
		t.Errorf("targetErr = %v, want nil: a listener that never bound was probed", targetErr)
	}
}

// bind に失敗した待ち受けは中継のフローを持たないので、Status の Sessions と Flows は 0 である。
// 宣言から消えた待ち受けは、何もしない closeF の後に枠を閉じて表から消える(shutdownLocked)。
func TestUnboundListenerReportsNoSessionsAndClosesItsBudget(t *testing.T) {
	tcpBlocker, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpBlocker.Close()
	for _, k := range []Key{
		{proto.UDP, blockedUDP(t)},
		{proto.TCP, uint16(tcpBlocker.Addr().(*net.TCPAddr).Port)},
	} {
		t.Run(string(k.Proto), func(t *testing.T) {
			r := newTransitionRig(t)
			r.m.Apply(map[Key]Desired{k: {"127.0.0.1:9", "r_x"}})
			r.m.mu.Lock()
			old := r.m.listeners[k]
			r.m.mu.Unlock()
			if old == nil || old.bound() {
				t.Fatalf("setup: the listener must have failed to bind: %+v", old)
			}
			st := r.m.Status()
			if len(st) != 1 || st[0].Listening || st[0].Sessions != 0 || st[0].Flows != 0 {
				t.Fatalf("status = %+v, want one listener that failed to bind with no sessions and no flows", st)
			}

			r.m.Apply(map[Key]Desired{})
			if st := r.m.Status(); len(st) != 0 {
				t.Fatalf("status after the rule went away = %+v, want none", st)
			}
			old.budget.Accept()
			if hasRule(r.pool(k), "r_x") {
				t.Errorf("rules %v: the closed listener's budget accepted again, so it was not closed", rules(r.pool(k)))
			}
			r.check()
		})
	}
}
