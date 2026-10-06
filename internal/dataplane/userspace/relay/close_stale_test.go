package relay

import (
	"net"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// Close より前に Prepare した Staged を Close の後に Commit しても、待ち受けは公開されず、Prepare で
// bind したソケットは閉じる。公開すると、Close の後にその待ち受けを閉じる経路が無い。
func TestStagedCommitAfterCloseReleasesSockets(t *testing.T) {
	lb := &loopback{}
	port := reserveTCP(t, lb)
	m := New(lb, Options{Logf: testLogf(t)})
	s := m.Prepare(map[Key]Desired{{Proto: proto.TCP, Port: port}: {Target: "127.0.0.1:9", RuleID: "r"}})
	m.Close()
	s.Commit(nil)
	if st := m.Status(); len(st) != 0 {
		t.Errorf("Commit after Close published %v", st)
	}
	// Prepare で bind したソケットが閉じていれば、同じポートをもう一度 bind できる
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatalf("the socket bound by Prepare is still open: %v", err)
	}
	ln.Close()
}

// Retiring の UDP の待ち受けを宣言に戻す Staged を、Close の後に Commit しても、閉じた待ち受けを
// 再開しない(Close が retiring の表から消した待ち受けを探して nil を参照しない)。
func TestStagedReviveAfterCloseOpensNothing(t *testing.T) {
	r := newTransitionRig(t)
	k, _, _ := retiringUDP(t, r)
	r.m.mu.Lock()
	echo := r.m.retiring[k].target
	r.m.mu.Unlock()
	s := r.m.Prepare(map[Key]Desired{k: {echo, "r_u"}})
	r.m.Close()
	s.Commit(nil)
	if st := r.m.Status(); len(st) != 0 {
		t.Errorf("Commit after Close published %v", st)
	}
	r.check()
}

// Close の後の Apply は待ち受けを開かない。
func TestApplyAfterCloseOpensNothing(t *testing.T) {
	lb := &loopback{}
	port := reserveTCP(t, lb)
	m := New(lb, Options{Logf: testLogf(t)})
	m.Close()
	if acts := m.Apply(map[Key]Desired{{Proto: proto.TCP, Port: port}: {Target: "127.0.0.1:9", RuleID: "r"}}); len(acts) != 0 {
		t.Errorf("Apply after Close returned %v", acts)
	}
	if st := m.Status(); len(st) != 0 {
		t.Errorf("Apply after Close published %v", st)
	}
}
