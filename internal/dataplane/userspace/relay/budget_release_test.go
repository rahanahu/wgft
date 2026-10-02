package relay

import (
	"net"
	"net/netip"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// 置き換えられた古い待ち受けの budget が閉じていることを確かめる。
//
// 受け付けていない待ち受け(Retiring と、bind に失敗した待ち受け)は、すでに Pool の登録から外れて
// いるので、budget.Close が登録に与える変化は今は見えない。違いが出るのは、閉じていない budget へ
// Accept を呼んだときである。閉じていなければ、置き換えられた待ち受けが Pool の登録に加わり直す。
// 閉じていれば、Accept は何もしない。この 2 つの試験は、その Accept を置き換え後の古い待ち受けに
// 対して呼び、そのルールの登録が現れないことを見る。

// 同じ TCP のポートを 2 回 fail-closed にすると、retireLocked が古い Retiring の待ち受けを閉じる。
// その budget が閉じていなければ、閉じた待ち受けが再び登録に加われる。
func TestRetireReplacementClosesTheOldBudget(t *testing.T) {
	r := newTransitionRig(t)
	echo := tcpEcho(t)
	k := Key{proto.TCP, reserveTCP(t, r.lb)}
	blocker, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	blocked := Key{proto.TCP, uint16(blocker.Addr().(*net.TCPAddr).Port)}
	keepAll := map[string]func(netip.Addr) bool{"r_x": func(netip.Addr) bool { return true }}

	r.commit(map[Key]Desired{k: {echo, "r_x"}}, true)
	// 成立済みの接続が残るあいだだけ、Retiring の待ち受けは閉じない
	tcpClient(t, k)
	r.commit(map[Key]Desired{blocked: {echo, "r_x"}}, true) // 1 回目の Retiring
	r.m.Prepare(map[Key]Desired{k: {echo, "r_x"}}).Commit(keepAll)
	r.check()
	tcpClient(t, k)
	r.m.mu.Lock()
	old := r.m.retiring[k]
	cur := r.m.listeners[k]
	r.m.mu.Unlock()
	if old == nil || cur == nil || old == cur {
		t.Fatalf("setup: old retiring %v, active %v", old, cur)
	}
	r.commit(map[Key]Desired{blocked: {echo, "r_x"}}, true) // 2 回目の Retiring。古いほうが閉じる
	r.m.mu.Lock()
	now := r.m.retiring[k]
	r.m.mu.Unlock()
	if now != cur {
		t.Fatal("the retiring table does not hold the newer listener")
	}
	if hasRule(r.tcp, "r_x") {
		t.Fatalf("rules %v: a retiring listener is registered before the probe", rules(r.tcp))
	}

	old.budget.Accept()
	if hasRule(r.tcp, "r_x") {
		t.Errorf("rules %v: the replaced retiring listener's budget accepted again, so it was not closed", rules(r.tcp))
	}
	r.check()
}

// bind に失敗した待ち受けを Retry が開き直すとき、古い待ち受けの budget を閉じてから表から消す。
// 開き直しがまた失敗しても、古い待ち受けは置き換えられている。その budget が閉じていなければ、
// 置き換えられた待ち受けが登録に加われる。
func TestRetryReplacementClosesTheOldBudget(t *testing.T) {
	r := newTransitionRig(t)
	echo := tcpEcho(t)
	blocker, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	k := Key{proto.TCP, uint16(blocker.Addr().(*net.TCPAddr).Port)}

	r.m.Apply(map[Key]Desired{k: {echo, "r_x"}})
	r.m.mu.Lock()
	old := r.m.listeners[k]
	r.m.mu.Unlock()
	if old == nil || old.bindErr == nil {
		t.Fatalf("setup: the listener must have failed to bind: %+v", old)
	}

	r.m.Retry() // ポートはふさがったままなので、開き直しもまた失敗する
	r.m.mu.Lock()
	cur := r.m.listeners[k]
	r.m.mu.Unlock()
	if cur == nil || cur == old || cur.bindErr == nil {
		t.Fatalf("Retry did not replace the failed listener with a new failed one: %+v", cur)
	}
	if hasRule(r.tcp, "r_x") {
		t.Fatalf("rules %v: a listener that never bound is registered before the probe", rules(r.tcp))
	}

	old.budget.Accept()
	if hasRule(r.tcp, "r_x") {
		t.Errorf("rules %v: the replaced listener's budget accepted again, so it was not closed", rules(r.tcp))
	}
	r.check()
}
