package relay

// 待ち受けの状態遷移 (閉じる、Retiring の待ち受けを閉じる、所属ルールの付け替え、Retiring からの再開) が、
// 呼ぶ位置で何をどの順に変えるかを確かめる。
//
//   - 閉じる遷移は、Manager の mu を持ったまま closeF を呼ぶ。closeF の時点では、待ち受けはまだ自分の表
//     (listeners か retiring) にあり、受け付けている待ち受けなら Pool の登録もまだある。その後に枠を外し、
//     表から消す。遷移の後は待ち受けソケットと成立済みのフローが閉じ、ポートは bind し直せる
//   - 付け替えは、relay の ruleID と Pool の登録のルールを対で変える。Commit の付け替えは、その後に呼ぶ
//     testHookCommitStep の時点で両方が済んでいる
//   - 再開は、Retiring の表から外し、宣言のルールへ付け替え、受け付けの印を立て、testHookRevive を呼び、
//     Pool の Accept を呼び、listeners の表へ入れる。どれも Manager の mu の中で行う

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

type transitionRig struct {
	t    *testing.T
	m    *Manager
	tcp  *resource.Pool
	udp  *resource.Pool
	lb   *loopback
	mu   sync.Mutex
	logs []string
}

func newTransitionRig(t *testing.T) *transitionRig {
	t.Helper()
	r := &transitionRig{t: t, tcp: resource.NewPool(64), udp: resource.NewPool(64), lb: &loopback{}}
	logf := testLogf(t)
	r.m = New(r.lb, Options{TCPPool: r.tcp, UDPPool: r.udp, UDPIdleTimeout: time.Hour, Logf: func(format string, args ...any) {
		r.mu.Lock()
		r.logs = append(r.logs, fmt.Sprintf(format, args...))
		r.mu.Unlock()
		logf(format, args...)
	}})
	t.Cleanup(r.m.Close)
	return r
}

func (r *transitionRig) pool(k Key) *resource.Pool {
	if k.Proto == proto.TCP {
		return r.tcp
	}
	return r.udp
}

func (r *transitionRig) logged(sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.logs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// commit は Prepare と Commit を 1 回で行う。失敗するルールがあれば、それを Retiring として keep で渡す。
func (r *transitionRig) commit(desired map[Key]Desired, keep bool) {
	r.t.Helper()
	s := r.m.Prepare(desired)
	retiring := map[string]func(netip.Addr) bool{}
	for id := range s.Failed() {
		retiring[id] = func(netip.Addr) bool { return keep }
	}
	s.Commit(retiring)
	r.check()
}

func (r *transitionRig) check() {
	r.t.Helper()
	checkPool(r.t, r.tcp)
	checkPool(r.t, r.udp)
}

// rules は Pool に今ある登録のルール ID (受け付けている待ち受けを持つルール)。
func rules(p *resource.Pool) []string {
	var out []string
	for id := range p.Ledger().RegSerial {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func hasRule(p *resource.Pool, id string) bool {
	_, ok := p.Ledger().RegSerial[id]
	return ok
}

// closeWatch は、1 つの待ち受けの closeF が呼ばれた時点の状態の記録。
type closeWatch struct {
	mu    sync.Mutex
	calls int
	// locked は Manager の mu が持たれていたか。
	locked bool
	// listenerAt と retiringAt は、そのキーの listeners と retiring の表の中身。
	listenerAt, retiringAt *listener
	// rules はその時点で Pool に登録のあるルール。
	rules []string
}

func (w *closeWatch) snapshot() closeWatch {
	w.mu.Lock()
	defer w.mu.Unlock()
	return closeWatch{calls: w.calls, locked: w.locked, listenerAt: w.listenerAt, retiringAt: w.retiringAt, rules: w.rules}
}

// watchClose は、キー k の待ち受け (retiring なら Retiring の表のもの) の closeF を、呼ばれた時点の
// 状態を記録してから元の closeF を呼ぶものに差し替える。
func (r *transitionRig) watchClose(k Key, retiring bool) (*listener, *closeWatch) {
	r.t.Helper()
	m := r.m
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.listeners[k]
	if retiring {
		l = m.retiring[k]
	}
	if l == nil {
		r.t.Fatalf("no listener for %s (retiring %v)", k, retiring)
	}
	w := &closeWatch{}
	orig := l.closeF
	pool := r.pool(k)
	l.closeF = func() {
		// 呼び出し側が mu を持っていれば TryLock は失敗する。成功したら mu の外で呼ばれたので、
		// 記録を取ってから放す
		locked := !m.mu.TryLock()
		w.mu.Lock()
		w.calls++
		w.locked = locked
		w.listenerAt = m.listeners[k]
		w.retiringAt = m.retiring[k]
		w.rules = rules(pool)
		w.mu.Unlock()
		if !locked {
			m.mu.Unlock()
		}
		orig()
	}
	return l, w
}

func containsRule(rs []string, id string) bool {
	for _, r := range rs {
		if r == id {
			return true
		}
	}
	return false
}

// tcpClosed は、中継が c を閉じたか (読み取りが期限切れでない誤りで終わるか) を返す。
func tcpClosed(c net.Conn) bool {
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

// rebindable は、ポートをもう一度 bind できるか (中継が待ち受けのソケットを閉じたか) を返す。
func rebindable(k Key) bool {
	if k.Proto == proto.TCP {
		l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(k.Port)})
		if err != nil {
			return false
		}
		l.Close()
		return true
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(k.Port)})
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func udpClient(t *testing.T, k Key) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(k.Port)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func tcpClient(t *testing.T, k Key) net.Conn {
	t.Helper()
	c, err := dialLoopback(k.Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if got, err := echoLine(c, "x"); err != nil || got != "x\n" {
		t.Fatalf("echo = %q, %v", got, err)
	}
	c.SetDeadline(time.Time{})
	return c
}

// wantActiveClose は、受け付けている待ち受け l の閉じる遷移の closeF の時点の記録を確かめる。
func wantActiveClose(t *testing.T, w *closeWatch, l *listener, rule string) {
	t.Helper()
	s := w.snapshot()
	if s.calls != 1 {
		t.Fatalf("closeF called %d times, want 1", s.calls)
	}
	if !s.locked {
		t.Error("closeF ran without the Manager lock")
	}
	if s.listenerAt != l {
		t.Error("the listener left the listeners table before closeF")
	}
	if s.retiringAt != nil {
		t.Error("a retiring listener appeared at the key before closeF")
	}
	if !containsRule(s.rules, rule) {
		t.Errorf("rules at closeF = %v; the budget of %s was closed before closeF", s.rules, rule)
	}
}

// 受け付けている待ち受けを閉じる遷移: Apply の close と reopen、Commit の close、Manager.Close。
func TestCloseTransition(t *testing.T) {
	t.Run("apply close", func(t *testing.T) {
		r := newTransitionRig(t)
		k := Key{proto.TCP, reserveTCP(t, r.lb)}
		r.m.Apply(map[Key]Desired{k: {tcpEcho(t), "r_a"}})
		c := tcpClient(t, k)
		l, w := r.watchClose(k, false)
		r.m.Apply(map[Key]Desired{})
		r.check()
		wantActiveClose(t, w, l, "r_a")
		wantClosedActive(t, r, k, c, "r_a")
	})
	t.Run("apply reopen", func(t *testing.T) {
		r := newTransitionRig(t)
		k := Key{proto.TCP, reserveTCP(t, r.lb)}
		r.m.Apply(map[Key]Desired{k: {tcpEcho(t), "r_a"}})
		c := tcpClient(t, k)
		l, w := r.watchClose(k, false)
		target2 := tcpEcho(t)
		acts := r.m.Apply(map[Key]Desired{k: {target2, "r_a"}})
		r.check()
		if len(acts) != 1 || acts[0].Op != "reopen" {
			t.Fatalf("actions %v, want one reopen", acts)
		}
		wantActiveClose(t, w, l, "r_a")
		if !tcpClosed(c) {
			t.Error("the reopen did not close the established connection")
		}
		r.m.mu.Lock()
		nl := r.m.listeners[k]
		r.m.mu.Unlock()
		if nl == nil || nl == l || nl.target != target2 {
			t.Errorf("listener after reopen = %+v, want a new one to %s", nl, target2)
		}
		if !hasRule(r.tcp, "r_a") {
			t.Error("the reopened listener is not registered")
		}
	})
	t.Run("commit close", func(t *testing.T) {
		r := newTransitionRig(t)
		k := Key{proto.TCP, reserveTCP(t, r.lb)}
		r.commit(map[Key]Desired{k: {tcpEcho(t), "r_a"}}, true)
		c := tcpClient(t, k)
		l, w := r.watchClose(k, false)
		r.commit(map[Key]Desired{}, true)
		wantActiveClose(t, w, l, "r_a")
		wantClosedActive(t, r, k, c, "r_a")
	})
	t.Run("manager close", func(t *testing.T) {
		r := newTransitionRig(t)
		k := Key{proto.TCP, reserveTCP(t, r.lb)}
		r.commit(map[Key]Desired{k: {tcpEcho(t), "r_a"}}, true)
		c := tcpClient(t, k)
		l, w := r.watchClose(k, false)
		r.m.Close()
		r.check()
		wantActiveClose(t, w, l, "r_a")
		wantClosedActive(t, r, k, c, "r_a")
	})
}

// wantClosedActive は、閉じる遷移の後の状態を確かめる: 表から消え、枠を外し、成立済みの接続を切り、
// ポートを放した。
func wantClosedActive(t *testing.T, r *transitionRig, k Key, c net.Conn, rule string) {
	t.Helper()
	r.m.mu.Lock()
	_, inL := r.m.listeners[k]
	_, inR := r.m.retiring[k]
	r.m.mu.Unlock()
	if inL || inR {
		t.Errorf("after close: in listeners %v, in retiring %v", inL, inR)
	}
	if hasRule(r.tcp, rule) {
		t.Errorf("after close: rules %v still hold %s", rules(r.tcp), rule)
	}
	if !tcpClosed(c) {
		t.Error("after close: the established connection is still open")
	}
	if !rebindable(k) {
		t.Errorf("after close: port %d is still bound", k.Port)
	}
	if !r.logged(fmt.Sprintf("listener %s closed", k)) {
		t.Error("after close: no close log")
	}
}

// retiringUDP は、UDP の待ち受けを 1 つ開き、成立済みのセッションを 1 つ持たせてから Retiring にする。
func retiringUDP(t *testing.T, r *transitionRig) (k, blocked Key, keeper *net.UDPConn) {
	t.Helper()
	echo, _ := udpEcho(t)
	k = Key{proto.UDP, reserveUDP(t, r.lb)}
	b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	blocked = Key{proto.UDP, uint16(b.LocalAddr().(*net.UDPAddr).Port)}
	r.commit(map[Key]Desired{k: {echo, "r_u"}}, true)
	keeper = udpClient(t, k)
	if !udpRoundTrip(keeper, 2*time.Second) {
		t.Fatal("keeper session not relayed")
	}
	r.commit(map[Key]Desired{blocked: {echo, "r_u"}}, true)
	if got := r.m.Retiring(); len(got) != 1 || got[0] != k {
		t.Fatalf("Retiring = %v, want %s", got, k)
	}
	return k, blocked, keeper
}

// wantRetiringClose は、Retiring の待ち受け l を閉じる遷移の closeF の時点の記録を確かめる。
func wantRetiringClose(t *testing.T, w *closeWatch, l *listener) {
	t.Helper()
	s := w.snapshot()
	if s.calls != 1 {
		t.Fatalf("closeF called %d times, want 1", s.calls)
	}
	if !s.locked {
		t.Error("closeF ran without the Manager lock")
	}
	if s.retiringAt != l {
		t.Error("the listener left the retiring table before closeF")
	}
	if s.listenerAt != nil {
		t.Error("an active listener appeared at the key before closeF")
	}
}

func wantClosedRetiring(t *testing.T, r *transitionRig, k Key, l *listener) {
	t.Helper()
	if got := r.m.Retiring(); len(got) != 0 {
		t.Errorf("Retiring after close = %v, want none", got)
	}
	if n := l.sessions(); n != 0 {
		t.Errorf("sessions after close = %d, want 0", n)
	}
	if !rebindable(k) {
		t.Errorf("port %d is still bound after close", k.Port)
	}
	r.m.mu.Lock()
	_, inL := r.m.listeners[k]
	r.m.mu.Unlock()
	if inL {
		t.Error("the closed retiring listener is in the listeners table")
	}
}

// Retiring の待ち受けを閉じる遷移: Commit の 2 つの経路 (ルールがもう Retiring でない、成立済みのフローが
// 残っていない) と Manager.Close。
func TestRetiringCloseTransition(t *testing.T) {
	t.Run("rule no longer retiring", func(t *testing.T) {
		r := newTransitionRig(t)
		k, _, _ := retiringUDP(t, r)
		l, w := r.watchClose(k, true)
		r.commit(map[Key]Desired{}, true)
		wantRetiringClose(t, w, l)
		wantClosedRetiring(t, r, k, l)
		if !r.logged(fmt.Sprintf("listener %s closed: rule r_u is no longer retiring", k)) {
			t.Error("no log for the closed retiring listener")
		}
	})
	t.Run("no flows left", func(t *testing.T) {
		r := newTransitionRig(t)
		k, blocked, _ := retiringUDP(t, r)
		l, w := r.watchClose(k, true)
		echo := l.target
		r.commit(map[Key]Desired{blocked: {echo, "r_u"}}, false)
		wantRetiringClose(t, w, l)
		wantClosedRetiring(t, r, k, l)
		if !r.logged(fmt.Sprintf("listener %s closed: no established flows left", k)) {
			t.Error("no log for the closed retiring listener")
		}
	})
	t.Run("manager close", func(t *testing.T) {
		r := newTransitionRig(t)
		k, _, _ := retiringUDP(t, r)
		l, w := r.watchClose(k, true)
		r.m.Close()
		r.check()
		wantRetiringClose(t, w, l)
		wantClosedRetiring(t, r, k, l)
		deadline := time.Now().Add(5 * time.Second)
		for r.udp.InUse() != 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if lg := checkPool(t, r.udp); lg.InUse != 0 || lg.RetiredFlows != 0 {
			t.Errorf("after Close: in use %d, retired flows %d; want the retiring session's slot back", lg.InUse, lg.RetiredFlows)
		}
	})
}

// 同じ TCP のポートを 2 回 fail-closed にすると、retireLocked は古い Retiring の待ち受けを閉じてから
// 新しい待ち受けの受け付けをやめる。
func TestRetireTwiceClosesTheOlderRetiring(t *testing.T) {
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
	c1 := tcpClient(t, k)
	r.commit(map[Key]Desired{blocked: {echo, "r_x"}}, true) // 1 回目の Retiring
	// r_x を Retiring のまま、同じポートに新しい待ち受けを開く (Retiring の TCP の待ち受けは
	// 待ち受けソケットを閉じているので、bind し直せる)
	r.m.Prepare(map[Key]Desired{k: {echo, "r_x"}}).Commit(keepAll)
	r.check()
	c2 := tcpClient(t, k)
	r.m.mu.Lock()
	cur := r.m.listeners[k]
	r.m.mu.Unlock()
	if cur == nil {
		t.Fatal("no active listener after reopening the port")
	}
	old, w := r.watchClose(k, true)
	r.commit(map[Key]Desired{blocked: {echo, "r_x"}}, true) // 2 回目の Retiring

	s := w.snapshot()
	if s.calls != 1 || !s.locked {
		t.Fatalf("old closeF: calls %d locked %v", s.calls, s.locked)
	}
	if s.listenerAt != nil {
		t.Error("the new listener was still in the listeners table when the old retiring one closed")
	}
	if s.retiringAt != old {
		t.Error("the old retiring listener was replaced before it closed")
	}
	if !containsRule(s.rules, "r_x") {
		t.Errorf("rules at the old closeF = %v; the new listener stopped accepting before the old one closed", s.rules)
	}
	if !tcpClosed(c1) {
		t.Error("the old retiring listener's connection is still open")
	}
	if got, err := echoLine(c2, "kept"); err != nil || got != "kept\n" {
		t.Errorf("the new retiring listener's connection: %q, %v", got, err)
	}
	r.m.mu.Lock()
	now := r.m.retiring[k]
	r.m.mu.Unlock()
	if now != cur {
		t.Error("the retiring table does not hold the newer listener")
	}
	if hasRule(r.tcp, "r_x") {
		t.Errorf("rules %v: the newer listener still accepts", rules(r.tcp))
	}
}

// 所属ルールの付け替え: relay の ruleID と Pool の登録のルールが対で変わる。
func TestSetRuleTransition(t *testing.T) {
	wantRelabelled := func(t *testing.T, r *transitionRig, k Key, c net.Conn, target string) {
		t.Helper()
		st := r.m.Status()
		if len(st) != 1 || st[0].RuleID != "r_b" || st[0].Target != target {
			t.Errorf("status %+v, want rule r_b to %s", st, target)
		}
		lg := checkPool(t, r.tcp)
		if got := rules(r.tcp); len(got) != 1 || got[0] != "r_b" {
			t.Errorf("rules %v, want [r_b]", got)
		}
		if c != nil && (lg.RegCarried["r_b"] != 1 || lg.RegFlows["r_b"] != 1) {
			t.Errorf("ledger %+v; the established connection did not move to r_b", lg)
		}
	}
	// stepHook は、Commit の付け替えの直後に呼ぶ差し込み口で、付け替えが mu の中で済んでいることを確かめる。
	stepHook := func(t *testing.T, r *transitionRig, want string, seen *atomic.Int32) {
		r.m.testHookCommitStep = func(k Key, op string) {
			if op != want {
				return
			}
			seen.Add(1)
			if r.m.mu.TryLock() {
				r.m.mu.Unlock()
				t.Error("the step hook ran without the Manager lock")
				return
			}
			l := r.m.listeners[k]
			if l == nil || l.ruleID != "r_b" {
				t.Errorf("at the %s step the listener is %+v, want rule r_b", op, l)
			}
			if got := rules(r.tcp); len(got) != 1 || got[0] != "r_b" {
				t.Errorf("at the %s step rules = %v, want [r_b]", op, got)
			}
		}
	}
	t.Run("apply relabel", func(t *testing.T) {
		r := newTransitionRig(t)
		echo := tcpEcho(t)
		k := Key{proto.TCP, reserveTCP(t, r.lb)}
		r.m.Apply(map[Key]Desired{k: {echo, "r_a"}})
		c := tcpClient(t, k)
		acts := r.m.Apply(map[Key]Desired{k: {echo, "r_b"}})
		if len(acts) != 1 || acts[0].Op != "relabel" {
			t.Fatalf("actions %v, want one relabel", acts)
		}
		wantRelabelled(t, r, k, c, echo)
		if got, err := echoLine(c, "kept"); err != nil || got != "kept\n" {
			t.Errorf("the relabel cut the connection: %q, %v", got, err)
		}
	})
	t.Run("commit relabel", func(t *testing.T) {
		r := newTransitionRig(t)
		echo := tcpEcho(t)
		k := Key{proto.TCP, reserveTCP(t, r.lb)}
		r.commit(map[Key]Desired{k: {echo, "r_a"}}, true)
		c := tcpClient(t, k)
		var seen atomic.Int32
		stepHook(t, r, "relabel", &seen)
		r.commit(map[Key]Desired{k: {echo, "r_b"}}, true)
		if seen.Load() != 1 {
			t.Fatalf("relabel steps %d, want 1", seen.Load())
		}
		wantRelabelled(t, r, k, c, echo)
		if got, err := echoLine(c, "kept"); err != nil || got != "kept\n" {
			t.Errorf("the relabel cut the connection: %q, %v", got, err)
		}
	})
	t.Run("commit retarget", func(t *testing.T) {
		r := newTransitionRig(t)
		k := Key{proto.TCP, reserveTCP(t, r.lb)}
		r.commit(map[Key]Desired{k: {tcpEcho(t), "r_a"}}, true)
		c := tcpClient(t, k)
		var seen atomic.Int32
		stepHook(t, r, "retarget", &seen)
		target2 := tcpEcho(t)
		r.commit(map[Key]Desired{k: {target2, "r_b"}}, true)
		if seen.Load() != 1 {
			t.Fatalf("retarget steps %d, want 1", seen.Load())
		}
		if !tcpClosed(c) {
			t.Error("the retarget did not close the established connection")
		}
		deadline := time.Now().Add(5 * time.Second)
		for r.tcp.InUse() != 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		wantRelabelled(t, r, k, nil, target2)
		c2 := tcpClient(t, k)
		if got, err := echoLine(c2, "new"); err != nil || got != "new\n" {
			t.Errorf("through the new target: %q, %v", got, err)
		}
		if lg := checkPool(t, r.tcp); lg.RegFlows["r_b"] != 1 || lg.RegCarried["r_b"] != 1 {
			t.Errorf("ledger %+v, want the new connection under r_b", lg)
		}
	})
}

// Apply の付け替えを、接続を受け付け続ける間に繰り返す。帳簿は付け替えのたびに整合し、-race では
// 付け替えが Manager の mu の外で ruleID を書けば検出する。
func TestApplyRelabelUnderTraffic(t *testing.T) {
	r := newTransitionRig(t)
	echo := tcpEcho(t)
	k := Key{proto.TCP, reserveTCP(t, r.lb)}
	r.m.Apply(map[Key]Desired{k: {echo, "r_a"}})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var relayed, budget atomic.Int64
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// 一時ポートを使い切らないよう、1 回の実行の接続を 600 までにし、間を空ける
				if budget.Add(1) > 600 {
					return
				}
				time.Sleep(time.Millisecond)
				c, err := dialLoopback(k.Port)
				if err != nil {
					continue
				}
				if got, err := echoLine(c, "x"); err == nil && got == "x\n" {
					relayed.Add(1)
				}
				c.Close()
			}
		}()
	}
	deadline := time.Now().Add(time.Second)
	n := 0
	for time.Now().Before(deadline) {
		rule := "r_a"
		if n%2 == 0 {
			rule = "r_b"
		}
		r.m.Apply(map[Key]Desired{k: {echo, rule}})
		r.check()
		n++
		time.Sleep(2 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if relayed.Load() == 0 {
		t.Error("no connection was relayed during the relabels")
	}
	t.Logf("relabels=%d relayed=%d", n, relayed.Load())
}

// Retiring からの再開の順: Retiring の表から外し、宣言のルールへ付け替え、受け付けの印を立ててから
// testHookRevive を呼び、Pool の Accept の後に listeners の表へ入れる。どれも Manager の mu の中で行う。
func TestReviveTransition(t *testing.T) {
	for _, rule := range []string{"r_u", "r_v"} {
		t.Run("revive as "+rule, func(t *testing.T) {
			r := newTransitionRig(t)
			k, _, keeper := retiringUDP(t, r)
			r.m.mu.Lock()
			l := r.m.retiring[k]
			echo := l.target
			r.m.mu.Unlock()
			var calls atomic.Int32
			r.m.testHookRevive = func(hl *listener) {
				calls.Add(1)
				if r.m.mu.TryLock() {
					r.m.mu.Unlock()
					t.Error("the revive ran without the Manager lock")
					return
				}
				if hl != l {
					t.Error("the revive hook got another listener")
				}
				if r.m.retiring[k] != nil {
					t.Error("the listener was still in the retiring table at the revive hook")
				}
				if r.m.listeners[k] != nil {
					t.Error("the listener entered the listeners table before Pool.Accept")
				}
				if l.ruleID != rule {
					t.Errorf("rule at the revive hook = %s, want %s", l.ruleID, rule)
				}
				if !l.accepting.Load() {
					t.Error("the accepting flag was not set before the revive hook")
				}
				if hasRule(r.udp, rule) {
					t.Errorf("rules at the revive hook = %v; Pool.Accept ran before it", rules(r.udp))
				}
			}
			r.commit(map[Key]Desired{k: {echo, rule}}, true)
			if calls.Load() != 1 {
				t.Fatalf("revive hook calls %d, want 1", calls.Load())
			}
			r.m.mu.Lock()
			now := r.m.listeners[k]
			r.m.mu.Unlock()
			if now != l {
				t.Error("the revived listener is not the kept one")
			}
			if got := r.m.Retiring(); len(got) != 0 {
				t.Errorf("Retiring = %v, want none", got)
			}
			lg := checkPool(t, r.udp)
			if lg.RegFlows[rule] != 1 || lg.RegCarried[rule] != 1 || lg.RetiredFlows != 0 {
				t.Errorf("ledger %+v, want the kept session under %s", lg, rule)
			}
			if st := r.m.Status(); len(st) != 1 || st[0].RuleID != rule {
				t.Errorf("status %+v, want rule %s", st, rule)
			}
			if !udpRoundTrip(keeper, 2*time.Second) {
				t.Error("the kept session stopped")
			}
			if !udpRoundTrip(udpClient(t, k), 2*time.Second) {
				t.Error("a new source is not relayed after the revive")
			}
			if !r.logged(fmt.Sprintf("listener %s accepting again", k)) {
				t.Error("no revive log")
			}
		})
	}
}
