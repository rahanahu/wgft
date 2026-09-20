package proxyrelay

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/internal/policy/goengine"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// ルールごとの上限は、明示しなければ Cap.Total から導く(resource.Limits.TCPPerRuleCap、仕様 7 節)。
func TestConnsMaxDefaultsFromCapTotal(t *testing.T) {
	m := New(Options{Cap: &resource.Counter{Total: 4000}})
	if m.opts.ConnsMax != 2000 {
		t.Errorf("ConnsMax = %d, want 2000 (half of Cap.Total)", m.opts.ConnsMax)
	}
	// Cap を渡さなければ既定の resource.TCPTotal(2048)から導き、導入前の固定値(1024)と一致する
	m = New(Options{})
	if m.opts.ConnsMax != 1024 {
		t.Errorf("default ConnsMax = %d, want 1024", m.opts.ConnsMax)
	}
	// 呼び出し側が明示すれば、それが勝つ
	m = New(Options{Cap: &resource.Counter{Total: 40}, ConnsMax: 3})
	if m.opts.ConnsMax != 3 {
		t.Errorf("explicit ConnsMax = %d, want 3 (must not be overridden by the derived default)", m.opts.ConnsMax)
	}
}

// fakeAgent は PROXY protocol を解する受信側(エージェント経由の先の Caddy 相当)。
// 受けた接続の「元クライアント IP」を ipCh に流し、受け取った行をそのまま返す。
func fakeAgent(t *testing.T) (addr string, ipCh chan string) {
	t.Helper()
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	ln := &proxyproto.Listener{Listener: raw, ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) { return proxyproto.USE, nil }}
	ipCh = make(chan string, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
				ipCh <- host
				b, _ := bufio.NewReader(c).ReadString('\n')
				c.Write([]byte("echo:" + b))
			}(c)
		}
	}()
	return raw.Addr().String(), ipCh
}

// managerFor は、公開側を loopback に開き、Dial を fakeAgent に向ける Manager を作る。
func managerFor(t *testing.T, agentAddr string) (*Manager, func() net.Conn) {
	t.Helper()
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pubAddr := raw.Addr().String()
	m := New(Options{
		Listen: func(uint16) (net.Listener, error) { return raw, nil },
		Dial:   func(string) (net.Conn, error) { return net.Dial("tcp", agentAddr) },
		Logf:   testLogf(t),
	})
	t.Cleanup(m.Close)
	dialPublic := func() net.Conn {
		c, err := net.Dial("tcp", pubAddr)
		if isReset(err) {
			// 拒否の RST(SetLinger(0))は、loopback では connect が戻る前に届くことがある。
			// Dial の reset も、Dial の後の Read の reset も同じ拒否なので、Read がその reset を
			// 返す接続にして渡す。成立するはずの接続がこれを受け取れば、Write や Read で落ちる。
			return resetConn{err: err}
		}
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	return m, dialPublic
}

func rule(pp bool, deny, allow []string) Rule {
	return Rule{ID: "r", ListenPort: 443, AgentAddr: netip.MustParseAddr("10.200.0.2"), AgentPort: 25565,
		ProxyProtocol: pp, Agent: "home", SourceDeny: prefixes(deny), SourceAllow: prefixes(allow)}
}
func prefixes(ss []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestProxyProtocolInjected(t *testing.T) {
	agentAddr, ipCh := fakeAgent(t)
	m, dialPublic := managerFor(t, agentAddr)
	m.Apply([]Rule{rule(true, nil, nil)})

	c := dialPublic()
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte("hi\n"))
	// 受信側が見る元クライアント IP は 127.0.0.1(この接続の実ピア)。PROXY ヘッダが素通しで届いている証拠
	select {
	case ip := <-ipCh:
		if ip != "127.0.0.1" {
			t.Errorf("agent saw src %q", ip)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent が接続を受けない")
	}
	out, _ := bufio.NewReader(c).ReadString('\n')
	if out != "echo:hi\n" {
		t.Errorf("echo = %q", out)
	}
}

func TestSourceDenyAtAccept(t *testing.T) {
	agentAddr, ipCh := fakeAgent(t)
	m, dialPublic := managerFor(t, agentAddr)
	// 127.0.0.0/8 を拒否 → 受け付けても即座に閉じ、エージェントには繋がない
	m.Apply([]Rule{rule(false, []string{"127.0.0.0/8"}, nil)})
	c := dialPublic()
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	// 拒否は SetLinger(0) の RST で即座に終える(仕様 6.3 節、design.md 7a.10 節 Phase 6 移行手順 3)。
	// グレースフルクローズ(通常の Close)なら次の Read は io.EOF になるので、そうでないことを見る。
	// RST が connect の戻る前に届いた場合は、dialPublic が同じ reset を Read で返す接続を渡す。
	if _, err := c.Read(make([]byte, 1)); !isReset(err) {
		t.Errorf("refused (source deny) connection: err = %v, want connection reset by peer", err)
	}
	select {
	case <-ipCh:
		t.Error("拒否された接続がエージェントに届いた")
	case <-time.After(300 * time.Millisecond):
	}
}

// 通常に終わる中継は、拒否と違って RST を送らず、これまでどおりグレースフルクローズ(EOF)で
// 終わることを確かめる(design.md 7a.10 節 Phase 6 移行手順 3。拒否だけが変わり、成立した中継の
// 通常のクローズは変えない)。
func TestNormalCloseEndsWithEOF(t *testing.T) {
	agentAddr, ipCh := fakeAgent(t)
	m, dialPublic := managerFor(t, agentAddr)
	m.Apply([]Rule{rule(false, nil, nil)})
	c := dialPublic()
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte("hi\n"))
	select {
	case <-ipCh:
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not receive the connection")
	}
	out, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || out != "echo:hi\n" {
		t.Fatalf("echo = %q, err = %v", out, err)
	}
	// fakeAgent は書き終えたら自分の側を閉じる。ハーフクローズ越しに伝わるのは FIN(EOF)であって
	// RST ではないことを見る。
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("normal close: err = %v, want io.EOF", err)
	}
}

// isReset は接続が RST で切られた誤りかを見る。Windows の WSAECONNRESET (10054) は
// syscall.ECONNRESET と別の値なので、数値でも比べる
// (internal/dataplane/userspace/relay の同名のテストヘルパーと同じ考え方)。
// resetConn は、Dial の時点で reset された接続の代わり。どの操作もその reset を返す。
type resetConn struct {
	net.Conn
	err error
}

func (c resetConn) Read([]byte) (int, error)         { return 0, c.err }
func (c resetConn) Write([]byte) (int, error)        { return 0, c.err }
func (c resetConn) Close() error                     { return nil }
func (c resetConn) SetDeadline(time.Time) error      { return nil }
func (c resetConn) SetReadDeadline(time.Time) error  { return nil }
func (c resetConn) SetWriteDeadline(time.Time) error { return nil }

func isReset(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == syscall.ECONNRESET || (runtime.GOOS == "windows" && errno == 10054)
}

func TestRestrictionChangeClosesLive(t *testing.T) {
	agentAddr, ipCh := fakeAgent(t)
	m, dialPublic := managerFor(t, agentAddr)
	m.Apply([]Rule{rule(false, nil, nil)}) // 最初は許可
	c := dialPublic()
	defer c.Close()
	c.Write([]byte("x\n"))
	select {
	case <-ipCh:
	case <-time.After(3 * time.Second):
		t.Fatal("最初の接続が通らない")
	}
	// 進行中に拒否を足す → その接続が閉じられる
	m.Apply([]Rule{rule(false, []string{"127.0.0.0/8"}, nil)})
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	// 相手(vpsd 側)が閉じるので、いずれ読みが EOF になる
	for {
		_, err := c.Read(buf)
		if err != nil {
			return // 期待どおり閉じられた
		}
	}
}

// 同時接続数の上限(仕様 7 節):超えた接続はエージェントに繋がずに閉じ、既存の接続が閉じれば枠が戻る。
func TestConnCap(t *testing.T) {
	agentAddr, ipCh := fakeAgent(t)
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// ユーザー空間モードと同じく、Admission Policy は Go の評価器が判定する
	cnt := &resource.Counter{Total: 10}
	eng := goengine.New(nil)
	eng.Update(policy.Policy{Rules: []policy.RulePolicy{{RuleID: "r", Proto: proto.TCP}}, PerSourceFlowCaps: policy.PerSourceFlowCaps{TCP: 1}})
	m := New(Options{
		Listen: func(uint16) (net.Listener, error) { return raw, nil },
		Dial:   func(string) (net.Conn, error) { return net.Dial("tcp", agentAddr) },
		Logf:   testLogf(t),
		Cap:    cnt,
		Admit: func(ruleID string, src netip.Addr) (func(), bool) {
			d, tk := eng.AdmitFlow(ruleID, src, 0)
			return tk.Release, d.Allow
		},
	})
	t.Cleanup(m.Close)
	m.Apply([]Rule{rule(true, nil, nil)}) // fakeAgent は PROXY ヘッダが届くまで接続元を返さない
	dial := func() net.Conn {
		c, err := net.Dial("tcp", raw.Addr().String())
		if isReset(err) {
			return resetConn{err: err} // 拒否の RST が connect の戻る前に届いた(managerFor と同じ扱い)
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	reached := func() bool {
		select {
		case <-ipCh:
			return true
		case <-time.After(300 * time.Millisecond):
			return false
		}
	}
	c1 := dial()
	if !reached() {
		t.Fatal("first connection must reach the agent")
	}
	c2 := dial()
	if reached() {
		t.Error("connection over the per-source limit reached the agent")
	}
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	// 上限を超えた接続は SetLinger(0) の RST で即座に終える(仕様 6.3 節、design.md 7a.10 節
	// Phase 6 移行手順 3)。以前はグレースフルクローズ(io.EOF)だった
	if _, err := c2.Read(make([]byte, 1)); !isReset(err) {
		t.Errorf("refused connection: err = %v, want connection reset by peer", err)
	}
	c1.Close()
	deadline := time.Now().Add(2 * time.Second)
	for cnt.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if cnt.Len() != 0 {
		t.Fatalf("counter after close = %d, want 0", cnt.Len())
	}
	if d := eng.Drops(); len(d) != 1 || d[0].RuleID != "r" || d[0].Kind != "src_flow" || d[0].Packets != 1 {
		t.Errorf("drops = %+v, want one src_flow drop of rule r", d)
	}
	// 評価器の枠は接続の後始末で返るので、返るまで試し直す
	for retry := 0; ; retry++ {
		dial()
		if reached() {
			break
		}
		if retry == 5 {
			t.Error("connection after a slot was freed must reach the agent")
			break
		}
	}
}

// admissionManager は、ユーザー空間モードの Relay の中継と同じ配線(Admission Policy のすべての段を
// Go の評価器が判定する。仕様 6.2 節)の Manager を作り、公開側へつなぐ関数と、その接続がエージェント
// まで届いたかを返す関数を返す。
func admissionManager(t *testing.T, eng *goengine.Engine) (dial func() net.Conn, reached func() bool) {
	t.Helper()
	agentAddr, ipCh := fakeAgent(t)
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := New(Options{
		Listen: func(uint16) (net.Listener, error) { return raw, nil },
		Dial:   func(string) (net.Conn, error) { return net.Dial("tcp", agentAddr) },
		Logf:   testLogf(t),
		Cap:    &resource.Counter{Total: 10},
		Admit: func(ruleID string, src netip.Addr) (func(), bool) {
			d, tk := eng.AdmitFlow(ruleID, src, 0)
			return tk.Release, d.Allow
		},
	})
	t.Cleanup(m.Close)
	m.Apply([]Rule{rule(true, nil, nil)}) // fakeAgent は PROXY ヘッダが届くまで接続元を返さない
	dial = func() net.Conn {
		c, err := net.Dial("tcp", raw.Addr().String())
		if isReset(err) {
			return resetConn{err: err} // 拒否の RST が connect の戻る前に届いた(managerFor と同じ扱い)
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	reached = func() bool {
		select {
		case <-ipCh:
			return true
		case <-time.After(300 * time.Millisecond):
			return false
		}
	}
	return dial, reached
}

// wantRefused は、拒んだ接続が SetLinger(0) の RST で閉じられ、エージェントに届いていないことを
// 確かめる。読みが RST を返した時点で、評価器の判定と drop の記録は済んでいる。
func wantRefused(t *testing.T, c net.Conn, reached func() bool) {
	t.Helper()
	if reached() {
		t.Error("a refused connection reached the agent")
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !isReset(err) {
		t.Errorf("refused connection: err = %v, want connection reset by peer", err)
	}
}

// ユーザー空間モードの Relay の中継は、送信元の許可拒否も評価器に判定させ、deny の drop に数える
// (仕様 6.2 節)。中継の宣言そのものには deny を置かないので、拒んだのは評価器である。
func TestRelayDenyJudgedByEvaluator(t *testing.T) {
	eng := goengine.New(nil)
	eng.Update(policy.Policy{Rules: []policy.RulePolicy{{RuleID: "r", Proto: proto.TCP,
		SourceDeny: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}})
	dial, reached := admissionManager(t, eng)
	wantRefused(t, dial(), reached)
	if d := eng.Drops(); len(d) != 1 || d[0].RuleID != "r" || d[0].Kind != "deny" || d[0].Packets != 1 {
		t.Errorf("drops = %+v, want one deny drop of rule r", d)
	}
}

// Relay のルールのレートも効き(仕様 6.2 節)、拒んだ接続は new_flow の drop に数え、送信元ごとの
// 同時フロー数の枠を返す。枠を返さないと、上限 1 のこの場面で次のフローが src_flow で落ちる。
func TestRelayRateRefusalCountsAndReleasesTicket(t *testing.T) {
	eng := goengine.New(nil)
	eng.Update(policy.Policy{
		Rules:             []policy.RulePolicy{{RuleID: "r", Proto: proto.TCP, NewFlowRate: rateOf(t, "1/minute")}},
		PerSourceFlowCaps: policy.PerSourceFlowCaps{TCP: 1},
	})
	// new_flow_rate の burst を使い切る。枠は都度返すので、送信元ごとの数は 0 に戻る
	src := netip.MustParseAddr("127.0.0.1")
	for range policy.TokenBucketBurst {
		d, tk := eng.AdmitFlow("r", src, 0)
		if !d.Allow {
			t.Fatalf("draining the burst: %+v", d)
		}
		tk.Release()
	}
	dial, reached := admissionManager(t, eng)
	wantRefused(t, dial(), reached)
	if d := eng.Drops(); len(d) != 1 || d[0].RuleID != "r" || d[0].Kind != "new_flow" || d[0].Packets != 1 {
		t.Errorf("drops = %+v, want one new_flow drop of rule r", d)
	}
	// 枠が返っていれば、次のフローは送信元ごとの上限ではなく new_flow で落ちる
	if d, _ := eng.AdmitFlow("r", src, 0); d.Kind != "new_flow" {
		t.Errorf("the flow after a rate refusal = %+v, want drop:new_flow (the ticket was not released)", d)
	}
}

func rateOf(t *testing.T, s string) *proto.Rate {
	t.Helper()
	r, err := proto.ParseRate(s)
	if err != nil {
		t.Fatal(err)
	}
	return &r
}

// twoPhase は、ポートごとに loopback の待ち受けを開く Manager と、そのポートに今つながるかを返す。
// busy のポートは bind に失敗する。
func twoPhase(t *testing.T, busy map[uint16]bool) (*Manager, func(uint16) bool) {
	t.Helper()
	var mu sync.Mutex
	addrs := map[uint16]string{}
	m := New(Options{
		Listen: func(port uint16) (net.Listener, error) {
			if busy[port] {
				return nil, errors.New("address already in use")
			}
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err == nil {
				mu.Lock()
				addrs[port] = ln.Addr().String()
				mu.Unlock()
			}
			return ln, err
		},
		Dial: func(string) (net.Conn, error) { return nil, errors.New("no agent in this test") },
		Logf: testLogf(t),
	})
	t.Cleanup(m.Close)
	open := func(port uint16) bool {
		mu.Lock()
		a, ok := addrs[port]
		mu.Unlock()
		if !ok {
			return false
		}
		c, err := net.DialTimeout("tcp", a, time.Second)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}
	return m, open
}

func ruleOn(id string, port uint16) Rule {
	r := rule(false, nil, nil)
	r.ID, r.ListenPort = id, port
	return r
}

// Prepare は新しい待ち受けだけを開き、旧い待ち受けを閉じない。Listening は Commit 後の姿
// (残る待ち受けと新しく開けた待ち受け。消えるポートと bind に失敗したポートは含まない)を返す(仕様 6.1 節)。
func TestPrepareListeningIsPostCommitView(t *testing.T) {
	m, open := twoPhase(t, map[uint16]bool{9443: true})
	m.Apply([]Rule{ruleOn("old", 8443)})
	p := m.Prepare([]Rule{ruleOn("new", 8444), ruleOn("busy", 9443)})
	if got := p.Listening(); !reflect.DeepEqual(got, map[uint16]bool{8444: true}) {
		t.Errorf("Listening = %v, want only 8444 (8443 is being removed, 9443 failed to bind)", got)
	}
	if !open(8443) {
		t.Error("Prepare closed the old listener 8443; it must stay until Commit")
	}
	if !open(8444) {
		t.Error("Prepare did not open the new listener 8444")
	}
	p.Rollback()
}

// nftables の差し替えが失敗したときの Rollback は、新しい待ち受けだけを閉じ、旧い待ち受けを残す。
func TestRollbackKeepsOldListeners(t *testing.T) {
	m, open := twoPhase(t, nil)
	m.Apply([]Rule{ruleOn("old", 8443)})
	p := m.Prepare([]Rule{ruleOn("new", 8444)})
	p.Rollback()
	if open(8444) {
		t.Error("after Rollback the new listener 8444 is still open")
	}
	if !open(8443) {
		t.Error("after Rollback the old listener 8443 is gone")
	}
	// Rollback の後の Commit は何もしない
	p.Commit(nil)
	if !open(8443) || open(8444) {
		t.Error("Commit after Rollback changed the listeners")
	}
}

// Commit は、宣言から消えた待ち受けを閉じ、新しい待ち受けを残す。bind に失敗したポートは
// 次の Prepare で開き直す。
func TestCommitClosesRemovedAndRetriesFailedBind(t *testing.T) {
	busy := map[uint16]bool{9443: true}
	m, open := twoPhase(t, busy)
	m.Apply([]Rule{ruleOn("old", 8443)})
	p := m.Prepare([]Rule{ruleOn("new", 8444), ruleOn("busy", 9443)})
	p.Commit(nil)
	if open(8443) {
		t.Error("after Commit the removed listener 8443 is still open")
	}
	if !open(8444) {
		t.Error("after Commit the new listener 8444 is not open")
	}
	delete(busy, 9443)
	p = m.Prepare([]Rule{ruleOn("new", 8444), ruleOn("busy", 9443)})
	if got := p.Listening(); !reflect.DeepEqual(got, map[uint16]bool{8444: true, 9443: true}) {
		t.Errorf("after the port is freed: Listening = %v, want 8444 and 9443", got)
	}
	p.Commit(nil)
	if !open(9443) {
		t.Error("9443 was not opened once the port was free")
	}
}

// testLogf は t.Logf を包み、テストの後始末が始まった後のログを捨てる。Manager の goroutine は
// 待ち受けを閉じた後にもログを書くことがあり、t.Logf がテストの終了後に呼ばれると
// "Log in goroutine after test has completed" でテストが失敗するためである。
func testLogf(t *testing.T) func(string, ...any) {
	var mu sync.Mutex
	done := false
	t.Cleanup(func() {
		mu.Lock()
		done = true
		mu.Unlock()
	})
	return func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if !done {
			t.Logf(format, args...)
		}
	}
}
