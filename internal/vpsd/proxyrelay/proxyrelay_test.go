package proxyrelay

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/rahanahu/wgft/internal/flowcap"
)

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
		Logf:   t.Logf,
	})
	t.Cleanup(m.Close)
	dialPublic := func() net.Conn {
		c, err := net.Dial("tcp", pubAddr)
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
	if _, err := io.ReadAll(c); err != nil {
		// 接続は即閉じられる(読みは EOF/エラーで終わる)
	}
	select {
	case <-ipCh:
		t.Error("拒否された接続がエージェントに届いた")
	case <-time.After(300 * time.Millisecond):
	}
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
	cnt := &flowcap.Counter{Total: 10, PerSource: 1}
	m := New(Options{
		Listen: func(uint16) (net.Listener, error) { return raw, nil },
		Dial:   func(string) (net.Conn, error) { return net.Dial("tcp", agentAddr) },
		Logf:   t.Logf,
		Cap:    cnt,
	})
	t.Cleanup(m.Close)
	m.Apply([]Rule{rule(true, nil, nil)}) // fakeAgent は PROXY ヘッダが届くまで接続元を返さない
	dial := func() net.Conn {
		c, err := net.Dial("tcp", raw.Addr().String())
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
	if _, err := c2.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("refused connection: err = %v, want EOF", err)
	}
	c1.Close()
	deadline := time.Now().Add(2 * time.Second)
	for cnt.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if cnt.Len() != 0 {
		t.Fatalf("counter after close = %d, want 0", cnt.Len())
	}
	dial()
	if !reached() {
		t.Error("connection after a slot was freed must reach the agent")
	}
}
