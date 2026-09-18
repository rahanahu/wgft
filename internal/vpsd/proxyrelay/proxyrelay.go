// Package proxyrelay は vpsd 側のプロキシモードの中継(仕様 6.2 節)。
// vps_mode=proxy のルールについて、vpsd が公開ポートで TCP を受け、接続元制限を判定し、
// (proxy_protocol なら)PROXY protocol v2 ヘッダを先頭に付けて、wg0 経由でエージェントの
// リスナー(10.200.0.x:listen_port)へ中継する。中継はハーフクローズを保つ。
package proxyrelay

import (
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/internal/netpipe"
	"github.com/rahanahu/wgft/proto"
)

// Rule は中継 1 つ分の宣言。
type Rule struct {
	ID            string
	ListenPort    uint16 // 公開側の待ち受けポート(proxy は単一ポート運用を基本とする)
	AgentAddr     netip.Addr
	AgentPort     uint16 // エージェントのリスナー(= listen_port の先頭)
	ProxyProtocol bool
	SourceDeny    []netip.Prefix
	SourceAllow   []netip.Prefix
	Agent         string
}

// Options は依存の差し替え(テスト用)。
type Options struct {
	// Listen は公開側の待ち受けを開く。既定は net.Listen("tcp", ":port")。
	Listen func(port uint16) (net.Listener, error)
	// Dial はエージェントのリスナーへ繋ぐ。既定は net.Dial("tcp", addr)。
	Dial func(addr string) (net.Conn, error)
	Logf func(string, ...any)
	// ConnsMax はルールごとの同時接続数の上限(既定 flowcap.TCPPerRule)。
	ConnsMax int
	// Cap はプロセス全体と接続元 IP ごとの上限(仕様 7 節)。nil なら既定値で作る。
	// ユーザー空間モードの vpsd は relay と同じ Counter を渡し、合計で数える
	Cap *flowcap.Counter
}

// Manager は現在のプロキシ中継のリスナー集合を持ち、宣言に収束させる。
type Manager struct {
	opts Options
	mu   sync.Mutex
	ls   map[uint16]*listener
}

type listener struct {
	rule   Rule
	ln     net.Listener
	mu     sync.Mutex
	conns  map[net.Conn]string // 進行中の中継(公開側の接続 → 接続元 IP 文字列)
	closed bool
	// pending は上限の枠を取ってから track するまでの接続の数(エージェントへの接続中)
	pending int
	capLog  flowcap.LogGate
	// dialLog はエージェントへの接続失敗のログを絞る(agent 側が落ちている間、公開ポートへの
	// 接続のたびに 1 行出ると高頻度になりうるため。仕様 10.4 節)。
	dialLog flowcap.LogGate
}

// New は空の Manager を作る。
func New(opts Options) *Manager {
	if opts.Listen == nil {
		opts.Listen = func(port uint16) (net.Listener, error) {
			return net.Listen("tcp", net.JoinHostPort("", itoa(port)))
		}
	}
	if opts.Dial == nil {
		d := &net.Dialer{}
		opts.Dial = func(addr string) (net.Conn, error) { return d.Dial("tcp", addr) }
	}
	if opts.Logf == nil {
		opts.Logf = log.Printf
	}
	if opts.ConnsMax <= 0 {
		opts.ConnsMax = flowcap.TCPPerRule
	}
	if opts.Cap == nil {
		opts.Cap = &flowcap.Counter{Total: flowcap.TCPTotal, PerSource: flowcap.TCPPerSource}
	}
	return &Manager{opts: opts, ls: map[uint16]*listener{}}
}

// FromRules は、有効なプロキシモードの TCP ルールから中継の宣言を作る。
func FromRules(rules []proto.Rule, agentAddr map[string]netip.Addr) []Rule {
	var out []Rule
	for i := range rules {
		r := &rules[i]
		if !r.Enabled || r.VPSMode != proto.ModeProxy || r.Proto != proto.TCP {
			continue
		}
		addr, ok := agentAddr[r.Agent]
		if !ok {
			continue
		}
		// proxy は単一ポート運用。proto.Rule.Validate は新規・変更のルールで範囲を拒否するが、
		// それ以前に保存された範囲のルールは proto.ValidateUpsert が検査対象から外すのでここを
		// 通り得る。安全側として先頭ポートだけを使う(仕様 5.4、6.2 節)
		out = append(out, Rule{
			ID: r.ID, ListenPort: r.ListenPort.Lo, AgentAddr: addr, AgentPort: r.ListenPort.Lo,
			ProxyProtocol: r.ProxyProtocol, SourceDeny: r.SourceDeny, SourceAllow: r.SourceAllow, Agent: r.Agent,
		})
	}
	return out
}

// Apply は宣言に収束させる。新しい中継を開き、消えたものは閉じ、
// 残るものは接続元制限を更新して、許可されなくなった進行中の接続を閉じる(仕様 6.2 節)。
func (m *Manager) Apply(rules []Rule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := map[uint16]Rule{}
	for _, r := range rules {
		want[r.ListenPort] = r
	}
	// 消えたものを閉じる
	for port, l := range m.ls {
		if _, ok := want[port]; !ok {
			l.close()
			delete(m.ls, port)
			m.opts.Logf("proxy: closed relay for %d", port)
		}
	}
	// 開く・更新する
	for port, r := range want {
		if l, ok := m.ls[port]; ok {
			l.updateRestriction(r)
			continue
		}
		ln, err := m.opts.Listen(port)
		if err != nil {
			m.opts.Logf("proxy: cannot open listener for %d: %v", port, err)
			continue
		}
		l := &listener{rule: r, ln: ln, conns: map[net.Conn]string{}}
		m.ls[port] = l
		go m.serve(l)
		m.opts.Logf("proxy: opened relay %d -> %s:%d proxy_protocol=%v", port, r.AgentAddr, r.AgentPort, r.ProxyProtocol)
	}
}

// CloseAgent はそのエージェント宛の全中継を閉じる(トークン無効化)。
func (m *Manager) CloseAgent(agent string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for port, l := range m.ls {
		if l.rule.Agent == agent {
			l.close()
			delete(m.ls, port)
		}
	}
}

// Close は全中継を閉じる。
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for port, l := range m.ls {
		l.close()
		delete(m.ls, port)
	}
}

func (m *Manager) serve(l *listener) {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return
		}
		go m.handle(l, c)
	}
}

func (m *Manager) handle(l *listener, c net.Conn) {
	src := ipOf(c.RemoteAddr())
	l.mu.Lock()
	rule := l.rule
	l.mu.Unlock()
	// 接続元制限(vpsd が受け付け時に判定する。プロキシは DNAT を通らないので nftables では効かない)
	if !sourceAllowed(src, rule) {
		c.Close()
		return
	}
	// 同時フロー数の上限(仕様 7 節)。超えた接続はすぐ閉じる(既存の接続は追い出さない)
	l.mu.Lock()
	full := len(l.conns)+l.pending >= m.opts.ConnsMax
	if !full {
		l.pending++
	}
	l.mu.Unlock()
	if full || !m.opts.Cap.Acquire(src) {
		if !full {
			l.mu.Lock()
			l.pending--
			l.mu.Unlock()
		}
		c.Close()
		if l.capLog.Allow() {
			m.opts.Logf("proxy: %d: connection limit reached; refusing new connections", rule.ListenPort)
		}
		return
	}
	defer m.opts.Cap.Release(src)
	pending := true
	unpend := func() {
		if pending {
			pending = false
			l.mu.Lock()
			l.pending--
			l.mu.Unlock()
		}
	}
	defer unpend()
	up, err := m.opts.Dial(net.JoinHostPort(rule.AgentAddr.String(), itoa(rule.AgentPort)))
	if err != nil {
		if l.dialLog.Allow() {
			m.opts.Logf("proxy: %d: cannot connect to agent %s:%d: %v", rule.ListenPort, rule.AgentAddr, rule.AgentPort, err)
		}
		c.Close()
		return
	}
	if rule.ProxyProtocol {
		hdr := proxyproto.HeaderProxyFromAddrs(2, c.RemoteAddr(), c.LocalAddr())
		if _, err := hdr.WriteTo(up); err != nil {
			c.Close()
			up.Close()
			return
		}
	}
	unpend()
	l.track(c, src)
	defer l.untrack(c)
	netpipe.Pipe(c, up)
}

// updateRestriction は接続元制限を更新し、許可されなくなった進行中の接続を閉じる。
func (l *listener) updateRestriction(r Rule) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rule.SourceDeny, l.rule.SourceAllow = r.SourceDeny, r.SourceAllow
	l.rule.ProxyProtocol, l.rule.AgentAddr, l.rule.AgentPort = r.ProxyProtocol, r.AgentAddr, r.AgentPort
	for c, srcStr := range l.conns {
		src, err := netip.ParseAddr(srcStr)
		if err == nil && !sourceAllowed(src, l.rule) {
			c.Close()
		}
	}
}

func (l *listener) track(c net.Conn, src netip.Addr) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		c.Close()
		return
	}
	l.conns[c] = src.String()
	l.mu.Unlock()
}

func (l *listener) untrack(c net.Conn) {
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
}

func (l *listener) close() {
	l.mu.Lock()
	l.closed = true
	l.ln.Close()
	for c := range l.conns {
		c.Close()
	}
	l.conns = map[net.Conn]string{}
	l.mu.Unlock()
}

func sourceAllowed(src netip.Addr, r Rule) bool {
	for _, p := range r.SourceDeny {
		if p.Contains(src) {
			return false
		}
	}
	if len(r.SourceAllow) == 0 {
		return true
	}
	for _, p := range r.SourceAllow {
		if p.Contains(src) {
			return true
		}
	}
	return false
}

func ipOf(a net.Addr) netip.Addr {
	if ta, ok := a.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(ta.IP); ok {
			return ip.Unmap()
		}
	}
	host, _, err := net.SplitHostPort(a.String())
	if err == nil {
		if ip, err := netip.ParseAddr(host); err == nil {
			return ip
		}
	}
	return netip.Addr{}
}

func itoa(p uint16) string { return strconv.Itoa(int(p)) }
