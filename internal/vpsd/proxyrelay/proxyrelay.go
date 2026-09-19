// Package proxyrelay は vpsd 側のプロキシモードの中継(仕様 6.2 節)。
// vps_mode=proxy のルールについて、vpsd が公開ポートで TCP を受け、接続元制限を判定し、
// (proxy_protocol なら)PROXY protocol v2 ヘッダを先頭に付けて、wg0 経由でエージェントの
// リスナー(10.200.0.x:listen_port)へ中継する。中継はハーフクローズを保つ。
package proxyrelay

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/internal/netpipe"
	"github.com/rahanahu/wgft/internal/policy"
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
	// ConnsMax はルールごとの同時接続数の上限(既定は Cap.Total から flowcap.Limits.TCPPerRuleCap で導く)。
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
	// retiring は fail-closed にしたルールの待ち受け(待ち受けソケットは閉じ、成立済みの接続だけを
	// 持つ。設計文書 7a.3 節の StopAccepting と Retire)。
	retiring []*listener
	// bindFail は bind に失敗し続けているポートの、最後に記録した理由と失敗の回数。適用は 30 秒ごとに
	// 再試行されるので、同じ理由の失敗はログに 1 回だけ出し、開けたときに 1 回だけ回復を出す。
	bindFail map[uint16]*failure
}

// failure は bind の失敗が続いている 1 つのポートの記録。
type failure struct {
	reason   string
	attempts int
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

// abortRefused は、accept の直後、まだデータをやり取りしていない接続を拒むときに使う(接続元制限、
// 同時フロー数の上限)。通常の Close はグレースフルクローズ(FIN の後 TIME_WAIT)になるが、ここは実
// ソケット(net.Listen で開く公開側の accept)なので、SetLinger(0) で RST を送って即座に終える
// (仕様 6.3 節「実ソケットでも拒否は SetLinger(0) の RST で閉じ」)。フラッドの間に不要な TIME_WAIT の TCP 状態を大量に残さず、
// その分のカーネル資源を保持し続けないためで、成立した中継の通常のクローズ(ハーフクローズを保つ)には使わない。
// internal/dataplane/userspace/relay の同名の考え方(abortRefused)と揃えているが、proxyrelay の
// accept は常に実ソケットで netstack の aborter を持たないため、ここでは *net.TCPConn だけを扱う。
func abortRefused(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetLinger(0)
	}
	c.Close()
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
	if opts.Cap == nil {
		opts.Cap = &flowcap.Counter{Total: flowcap.TCPTotal, PerSource: flowcap.TCPPerSource}
	}
	if opts.ConnsMax <= 0 {
		opts.ConnsMax = flowcap.Limits{TCPTotal: opts.Cap.Total}.TCPPerRuleCap()
	}
	return &Manager{opts: opts, ls: map[uint16]*listener{}, bindFail: map[uint16]*failure{}}
}

// Apply は宣言に収束させる(Prepare の直後に Commit する)。
func (m *Manager) Apply(rules []Rule) { m.Prepare(rules).Commit(nil) }

// Prepared は、Prepare で開いた新しい待ち受けを、Commit か Rollback まで保留する(仕様 6.1、6.2 節)。
// nftables の差し替えが失敗したときに、待ち受けと nftables の片方だけが新しい状態になるのを防ぐ。
type Prepared struct {
	m      *Manager
	want   map[uint16]Rule
	opened map[uint16]net.Listener
	failed map[string]error
	done   bool
}

// Prepare は、宣言のうちまだ開いていない待ち受けだけを開く。既存の待ち受けは閉じず、
// 新しい待ち受けも Commit まで中継を始めない。bind に失敗したポートはログに出して飛ばし、
// そのルールを Failed に入れる(設計文書 7a.3 節のルール単位の失敗)。次の Prepare で開き直す。
func (m *Manager) Prepare(rules []Rule) *Prepared {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := &Prepared{m: m, want: map[uint16]Rule{}, opened: map[uint16]net.Listener{}, failed: map[string]error{}}
	for _, r := range rules {
		p.want[r.ListenPort] = r
	}
	for port := range p.want {
		if _, ok := m.ls[port]; ok {
			continue
		}
		ln, err := m.opts.Listen(port)
		if err != nil {
			f := m.bindFail[port]
			if f == nil {
				f = &failure{}
				m.bindFail[port] = f
			}
			f.attempts++
			if f.reason != err.Error() {
				f.reason = err.Error()
				m.opts.Logf("proxy: cannot open listener for %d: %v", port, err)
			}
			p.failed[p.want[port].ID] = fmt.Errorf("bind failed: %w", err)
			continue
		}
		p.opened[port] = ln
	}
	// 宣言から消えたポートの失敗の記録は捨てる
	for port := range m.bindFail {
		if _, ok := p.want[port]; !ok {
			delete(m.bindFail, port)
		}
	}
	return p
}

// Listening は、Commit した後に待ち受けているポート(残る待ち受けと、新しく開けた待ち受け)。
// 消えるポートと bind に失敗したポートは含まない。nftables の接続元 IP ごとの上限の行はこのポートにだけ付ける。
func (p *Prepared) Listening() map[uint16]bool {
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	out := map[uint16]bool{}
	for port := range p.want {
		if _, ok := p.m.ls[port]; ok {
			out[port] = true
		}
	}
	for port := range p.opened {
		out[port] = true
	}
	return out
}

// Failed は bind に失敗したルールと、その理由。
func (p *Prepared) Failed() map[string]error { return p.failed }

// Commit は、新しい待ち受けで中継を始め、宣言から消えた待ち受けを閉じ、残るものの接続元制限を
// 更新して、許可されなくなった進行中の接続を閉じる(仕様 6.2 節)。
//
// retiring は fail-closed にしたルールの ID と、成立済みの接続を残してよいかの判定(設計文書 7a.3 節)。
// そのルールの待ち受けは閉じずに StopAccepting(待ち受けソケットだけを閉じる)と Retire(判定が
// 偽を返す接続だけを閉じる)を行い、残りの接続は自然に終わるまで中継を続ける。ルールの削除と
// 無効化は retiring に入らないので、成立済みの接続も今までどおり切れる。以前から Retiring の
// 待ち受けは、そのルールがまだ retiring にあるあいだだけ残し、判定をし直す。
func (p *Prepared) Commit(retiring map[string]func(src netip.Addr) bool) {
	if p.done {
		return
	}
	p.done = true
	m := p.m
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.retiring[:0]
	for _, l := range m.retiring {
		keep, ok := retiring[l.ruleID()]
		if !ok {
			l.close()
			m.opts.Logf("proxy: closed retiring relay for %d (rule %s is no longer retiring)", l.port(), l.ruleID())
			continue
		}
		if l.retire(keep); l.idle() {
			l.close()
			continue
		}
		kept = append(kept, l)
	}
	m.retiring = kept
	for port, l := range m.ls {
		if _, ok := p.want[port]; !ok {
			delete(m.ls, port)
			if keep, ok := retiring[l.ruleID()]; ok {
				l.stopAccepting()
				n := l.retire(keep)
				m.retiring = append(m.retiring, l)
				m.opts.Logf("proxy: relay for %d stopped accepting (rule %s is not active); closed %d connections its new declaration refuses", port, l.ruleID(), n)
				continue
			}
			l.close()
			m.opts.Logf("proxy: closed relay for %d", port)
		}
	}
	for port, r := range p.want {
		if l, ok := m.ls[port]; ok {
			l.updateRestriction(r)
			continue
		}
		ln, ok := p.opened[port]
		if !ok {
			continue
		}
		l := &listener{rule: r, ln: ln, conns: map[net.Conn]string{}}
		m.ls[port] = l
		go m.serve(l)
		m.opts.Logf("proxy: opened relay %d -> %s:%d proxy_protocol=%v", port, r.AgentAddr, r.AgentPort, r.ProxyProtocol)
		if f := m.bindFail[port]; f != nil {
			m.opts.Logf("proxy: %d: listener opened after %d failed attempts", port, f.attempts)
			delete(m.bindFail, port)
		}
	}
}

// Rollback は Prepare で開いた待ち受けを閉じる。既存の待ち受けには触らない。
func (p *Prepared) Rollback() {
	if p.done {
		return
	}
	p.done = true
	for port, ln := range p.opened {
		ln.Close()
		p.m.opts.Logf("proxy: released listener for %d (dataplane apply failed)", port)
	}
}

// CloseAgent はそのエージェント宛の全中継を閉じる(トークン無効化)。Retiring の中継も閉じる。
func (m *Manager) CloseAgent(agent string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for port, l := range m.ls {
		if l.agent() == agent {
			l.close()
			delete(m.ls, port)
		}
	}
	kept := m.retiring[:0]
	for _, l := range m.retiring {
		if l.agent() == agent {
			l.close()
			continue
		}
		kept = append(kept, l)
	}
	m.retiring = kept
}

// Close は全中継を閉じる。Retiring の中継も閉じる。
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for port, l := range m.ls {
		l.close()
		delete(m.ls, port)
	}
	for _, l := range m.retiring {
		l.close()
	}
	m.retiring = nil
}

// RetiringPorts は Retiring の中継のポート(テストとログ用)。
func (m *Manager) RetiringPorts() []uint16 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]uint16, 0, len(m.retiring))
	for _, l := range m.retiring {
		out = append(out, l.port())
	}
	return out
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
		abortRefused(c)
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
		abortRefused(c)
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
// 同じポートのルールが分割・統合やエージェントの変更で入れ替わった場合に備え、ID と所属エージェントも
// 新しい宣言に合わせる(CloseAgent がエージェントで探すため)。
func (l *listener) updateRestriction(r Rule) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rule.ID, l.rule.Agent = r.ID, r.Agent
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

func (l *listener) ruleID() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rule.ID
}

func (l *listener) agent() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rule.Agent
}

func (l *listener) port() uint16 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rule.ListenPort
}

// idle は Retiring の中継に、成立済みの接続も接続中の接続も残っていないか。
func (l *listener) idle() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.conns) == 0 && l.pending == 0
}

// stopAccepting は待ち受けソケットだけを閉じ、成立済みの接続には触れない(設計文書 7a.3 節の
// StopAccepting)。触れなかった接続は Retiring になり、自然に終わるまで中継を続ける。
func (l *listener) stopAccepting() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ln.Close()
}

// retire は keep が偽を返す接続元の接続だけを閉じ、閉じた数を返す(設計文書 7a.3 節の Retire)。
func (l *listener) retire(keep func(src netip.Addr) bool) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for c, srcStr := range l.conns {
		src, err := netip.ParseAddr(srcStr)
		if err != nil || !keep(src) {
			c.Close()
			n++
		}
	}
	return n
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

// sourceAllowed の deny/allow の判定は internal/policy.RulePolicy.SourceAllowed に委ねる
// (design.md 7a.9 節「Phase 5 の移行の手順」1:4 か所に分かれていた同じ判定を IR の 1 実装へ
// 集約する最初の 1 か所)。
func sourceAllowed(src netip.Addr, r Rule) bool {
	return policy.RulePolicy{SourceDeny: r.SourceDeny, SourceAllow: r.SourceAllow}.SourceAllowed(src)
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
