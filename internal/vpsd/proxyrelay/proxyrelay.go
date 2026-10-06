// Package proxyrelay は vpsd 側のプロキシモードの中継(仕様 6.2 節)。
// vps_mode=proxy のルールについて、vpsd が公開ポートで TCP を受け、Admission Policy で判定し、
// (proxy_protocol なら)PROXY protocol v2 ヘッダを先頭に付けて、wg0 経由でエージェントの
// リスナー(10.200.0.x:listen_port)へ中継する。中継はハーフクローズを保つ。
package proxyrelay

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/rahanahu/wgft/internal/lograte"
	"github.com/rahanahu/wgft/internal/netpipe"
	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/internal/reasontext"
	"github.com/rahanahu/wgft/internal/resource"
)

// Rule は中継 1 つ分の宣言。
type Rule struct {
	ID            string
	ListenPort    uint16 // 公開側の待ち受けポート(proxy は単一ポート運用を基本とする)
	AgentAddr     netip.Addr
	AgentPort     uint16 // エージェントのリスナー(= listen_port の先頭)
	ProxyProtocol bool
	// Policy は、この中継の接続元 deny/allow(design.md 7a.9 節)。planner.PortPlan.Policy の写しで、
	// 接続元以外のレート等の項目は proxyrelay が判定に使わない(Options.Admit がユーザー空間モードで
	// 全段を判定し、カーネルモードは nftables が判定する。仕様 6.1、6.2 節)
	Policy policy.RulePolicy
	Agent  string
}

// Options は依存の差し替え(テスト用)。
type Options struct {
	// Listen は公開側の待ち受けを開く。既定は net.Listen("tcp4", ":port")。v1 は IPv4 だけを扱い
	// (設計文書 4、7a.9 節)、IPv6 の送信元は IPv4 の CIDR だけを並べた deny に一致せずに通るので、
	// IPv6 では待ち受けない。
	Listen func(port uint16) (net.Listener, error)
	// Dial はエージェントのリスナーへ繋ぐ。既定は net.Dial("tcp", addr)。
	Dial func(addr string) (net.Conn, error)
	// FloorAtAccept は、accept した公開側の接続の受信のバッファを、Admission と dial の前に floor に
	// 固定するか(netpipe.FixAtAccept)。ユーザー空間モードの vpsd が立てる。カーネルモードでは組の
	// 両側がカーネルのソケットで枠に合わせないので、立てない(設計文書 7 節)
	FloorAtAccept bool
	// HoldUntilDelivered は、中継が終わった後も、組が送り残しを相手に届け終えるまで Resource Guard の
	// 枠を持つか(netpipe.PipeHold と netpipe.AwaitDelivered。設計文書 7 節の「中継が終わった後の末尾の
	// 配送」)。ユーザー空間モードの vpsd が立てる。カーネルモードでは立てず、今までどおり中継の終わりで
	// 枠を返し、両側を閉じる
	HoldUntilDelivered bool
	Logf               func(string, ...any)
	// Pool はプロセス全体の予算と、そこから導くルールごとの上限と最低分(仕様 7 節、
	// 設計文書 7a.10 節の Resource Guard)。nil なら既定値で作る。
	// ユーザー空間モードの vpsd は relay と同じ Pool を渡し、合計で数える
	Pool *resource.Pool
	// Admit は新しい接続を Admission Policy のすべての段(deny、allow、3 つのレート、送信元ごとの
	// 同時フロー数の上限)で判定し、拒んだ段の drop を数える。通すときは枠を返す release も返し、
	// 中継は接続の終わりに 1 回呼ぶ。後の上限(Resource Guard)で拒んだときも呼ぶ。
	//
	// ユーザー空間モードの vpsd は Go の評価器(userspace.Backend.AdmitRelayFlow)を渡す。カーネル
	// モードでは nil で、段は nftables が待ち受けを開けているポートの行で評価する(仕様 6.1 節)。
	// nil のときに中継に残るのは、deny と allow の状態を持たない確認だけである(仕様 6.2 節)
	// Admit must return without calling Manager methods; stopping joins its synchronous call.
	Admit func(ruleID string, src netip.Addr) (release func(), ok bool)
}

// Manager は現在のプロキシ中継のリスナー集合を持ち、宣言に収束させる。
type Manager struct {
	opts Options
	// testHeaderWriter decorates only header writes; up retains its real connection identity.
	testHeaderWriter func(net.Conn) io.Writer
	mu               sync.Mutex
	ls               map[uint16]*listener
	// retiring は fail-closed にしたルールの待ち受け(待ち受けソケットは閉じ、成立済みの接続だけを
	// 持つ。設計文書 7a.3 節の StopAccepting と Retire)。
	retiring []*listener
	// bindFail は bind に失敗し続けているポートの、最後に記録した理由と失敗の回数。適用は 30 秒ごとに
	// 再試行されるので、同じ理由の失敗はログに 1 回だけ出し、開けたときに 1 回だけ回復を出す。
	bindFail map[uint16]*failure
	// closed は Close の後か。Close より前に Prepare した Prepared の Commit は、開いた待ち受けを閉じて
	// 何も公開しない(Close の後に残る待ち受けを閉じる経路は無いため)。
	closed bool
}

// failure は bind の失敗が続いている 1 つのポートの記録。
type failure struct {
	reason   string
	attempts int
}

type listener struct {
	rule  Rule
	ln    net.Listener
	mu    sync.Mutex
	conns map[net.Conn]relayed // 進行中の中継(公開側の接続 → 接続元とエージェントへの接続)
	// delivering は、中継が終わり、送り残しを届けている途中の組(HoldUntilDelivered のときだけ)。
	// 枠を持ったままで、切る経路は conns と同じくこの組も切り、待ちを起こす
	delivering map[net.Conn]delivering
	closed     bool
	stopping   bool
	admitting  net.Conn // owned by the accept loop until the locked handoff
	stopAccept chan struct{}
	serveDone  chan struct{}
	// pending は枠を取ってから track するまでの接続の数(エージェントへの接続中)。Retiring の
	// 待ち受けを閉じてよいか(idle)の判定に使う
	pending int
	// testHookPendingRegistration pauses the locked pending-to-record transition.
	testHookPendingRegistration func()
	// gen は実効宛先(エージェントのアドレスと待ち受けポート)を差し替えた回数。admission は accept の
	// 時点の値を控え、track のときに値が変わっていれば、その接続は旧い実効宛先へつながっているので
	// 中継を始めずに閉じる(仕様 6.2 節の実効宛先の変更)
	gen int
	// budget は Resource Guard の枠(プロセス全体の予算とルールごとの上限。設計文書 7a.10 節)
	budget *resource.Listener
	capLog lograte.Gate
	// dialLog はエージェントへの接続失敗のログを絞る(agent 側が落ちている間、公開ポートへの
	// 接続のたびに 1 行出ると高頻度になりうるため。仕様 10.4 節)。
	dialLog lograte.Gate
	// acceptLog は accept の失敗のログを絞る(ファイル記述子の枯渇のように、失敗が続く間は
	// 再試行のたびに 1 行出るため。仕様 10.4 節)。
	acceptLog lograte.Gate
	// heldLog と held は、数える前に floor に固定できなかった接続を切ったログの頻度と数。serve の
	// goroutine だけが触る
	heldLog lograte.Gate
	held    int
}

// relayed は進行中の中継 1 本の記録で、公開側の接続を鍵にして conns に置く。中継を切るときは、
// エージェントへの接続 up も cut で RST で切る。公開側だけを閉じると、netpipe はその読み取りの失敗を
// 受けて up を通常の Close で閉じるので、エージェントには RST ではなく FIN が届く。
type relayed struct {
	src string // 接続元 IP の文字列
	up  net.Conn
}

// delivering は送り残しを届けている途中の組の記録。wake は切る経路が待ちを起こすために閉じる。
type delivering struct {
	relayed
	wake chan struct{}
}

// cut は組を切り、待ちを起こす。
func (d delivering) cut(c net.Conn) {
	d.relayed.cut(c)
	close(d.wake)
}

// cut は中継の両側を閉じる。エージェントへの接続 up は RST で切る(仕様 6.2 節)。FIN で閉じると、
// エージェントの中継はそれをハーフクローズとして扱い、宛先へ FIN を送った後も宛先からの読み取りを
// 続けるので、FIN を受けても閉じない宛先では、エージェント側の宛先への接続と枠が残り続ける。
// up を先に切る。公開側を先に閉じると、netpipe がその読み取りの失敗を受けて up を通常の Close で
// 閉じ、RST の前に FIN が出ることがあるため
func (r relayed) cut(c net.Conn) {
	if r.up != nil {
		abortUpstream(r.up)
	}
	c.Close()
}

// abortUpstream はエージェントへの接続を RST で閉じる。
func abortUpstream(up net.Conn) {
	resetUpstream(up)
	up.Close()
}

// resetUpstream はエージェントへの接続を RST で切る。ユーザー空間モードの接続は netstack の
// 接続(nettun.TCPConn)で Abort を持ち、すぐに RST を送る。カーネルモードの接続は実ソケットで、
// SetLinger(0) の後の Close が RST を送るので、Close は呼び出し側が行う。
func resetUpstream(up net.Conn) {
	switch v := up.(type) {
	case interface{ Abort() }:
		v.Abort()
	case interface{ SetLinger(int) error }:
		v.SetLinger(0)
	}
}

// fixAtAccept は accept した接続を floor に固定して確かめる(netpipe.FixAtAccept)。テストが
// 失敗を差し込むために差し替える。
var fixAtAccept = netpipe.FixAtAccept

// abortRefused は、accept の直後、まだデータをやり取りしていない接続を拒むときに使う
// (Admission Policy と、ルールごととプロセス全体の同時フロー数の上限)。通常の Close はグレースフル
// クローズ(FIN の後 TIME_WAIT)になるが、ここは実ソケット(net.Listen で開く公開側の accept)なので、
// SetLinger(0) で RST を送って即座に終える(仕様 6.3 節「実ソケットでも拒否は SetLinger(0) の RST で
// 閉じ」)。フラッドの間に不要な TIME_WAIT の TCP 状態を大量に残さず、その分のカーネル資源を保持し
// 続けないためで、成立した中継の通常のクローズ(ハーフクローズを保つ)には使わない。
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
			return net.Listen("tcp4", net.JoinHostPort("", itoa(port)))
		}
	}
	if opts.Dial == nil {
		d := &net.Dialer{}
		opts.Dial = func(addr string) (net.Conn, error) { return d.Dial("tcp", addr) }
	}
	if opts.Logf == nil {
		opts.Logf = log.Printf
	}
	if opts.Pool == nil {
		lim := resource.Limits{}.WithDefaults()
		opts.Pool = resource.NewPool(lim.TCPTotal)
	}
	return &Manager{opts: opts, ls: map[uint16]*listener{}, bindFail: map[uint16]*failure{}}
}

// Pool is the TCP flow budget this Manager judges new connections against (design.md 7a.10 節
// 「拒否の報告」). The admin API reads it to report Resource Guard's status (in_use, limit and the
// per-rule, per-reason refusal counts); it is never nil (New fills a default when Options.Pool is
// nil).
func (m *Manager) Pool() *resource.Pool { return m.opts.Pool }

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
			p.failed[p.want[port].ID] = fmt.Errorf(reasontext.BindFailed+": %w", err)
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
	if m.closed {
		for port, ln := range p.opened {
			ln.Close()
			m.opts.Logf("proxy: released listener for %d: the relay is closed", port)
		}
		return
	}
	var stopped []*listener
	kept := make([]*listener, 0, len(m.retiring))
	for _, l := range m.retiring {
		keep, ok := retiring[l.ruleID()]
		if !ok {
			l.beginClose()
			stopped = append(stopped, l)
			m.opts.Logf("proxy: closed retiring relay for %d: rule %s is no longer retiring", l.port(), l.ruleID())
			continue
		}
		if l.retire(keep); l.idle() {
			l.beginClose()
			stopped = append(stopped, l)
			continue
		}
		kept = append(kept, l)
	}
	for port, l := range m.ls {
		if _, ok := p.want[port]; !ok {
			if keep, ok := retiring[l.ruleID()]; ok {
				l.beginStopAccepting()
				stopped = append(stopped, l)
				n := l.retire(keep)
				kept = append(kept, l)
				m.opts.Logf("proxy: relay for %d stopped accepting: rule %s is not active; closed %d connections its new declaration refuses", port, l.ruleID(), n)
				continue
			}
			l.beginClose()
			stopped = append(stopped, l)
			m.opts.Logf("proxy: closed relay for %d", port)
		}
	}
	for _, l := range stopped {
		l.waitServeDone()
	}
	m.retiring = kept
	for port := range m.ls {
		if _, ok := p.want[port]; !ok {
			delete(m.ls, port)
		}
	}
	for port, r := range p.want {
		if l, ok := m.ls[port]; ok {
			if retargeted, n := l.updateRestriction(r); retargeted {
				m.opts.Logf("proxy: relay for %d -> %s:%d retargeted; rule %s; closed %d connections", port, r.AgentAddr, r.AgentPort, r.ID, n)
			}
			continue
		}
		ln, ok := p.opened[port]
		if !ok {
			continue
		}
		// 枠は bind の済んだ待ち受けにだけ付け、中継を始める前に付ける。Prepare で bind に失敗した
		// ポートはここに来ないので、そのルールは受け付けているルールの集合 A に入らない
		// (設計文書 7a.10 節)
		l := &listener{rule: r, ln: ln, conns: map[net.Conn]relayed{}, delivering: map[net.Conn]delivering{}, budget: m.opts.Pool.Listener(r.ID), stopAccept: make(chan struct{}), serveDone: make(chan struct{})}
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
		p.m.opts.Logf("proxy: released listener for %d: dataplane apply failed", port)
	}
}

// CloseAgent はそのエージェント宛の全中継を閉じる(トークン無効化)。Retiring の中継も閉じる。
func (m *Manager) CloseAgent(agent string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var stopped []*listener
	for _, l := range m.ls {
		if l.agent() == agent {
			l.beginClose()
			stopped = append(stopped, l)
		}
	}
	for _, l := range m.retiring {
		if l.agent() == agent {
			l.beginClose()
			stopped = append(stopped, l)
		}
	}
	for _, l := range stopped {
		l.waitServeDone()
	}
	for port, l := range m.ls {
		if l.agent() == agent {
			delete(m.ls, port)
		}
	}
	kept := m.retiring[:0]
	for _, l := range m.retiring {
		if l.agent() != agent {
			kept = append(kept, l)
		}
	}
	m.retiring = kept
}

// Close stops every listener before joining any admission call. A later Commit releases the
// listeners its Prepare opened and starts nothing.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	for _, l := range m.ls {
		l.beginClose()
	}
	for _, l := range m.retiring {
		l.beginClose()
	}
	for _, l := range m.ls {
		l.waitServeDone()
	}
	for _, l := range m.retiring {
		l.waitServeDone()
	}
	clear(m.ls)
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

// acceptRetryMin と acceptRetryMax は、accept が閉じた待ち受け以外の理由で失敗したときの待ち時間の
// 下限と上限。net/http.Server.Serve と同じ形の後退で、失敗が続く間に accept の呼び出しが詰まるのを
// 避ける。
const (
	acceptRetryMin = 5 * time.Millisecond
	acceptRetryMax = time.Second
)

// serve は待ち受けで accept を続ける。待ち受けを閉じた場合(beginClose、beginStopAccepting)は
// net.ErrClosed で戻る。それ以外の失敗、例えばファイル記述子の枯渇(EMFILE、ENFILE)では、待ち受けを
// 開いたまま後退して試し直す。戻ってしまうと、ソケットは bind されたまま accept しない状態で残り、
// Prepare は m.ls にあるポートを開き直さないので、`vpsd` を再起動するまでそのポートの中継が止まる。
// Go の runtime は EINTR、EAGAIN、ECONNABORTED を自分で握って accept をやり直すので、ここに来る
// 失敗は一時的でないものだけである。
func (m *Manager) serve(l *listener) {
	defer close(l.serveDone)
	delay := time.Duration(0)
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if l.acceptLog.Allow() {
				m.opts.Logf("proxy: %d: accept failed: %v; the listener stays open and retries", l.port(), err)
			}
			delay *= 2
			if delay < acceptRetryMin {
				delay = acceptRetryMin
			}
			if delay > acceptRetryMax {
				delay = acceptRetryMax
			}
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-l.stopAccept:
				timer.Stop()
				return
			}
			continue
		}
		delay = 0
		// ユーザー空間モードでは、公開側のカーネルのソケットを Admission と dial を待つ間も floor に
		// 固定する。固定する前に floor を超えて溜めていた接続と、固定か確かめに失敗した接続は、数えずに
		// RST で切る(設計文書 7 節)
		if m.opts.FloorAtAccept && !fixAtAccept(c) {
			abortRefused(c)
			l.held++
			if l.heldLog.Allow() {
				m.opts.Logf("proxy: %d: reset a new connection before it was counted: its receive memory was above the floor or could not be held at the floor; %d so far", l.port(), l.held)
			}
			continue
		}
		if a := m.admitAccepted(l, c); a != nil {
			go m.relayAdmitted(l, a)
		}
	}
}

// admitted owns both admission charges after the locked handoff.
type admitted struct {
	c      net.Conn
	src    netip.Addr
	rule   Rule
	gen    int
	charge resource.Charge
}

// admitAccepted runs only in the accept loop, never in a per-connection goroutine.
func (m *Manager) admitAccepted(l *listener, c net.Conn) *admitted {
	src := ipOf(c.RemoteAddr())
	l.mu.Lock()
	if l.stopping || l.closed {
		l.mu.Unlock()
		abortRefused(c)
		return nil
	}
	rule, gen := l.rule, l.gen
	l.admitting = c
	l.mu.Unlock()
	var charge resource.Charge
	handed := false
	defer func() {
		if !handed {
			l.mu.Lock()
			l.admitting = nil
			l.mu.Unlock()
			abortRefused(c)
			charge.Release()
		}
	}()
	// Policy must precede the shared resource budget, including its refusal accounting.
	if m.opts.Admit != nil {
		release, ok := m.opts.Admit(rule.ID, src)
		if !ok {
			return nil
		}
		charge.HoldPolicy(release)
	} else if !sourceAllowed(src, rule) {
		return nil
	}
	lease, ref, ok, cancelled := l.acquireAdmission(gen, l.budget.Take)
	if cancelled {
		return nil
	}
	if !ok {
		if l.capLog.Allow() {
			m.opts.Logf("proxy: %d: %s; refusing new connections", rule.ListenPort, ref)
		}
		return nil
	}
	charge.HoldLease(lease)
	handed = true
	return &admitted{c: c, src: src, rule: rule, gen: gen, charge: charge}
}

// acquireAdmission serializes cancellation, the budget attempt and handoff.
// acquire is the synchronous Pool operation; it must not reenter the listener.
// The listener -> Pool lock order is also used by stop and restriction updates.
func (l *listener) acquireAdmission(gen int, take func() (*resource.Lease, resource.Refusal, resource.Outcome)) (lease *resource.Lease, ref resource.Refusal, ok, cancelled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopping || l.closed || l.gen != gen {
		return nil, ref, false, true
	}
	lease, ref, outcome := take()
	switch outcome {
	case resource.NotAccepting:
		// Unreachable while stopping, closed and gen are checked under l.mu, since a stop or
		// retarget changes them under the same lock before closing the Pool handle. Treated like
		// cancelled, a plain RST with no log, and not counted as a refusal (design.md 7a.10 節).
		return nil, ref, false, true
	case resource.Refused:
		return nil, ref, false, false
	}
	// A committed worker may start after stop; it owns the charges until done.
	l.admitting = nil
	l.pending++
	return lease, ref, true, false
}

func (m *Manager) relayAdmitted(l *listener, a *admitted) {
	c, src, rule, gen := a.c, a.src, a.rule, a.gen
	defer a.charge.Release()
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
	// A completed setup error becomes a delivery record only in userspace mode. Pending
	// ownership stays with this worker until registration or the existing intentional cut.
	failed := func(up net.Conn) {
		if !m.opts.HoldUntilDelivered {
			c.Close()
			if up != nil {
				up.Close()
			}
			return
		}
		wake, ok := l.finishPending(a, up, true)
		if !ok {
			relayed{up: up}.cut(c)
			return
		}
		pending = false
		if up != nil {
			// A partial header still ends gracefully; its real endpoint stays in the record.
			netpipe.CloseForDelivery(up)
		}
		netpipe.StopForDelivery(c)
		pair := []net.Conn{c}
		if up != nil {
			pair = append(pair, up)
		}
		netpipe.AwaitDelivered(wake, pair...)
		l.endDelivery(c)
		c.Close()
		if up != nil {
			up.Close()
		}
	}
	up, err := m.opts.Dial(net.JoinHostPort(rule.AgentAddr.String(), itoa(rule.AgentPort)))
	if err != nil {
		if l.dialLog.Allow() {
			m.opts.Logf("proxy: %d: cannot connect to agent %s:%d: %v", rule.ListenPort, rule.AgentAddr, rule.AgentPort, err)
		}
		failed(nil)
		return
	}
	if rule.ProxyProtocol {
		hdr := proxyproto.HeaderProxyFromAddrs(2, c.RemoteAddr(), c.LocalAddr())
		var writer io.Writer = up
		if m.testHeaderWriter != nil {
			writer = m.testHeaderWriter(up)
		}
		if _, err := hdr.WriteTo(writer); err != nil {
			failed(up)
			return
		}
	}
	if m.opts.HoldUntilDelivered {
		if _, ok := l.finishPending(a, up, false); !ok {
			relayed{up: up}.cut(c)
			return
		}
		pending = false
	} else {
		unpend()
		if !l.track(c, up, src, gen) {
			// 実効宛先が変わった後にこの接続を残すと、旧いエージェントへ中継し続ける
			return
		}
	}
	defer l.untrack(c)
	// ユーザー空間モードでは、公開側のカーネルのソケットの受信のバッファを netstack の接続 up の boost の
	// 枠に合わせる(設計文書 7 節)。カーネルモードの up は実ソケットなので何もしない
	netpipe.FollowBoost(c, up)
	// 公開側のクライアントが RST で切ったときは、up も通常の Close ではなく RST で切る(設計文書 6.2 節)。
	// FIN で閉じると、エージェントの中継はハーフクローズとして扱い、FIN を受けても閉じない宛先では、
	// エージェント側の宛先への接続と枠が宛先が閉じるまで残る
	if !m.opts.HoldUntilDelivered {
		netpipe.PipeResetB(c, up, func() { resetUpstream(up) })
		return
	}
	// ユーザー空間モードでは、中継が終わった後も、組が送り残しを届け終えるまでフローの 2 つの枠
	// (Resource Guard の枠と送信元ごとの枠)を持ち、届け終えた後に上の defer がまとめて返す(設計文書
	// 7 節の「中継が終わった後の末尾の配送」)
	netpipe.PipeHold(c, up, func() { resetUpstream(up) })
	if wake := l.beginDelivery(c); wake != nil {
		netpipe.AwaitDelivered(wake, c, up)
		l.endDelivery(c)
	}
	c.Close()
	up.Close()
}

// finishPending atomically moves a userspace worker from pending to its active or failed
// delivery record. Retirement and source-only updates retain the existing pending exception.
// If close or retarget won, the caller keeps pending until it has cut the returned pair.
func (l *listener) finishPending(a *admitted, up net.Conn, failed bool) (chan struct{}, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.gen != a.gen {
		return nil, false
	}
	r := relayed{src: a.src.String(), up: up}
	l.pending--
	if l.testHookPendingRegistration != nil {
		l.testHookPendingRegistration()
	}
	var wake chan struct{}
	if failed {
		wake = make(chan struct{})
		l.delivering[a.c] = delivering{relayed: r, wake: wake}
	} else {
		l.conns[a.c] = r
	}
	return wake, true
}

// beginDelivery は、中継を終えた組を conns から delivering へ移し、待ちを起こす channel を返す。切る経路が
// すでに組を切っていれば(conns に無ければ)nil を返す。
func (l *listener) beginDelivery(c net.Conn) chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.conns[c]
	if !ok {
		return nil
	}
	delete(l.conns, c)
	d := delivering{relayed: r, wake: make(chan struct{})}
	l.delivering[c] = d
	return d.wake
}

func (l *listener) endDelivery(c net.Conn) {
	l.mu.Lock()
	delete(l.delivering, c)
	l.mu.Unlock()
}

// updateRestriction は待ち受けを残したまま宣言を更新し、閉じるべき進行中の接続を閉じる。
// 同じポートのルールが分割・統合やエージェントの変更で入れ替わった場合に備え、ID と所属エージェントも
// 新しい宣言に合わせる(CloseAgent がエージェントで探すため)。
//
// 実効宛先(エージェントのアドレスと待ち受けポート)が変わったときは、進行中の接続をすべて閉じる
// (仕様 6.2 節、7 節の収束の表の「実効宛先が違う」)。成立済みの接続は accept の時点の実効宛先へ
// つながったままであり、宣言の値を書き換えても新しいエージェントへは向かないためである。
// 接続元制限だけが変わったときは、許可されなくなった接続元の接続だけを閉じる。
// 戻り値は、実効宛先が変わったかどうかと、閉じた接続の数である。
func (l *listener) updateRestriction(r Rule) (retargeted bool, closed int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	retargeted = r.AgentAddr != l.rule.AgentAddr || r.AgentPort != l.rule.AgentPort
	l.rule.ID, l.rule.Agent = r.ID, r.Agent
	// 分割と統合で所属ルールが変わっても、既存の接続は受け付けたときのルールの登録に数えたままで、
	// ルール 1 本の上限に使う listener が運ぶ数だけが移動先へ移る。元のルールの登録が退役すれば、
	// 既存の接続は帰属の規則で移動先の登録へ移る(設計文書 7a.10 節)
	l.budget.SetRule(r.ID)
	l.rule.Policy = r.Policy
	l.rule.ProxyProtocol, l.rule.AgentAddr, l.rule.AgentPort = r.ProxyProtocol, r.AgentAddr, r.AgentPort
	if retargeted {
		// 旧い実効宛先へ接続中の worker は、track のときに gen の違いで気付いて閉じる
		l.gen++
		for c, rc := range l.conns {
			rc.cut(c)
			closed++
		}
		// 送り残しを届けている途中の組も切る。中継は終わっているので、閉じた数には入れない
		for c, d := range l.delivering {
			d.cut(c)
		}
		clear(l.delivering)
		return retargeted, closed
	}
	for c, rc := range l.conns {
		src, err := netip.ParseAddr(rc.src)
		if err == nil && !sourceAllowed(src, l.rule) {
			rc.cut(c)
			closed++
		}
	}
	for c, d := range l.delivering {
		src, err := netip.ParseAddr(d.src)
		if err == nil && !sourceAllowed(src, l.rule) {
			d.cut(c)
			delete(l.delivering, c)
		}
	}
	return retargeted, closed
}

// track は中継を始める接続 c と、そのエージェントへの接続 up を記録する。待ち受けが閉じた後の接続と、
// 接続している間に実効宛先が変わった接続(gen の違い)は記録せずに両側を閉じ、偽を返す。
func (l *listener) track(c, up net.Conn, src netip.Addr, gen int) bool {
	r := relayed{src: src.String(), up: up}
	l.mu.Lock()
	if l.closed || l.gen != gen {
		l.mu.Unlock()
		r.cut(c)
		return false
	}
	l.conns[c] = r
	l.mu.Unlock()
	return true
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

// idle は Retiring の中継に、成立済みの接続も接続中の接続も、送り残しを届けている途中の組も残って
// いないか。
func (l *listener) idle() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.conns) == 0 && len(l.delivering) == 0 && l.pending == 0 && l.admitting == nil
}

// beginStopAccepting は待ち受けと判定中のソケットを閉じ、成立済みの接続には触れない(設計文書 7a.3 節の
// StopAccepting)。触れなかった接続は Retiring になり、自然に終わるまで中継を続ける。
// 残る接続はプロセス全体の数に入り続け、ルールごとの数からは外れる(設計文書 7a.10 節の A)。
func (l *listener) beginStopAccepting() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopLocked()
	l.budget.StopAccepting()
}

// retire は keep が偽を返す接続元の接続だけを閉じ、閉じた数を返す(設計文書 7a.3 節の Retire)。
// 閉じた接続は記録から外すので、直後の idle は閉じた接続を数えない。
func (l *listener) retire(keep func(src netip.Addr) bool) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for c, r := range l.conns {
		src, err := netip.ParseAddr(r.src)
		if err != nil || !keep(src) {
			r.cut(c)
			delete(l.conns, c)
			n++
		}
	}
	for c, d := range l.delivering {
		src, err := netip.ParseAddr(d.src)
		if err != nil || !keep(src) {
			d.cut(c)
			delete(l.delivering, c)
		}
	}
	return n
}

// stopLocked invalidates uncommitted admission; it never waits for policy work.
func (l *listener) stopLocked() {
	if !l.stopping {
		l.stopping = true
		close(l.stopAccept)
		l.ln.Close()
		if l.admitting != nil {
			abortRefused(l.admitting)
		}
	}
}

func (l *listener) waitServeDone() { <-l.serveDone }

func (l *listener) beginClose() {
	l.mu.Lock()
	l.closed = true
	l.stopLocked()
	// 閉じ終えていない接続の枠は、中継の goroutine が Release を呼ぶまでプロセス全体の数に残る
	l.budget.Close()
	for c, r := range l.conns {
		r.cut(c)
	}
	l.conns = map[net.Conn]relayed{}
	for c, d := range l.delivering {
		d.cut(c)
	}
	clear(l.delivering)
	l.mu.Unlock()
}

// sourceAllowed の deny/allow の判定は internal/policy.RulePolicy.SourceAllowed に委ねる
// (design.md 7a.9 節「Phase 5 の移行の手順」1:4 か所に分かれていた同じ判定を IR の 1 実装へ
// 集約する最初の 1 か所)。カーネルモードの受け付けと、成立済みの接続を残すかの判定(updateRestriction、
// retire)で使う。ユーザー空間モードの受け付けは Options.Admit が判定する。
func sourceAllowed(src netip.Addr, r Rule) bool {
	return r.Policy.SourceAllowed(src)
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
