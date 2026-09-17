// Package relay は、エージェントの netstack 上のリスナーと、LAN 内の target への中継を持つ(仕様 7 節)。
//
// 収束の単位はポートで、宣言 (proto, port) → (実効宛先, 所属ルール ID) と現在のリスナーを突き合わせる。
// リスナーをどこに開くかは Network で差し替えられるので、単体テストはホストのループバックで行う。
package relay

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/proto"
)

// Network はリスナーを開く先。本番は netstack、テストはホストのループバック。
type Network interface {
	ListenUDP(port uint16) (net.PacketConn, error)
	ListenTCP(port uint16) (net.Listener, error)
}

// Options は中継の調整値。
type Options struct {
	UDPIdleTimeout time.Duration // 無通信でセッションを閉じるまで(全体状態の udp_timeout_stream)
	UDPSessionsMax int           // ルールごとの UDP セッション数の上限(既定 flowcap.UDPPerRule)
	TCPConnsMax    int           // ルールごとの TCP 接続数の上限(既定 flowcap.TCPPerRule)
	// Limits はプロセス全体の上限(設定値)。UDPCap と TCPCap が nil のときに使う
	Limits flowcap.Limits
	// UDPCap と TCPCap はプロセス全体と接続元 IP ごとの上限(仕様 7 節)。nil なら全体の上限だけを Limits から作る。
	// vpsd はプロキシモードの中継と共有する Counter を渡す
	UDPCap *flowcap.Counter
	TCPCap *flowcap.Counter
	Dial   func(network, addr string) (net.Conn, error)
	Logf   func(format string, args ...any)
	// Admit は新しいフロー(TCP の accept、UDP の新しいセッション)を通すか。nil なら全部通す。
	// VPS 側のユーザー空間モード(仕様 6.3 節)が接続元制限とレート制限をここで判定する。エージェントでは nil。
	Admit func(ruleID string, src netip.Addr) bool
	// AdmitPacket は UDP のデータグラム 1 つを通すか(packet_rate)。nil なら全部通す。
	AdmitPacket func(ruleID string, size int) bool
}

// Key はリスナーの同一性。
type Key struct {
	Proto proto.Proto
	Port  uint16
}

// String は "udp/2456" の形で返す。ログとテストの表示用。
func (k Key) String() string { return fmt.Sprintf("%s/%d", k.Proto, k.Port) }

// Desired はリスナー 1 つの宣言値。
type Desired struct {
	Target string // 実効宛先 host:port
	RuleID string
}

// Manager は現在のリスナー集合を持ち、宣言に収束させる。
type Manager struct {
	net  Network
	opts Options

	mu        sync.Mutex
	listeners map[Key]*listener
}

type listener struct {
	key    Key
	target string
	ruleID string
	closeF func()
	// sweep は keep が偽を返す接続元のセッションを閉じ、閉じた数を返す(接続元制限の変更の即時反映。仕様 6.2 節)
	sweep func(keep func(src netip.Addr) bool) int
	// セッション数(ハートビートの表示用)
	sessions func() int
	// 上限の対象になるフロー数(UDP はセッション、TCP は公開側の接続)。
	// ルールごとの上限は Manager が同じルールのリスナーの合計で見る
	flows   func() int
	bindErr error // リスナーを開けなかった(bind 失敗)。Retry で開き直す
	// targetErr は TCP ルールで target への接続確認が失敗したときの誤り(仕様 5.2 節)。
	// リスナー自体は開いているので、Retry では開き直さず再確認だけする
	targetErr error
}

// err は報告する状態。bind 失敗が優先(リスナーがないので)。
func (l *listener) err() error {
	if l.bindErr != nil {
		return l.bindErr
	}
	return l.targetErr
}

// New は空の Manager を作る。
func New(n Network, opts Options) *Manager {
	if opts.UDPIdleTimeout <= 0 {
		opts.UDPIdleTimeout = 120 * time.Second
	}
	if opts.UDPSessionsMax <= 0 {
		opts.UDPSessionsMax = flowcap.UDPPerRule
	}
	if opts.TCPConnsMax <= 0 {
		opts.TCPConnsMax = flowcap.TCPPerRule
	}
	lim := opts.Limits.WithDefaults()
	if opts.UDPCap == nil {
		opts.UDPCap = &flowcap.Counter{Total: lim.UDPTotal}
	}
	if opts.TCPCap == nil {
		opts.TCPCap = &flowcap.Counter{Total: lim.TCPTotal}
	}
	if opts.Dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		opts.Dial = d.Dial
	}
	if opts.Logf == nil {
		opts.Logf = log.Printf
	}
	return &Manager{net: n, opts: opts, listeners: map[Key]*listener{}}
}

// DesiredFromRules は全体状態のルールから、ポートごとの宣言値を計算する。
// 無効なルールは宣言に現れない。実効宛先は target のポートに範囲内での位置を足したもの。
func DesiredFromRules(rules []proto.AgentRule) map[Key]Desired {
	out := map[Key]Desired{}
	for i := range rules {
		r := &rules[i]
		if !r.Enabled {
			continue
		}
		for p := int(r.ListenPort.Lo); p <= int(r.ListenPort.Hi); p++ {
			target, ok := r.EffectiveTarget(uint16(p))
			if !ok {
				continue
			}
			out[Key{Proto: r.Proto, Port: uint16(p)}] = Desired{Target: target, RuleID: r.ID}
		}
	}
	return out
}

// Action は収束で行う操作。テストで順序と種類を確かめる。
type Action struct {
	Op  string // open | close | reopen | relabel
	Key Key
}

// plan は現在と宣言の差分を操作に落とす(仕様 7 節の 4 規則)。
//   - 宣言にあって現在にない:open
//   - 現在にあって宣言にない:close
//   - 実効宛先が違う:reopen(閉じてから開く。セッションは切れる)
//   - 所属ルール ID だけが違う:relabel(何もしない。セッションは残る)
func plan(current map[Key]*listener, desired map[Key]Desired) []Action {
	var acts []Action
	for k, l := range current {
		d, ok := desired[k]
		switch {
		case !ok:
			acts = append(acts, Action{"close", k})
		case d.Target != l.target:
			acts = append(acts, Action{"reopen", k})
		case d.RuleID != l.ruleID:
			acts = append(acts, Action{"relabel", k})
		}
	}
	for k := range desired {
		if _, ok := current[k]; !ok {
			acts = append(acts, Action{"open", k})
		}
	}
	// 順序を決めて、ログとテストを読みやすくする
	sort.Slice(acts, func(i, j int) bool {
		if acts[i].Key.Proto != acts[j].Key.Proto {
			return acts[i].Key.Proto < acts[j].Key.Proto
		}
		return acts[i].Key.Port < acts[j].Key.Port
	})
	return acts
}

// Apply は宣言に収束させる。開けなかったポートは記録して続け(部分失敗でも進める)、まとめて返す。
func (m *Manager) Apply(desired map[Key]Desired) []Action {
	m.mu.Lock()
	defer m.mu.Unlock()
	acts := plan(m.listeners, desired)
	for _, a := range acts {
		d := desired[a.Key]
		switch a.Op {
		case "close":
			m.closeLocked(a.Key)
		case "reopen":
			m.closeLocked(a.Key)
			m.openLocked(a.Key, d)
		case "relabel":
			m.listeners[a.Key].ruleID = d.RuleID
		case "open":
			m.openLocked(a.Key, d)
		}
	}
	return acts
}

func (m *Manager) closeLocked(k Key) {
	if l, ok := m.listeners[k]; ok {
		l.closeF()
		delete(m.listeners, k)
		m.opts.Logf("listener %s closed", k)
	}
}

func (m *Manager) openLocked(k Key, d Desired) {
	zero := func() int { return 0 }
	l := &listener{key: k, target: d.Target, ruleID: d.RuleID, sessions: zero, flows: zero}
	var err error
	switch k.Proto {
	case proto.UDP:
		err = m.startUDP(l)
	case proto.TCP:
		err = m.startTCP(l)
	default:
		err = fmt.Errorf("unknown proto %q", k.Proto)
	}
	if err != nil {
		// 開けなくても登録しておき、状態として見せる。次の Apply(再試行)で開き直す
		l.bindErr = err
		l.closeF = func() {}
		m.opts.Logf("listener %s: %v", k, err)
	} else {
		m.opts.Logf("listener %s -> %s opened; rule %s", k, d.Target, d.RuleID)
		if k.Proto == proto.TCP {
			l.targetErr = m.checkTarget(l.target)
			if l.targetErr != nil {
				m.opts.Logf("listener %s: cannot connect to target %s: %v", k, l.target, l.targetErr)
			}
		}
	}
	m.listeners[k] = l
}

// checkTarget は TCP の target へ試し接続する(接続してすぐ閉じる)。UDP は到達確認ができないので呼ばない。
func (m *Manager) checkTarget(target string) error {
	c, err := m.opts.Dial("tcp", target)
	if err != nil {
		return err
	}
	c.Close()
	return nil
}

// Retry は 30 秒ごとに、bind できなかったリスナーを開き直し、TCP は target への接続を再確認する
// (仕様 5.2 節)。target が復帰すれば targetErr が消え、落ちれば付く。状態の変化はハートビートで報告される。
func (m *Manager) Retry() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, l := range m.listeners {
		if l.bindErr != nil {
			d := Desired{Target: l.target, RuleID: l.ruleID}
			delete(m.listeners, k)
			m.openLocked(k, d)
			continue
		}
		if k.Proto == proto.TCP {
			l.targetErr = m.checkTarget(l.target)
		}
	}
}

// Status はリスナーごとの状態(ハートビート用)。
type Status struct {
	Key      Key
	Target   string
	RuleID   string
	Sessions int
	Err      error
}

// Status は現在のリスナーごとの宣言値と状態を返す(ハートビートの材料)。
func (m *Manager) Status() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.listeners))
	for _, l := range m.listeners {
		out = append(out, Status{Key: l.key, Target: l.target, RuleID: l.ruleID, Sessions: l.sessions(), Err: l.err()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key.String() < out[j].Key.String() })
	return out
}

// CloseSessions は、keep が偽を返す(ルール ID、接続元)のセッションを閉じ、閉じた数を返す。
// 接続元制限を変えたときに進行中のフローを切るために VPS 側のユーザー空間モードが使う。
func (m *Manager) CloseSessions(keep func(ruleID string, src netip.Addr) bool) int {
	m.mu.Lock()
	ls := make([]*listener, 0, len(m.listeners))
	for _, l := range m.listeners {
		ls = append(ls, l)
	}
	m.mu.Unlock()
	n := 0
	for _, l := range ls {
		if l.sweep == nil {
			continue
		}
		id := m.ruleOf(l)
		n += l.sweep(func(src netip.Addr) bool { return keep(id, src) })
	}
	return n
}

// addrOf は接続の相手のアドレスを netip.Addr にする(IPv4 射影は外す)。
func addrOf(a net.Addr) netip.Addr {
	var ip net.IP
	switch v := a.(type) {
	case *net.TCPAddr:
		ip = v.IP
	case *net.UDPAddr:
		ip = v.IP
	default:
		if ap, err := netip.ParseAddrPort(a.String()); err == nil {
			return ap.Addr().Unmap()
		}
		return netip.Addr{}
	}
	if addr, ok := netip.AddrFromSlice(ip); ok {
		return addr.Unmap()
	}
	return netip.Addr{}
}

// Close は全リスナーを閉じる。
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.listeners {
		m.closeLocked(k)
	}
}

// ruleFlows は同じルールに所属する全リスナーのフロー合計(上限の判定に使う)。
// 分割で移ったリスナーの既存セッションは移動先のルールで数える(仕様 7 節)。
func (m *Manager) ruleFlows(ruleID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, l := range m.listeners {
		if l.ruleID == ruleID {
			n += l.flows()
		}
	}
	return n
}

// ruleOf は現在の所属ルール ID(relabel で変わりうるので、その都度読む)。
func (m *Manager) ruleOf(l *listener) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return l.ruleID
}
