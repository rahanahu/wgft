// Package relay は、エージェントの netstack 上のリスナーと、LAN 内の target への中継を持つ(仕様 7 節)。
//
// 収束の単位はポートで、宣言 (proto, port) → (実効宛先, 所属ルール ID) と現在のリスナーを突き合わせる。
// リスナーをどこに開くかは Network で差し替えられるので、単体テストはホストのループバックで行う。
package relay

import (
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

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
	UDPSessionsMax int           // ルールごとの UDP セッション数の上限(既定 4096)
	Dial           func(network, addr string) (net.Conn, error)
	Logf           func(format string, args ...any)
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
	// セッション数(UDP)。ルールごとの上限は Manager が同じルールのリスナーの合計で見る
	sessions func() int
	bindErr  error // リスナーを開けなかった(bind 失敗)。Retry で開き直す
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
		opts.UDPSessionsMax = 4096
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
	l := &listener{key: k, target: d.Target, ruleID: d.RuleID, sessions: func() int { return 0 }}
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

// Close は全リスナーを閉じる。
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.listeners {
		m.closeLocked(k)
	}
}

// ruleSessions は同じルールに所属する全リスナーのセッション合計(上限の判定に使う)。
// 分割で移ったリスナーの既存セッションは移動先のルールで数える(仕様 7 節)。
func (m *Manager) ruleSessions(ruleID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, l := range m.listeners {
		if l.ruleID == ruleID {
			n += l.sessions()
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
