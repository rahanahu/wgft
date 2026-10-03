package relay

import (
	"fmt"
	"net"
	"net/netip"
	"sort"

	"github.com/rahanahu/wgft/internal/reasontext"
	"github.com/rahanahu/wgft/proto"
)

// Staged は Prepare で確保した待ち受けの変更を、Commit か Rollback まで保留する(設計文書 7a.2、
// 7a.3 節)。vpsd のユーザー空間モードの dataplane がこの経路を使い、エージェントは従来どおり
// Apply(部分的な失敗を記録して Retry で開き直す)を使う。
//
// Apply との違いは次のとおりである。
//   - bind は Prepare で行う。Commit は bind 済みのソケットで中継を始めるだけで、失敗しない
//   - bind に失敗したポートを持つルールは、そのルール全体を Failed として報告し、そのルールの
//     ポートを 1 つも公開しない(範囲のルールの一部のポートだけを転送することはしない)
//   - 実効宛先の変更は、待ち受けを開き直さずに宛先を差し替え、進行中のセッションを閉じる
//     (セッションが切れる点は Apply の reopen と同じ)。開き直しの bind が失敗する余地を残さないため
//   - 宣言から消えた待ち受けのうち、Retiring のルールのものは閉じずに新しいフローの受け付けだけを
//     やめる(stopAccept)
//   - 新しく開く TCP の待ち受けの target へ試し接続しない(設計文書 6.3 節)。target はエージェントの
//     トンネルのアドレスで、エージェントがそのポートを開くのは Commit の後だからである
type Staged struct {
	m       *Manager
	desired map[Key]Desired
	// opened は Prepare で bind したが、まだ中継を始めていない待ち受け。
	opened map[Key]boundSocket
	// revived は Retiring の UDP の待ち受けのうち、宣言に戻ったもの(ソケットを持ち続けているので
	// bind し直さずに使う)。
	revived map[Key]bool
	failed  map[string]error
	done    bool
}

// boundSocket は bind 済みで中継を始めていないソケット。どちらか一方だけを持つ。
type boundSocket struct {
	ln net.Listener
	pc net.PacketConn
}

func (s boundSocket) close() {
	if s.ln != nil {
		s.ln.Close()
	}
	if s.pc != nil {
		s.pc.Close()
	}
}

// Prepare は、宣言のうちまだ開いていない待ち受けを bind する。既存の待ち受けには触らず、
// 新しい待ち受けも Commit まで中継を始めない。bind に失敗したポートを 1 つでも持つルールは
// Failed に入り、そのルールのために bind したソケットはすべて閉じる。
func (m *Manager) Prepare(desired map[Key]Desired) *Staged {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &Staged{m: m, desired: map[Key]Desired{}, opened: map[Key]boundSocket{}, revived: map[Key]bool{}, failed: map[string]error{}}
	keys := make([]Key, 0, len(desired))
	for k := range desired {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keyLess(keys[i], keys[j]) })
	for _, k := range keys {
		d := desired[k]
		if _, ok := m.listeners[k]; ok {
			continue
		}
		if l, ok := m.retiring[k]; ok && k.Proto == proto.UDP && l.bound() {
			s.revived[k] = true
			continue
		}
		if _, bad := s.failed[d.RuleID]; bad {
			continue
		}
		sock, err := m.bind(k)
		if err != nil {
			f := m.bindFail[k]
			if f == nil {
				f = &bindFailure{}
				m.bindFail[k] = f
			}
			f.attempts++
			if f.reason != err.Error() {
				f.reason = err.Error()
				m.opts.Logf("listener %s: %v", k, err)
			}
			s.failed[d.RuleID] = fmt.Errorf(reasontext.BindFailed+": %w", err)
			continue
		}
		s.opened[k] = sock
	}
	// 宣言から消えたキーの失敗の記録は捨てる
	for k := range m.bindFail {
		if _, ok := desired[k]; !ok {
			delete(m.bindFail, k)
		}
	}
	for k, d := range desired {
		if _, bad := s.failed[d.RuleID]; bad {
			if sock, ok := s.opened[k]; ok {
				sock.close()
				delete(s.opened, k)
			}
			delete(s.revived, k)
			continue
		}
		s.desired[k] = d
	}
	return s
}

func keyLess(a, b Key) bool {
	if a.Proto != b.Proto {
		return a.Proto < b.Proto
	}
	return a.Port < b.Port
}

func (m *Manager) bind(k Key) (boundSocket, error) {
	switch k.Proto {
	case proto.UDP:
		pc, err := m.net.ListenUDP(k.Port)
		return boundSocket{pc: pc}, err
	case proto.TCP:
		ln, err := m.net.ListenTCP(k.Port)
		return boundSocket{ln: ln}, err
	}
	return boundSocket{}, fmt.Errorf("unknown proto %q", k.Proto)
}

// Failed は bind に失敗したルールと、その理由。
func (s *Staged) Failed() map[string]error { return s.failed }

// Commit は Prepare で bind した待ち受けで中継を始め、宣言から消えた待ち受けを閉じ、宛先と所属ルールの
// 変更を反映する。retiring にあるルール(fail-closed にしたルール)の待ち受けは閉じずに新しいフローの
// 受け付けをやめ、その値が偽を返す接続元のフローだけを閉じる(設計文書 7a.3 節)。Commit は戻れない
// 地点の後に呼ばれるので失敗しない。2 回目以降と Rollback の後は何もしない。
func (s *Staged) Commit(retiring map[string]func(src netip.Addr) bool) {
	if s.done {
		return
	}
	s.done = true
	m := s.m
	// 新しく開く TCP の待ち受けの target へは試し接続しない(設計文書 6.3 節)。この経路を使う vpsd の
	// target はエージェントのトンネルのアドレスで、エージェントはこの Commit の後に配られる全体状態で
	// 初めてそのポートを開く。この時点の確認は届かないのが普通で、カーネルモードのエージェントは開いて
	// いないポートへの SYN を黙って捨てるので、1 件ごとに期限まで待ち、適用と起動を遅らせる。宛先に
	// 届くかどうかは、エージェントが自分の確認の結果として報告する
	m.mu.Lock()
	defer m.mu.Unlock()
	// Retiring から宣言に戻った UDP の待ち受けは、ソケットを持ち続けているのでそのまま戻す
	for k := range s.revived {
		m.reviveLocked(k, s.desired[k])
	}
	for k, l := range m.listeners {
		d, ok := s.desired[k]
		step := ""
		switch {
		case !ok:
			if keep, r := retiring[l.ruleID]; r {
				m.retireLocked(k, l, keep)
				step = "retire"
			} else {
				m.closeLocked(k)
				step = "close"
			}
		case d.Target != l.target:
			l.target = d.Target
			l.setRuleLocked(d.RuleID)
			n := l.sweep(func(netip.Addr) bool { return false })
			m.opts.Logf("listener %s -> %s retargeted; rule %s; closed %d sessions", k, d.Target, d.RuleID, n)
			step = "retarget"
		case d.RuleID != l.ruleID:
			l.setRuleLocked(d.RuleID)
			step = "relabel"
		}
		if h := m.testHookCommitStep; h != nil && step != "" {
			h(k, step)
		}
	}
	for k, sock := range s.opened {
		d := s.desired[k]
		l := m.newListener(k, d)
		// ソケットは Prepare で bind してあるので、中継を始める前に受け付けにする。この順で、
		// 受け付けているルールの集合 A に入る待ち受けは開けたものだけになり、A に入る前に
		// フローを受けることもない(設計文書 7a.10 節)
		l.budget.Accept()
		if sock.pc != nil {
			m.serveUDP(l, sock.pc)
		} else {
			m.serveTCP(l, sock.ln)
		}
		m.listeners[k] = l
		m.opts.Logf("listener %s -> %s opened; rule %s", k, d.Target, d.RuleID)
		if f := m.bindFail[k]; f != nil {
			m.opts.Logf("listener %s: opened after %d failed attempts", k, f.attempts)
			delete(m.bindFail, k)
		}
	}
	// 以前から Retiring の待ち受けは、そのルールがまだ Retiring のあいだだけ残す。ルールが削除、
	// 無効化された、あるいは新しい値で Active になったときは閉じる(成立済みのフローも切れる)。
	// 残すものは新しい宣言の接続元制限で判定し直し、フローが残っていなければ閉じる。
	for k, l := range m.retiring {
		keep, r := retiring[l.ruleID]
		if !r {
			m.closeRetiringLocked(k, l)
			m.opts.Logf("listener %s closed: rule %s is no longer retiring", k, l.ruleID)
			continue
		}
		l.sweep(func(src netip.Addr) bool { return keep(src) })
		if l.sessions() == 0 {
			m.closeRetiringLocked(k, l)
			m.opts.Logf("listener %s closed: no established flows left", k)
		}
	}
}

// retireLocked は待ち受けを Retiring にする。新しいフローの受け付けをやめ、keep が偽を返す接続元の
// フローだけを閉じる。同じキーの Retiring の待ち受けが既にあれば(TCP で、同じポートを
// 何度も fail-closed にした場合)、古いほうは閉じる。
func (m *Manager) retireLocked(k Key, l *listener, keep func(src netip.Addr) bool) {
	delete(m.listeners, k)
	if old, ok := m.retiring[k]; ok {
		old.shutdownLocked()
	}
	if l.bound() {
		l.stopAccept()
	}
	// Retiring の待ち受けのフローは、プロセス全体の数には残り、ルールごとの数からは外れる
	// (設計文書 7a.10 節の A)。そのルールの待ち受けはすべて Retiring になるので、ルールごとの
	// 上限の判定はこの待ち受けを見ない
	l.budget.StopAccepting()
	n := 0
	if l.bound() {
		n = l.sweep(keep)
	}
	m.retiring[k] = l
	m.opts.Logf("listener %s stopped accepting: rule %s is not active; closed %d flows its new declaration refuses", k, l.ruleID, n)
}

// reviveLocked は、Retiring から宣言に戻った UDP の待ち受け k を受け付けに戻す。ソケットを持ち続けて
// いるので bind し直さない。d は k の宣言である。呼び出し側は m.mu を持つ。
func (m *Manager) reviveLocked(k Key, d Desired) {
	l := m.retiring[k]
	delete(m.retiring, k)
	// 宣言のルールが変わっていれば、受け付けを再開する前に付け替える。受け付けていない待ち受けの
	// 付け替えはラベルだけを変えるので、再開の加入で旧いセッションは宣言のルールの登録へ移る。
	// 再開の後に付け替えると、同じルールの別の待ち受けも同じ Commit で再開するとき、旧いセッションが
	// 生きている元のルールの登録に残る(設計文書 7a.10 節の「退役した登録のフローの帰属」)
	if d.RuleID != l.ruleID {
		l.setRuleLocked(d.RuleID)
	}
	// 受け付けの印を先に立て、Pool の Accept を後に呼ぶ(設計文書 7a.10 節)。読み取りの goroutine
	// は印を見た後に ruleOf で m.mu を待つので、取得はこの Commit の後になる。仮に 2 文の間に取得が
	// 入っても、Pool は受け付けていない handle として拒むので帳簿は崩れない
	l.accepting.Store(true)
	if h := m.testHookRevive; h != nil {
		h(l)
	}
	l.budget.Accept()
	m.listeners[k] = l
	m.opts.Logf("listener %s accepting again", k)
}

// closeRetiringLocked は Retiring の待ち受け l を閉じ、retiring の表から消す。呼び出し側は m.mu を持つ。
func (m *Manager) closeRetiringLocked(k Key, l *listener) {
	l.shutdownLocked()
	delete(m.retiring, k)
}

// Rollback は Prepare で bind したソケットを閉じる。既存の待ち受けには触らない。
func (s *Staged) Rollback() {
	if s.done {
		return
	}
	s.done = true
	for k, sock := range s.opened {
		sock.close()
		s.m.opts.Logf("listener %s released: data plane apply failed", k)
	}
}

// Retiring はいま Retiring の待ち受けのキー(テストとログ用)。
func (m *Manager) Retiring() []Key {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Key, 0, len(m.retiring))
	for k := range m.retiring {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return keyLess(out[i], out[j]) })
	return out
}
