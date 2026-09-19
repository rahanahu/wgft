package relay

import (
	"fmt"
	"net"
	"net/netip"
	"sort"

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
		if l, ok := m.retiring[k]; ok && k.Proto == proto.UDP && l.sweep != nil {
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
			s.failed[d.RuleID] = fmt.Errorf("bind failed: %w", err)
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
	m.mu.Lock()
	defer m.mu.Unlock()
	// Retiring から宣言に戻った UDP の待ち受けは、ソケットを持ち続けているのでそのまま戻す
	for k := range s.revived {
		l := m.retiring[k]
		delete(m.retiring, k)
		l.accepting.Store(true)
		l.budget.Accept()
		m.listeners[k] = l
		m.opts.Logf("listener %s accepting again", k)
	}
	for k, l := range m.listeners {
		d, ok := s.desired[k]
		switch {
		case !ok:
			if keep, r := retiring[l.ruleID]; r {
				m.retireLocked(k, l, keep)
			} else {
				m.closeLocked(k)
			}
		case d.Target != l.target:
			l.target, l.ruleID = d.Target, d.RuleID
			l.budget.SetRule(d.RuleID)
			n := l.sweep(func(netip.Addr) bool { return false })
			m.opts.Logf("listener %s -> %s retargeted; rule %s; closed %d sessions", k, d.Target, d.RuleID, n)
		case d.RuleID != l.ruleID:
			l.ruleID = d.RuleID
			l.budget.SetRule(d.RuleID)
		}
	}
	for k, sock := range s.opened {
		d := s.desired[k]
		l := m.newListener(k, d)
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
		if k.Proto == proto.TCP {
			if err := m.checkTarget(d.Target); err != nil {
				setTargetErrLocked(l, err)
				m.opts.Logf("listener %s: cannot connect to target %s: %v", k, d.Target, err)
			}
		}
	}
	// 以前から Retiring の待ち受けは、そのルールがまだ Retiring のあいだだけ残す。ルールが削除、
	// 無効化された、あるいは新しい値で Active になったときは閉じる(成立済みのフローも切れる)。
	// 残すものは新しい宣言の接続元制限で判定し直し、フローが残っていなければ閉じる。
	for k, l := range m.retiring {
		keep, r := retiring[l.ruleID]
		if !r {
			l.closeF()
			l.budget.Close()
			delete(m.retiring, k)
			m.opts.Logf("listener %s closed (rule %s is no longer retiring)", k, l.ruleID)
			continue
		}
		l.sweep(func(src netip.Addr) bool { return keep(src) })
		if l.sessions() == 0 {
			l.closeF()
			l.budget.Close()
			delete(m.retiring, k)
			m.opts.Logf("listener %s closed (no established flows left)", k)
		}
	}
}

// retireLocked は待ち受けを Retiring にする。新しいフローの受け付けをやめ、keep が偽を返す接続元の
// フローだけを閉じる。同じキーの Retiring の待ち受けが既にあれば(TCP で、同じポートを
// 何度も fail-closed にした場合)、古いほうは閉じる。
func (m *Manager) retireLocked(k Key, l *listener, keep func(src netip.Addr) bool) {
	delete(m.listeners, k)
	if old, ok := m.retiring[k]; ok {
		old.closeF()
		old.budget.Close()
	}
	if l.stopAccept != nil {
		l.stopAccept()
	}
	// Retiring の待ち受けのフローは、プロセス全体の数には残り、ルールごとの数からは外れる
	// (設計文書 7a.10 節の A)。そのルールの待ち受けはすべて Retiring になるので、ルールごとの
	// 上限の判定はこの待ち受けを見ない
	l.budget.StopAccepting()
	n := 0
	if l.sweep != nil {
		n = l.sweep(keep)
	}
	m.retiring[k] = l
	m.opts.Logf("listener %s stopped accepting (rule %s is not active); closed %d flows its new declaration refuses", k, l.ruleID, n)
}

// Rollback は Prepare で bind したソケットを閉じる。既存の待ち受けには触らない。
func (s *Staged) Rollback() {
	if s.done {
		return
	}
	s.done = true
	for k, sock := range s.opened {
		sock.close()
		s.m.opts.Logf("listener %s released (data plane apply failed)", k)
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
