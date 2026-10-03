package relay

import (
	"sort"

	"github.com/rahanahu/wgft/proto"
)

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
// 開いた TCP の待ち受けの target への到達確認は、錠を放してからまとめて行う(設計文書 5.2 節)。
// Apply はその結果を待ってから戻るので、ルールの最初の状態は適用の直後のハートビートに載る。
func (m *Manager) Apply(desired map[Key]Desired) []Action {
	m.mu.Lock()
	acts := plan(m.listeners, desired)
	var probes []targetProbe
	for _, a := range acts {
		d := desired[a.Key]
		switch a.Op {
		case "close":
			m.closeLocked(a.Key)
		case "reopen":
			m.closeLocked(a.Key)
			probes = appendProbe(probes, a.Key, m.openLocked(a.Key, d))
		case "relabel":
			m.listeners[a.Key].setRuleLocked(d.RuleID)
		case "open":
			probes = appendProbe(probes, a.Key, m.openLocked(a.Key, d))
		}
	}
	m.mu.Unlock()
	m.runProbes(probes)
	m.applyProbes(probes)
	return acts
}

// openLocked は待ち受けを 1 つ開いて中継を始める(Apply の経路)。bind を先に行い、開けてから
// Resource Guard の枠を受け付けにする。逆の順にすると、bind の最中と bind に失敗した待ち受けの
// ルールが A に入り、その間だけ他のルールの予約が減る(設計文書 7a.10 節の A の定義)。
// target への到達確認は錠を持ったまま行えないので、開いた待ち受けを返すだけにする。呼び出し側が
// 錠を放してから確認する(設計文書 5.2 節)。
func (m *Manager) openLocked(k Key, d Desired) *listener {
	// 許可一覧の外にある IP リテラルの宛先は、待ち受けを開かずに理由を報告する(設計文書 7 節)
	var sock boundSocket
	err := m.allowedAtApply(d.Target)
	if err == nil {
		sock, err = m.bind(k)
	}
	l := m.newListener(k, d)
	if err != nil {
		// 開けなくても登録しておき、状態として見せる。次の Apply(再試行)で開き直す。枠は
		// 受け付けていないままなので、このルールは A に入らない
		l.bindErr = err
		l.listenerOps = unboundOps()
		m.opts.Logf("listener %s: %v", k, err)
	} else {
		// 受け付けを先に始めてから中継を始める。逆の順にすると、A に入る前に来たフローが
		// ルールごとの数に入らない
		l.budget.Accept()
		if sock.pc != nil {
			m.serveUDP(l, sock.pc)
		} else {
			m.serveTCP(l, sock.ln)
		}
		m.opts.Logf("listener %s -> %s opened; rule %s", k, d.Target, d.RuleID)
	}
	m.listeners[k] = l
	return l
}

// Retry は 30 秒ごとに、bind できなかったリスナーを開き直し、TCP は target への接続を再確認する
// (仕様 5.2 節)。target が復帰すれば targetErr が消え、落ちれば付く。状態の変化はハートビートで報告される。
//
// 確認は錠を放してから同時に行う(設計文書 5.2 節)。錠を持ったまま 1 つずつ確認すると、黙って
// パケットを捨てる target が 1 つあるだけで、その待ちのあいだ accept した接続の処理と UDP の新しい
// セッションの作成が止まる。
func (m *Manager) Retry() {
	m.mu.Lock()
	var probes []targetProbe
	var rebind []Key
	for k, l := range m.listeners {
		if !l.bound() {
			// 開き直しは map を書き換えるので、走査の後にまとめて行う
			rebind = append(rebind, k)
			continue
		}
		if k.Proto == proto.TCP {
			probes = append(probes, targetProbe{key: k, l: l, target: l.target})
		}
	}
	for _, k := range rebind {
		l := m.listeners[k]
		d := Desired{Target: l.target, RuleID: l.ruleID}
		// bind に失敗した待ち受けの closeF は unboundOps の何もしない関数なので、shutdownLocked は使わず
		// 枠だけを外す
		l.budget.Close()
		delete(m.listeners, k)
		probes = appendProbe(probes, k, m.openLocked(k, d))
	}
	m.mu.Unlock()
	m.runProbes(probes)
	m.applyProbes(probes)
}

// appendProbe は、開けた TCP の待ち受けを確認の対象に加える。UDP は到達確認ができないので加えない。
// bind に失敗した待ち受けも、リスナーが無いので加えない。呼び出し側は m.mu を持つ。
func appendProbe(probes []targetProbe, k Key, l *listener) []targetProbe {
	if l == nil || !l.bound() || k.Proto != proto.TCP {
		return probes
	}
	return append(probes, targetProbe{key: k, l: l, target: l.target})
}

// applyProbes は確認の結果を待ち受けに反映する。錠を放しているあいだに待ち受けが閉じた場合、開き直された
// 場合、宛先が変わった場合は、その結果を捨てる(設計文書 5.2 節)。到達性が変わった待ち受けだけ、
// ログを 1 行出す。確認は 30 秒ごとなので、変化のときだけ出せば 1 つの待ち受けにつき 30 秒に 1 行を
// 超えない。lograte の門を重ねると、往復する target の最後の行が実際の状態と食い違う。
func (m *Manager) applyProbes(probes []targetProbe) {
	if len(probes) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range probes {
		p := &probes[i]
		l := m.listeners[p.key]
		if l != p.l || l.target != p.target {
			continue
		}
		before := l.targetErr
		setTargetErrLocked(l, p.err)
		switch {
		case before == nil && p.err != nil:
			m.opts.Logf("listener %s: cannot connect to target %s: %v", p.key, p.target, p.err)
		case before != nil && p.err == nil:
			m.opts.Logf("listener %s: target %s is reachable again", p.key, p.target)
		}
	}
}
