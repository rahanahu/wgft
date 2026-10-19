//go:build linux

package kernelmode

import (
	"log"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/conntrack"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/proto"
)

// 他のアドレスへの切り替え(設計文書 7b.2 節)。宛先がホスト名の TCP のルールで、公開した最初の範囲の
// 宛先が 30 秒ごとの見直しの接続確認に 2 回続けて失敗し、同じ名前の他の候補が応えれば、応えた候補の
// うち最も小さいアドレスへ DNAT を移す。
//
// 1 回目の失敗は Refresh の接続確認が noteFailures で控える。2 回目は次の見直しの ObserveCommit が、
// 名前を引いた後、公開し直す前に failover で確かめる。切り替えた先は pin に入れ、planWith がそれを使って
// 計画するので、公開し直しは名前の解決し直しで DNAT が変わったときと同じ経路を通る。UDP のルールには
// 到達を確かめる手段が無いので、切り替えない。

// noteFailures は、30 秒ごとの見直しの接続確認で失敗した、ルールの公開した最初の範囲の宛先を控える。
// 宛先がホスト名のルールだけを控える。IP リテラルの宛先には他のアドレスが無いためである。応えた
// ルールの控えは消すので、控えは続けて失敗している宛先だけを持つ。
func (d *Dataplane) noteFailures(failedFirst map[string]netip.AddrPort) {
	next := map[string]failEntry{}
	if d.Pub != nil {
		for _, r := range d.Pub.Rules {
			dest, ok := failedFirst[r.RuleID]
			if !ok {
				continue
			}
			if _, named := targetHostName(r.Target); !named {
				continue
			}
			old := d.failed[r.RuleID]
			same := old.dest == dest && old.target == r.Target
			next[r.RuleID] = failEntry{dest: dest, target: r.Target, noted: same && old.noted}
		}
	}
	d.failed = next
}

// 1 回の見直しの切り替えの試し接続の上限である(7b.2 節)。failoverMaxCandidates は 1 つのルールで
// 使っているアドレスの他に試す候補の数で、昇順の先頭から選ぶ。failoverMaxProbes は 1 回の見直しで
// 試す宛先の数の合計で、ルールの間で同じ宛先は 1 回と数える。試し接続は rt.mu を持ったまま行うので、
// 期限の 2 秒と同時に試す数の 32 から、上限の 64 で 4 秒ほどに収まる。上限に収まらないルールは
// 次の見直しへ回す。1 回の見直しは、前の見直しが最後に試したルールの次から順に試し、収まらないルールに
// 当たったらそこで止める。1 つのルールは 1+failoverMaxCandidates の 9 つまでの宛先を使うので、1 回の
// 見直しは少なくとも 7 つのルールを試す。続けて失敗しているルールが n 個のままなら、どのルールも n/7 を
// 切り上げた回数の見直しのうちに試される。
const (
	failoverMaxCandidates = 8
	failoverMaxProbes     = 64
)

// failover は、前の見直しの接続確認に失敗した宛先を、その宛先と他の候補へ同時に試し接続して確かめ、
// その宛先がまた失敗して他の候補が応えれば、応えた候補のうち最も小さいアドレスへ切り替える。
// resolved はこの見直しの名前の解決の結果で、解決に失敗した名前は直前に解決できた結果から候補を選ぶ。
// 計画は planWith が行う。切り替えた先がそのポートの最も小さいアドレスなら、切り替えを忘れる。
func (d *Dataplane) failover(resolved map[string]nft.Resolution) {
	if len(d.failed) == 0 || d.Pub == nil {
		return
	}
	cfg := d.nftConfig()
	type try struct {
		rule     nft.AgentRuleResult
		host     string
		cur      netip.AddrPort
		smallest netip.Addr   // そのポートで最も小さい候補で、cur のアドレスでもありうる
		cands    []netip.Addr // cur のアドレスを除く候補の昇順の先頭
	}
	var eligible []try
	for _, r := range d.Pub.Rules {
		fe, ok := d.failed[r.RuleID]
		// 控えは planWith が今の計画に合わせて消してあるので(pruneFailed)、控えの宛先は使っている宛先である
		if !ok || r.Proto != proto.TCP || len(r.Ranges) == 0 {
			continue
		}
		host, named := targetHostName(r.Target)
		if !named {
			continue
		}
		all := nft.AgentCandidates(host, d.candidateAddrs(r, host, resolved), fe.dest.Port(), cfg)
		if !slices.Contains(all, fe.dest.Addr()) {
			// 解決し直しか許可一覧で候補から外れた。計画が最も小さいアドレスの規則で選び直す
			continue
		}
		cands := slices.DeleteFunc(slices.Clone(all), func(a netip.Addr) bool { return a == fe.dest.Addr() })
		if len(cands) == 0 {
			continue
		}
		eligible = append(eligible, try{rule: r, host: host, cur: fe.dest, smallest: all[0], cands: cands[:min(len(cands), failoverMaxCandidates)]})
	}
	if len(eligible) == 0 {
		return
	}
	// 前の見直しが最後に試したルールの次から順に、上限に収まる間だけ試す。収まらないルールに当たったら
	// そこで止め、次の見直しはそのルールから始める。宛先は重ねて試さない。eligible は公開の記録の順
	// (プロトコル、待ち受けの先頭のポート、ルール ID)に並ぶ
	start := 0
	if d.failoverLast != nil {
		for i, t := range eligible {
			if ruleAfter(t.rule, *d.failoverLast) {
				start = i
				break
			}
		}
	}
	var tries []try
	var dests []netip.AddrPort
	index := map[netip.AddrPort]int{}
	for i := range eligible {
		t := eligible[(start+i)%len(eligible)]
		want := []netip.AddrPort{t.cur}
		for _, a := range t.cands {
			want = append(want, netip.AddrPortFrom(a, t.cur.Port()))
		}
		fresh := 0
		for _, w := range want {
			if _, ok := index[w]; !ok {
				fresh++
			}
		}
		if len(dests)+fresh > failoverMaxProbes {
			// 後ろの小さいルールで埋めない。埋めると、収まらないルールを次の見直しもまた飛ばす
			break
		}
		for _, w := range want {
			if _, ok := index[w]; !ok {
				index[w] = len(dests)
				dests = append(dests, w)
			}
		}
		tries = append(tries, t)
		last := t.rule
		d.failoverLast = &last
	}
	errs := d.probeEach(dests)
	for _, t := range tries {
		var answer netip.Addr
		for _, a := range t.cands {
			if errs[index[netip.AddrPortFrom(a, t.cur.Port())]] == nil {
				answer = a
				break
			}
		}
		id := t.rule.RuleID
		switch {
		case errs[index[t.cur]] == nil:
			// 応えたので、続けて失敗してはいない
			delete(d.failed, id)
		case answer.IsValid():
			log.Printf("kernel mode: rule %s: target %s failed the TCP check twice in a row; new flows go to %s, another address of %q that answers",
				id, t.cur, netip.AddrPortFrom(answer, t.cur.Port()), t.host)
			host := strings.ToLower(t.host)
			if d.leaving == nil {
				d.leaving = map[string]map[netip.Addr]bool{}
			}
			if d.leaving[host] == nil {
				d.leaving[host] = map[netip.Addr]bool{}
			}
			d.leaving[host][t.cur.Addr()] = true
			if answer == t.smallest {
				delete(d.pin, id)
			} else {
				d.pin[id] = pinEntry{target: t.rule.Target, addr: answer}
			}
			delete(d.failed, id)
		case !d.failed[id].noted:
			log.Printf("kernel mode: rule %s: target %s failed the TCP check twice in a row and no other allowed address of %q that was tried answers; it stays in use",
				id, t.cur, t.host)
			fe := d.failed[id]
			fe.noted = true
			d.failed[id] = fe
		}
	}
}

// ruleAfter は、公開の記録の順で a が b より後ろにあるかどうかである。
func ruleAfter(a, b nft.AgentRuleResult) bool {
	if a.Proto != b.Proto {
		return a.Proto > b.Proto
	}
	if a.ListenPort.Lo != b.ListenPort.Lo {
		return a.ListenPort.Lo > b.ListenPort.Lo
	}
	return a.RuleID > b.RuleID
}

// pruneFailed は、計画 pub で公開した最初の範囲の宛先か宣言の宛先が、控えと変わったルールの控えを消す。
// 宛先が変わったルールは続けて失敗したとは言えず、宣言の宛先を変えたルールは切り替えを引き継がない(7b.2 節)。
func (d *Dataplane) pruneFailed(pub nft.AgentPublication) {
	for _, r := range pub.Rules {
		fe, ok := d.failed[r.RuleID]
		if ok && (r.Proto != proto.TCP || len(r.Ranges) == 0 || r.Ranges[0].Dest != fe.dest || r.Target != fe.target) {
			delete(d.failed, r.RuleID)
		}
	}
	for id := range d.failed {
		if !slices.ContainsFunc(pub.Rules, func(r nft.AgentRuleResult) bool { return r.RuleID == id }) {
			delete(d.failed, id)
		}
	}
}

// candidateAddrs は、ルール r の宛先の名前 host の候補のアドレスである。この見直しで解決できれば
// その結果を、解決に失敗していれば、宣言の宛先の文字列が同じ間だけ直前に解決できた結果を使う。
func (d *Dataplane) candidateAddrs(r nft.AgentRuleResult, host string, resolved map[string]nft.Resolution) []netip.Addr {
	rs, ok := resolved[host]
	switch {
	case ok && rs.Err == nil:
		return rs.Addrs
	case !ok || rs.Failed():
		if old, ok := d.lkg[r.RuleID]; ok && old.target == r.Target {
			return old.addrs
		}
	}
	return nil
}

// targetHostName は、宣言の宛先 host:port のホストがホスト名なら、それを返す。IP リテラルなら偽である。
func targetHostName(target string) (string, bool) {
	host, _, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return "", false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", false
	}
	return host, true
}

// closeLeftUDP は、切り替えで TCP のルールが離れたアドレスから同じ名前の UDP のルールも離れたポートについて、
// そのアドレスへの UDP のフローの conntrack のエントリを消す(7b.2 節)。公開に成功した直後に、直前に公開して
// いた prev と今の公開 cur を比べて呼ぶ。対象は、prev で宛先が離れたアドレスのどれかで、cur の同じルールの
// 同じポートの宛先がそれと違うポートだけである。cur で同じ宛先に戻ったポートと、従えずに残ったポートは
// 消さない。conntrack は、元の向きのパケットが続く間は応答の無い UDP のエントリも残すので、同じ送信元の
// ポートから送り続ける利用者は、消さなければ応えないアドレスへ向かい続ける。そのアドレスは TCP の接続確認に
// 2 回続けて失敗しているので、消しても失うものは無い。他のルール、他のアドレス、TCP のフローには触れない。
func (d *Dataplane) closeLeftUDP(prev, cur nft.AgentPublication) {
	if len(d.leaving) == 0 {
		return
	}
	now := map[string]nft.AgentRuleResult{}
	for _, r := range cur.Rules {
		now[r.RuleID] = r
	}
	var left []conntrack.AgentLeft
	var ids []string
	for _, r := range prev.Rules {
		host, named := targetHostName(r.Target)
		if r.Proto != proto.UDP || !named {
			continue
		}
		addrs := d.leaving[strings.ToLower(host)]
		if len(addrs) == 0 {
			continue
		}
		next, same := now[r.RuleID], now[r.RuleID].Target == r.Target
		n := len(left)
		for _, rg := range r.Ranges {
			if !addrs[rg.Dest.Addr()] {
				continue
			}
			// ポートごとに比べ、新しい宛先が前の宛先と違うポートの並びだけを加える
			run := -1
			for p := int(rg.Ports.Lo); p <= int(rg.Ports.Hi); p++ {
				old := netip.AddrPortFrom(rg.Dest.Addr(), rg.Dest.Port()+uint16(p-int(rg.Ports.Lo)))
				if same && destAt(next, uint16(p)) == old {
					run = -1
					continue
				}
				if run >= 0 && int(left[run].Range.Ports.Hi)+1 == p {
					left[run].Range.Ports.Hi = uint16(p)
					continue
				}
				left = append(left, conntrack.AgentLeft{Proto: proto.UDP, Range: nft.AgentRange{Ports: proto.PortRange{Lo: uint16(p), Hi: uint16(p)}, Dest: old}})
				run = len(left) - 1
			}
		}
		if len(left) > n {
			ids = append(ids, r.RuleID)
		}
	}
	if len(left) == 0 {
		return
	}
	addr, err := netip.ParsePrefix(d.WG.Address)
	if err != nil {
		return
	}
	n, err := d.Ops.CloseLeft(left, conntrack.AgentScope{Local: addr.Addr(), Peer: d.server})
	if n > 0 {
		log.Printf("kernel mode: conntrack: closed %d UDP flows of %s to the address the TCP check left", n, strings.Join(ids, ", "))
	}
	if err != nil {
		log.Printf("kernel mode: conntrack: %v; UDP flows of %s that keep sending may stay on the address the TCP check left until they go quiet", err, strings.Join(ids, ", "))
	}
}

// destAt は、公開の結果 r のポート port の DNAT の宛先である。公開していなければゼロである。
func destAt(r nft.AgentRuleResult, port uint16) netip.AddrPort {
	for _, rg := range r.Ranges {
		if rg.Ports.Contains(port) {
			return netip.AddrPortFrom(rg.Dest.Addr(), rg.Dest.Port()+(port-rg.Ports.Lo))
		}
	}
	return netip.AddrPort{}
}
