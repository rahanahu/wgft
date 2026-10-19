//go:build linux

package kernelmode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/conntrack"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/reasontext"
	"github.com/rahanahu/wgft/proto"
)

// ApplyRules は wgft0 を収束させ、宛先を解決してテーブルを組み、1 つのバッチで公開する(7b.1 節から 7b.3 節)。
// wgft0 を先に収束させるのは、ピアを公開の前に置くためである(7a.3 節)。
//
// 誤りを返すのはテーブル全体の失敗(7b.3 節の 3 つ目の種類)だけで、このとき旧いテーブルと記録を残す。
// ルール単位の失敗は公開の記録の理由に載り、Read が報告する。
//
// prepared は PrepareApply の結果で、名前の解決を rt.mu の外で済ませてある。nil なら、ここで引く。
func (d *Dataplane) ApplyRules(gen uint64, rules []proto.AgentRule, prepared any) (string, error) {
	p, ok := prepared.(*kernelPrepared)
	if !ok || p == nil {
		p = d.PrepareApply(&proto.State{WG: d.WG, Rules: rules}).(*kernelPrepared)
	}
	if p.err != nil || d.ctx.Err() != nil {
		return "", errors.New("not publishing: the agent is stopping")
	}
	d.useEndpoint(p)
	cfg, err := d.LinkConfig()
	if err != nil {
		return "", err
	}
	changes, err := d.Ops.EnsureLink(cfg)
	if err != nil {
		if !d.converged && startupFatal(err) {
			return "", &agentdp.FatalError{Err: err}
		}
		return "", fmt.Errorf("converge %s: %w", d.iface, err)
	}
	if !d.converged {
		d.converged = true
	}
	if len(changes) > 0 {
		log.Printf("kernel mode: %s: %s", d.iface, strings.Join(changes, "; "))
	}
	d.checkRoute()

	pub := d.planWith(gen, rules, p.resolved)
	if err := d.publish(pub); err != nil {
		return "", err
	}
	d.probeAll()
	return d.summary(), nil
}

// publish はテーブルを 1 つのバッチで差し替え、成功したら記録を認証情報ファイルへ写し、差し替えた
// テーブルの指紋を読み直し、成立済みのフローを収束させる(7b.4 節、7a.3 節の実際の状態への収束)。
// 失敗したら旧いテーブルと記録を残す。認証情報ファイルの保存は呼び出し側が行う。成否は gate に記録し、
// 通知による公開し直しの間隔を決める。見直し(compare)の wgft0 の収束の失敗も gate に記録する。
// 全体状態の適用の失敗は、試し直しを待つ間の通知の後の見直しを runtime が止めるので、間隔に関わらない。
// エンドポイントの引き直しの後の収束の失敗は記録しない。通知の後の見直しはエンドポイントを比べないので、
// 記録するとテーブルの修復だけを遅らせる。
func (d *Dataplane) publish(pub nft.AgentPublication) error {
	if err := d.Ops.Publish(pub, d.nftConfig()); err != nil {
		d.gate.Failed()
		return fmt.Errorf("publish table inet %s: %w", nft.AgentTableName, err)
	}
	d.gate.Succeeded()
	prev := d.Pub
	// 切り替えで離れたアドレスは、DNAT を変えた公開に成功したときに使って空にする。同じ DNAT を置き直す
	// 修復の公開では UDP のルールはまだ動いていないので、持ち続ける(7b.2 節)
	if prev != nil && !sameDNATs(*prev, pub) {
		d.closeLeftUDP(*prev, pub)
		d.leaving = nil
	}
	d.Pub = &pub
	d.writeRecord(recordPublication, &d.f.KernelPublication, pub)
	// 指紋を読めなければ、比べる基準が分からない。次の見直しは食い違いとして公開し直し、読み直す
	// (7a.3 節の指紋の読み直しの失敗と同じ扱い)
	fp, present, err := d.Ops.Fingerprint(nft.AgentTableName)
	d.fp, d.fpKnown = fp, err == nil && present
	// route_localnet は、守りの行を含むテーブルを公開した後に合わせる(7b.2 節)
	d.syncLocalnet(pub.HasLoopback(), true)
	if prev != nil {
		d.unconverged = appendUnconverged(d.unconverged, *prev)
	}
	d.convergeFlows()
	return nil
}

// MaxUnconverged は、収束が済んでいない前の公開を残す数の上限である。収束が失敗し続ける間に公開が
// 続いても、認証情報ファイルが大きくならないようにする。上限を超えた古い公開のフローは見分けられなく
// なり、残る。
const MaxUnconverged = 32

// appendUnconverged は、収束が済んでいない前の公開の列に p を加える。直前の要素と DNAT も宣言も同じなら、
// 収束の判定に使う中身が変わらないので、置き換えて並びを伸ばさない。DNAT が同じでも宣言の宛先の文字列が
// 違う公開は畳まない。収束は宣言の宛先の変化で宛先の変更を見分けるので、IP リテラルへ変えてから同じ
// ホスト名へ戻した中間の公開を落とすと、宛先の変更を見落とす(7b.4 節)。
func appendUnconverged(list []nft.AgentPublication, p nft.AgentPublication) []nft.AgentPublication {
	if n := len(list); n > 0 && sameDNATs(list[n-1], p) && sameDeclarations(list[n-1], p) {
		list[n-1] = p
		return list
	}
	list = append(list, p)
	if len(list) > MaxUnconverged {
		list = list[len(list)-MaxUnconverged:]
	}
	return list
}

// sameDeclarations は、2 つの公開のルールの宣言、つまりルールごとのプロトコル、待ち受けのポートの範囲、
// 宣言の宛先の文字列が同じかどうかである。世代と理由は比べない。
func sameDeclarations(a, b nft.AgentPublication) bool {
	type decl struct {
		proto  proto.Proto
		listen proto.PortRange
		target string
	}
	byID := func(p nft.AgentPublication) map[string]decl {
		m := make(map[string]decl, len(p.Rules))
		for _, r := range p.Rules {
			m[r.RuleID] = decl{r.Proto, r.ListenPort, r.Target}
		}
		return m
	}
	return reflect.DeepEqual(byID(a), byID(b))
}

// convergeFlows は、conntrack を今の公開に収束させる(7b.4 節)。wgft0 から入って DNAT されたフローの
// うち、宣言から消えたポートのフロー、実効宛先の宣言が変わったポートのフロー、今の許可一覧の外に
// DNAT したフローを消す。成功したら収束が済んでいない前の公開の列を消し、失敗したら列を残して、
// 30 秒ごとの見直しでテーブルを差し替えずに試し直す(7a.3 節の修復)。列は認証情報ファイルに写す。
// 前の公開が 1 つも無ければ、どのフローも wgft のものと見分けられないので、何もしない。
func (d *Dataplane) convergeFlows() {
	if d.Pub == nil || len(d.unconverged) == 0 {
		d.recordUnconverged()
		return
	}
	addr, err := netip.ParsePrefix(d.WG.Address)
	if err != nil {
		return
	}
	// 許可一覧の外と、ブロードキャストかマルチキャストのアドレスへ DNAT したフローを残さない(7 節)
	scope := conntrack.AgentScope{Local: addr.Addr(), Peer: d.server, AllowTarget: d.targetAllowed}
	res, err := d.Ops.ConvergeFlows(d.unconverged, *d.Pub, scope)
	// 閉じたフローがあれば出す。閉じられなかったフローは誤りに数が入るので、誤りと同じく変わったときだけ
	// 出す。同じ削除の失敗が 30 秒ごとに繰り返す間、同じ行を出し続けないためである
	if res.Deleted() > 0 {
		log.Printf("kernel mode: conntrack: %s", res)
	}
	switch {
	case err == nil:
		if d.convergeErr != "" {
			log.Printf("kernel mode: conntrack converges again")
		}
		d.convergeErr = ""
		d.unconverged = nil
	case err.Error() != d.convergeErr:
		log.Printf("kernel mode: conntrack: %v; established flows the new table does not allow may still pass until this succeeds, and the 30-second check tries again", err)
		d.convergeErr = err.Error()
	}
	d.recordUnconverged()
}

// recordUnconverged は、収束が済んでいない前の公開の列を認証情報ファイルの項目に写す。
func (d *Dataplane) recordUnconverged() {
	if len(d.unconverged) == 0 {
		d.f.KernelUnconverged = nil
		delete(d.marshalErr, recordUnconverged)
		return
	}
	d.writeRecord(recordUnconverged, &d.f.KernelUnconverged, d.unconverged)
}

// 認証情報ファイルへ写す記録の名前である。ログと marshalErr の鍵に使う。
const (
	recordPublication = "publication"
	recordUnconverged = "list of unconverged publications"
)

// writeRecord は、v を JSON にして認証情報ファイルの項目 dst へ写す。what は記録の名前で、ログに出す。
// 今の型では失敗しないので、失敗は将来の型の変更の誤りである。失敗したら dst を書き換えず、false を返す。
// 書くかどうかは呼び出し側に任せず、ここで決める。同じ誤りが公開や収束のたびに繰り返しても、記録ごとに
// 変わったときだけ 1 行出す。
func (d *Dataplane) writeRecord(what string, dst *json.RawMessage, v any) bool {
	b, err := json.Marshal(v)
	if err == nil {
		delete(d.marshalErr, what)
		*dst = b
		return true
	}
	if msg := err.Error(); d.marshalErr[what] != msg {
		if d.marshalErr == nil {
			d.marshalErr = map[string]string{}
		}
		d.marshalErr[what] = msg
		log.Printf("kernel mode: cannot encode the %s for the credentials file: %v; the record is left unchanged", what, err)
	}
	return false
}

// probeAll は、公開した TCP のルールの宛先へ試し接続する(7b.3 節の 2 つ目の種類)。試すのは、連続する
// ポートと宛先の範囲(公開の記録の AgentRange)ごとに、その先頭のポートの 1 つだけである(2026-09-24 の
// 所有者の決定)。ユーザー空間モードはポートごとに試す。失敗は報告にだけ使い、DNAT は残す。
// 返すのは、ルールごとの公開した最初の範囲の宛先のうち、失敗したものである。30 秒ごとの見直しは
// これを他のアドレスへの切り替えに使う(7b.2 節)。
func (d *Dataplane) probeAll() map[string]netip.AddrPort {
	d.probeErr = map[string]string{}
	if d.Pub == nil {
		return nil
	}
	type job struct {
		rule  string
		dest  netip.AddrPort
		first bool
	}
	var jobs []job
	var dests []netip.AddrPort
	for _, r := range d.Pub.Rules {
		if r.Proto != proto.TCP {
			continue
		}
		for i, rg := range r.Ranges {
			jobs = append(jobs, job{r.RuleID, rg.Dest, i == 0})
			dests = append(dests, rg.Dest)
		}
	}
	errs := d.probeEach(dests)
	failedFirst := map[string]netip.AddrPort{}
	for i, j := range jobs {
		if errs[i] != nil {
			if _, done := d.probeErr[j.rule]; !done {
				d.probeErr[j.rule] = fmt.Sprintf("target %s: %v", j.dest, errs[i])
			}
			if j.first {
				failedFirst[j.rule] = j.dest
			}
		}
	}
	return failedFirst
}

// probeEach は dests のそれぞれへ同時に試し接続し、同じ順に誤りを返す。期限と同時に試す数は
// probeAll と同じである。
func (d *Dataplane) probeEach(dests []netip.AddrPort) []error {
	errs := make([]error, len(dests))
	sem := make(chan struct{}, kernelProbeConcurrent)
	var wg sync.WaitGroup
	for i, dest := range dests {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(d.ctx, kernelProbeTimeout)
			defer cancel()
			errs[i] = d.Ops.Probe(ctx, dest)
		}()
	}
	wg.Wait()
	return errs
}

// summary は適用のログの 1 行に載せる要約である。
func (d *Dataplane) summary() string {
	published, refused := 0, 0
	for _, r := range d.Pub.Rules {
		if len(r.Ranges) > 0 {
			published++
		}
		if r.Reason != "" {
			refused++
		}
	}
	return fmt.Sprintf("published table inet %s: %d rules with DNAT, %d rules with a reason", nft.AgentTableName, published, refused)
}

// Refresh は 30 秒ごとの見直しである。TCP の宛先へ試し接続し直し、ip_forward を読み直す(7b.1・7b.3 節)。
// 失敗した宛先は、次の見直しで他のアドレスへ切り替えるかを決めるために控える(7b.2 節)。
func (d *Dataplane) Refresh() {
	if !d.have {
		return
	}
	on, err := d.Ops.ReadIPForward()
	switch {
	case err == nil && on && d.forwardErr != nil:
		log.Printf("net.ipv4.ip_forward is 1 now; rules whose target is not this host are no longer reported as errors")
		d.forwardErr, d.forwardUnknown, d.forwardWriteErr = nil, false, nil
	case err == nil && !on && (d.forwardErr == nil || d.forwardUnknown):
		// 読めなかった値を今は読めて 0 だったときは、断定できる文言に改める。起動時に書けなかった
		// ことが分かっていれば、0 を読んで書けなかった場合と同じ文言にして、その事実を保つ
		d.forwardUnknown = false
		if d.forwardWriteErr != nil {
			d.forwardErr = fmt.Errorf(reasontext.IPForward+" is not 1 and cannot be set: %w", d.forwardWriteErr)
		} else {
			d.forwardErr = errors.New(reasontext.IPForward + " is 0")
		}
		log.Printf("warning: net.ipv4.ip_forward is 0; rules whose target is not this host are reported as errors until it is 1")
	}
	if d.forwardErr != nil {
		if l, err := d.Ops.LocalAddrs(); err == nil {
			d.local = l
		}
	}
	// 収束が済んでいなければ、テーブルを差し替えずに収束だけを試し直す(7a.3 節の修復)
	if len(d.unconverged) > 0 && d.converged {
		d.convergeFlows()
		if len(d.unconverged) == 0 && d.save != nil {
			if err := d.save(); err != nil {
				log.Printf("save credentials file after conntrack converged: %v", err)
			}
		}
	}
	d.noteFailures(d.probeAll())
}

// sameDNATs は、2 つの公開が同じ DNAT を持つかどうかである。世代と理由の文言は比べない。
func sameDNATs(a, b nft.AgentPublication) bool {
	return reflect.DeepEqual(a.DNATs(), b.DNATs())
}

// changedRules は、DNAT が変わったルールの ID を並べる。
func changedRules(a, b nft.AgentPublication) []string {
	byID := func(p nft.AgentPublication) map[string][]nft.AgentRange {
		m := map[string][]nft.AgentRange{}
		for _, r := range p.Rules {
			m[r.RuleID] = r.Ranges
		}
		return m
	}
	am, bm := byID(a), byID(b)
	var out []string
	for id, rb := range bm {
		if !reflect.DeepEqual(am[id], rb) {
			out = append(out, id)
		}
	}
	for id := range am {
		if _, ok := bm[id]; !ok {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// syncLocalnet は wgft0 の route_localnet を want に合わせる(7b.2 節)。want は、公開したテーブルに
// ループバックの宛先の DNAT があり、そのテーブルが今あることである。tableOK は、wgft の守りの行を持つ
// テーブルが今あるかどうかで、0 に戻せなかったときの警告の文言を決める。値が want と同じなら何も書かない。
// 0 に合わせるとき、値を読めず、直前の公開にループバックの宛先も無ければ書かない。ループバックの宛先を
// 持たない配置で、wgft0 が無い間などに毎回の警告を出さないためである。wgft0 が無ければ値も無いので書かない。
// 1 にできなければ、ループバックの宛先のルールの error の理由に載せる(ruleStatuses)。0 に戻せなければ、
// 警告を変わったときだけ 1 行出す。
func (d *Dataplane) syncLocalnet(want, tableOK bool) {
	name := linux.RouteLocalnetName(d.iface)
	cur, rerr := d.Ops.ReadRouteLocalnet(d.iface)
	switch {
	case rerr == nil && cur == want:
		d.noteLocalnet(want, tableOK, nil)
		return
	case rerr != nil && !want && (errors.Is(rerr, fs.ErrNotExist) || d.Pub == nil || !d.Pub.HasLoopback()):
		d.noteLocalnet(want, tableOK, nil)
		return
	}
	if werr := d.Ops.WriteRouteLocalnet(d.iface, want); werr != nil {
		d.noteLocalnet(want, tableOK, werr)
		return
	}
	d.noteLocalnet(want, tableOK, nil)
	switch {
	case want:
		log.Printf("kernel mode: set %s to 1, so that the kernel delivers the DNAT to loopback targets; it goes away with %s", name, d.iface)
	case !tableOK:
		// 公開した表が無いか変わった間である(repair と起動時)
		log.Printf("kernel mode: set %s to 0 until table inet %s is published again", name, nft.AgentTableName)
	default:
		log.Printf("kernel mode: set %s to 0; no published rule forwards to a loopback target now", name)
	}
}

// noteLocalnet は route_localnet を want に合わせた結果を控える。err は書き込みの誤りで、nil なら合った。
func (d *Dataplane) noteLocalnet(want, tableOK bool, err error) {
	name := linux.RouteLocalnetName(d.iface)
	if want {
		d.localnetOffErr = ""
		if err == nil {
			d.localnetErr = ""
			return
		}
		msg := fmt.Sprintf("%s cannot be set to 1: %v", name, err)
		if msg != d.localnetErr {
			log.Printf("warning: kernel mode: %s; rules whose target is a loopback address are reported as errors until it is 1", msg)
		}
		d.localnetErr = msg
		return
	}
	d.localnetErr = ""
	if err == nil {
		d.localnetOffErr = ""
		return
	}
	msg := fmt.Sprintf("%s cannot be set to 0: %v", name, err)
	if msg != d.localnetOffErr {
		if tableOK {
			log.Printf("warning: kernel mode: %s; the input and filter_pre rows of table inet %s still drop packets from %s to loopback that no DNAT sent there", msg, nft.AgentTableName, d.iface)
		} else {
			log.Printf("warning: kernel mode: %s; until table inet %s is published again, packets from %s may reach services that listen on this host's loopback", msg, nft.AgentTableName, d.iface)
		}
	}
	d.localnetOffErr = msg
}

// closeLocalnetWithoutTable は、起動時に table inet wgft_agent が無いか読めなければ、wgft0 の
// route_localnet を 0 にする(7b.2 節)。最初の公開までに全体状態が届かない間も、DNAT を経ない
// ループバックへの面を開けたままにしないためである。テーブルがあれば、その守りの行に任せて値を残す。
// 最初の公開が値を合わせ直す。
func (d *Dataplane) closeLocalnetWithoutTable() {
	if _, present, err := d.Ops.Fingerprint(nft.AgentTableName); err == nil && present {
		return
	}
	d.syncLocalnet(false, false)
}
