//go:build linux

package kernelmode

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/proto"
)

// ObservePrepare は 30 秒ごとの見直しのうち、名前の解決だけを行う(7b.2 節)。rt.mu の外で呼ぶ。
// 停止で打ち切られたら nil を返し、見直しは何もしない。
func (d *Dataplane) ObservePrepare(rules []proto.AgentRule) any {
	ctx, cancel := context.WithTimeout(d.ctx, kernelResolveTimeout)
	defer cancel()
	p := &observePrepared{}
	d.epMu.Lock()
	stale, name := d.endpointStale, d.declared
	d.epMu.Unlock()
	if stale && name != "" {
		p.endpoint = &kernelPrepared{tried: true, endpointOf: name}
		p.endpoint.endpoint, p.endpoint.endpointEr = resolveEndpointAddr(ctx, name, d.Ops.Lookup)
	}
	p.resolved = resolveTargets(ctx, rules, d.Ops.Lookup)
	if d.ctx.Err() != nil {
		return nil
	}
	return p
}

// observePrepared は ObservePrepare の結果である。endpoint は、エンドポイントを引き直したときだけある。
type observePrepared struct {
	resolved map[string]nft.Resolution
	endpoint *kernelPrepared
}

// ObserveCommit は 30 秒ごとの見直しの残りである(7b.2・7b.4 節)。rt.mu を持って呼ぶ。
//
//   - 名前の解決し直し:PlanAgent の結果の DNAT が直前の公開と違うときだけテーブルを公開し直す。解決の
//     結果が変わっても、選ぶアドレスが同じなら公開し直さない。理由の文言だけが変わったときは、記録を
//     書き換えるが、テーブルは差し替えない
//   - 外からの変更:実際のテーブルの指紋と wgft0 の状態を、直前の公開と宣言に比べる。食い違えば、wgft0 を
//     収束させてからテーブルを公開し直す。エンドポイントだけの違いは食い違いとして扱わない(7b.1 節)
//
// saved は記録が変わったかどうかで、真なら呼び出し側が認証情報ファイルを保存する。見直しの失敗は
// 旧いテーブルを残し、次の見直しで試し直す。
func (d *Dataplane) ObserveCommit(gen uint64, rules []proto.AgentRule, prepared any) (saved bool, err error) {
	op, ok := prepared.(*observePrepared)
	if !ok || !d.have || !d.converged || d.Pub == nil {
		return false, nil
	}
	return d.compare(gen, rules, op)
}

// Sensor はカーネルの変更の通知の購読である(7b.4 節の変更の通知)。
func (d *Dataplane) Sensor() dataplane.Sensor { return d.Ops.Notify }

// ObserveNotified は、変更の通知をまとめた後の見直しである(7b.4 節の変更の通知)。rt.mu を持って呼ぶ。
// 30 秒ごとの見直しのうち外からの変更だけを扱い、名前を引かず、試し接続もしない。比べるのは直前の
// 公開そのものである。自分の公開と wgft0 の収束も通知を生むが、公開の直後に指紋を読み直してあるので、
// その通知の後の見直しは一致を確かめて終わる。
func (d *Dataplane) ObserveNotified(gen uint64, rules []proto.AgentRule) (saved bool, err error) {
	if !d.have || !d.converged || d.Pub == nil {
		return false, nil
	}
	return d.compare(gen, rules, nil)
}

// compare は、実際のテーブルと wgft0 を直前の公開と宣言に比べ、食い違えば直す。op は 30 秒ごとの
// 見直しの名前の解決の結果で、nil なら変更の通知の後の見直しである。
//
// 通知の後の見直しは、公開し直しが失敗した後、gate が開くまで公開し直さない。ただし新しく見つかった
// 食い違い、つまり新たにログに出す食い違いは待たずに直す。30 秒ごとの見直しは gate を見ない。
//
// 同じ食い違いのログは、30 秒ごとの見直しが食い違いを見つけない回を挟むまで 1 行だけにする。通知の
// 後の見直しが食い違いを見つけない回は区切りに数えない。自分の公開の直後の通知は必ず一致を見つけるので、
// 数えると、他のプロセスが同じ変更を繰り返すたびに 1 行出すことになるためである。
func (d *Dataplane) compare(gen uint64, rules []proto.AgentRule, op *observePrepared) (saved bool, err error) {
	// 引き直したエンドポイントの収束に失敗しても、表の修復と経路の確認へ進み、誤りは最後に返す。
	// 印は残るので、次の見直しが試し直す。ここで返すと、収束の失敗が続く間(稼働中に現れた重なりなど)、
	// 30 秒ごとの見直しが表の修復に届かない
	var reErr error
	if op != nil && op.endpoint != nil {
		reErr = d.reResolved(op.endpoint)
	}
	saved, held, err := d.repair(gen, rules, op)
	// 門が閉じて何も試さなかった見直しは、前の誤りを残す。試していないので、直ったとは言えない。
	// 名前の解決し直しの公開の失敗は repair が resolveErr にも入れるので、通知の後の見直しが repairErr を
	// 消しても残る
	if !held {
		d.repairErr = errText(err)
	}
	// エンドポイントの誤りは 30 秒ごとの見直しだけが書き換える
	if op != nil {
		d.endpointErr = errText(reErr)
	}
	d.noteObserveErr()
	if err == nil {
		err = reErr
	}
	return saved, err
}

// repair は compare の本体で、テーブルと wgft0 を比べて直す。held は、通知の後の見直しが門のために
// 何も試さずに終わったことを表す。名前の解決し直しで変わった DNAT の公開の失敗は resolveErr に入れる。
// 30 秒ごとの見直しは、DNAT が変わらなかったときと、変わった DNAT を公開できたときに resolveErr を消す。
func (d *Dataplane) repair(gen uint64, rules []proto.AgentRule, op *observePrepared) (saved, held bool, err error) {
	next, changedDNAT := *d.Pub, false
	if op != nil {
		next = d.planWith(gen, rules, op.resolved)
		changedDNAT = !sameDNATs(*d.Pub, next)
		if !changedDNAT {
			d.resolveErr = ""
		}
	}
	tableDrift, linkDrift, link, err := d.drift()
	if err != nil {
		return false, false, err
	}
	d.watchHandshake(link)
	drift := strings.Join(nonEmpty(tableDrift, linkDrift), "; ")
	fresh := drift != "" && drift != d.driftSeen
	if fresh {
		log.Printf("kernel mode: %s; publishing the table again", drift)
	}
	if drift != "" || op != nil {
		d.driftSeen = drift
	}
	if op == nil && drift != "" && !d.gate.Allow(fresh) {
		return false, true, nil
	}
	if linkDrift != "" {
		cfg, err := d.LinkConfig()
		if err != nil {
			return false, false, err
		}
		changes, err := d.Ops.EnsureLink(cfg)
		if err != nil {
			d.gate.Failed()
			return false, false, fmt.Errorf("converge %s: %w", d.iface, err)
		}
		if len(changes) > 0 {
			log.Printf("kernel mode: %s: %s", d.iface, strings.Join(changes, "; "))
		}
	}
	// 経路は wgft0 が宣言どおりになってから確かめる。wgft0 が消えたり down だったりする間は、経路が
	// 既定経路へ出るのは当然で、確かめる意味が無い(7b.1 節)
	d.checkRoute()
	switch {
	case changedDNAT:
		log.Printf("kernel mode: target resolution changed the DNAT of %s; publishing the table again", strings.Join(changedRules(*d.Pub, next), ", "))
	case drift != "":
	default:
		if reflect.DeepEqual(d.Pub.Rules, next.Rules) {
			return false, false, nil
		}
		// 理由の文言だけが変わった。テーブルは同じなので差し替えない
		d.Pub = &next
		if b, ok := d.marshalRecord("publication", next); ok {
			d.f.KernelPublication = b
		}
		return true, false, nil
	}
	if err := d.publish(next); err != nil {
		if changedDNAT {
			d.resolveErr = err.Error()
		}
		return false, false, err
	}
	if changedDNAT {
		d.resolveErr = ""
	}
	// driftSeen は公開し直しても残す。他のプロセスが同じ変更を繰り返す間、見直しは直し続けるが、
	// ログは 30 秒ごとの見直しが食い違いを見つけない回を挟むまで 1 行だけにする
	if changedDNAT {
		d.probeAll()
	}
	return true, false, nil
}

// noteObserveErr は、repairErr と resolveErr と endpointErr をつないだ見直しの誤りを、変わったときだけ 1 行出す。
// 30 秒ごとの見直しと通知の後の見直しで同じ控えを使う。どちらも同じテーブルと wgft0 を読み、同じ誤りに
// 当たるためである。
func (d *Dataplane) noteObserveErr() {
	msg := strings.Join(uniq(nonEmpty(d.repairErr, d.resolveErr, d.endpointErr)), "; ")
	switch {
	case msg == d.ObserveErr:
	case msg == "":
		log.Printf("kernel mode: checking table inet %s and %s works again", nft.AgentTableName, d.iface)
	default:
		log.Printf("kernel mode: checking table inet %s and %s failed: %s; the previous publication stays in place and the next check tries again", nft.AgentTableName, d.iface, msg)
	}
	d.ObserveErr = msg
}

// uniq は、同じ文面を 1 つにまとめる。テーブルの修復と名前の解決し直しの公開が同じ誤りで失敗した
// ときに、同じ文面を 2 回つながないためである。
func uniq(s []string) []string {
	var out []string
	for _, x := range s {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// errText は誤りの文面である。nil なら空である。
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// drift は、実際のテーブルと wgft0 が直前の公開と宣言に一致しなければ、それぞれ何が違うかを返す。
// 一致すれば空である。テーブルは指紋で、wgft0 は種別、鍵、up、MTU、アドレス、ピアの集合と
// AllowedIPs と keepalive で比べる。エンドポイントは比べない(7b.1 節)。
func (d *Dataplane) drift() (table, link string, st wg.AgentState, err error) {
	fp, present, err := d.Ops.Fingerprint(nft.AgentTableName)
	switch {
	case err != nil:
		return "", "", st, fmt.Errorf("read table inet %s: %w", nft.AgentTableName, err)
	case !present:
		table = "table inet " + nft.AgentTableName + " is gone"
	case !d.fpKnown:
		table = "the fingerprint of table inet " + nft.AgentTableName + " was not read after the last publication"
	case fp != d.fp:
		table = "table inet " + nft.AgentTableName + " was changed outside wgft"
	}
	prev, _ := d.f.PreviousKey()
	st, err = d.Ops.InspectLink(d.iface, d.Priv, prev)
	if err != nil {
		return "", "", st, fmt.Errorf("read %s: %w", d.iface, err)
	}
	return table, d.linkDrift(st), st, nil
}

// checkRoute は、vpsd のトンネルアドレスへの経路が wgft0 を通るかを、ポリシールーティングの規則を
// 含めて確かめる(7b.1 節)。アドレス帯の重なりの検査は main の経路表だけを読むので、先に引かれる
// 規則の表(Tailscale の表 52 など)が奪う経路はここでだけ見える。稼働中に main の表に現れた重なりも
// ここで見える。警告はカーネルの引き当てが示す事実だけを述べ、原因は決めつけない。警告だけを出し、
// 起動は止めない(2026-09-24、所有者の決定)。ポリシールーティングは稼働中にも変わるためである。
// 変わったときだけ 1 行出す。wgft0 が宣言どおりになった後に呼ぶ。
func (d *Dataplane) checkRoute() {
	iface, err := d.Ops.RouteIface(d.server)
	finding := ""
	switch {
	case err != nil:
		finding = fmt.Sprintf("cannot look up the route to the server's tunnel address %s: %v", d.server, err)
	case iface != d.iface:
		finding = fmt.Sprintf("policy rules included, the route to the server's tunnel address %s leaves through %s, not %s; replies to the server may not go through the tunnel; look for a policy routing rule that sends %s to another table, such as the one Tailscale adds for accepted subnet routes, or for an address or route on another interface that covers it", d.server, iface, d.iface, d.server)
	}
	if finding == d.routeFinding {
		return
	}
	switch {
	case finding != "":
		log.Printf("warning: %s", finding)
	default:
		log.Printf("kernel mode: the route to the server's tunnel address %s leaves through %s again", d.server, d.iface)
	}
	d.routeFinding = finding
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, x := range s {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

// linkDrift は wgft0 の状態 st が宣言と違えば、その説明を返す。
func (d *Dataplane) linkDrift(st wg.AgentState) string {
	cfg, err := d.LinkConfig()
	if err != nil {
		return ""
	}
	if !st.Exists {
		return d.iface + " is gone"
	}
	diff := linkDiffs(st, cfg)
	if len(diff) == 0 {
		return ""
	}
	return fmt.Sprintf("%s differs from the declaration in %s", d.iface, strings.Join(diff, ", "))
}

// linkDiffs は、ある wgft0 の状態 st が宣言 cfg と違う点を並べる。30 秒ごとの見直しと agent doctor の
// dataplane.interface が同じ関数を使う(設計文書 10.2c 節)。エンドポイントは比べない(7b.1 節)。
func linkDiffs(st wg.AgentState, cfg wg.AgentConfig) []string {
	var diff []string
	if st.Ownership != wg.OwnedByCurrentKey {
		diff = append(diff, "the key")
	}
	if !st.Up {
		diff = append(diff, "the up flag")
	}
	if st.MTU != cfg.MTU {
		diff = append(diff, "the MTU")
	}
	if len(st.Addresses) != 1 || st.Addresses[0] != cfg.Address {
		diff = append(diff, "the address")
	}
	want := netip.PrefixFrom(cfg.Server.Address, 32)
	if len(st.Peers) != 1 || st.Peers[0].PublicKey != cfg.Server.PublicKey ||
		len(st.Peers[0].AllowedIPs) != 1 || st.Peers[0].AllowedIPs[0] != want ||
		st.Peers[0].Keepalive != cfg.Server.Keepalive {
		diff = append(diff, "the peer")
	}
	return diff
}
