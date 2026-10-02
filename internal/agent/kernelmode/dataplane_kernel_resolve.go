//go:build linux

package kernelmode

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"sync"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/lograte"
	"github.com/rahanahu/wgft/internal/reasontext"
	"github.com/rahanahu/wgft/internal/textsafe"
	"github.com/rahanahu/wgft/proto"
)

// cachedEndpoint は直前に解決できたエンドポイントである。まだ無ければゼロで、インタフェースの収束は
// カーネルが持つエンドポイントを残す(7b.1 節)。
func (d *Dataplane) cachedEndpoint() netip.AddrPort {
	d.epMu.Lock()
	defer d.epMu.Unlock()
	return d.endpoint
}

// kernelPrepared は、rt.mu の外で行った名前の解決の結果である(PrepareApply)。
type kernelPrepared struct {
	// endpoint は、エンドポイントを引いたときの結果である。引かなかったら tried が偽である
	tried      bool
	endpointOf string
	endpoint   netip.AddrPort
	endpointEr error
	// resolved はルールの宛先の名前の解決の結果である
	resolved map[string]nft.Resolution
	// err は、停止で解決が打ち切られたことを表す。このとき公開しない
	err error
}

// PrepareApply は全体状態 st の適用に要る名前を rt.mu の外で引く。runtime は結果を ApplyRules に
// 渡す。DNS を待つ間、ハートビートと doctor が排他を待たないためである。読むのは変わらない値
// (Ops と ctx)と、epMu が守るエンドポイントの控えだけである。
//
// エンドポイントを引くのは、宣言のエンドポイントが変わったときと、まだ一度も解決できていないとき
// だけである(7b.1 節)。解決できていた名前を引けなくなっても、控えたアドレスを使い続ける。
// 宛先の名前は同時に引き、1 つの遅い名前が他の名前の期限を使い切らないようにする。
func (d *Dataplane) PrepareApply(st *proto.State) any {
	p := &kernelPrepared{endpointOf: st.WG.Endpoint}
	d.epMu.Lock()
	need := !d.endpoint.IsValid() || d.endpointOf != st.WG.Endpoint
	d.epMu.Unlock()
	ctx, cancel := context.WithTimeout(d.ctx, kernelResolveTimeout)
	defer cancel()
	if need {
		p.tried = true
		p.endpoint, p.endpointEr = resolveEndpointAddr(ctx, st.WG.Endpoint, d.Ops.Lookup)
	}
	p.resolved = resolveTargets(ctx, st.Rules, d.Ops.Lookup)
	if d.ctx.Err() != nil {
		p.err = errors.New("not publishing: the agent is stopping")
	}
	return p
}

// resolveTargets は、ルールの宛先の名前を同時に引いてから、nft.ResolveAgentTargets に結果を渡す。
// IPv4 の選び方と誤りの扱いは nft.ResolveAgentTargets のままである。
func resolveTargets(ctx context.Context, rules []proto.AgentRule, lookup nft.LookupFunc) map[string]nft.Resolution {
	type answer struct {
		addrs []netip.Addr
		err   error
	}
	hosts := map[string]bool{}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		host, _, err := net.SplitHostPort(r.Target)
		if err != nil || host == "" {
			continue
		}
		if _, err := netip.ParseAddr(host); err == nil {
			continue
		}
		hosts[host] = true
	}
	answers := make(map[string]answer, len(hosts))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for h := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := lookup(ctx, h)
			mu.Lock()
			// 誤りの文面はルールの理由になり、見直しは理由の変化で記録を書き換える(7b.2 節)。問い合わせ
			// ごとに変わる送信元のポートを除き、同じ誤りを 30 秒ごとの変化にしない
			answers[h] = answer{a, lograte.StableError(err)}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return nft.ResolveAgentTargets(ctx, rules, func(_ context.Context, host string) ([]netip.Addr, error) {
		a := answers[host]
		return a.addrs, a.err
	})
}

// useEndpoint は、PrepareApply で引いたエンドポイントを控えに入れる。引けなかったら、控えたアドレスを
// 使い続け、理由が変わったときだけ 1 行出す。
func (d *Dataplane) useEndpoint(p *kernelPrepared) {
	if !p.tried {
		return
	}
	d.epMu.Lock()
	defer d.epMu.Unlock()
	if p.endpointEr != nil {
		if d.endpointEr == nil || d.endpointEr.Error() != p.endpointEr.Error() {
			log.Printf("kernel mode: cannot resolve the server endpoint %s: %v; keeping the endpoint %s has now", p.endpointOf, p.endpointEr, d.iface)
		}
		d.endpointEr = p.endpointEr
		return
	}
	d.endpoint, d.endpointOf, d.endpointEr = p.endpoint, p.endpointOf, nil
}

// resolveEndpointAddr は host:port のエンドポイントを IPv4 のアドレスに解決する。複数あれば最も小さいもの
// を使う。カーネルの WireGuard のピアは 1 つのエンドポイントしか持たないためである。
func resolveEndpointAddr(ctx context.Context, endpoint string, lookup nft.LookupFunc) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, err
	}
	p, err := net.LookupPort("udp", port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if !a.Unmap().Is4() {
			return netip.AddrPort{}, fmt.Errorf("%s is not an IPv4 address", a)
		}
		return netip.AddrPortFrom(a.Unmap(), uint16(p)), nil
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var v4 []netip.Addr
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() {
			v4 = append(v4, a)
		}
	}
	if len(v4) == 0 {
		return netip.AddrPort{}, fmt.Errorf("%s has no IPv4 address", host)
	}
	return netip.AddrPortFrom(sortedAddrs(v4)[0], uint16(p)), nil
}

// planWith は解決の結果からポートごとの DNAT を決める(7b.2 節)。解決に失敗した名前は、宣言の宛先の
// 文字列が同じ間だけ、直前に解決できたアドレスを使い続ける(2026-09-24 の所有者の決定)。使い続けるときも
// 今の許可一覧、IPv4 だけの規則、ループバックと未指定のアドレスの拒否を当てはめ直し、そのことを理由に
// 示す。一度も解決できていないルールは公開しない。
func (d *Dataplane) planWith(gen uint64, rules []proto.AgentRule, resolved map[string]nft.Resolution) nft.AgentPublication {
	cfg := d.nftConfig()
	pub := nft.PlanAgent(nft.AgentInput{Generation: gen, Rules: rules, Resolved: resolved}, cfg)
	byID := make(map[string]proto.AgentRule, len(rules))
	for _, r := range rules {
		byID[r.ID] = r
	}
	lkg := map[string]lkgEntry{}
	for i, res := range pub.Rules {
		r := byID[res.RuleID]
		host, _, err := net.SplitHostPort(r.Target)
		if err != nil {
			continue
		}
		if _, err := netip.ParseAddr(host); err == nil {
			continue
		}
		rs := resolved[host]
		if !rs.Failed() {
			if rs.Err == nil && len(rs.Addrs) > 0 {
				lkg[r.ID] = lkgEntry{target: r.Target, addrs: rs.Addrs}
			}
			continue
		}
		old, ok := d.lkg[r.ID]
		if !ok || old.target != r.Target {
			continue // 一度も解決できていない宛先は公開しない
		}
		lkg[r.ID] = old
		again := nft.PlanAgent(nft.AgentInput{Generation: gen, Rules: []proto.AgentRule{r},
			Resolved: map[string]nft.Resolution{host: {Addrs: old.addrs}}}, cfg).Rules[0]
		again.Reason = staleReason(host, rs.Err, again)
		pub.Rules[i] = again
	}
	d.lkg = lkg
	return pub
}

// staleReasonLimit は、hub がハートビートの理由に許す長さ(internal/vpsd/stream の
// maxHeartbeatReasonLen)である。agent は vpsd を import できないので値を写す。写しがずれれば、
// reason_roundtrip_linux_test.go の TestStaleReasonLimitMatchesTheHub が落ちる。staleReasonTailReserve は、
// 目印の後ろに続く文言のために残す長さである。server doctor が rule.target を分類する試し接続の誤り
// (`; target <宛先>: dial tcp <宛先>: connect: connection refused` など、最長で 95 バイト)を収める。解決の
// 誤りの文面の切り詰めの印(staleClipMark)は、その外の予算から引く。
const (
	staleReasonLimit       = 512
	staleReasonTailReserve = 128
	// staleClipMark は textsafe.ClipText が切り詰めたときに後ろへ付ける印の長さである(予算の外に付く)
	staleClipMark = len("... truncated")
)

// staleReason は、名前の解決に失敗して直前の解決の結果を使ったルールの理由である。文言に
// "name resolution" を含め、server doctor が target_resolve_failed に分類できるようにする。
//
// ホスト名は、頭に引用して 1 回と、解決の誤りの文面に 1 回の計 2 回入る。ホスト名は 253 バイトまで
// 有効なので、誤りの文面をそのまま置くと、目印 "; still forwarding to " が hub の切り詰めの外に出て、
// server doctor が転送を続けているルールを止まったと判定する(10.2a 節)。そこで、目印までが切り詰めに
// 収まるように、解決の誤りの文面だけを短くする。目印までの長さはホスト名と宛先のアドレスで決まり、
// 253 バイトのホスト名でも 400 バイトに満たない。
func staleReason(host string, err error, res nft.AgentRuleResult) string {
	if len(res.Ranges) == 0 {
		return reasontext.NameResolutionFailed(host, err) + "; the address from the last successful resolution is not usable either: " + res.Reason
	}
	mark := reasontext.StillForwardingTo + res.Ranges[0].Dest.Addr().String() + reasontext.FromLastResolution
	cause := "<nil>"
	if err != nil {
		cause = textsafe.SanitizeForTerminal(err.Error())
	}
	fixed := len(reasontext.NameResolutionFailed(host, errors.New(""))) + len(mark)
	cause = textsafe.ClipText(cause, max(0, staleReasonLimit-staleReasonTailReserve-fixed-staleClipMark))
	s := reasontext.NameResolutionFailed(host, errors.New(cause)) + mark
	if res.Reason != "" {
		s += "; " + res.Reason
	}
	return s
}

func sortedAddrs(a []netip.Addr) []netip.Addr {
	out := append([]netip.Addr(nil), a...)
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	var uniq []netip.Addr
	for i, x := range out {
		if i == 0 || x != out[i-1] {
			uniq = append(uniq, x)
		}
	}
	return uniq
}
