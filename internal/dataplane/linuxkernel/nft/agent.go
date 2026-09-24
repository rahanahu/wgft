//go:build linux

package nft

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/rahanahu/wgft/proto"
)

// エージェントのカーネルモードの table inet wgft_agent(設計文書 7b.1 節)。
//
// 組み立ては 2 段に分ける。PlanAgent は、ルールと名前の解決の結果と宛先の許可一覧から、ポートごとに
// DNAT するかどうかと実効宛先を決める(netlink を使わない純粋な判定)。StageAgent は、その結果から
// テーブル全体の差し替えを 1 つのバッチに組む(agent_emit.go)。PlanAgent の結果はそのまま公開の記録であり、
// エージェントは公開に成功するたびにこれを状態ファイルに記録する(7b.4 節)。停止中の agent doctor は、
// 記録と InspectAgent が読み戻したテーブルを比べる(agent_inspect.go)。
//
// 表は wgft0 の側だけで書く。LAN のインタフェース名は使わない(7b.1 節)。
// 読み戻せない式は使わない。google/nftables v0.3.0 は `ct original ...` の向きの属性を読み戻せず、
// GetRules が誤りを返す(build.go の udp_reply の注)。この表は ct の status と state だけを読む。

// AgentTableName はエージェントのテーブル名である。server の TableName と衝突しない(7b.1 節)。
const AgentTableName = "wgft_agent"

// AgentConfig は、ルール以外にエージェントの表の組み立てに要る値である。
type AgentConfig struct {
	// WGInterface は WireGuard インタフェースの名前(既定は wgft0。11a 節の WGFT_WG_INTERFACE)。
	WGInterface string
	// AllowTarget は宛先の許可一覧の判定である(7b.2 節、WGFT_AGENT_ALLOW_TARGETS)。nil なら制限しない。
	AllowTarget func(netip.AddrPort) bool
	// AllowTargetSource は許可一覧の設定の名前である。拒否の理由に出す。
	AllowTargetSource string
}

// Resolution は、ルールの宛先のホスト名を解決した結果である(7b.2 節)。ResolveAgentTargets が作る。
// Addrs は IPv4 のアドレスのすべてである。どれを使うかは PlanAgent が許可一覧を見て選ぶ。
type Resolution struct {
	Addrs []netip.Addr
	Err   error
}

// AgentInput は、組み立ての入力のうち全体状態から来るものである。
type AgentInput struct {
	// Generation は、ルールを受け取った全体状態の世代である。公開の記録にそのまま写す。
	Generation uint64
	// Rules は全体状態のルールである。enabled:false のルールは表に載せない。
	Rules []proto.AgentRule
	// Resolved は、宛先のホスト名からその解決の結果への対応である。IP リテラルの宛先は引かない。
	// 対応の無いホスト名は解決できなかったものとして扱う。
	Resolved map[string]Resolution
}

// AgentPublication は 1 回の組み立ての結果であり、公開の記録である(7b.4 節)。ルールごとに、DNAT を
// 公開したポートの範囲と実効宛先、または公開できなかった理由を持つ(7b.3 節の 1 つ目の種類)。
// 記録はポートごとではなく範囲ごとに持つので、ポートの数に比例して大きくならない。
type AgentPublication struct {
	Generation uint64            `json:"generation"`
	Rules      []AgentRuleResult `json:"rules"`
}

// AgentRuleResult は 1 つのルールの公開の結果である。Reason が空なら、宣言のすべてのポートを公開した。
// 範囲のルールで一部のポートだけを許可一覧が拒んだ場合は、残りのポートを Ranges に持ち、Reason も持つ。
type AgentRuleResult struct {
	RuleID     string          `json:"rule_id"`
	Proto      proto.Proto     `json:"proto"`
	ListenPort proto.PortRange `json:"listen_port"`
	// Target は宣言の宛先の文字列である。成立済みのフローを残すかどうかは、この文字列で比べる(7b.4 節)。
	Target string       `json:"target"`
	Ranges []AgentRange `json:"ranges,omitempty"`
	Reason string       `json:"reason,omitempty"`
}

// AgentRange は DNAT を公開した連続するポートと、その先頭のポートの実効宛先である。範囲の i 番目の
// ポートは、Dest のアドレスの Dest のポート + i へ向かう(7 節の実効宛先)。
type AgentRange struct {
	Ports proto.PortRange `json:"ports"`
	Dest  netip.AddrPort  `json:"dest"`
}

// AgentDNAT は、表の DNAT をルールと連続するポートごとに平らに並べた 1 項目である。記録した公開
// (AgentPublication.DNATs)と、読み戻した表(InspectAgent)を同じ形で比べるために使う。
// Dest は Ports.Lo の実効宛先である。
type AgentDNAT struct {
	RuleID string
	Proto  proto.Proto
	Ports  proto.PortRange
	Dest   netip.AddrPort
}

// DNATs は、公開した範囲を (Proto, Ports.Lo, RuleID) の順に平らに並べる。
func (p AgentPublication) DNATs() []AgentDNAT {
	var out []AgentDNAT
	for _, r := range p.Rules {
		for _, rg := range r.Ranges {
			out = append(out, AgentDNAT{RuleID: r.RuleID, Proto: r.Proto, Ports: rg.Ports, Dest: rg.Dest})
		}
	}
	sortDNATs(out)
	return out
}

func sortDNATs(d []AgentDNAT) {
	sort.Slice(d, func(i, j int) bool {
		if d[i].Proto != d[j].Proto {
			return d[i].Proto < d[j].Proto
		}
		if d[i].Ports.Lo != d[j].Ports.Lo {
			return d[i].Ports.Lo < d[j].Ports.Lo
		}
		return d[i].RuleID < d[j].RuleID
	})
}

// PlanAgent はルールごとに、DNAT を公開するポートと実効宛先を決める(7b.2、7b.3 節)。
// 次の場合はそのルールの DNAT を作らず、理由を Reason に書く。他のルールの判定は続ける。
//
//   - 宛先のホスト名を解決できない場合、または IPv4 のアドレスを持たない場合
//   - 宛先が IPv6 のアドレスの場合。カーネルモードは IPv4 の宛先だけを扱う
//   - 宛先がループバック(127.0.0.0/8)か未指定のアドレス(0.0.0.0)の場合
//
// 宛先の許可一覧はポートごとの実効宛先で判定する。ホスト名が複数のアドレスに解決されたときは、ポートごとに
// 一覧が通すアドレスだけを残し、その中で最も小さいアドレスを使う(7b.2 節)。どのアドレスも通らない
// ポートにだけ DNAT を作らない。
// 結果は (Proto, ListenPort.Lo, RuleID) の順に並ぶ。この順がテーブルの行の順になる。
func PlanAgent(in AgentInput, cfg AgentConfig) AgentPublication {
	rules := make([]proto.AgentRule, 0, len(in.Rules))
	for _, r := range in.Rules {
		if r.Enabled {
			rules = append(rules, r)
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.ListenPort.Lo != b.ListenPort.Lo {
			return a.ListenPort.Lo < b.ListenPort.Lo
		}
		return a.ID < b.ID
	})
	out := AgentPublication{Generation: in.Generation, Rules: make([]AgentRuleResult, 0, len(rules))}
	for _, r := range rules {
		out.Rules = append(out.Rules, planAgentRule(r, in.Resolved, cfg))
	}
	return out
}

func planAgentRule(r proto.AgentRule, resolved map[string]Resolution, cfg AgentConfig) AgentRuleResult {
	res := AgentRuleResult{RuleID: r.ID, Proto: r.Proto, ListenPort: r.ListenPort, Target: r.Target}
	host, portStr, err := net.SplitHostPort(r.Target)
	n, perr := strconv.ParseUint(portStr, 10, 16)
	if err != nil || host == "" || perr != nil || n == 0 {
		res.Reason = fmt.Sprintf("target %q is not in host:port form", r.Target)
		return res
	}
	base := int(n)
	if base+r.ListenPort.Len()-1 > 65535 {
		res.Reason = fmt.Sprintf("target port %d plus the width of range %s exceeds 65535", base, r.ListenPort)
		return res
	}
	addrs, reason := targetAddrs(host, resolved)
	if reason != "" {
		res.Reason = reason
		return res
	}
	// 許可一覧は実効宛先ごとに判定する。ポートごとに、一覧が通すアドレスのうち最も小さいものを使う
	// (7b.2 節)。どのアドレスも通らないポートは作らず、範囲の他のポートは公開する
	var refused []int // どのアドレスも許可一覧が通さなかったポート
	run := -1         // res.Ranges のうち、伸ばしている最後の範囲。-1 なら無い
	for p := int(r.ListenPort.Lo); p <= int(r.ListenPort.Hi); p++ {
		to := uint16(base + p - int(r.ListenPort.Lo))
		dest, ok := pickDest(addrs, to, cfg.AllowTarget)
		if !ok {
			refused = append(refused, p)
			run = -1
			continue
		}
		if run >= 0 {
			last := &res.Ranges[run]
			width := int(last.Ports.Hi) - int(last.Ports.Lo) + 1
			if dest.Addr() == last.Dest.Addr() && int(dest.Port()) == int(last.Dest.Port())+width {
				last.Ports.Hi = uint16(p)
				continue
			}
		}
		res.Ranges = append(res.Ranges, AgentRange{Ports: proto.PortRange{Lo: uint16(p), Hi: uint16(p)}, Dest: dest})
		run = len(res.Ranges) - 1
	}
	if len(refused) > 0 {
		res.Reason = refusedReason(host, addrs, uint16(base+refused[0]-int(r.ListenPort.Lo)), cfg.AllowTargetSource)
		if len(refused) > 1 {
			res.Reason += fmt.Sprintf("; %d of the rule's %d ports are not published", len(refused), r.ListenPort.Len())
		}
	}
	return res
}

// pickDest は、実効宛先のポート to について、許可一覧が通すアドレスのうち最も小さいものを選ぶ。
// addrs は昇順に並んでいる。許可一覧が無ければ最も小さいアドレスである。
func pickDest(addrs []netip.Addr, to uint16, allow func(netip.AddrPort) bool) (netip.AddrPort, bool) {
	for _, a := range addrs {
		d := netip.AddrPortFrom(a, to)
		if allow == nil || allow(d) {
			return d, true
		}
	}
	return netip.AddrPort{}, false
}

// refusedReason は、実効宛先のポート to にどのアドレスも使えなかった理由である。文言は中継の拒否
// (internal/dataplane/userspace/relay)と同じ形にする。server doctor は設定の名前か "is not allowed" で
// target_not_allowed に分類する。
func refusedReason(host string, addrs []netip.Addr, to uint16, source string) string {
	if len(addrs) == 1 {
		d := netip.AddrPortFrom(addrs[0], to)
		if source != "" {
			return fmt.Sprintf("target %s is not in %s", d, source)
		}
		return fmt.Sprintf("target %s is not allowed", d)
	}
	list := make([]string, len(addrs))
	for i, a := range addrs {
		list[i] = a.String()
	}
	if source != "" {
		return fmt.Sprintf("target host %q resolved to %s; none of them at port %d is in %s", host, strings.Join(list, ", "), to, source)
	}
	return fmt.Sprintf("target host %q resolved to %s; each of them at port %d is not allowed", host, strings.Join(list, ", "), to)
}

// targetAddrs は宛先のホストを、DNAT に使える IPv4 のアドレスの昇順の並びにする。使えなければ理由を返す。
// ホスト名の解決の結果にループバックか未指定のアドレスが混ざっていれば、それを除いて残りを使う。
func targetAddrs(host string, resolved map[string]Resolution) ([]netip.Addr, string) {
	var cands []netip.Addr
	if addr, err := netip.ParseAddr(host); err == nil {
		cands = []netip.Addr{addr}
	} else {
		rs, ok := resolved[host]
		switch {
		case ok && errors.Is(rs.Err, errOnlyIPv6):
			return nil, fmt.Sprintf("target host %q has only IPv6 addresses; kernel mode forwards only to IPv4 targets", host)
		case !ok || (rs.Err == nil && len(rs.Addrs) == 0):
			// 文言に "name resolution" を含め、server doctor が target_resolve_failed に分類できるようにする
			return nil, fmt.Sprintf("target host %q has no name resolution result", host)
		case rs.Err != nil:
			return nil, fmt.Sprintf("name resolution of target host %q failed: %v", host, rs.Err)
		}
		cands = rs.Addrs
	}
	var usable []netip.Addr
	reason := ""
	for _, a := range cands {
		a = a.Unmap()
		switch {
		case !a.Is4():
			// カーネルモードは IPv4 の宛先だけを扱う。実装の制限ではなく、モードの機能の違いである(7b.2 節)
			reason = fmt.Sprintf("target %s is an IPv6 address; kernel mode forwards only to IPv4 targets", a)
		case a.IsLoopback():
			// カーネルは DNAT でループバックへ向けたパケットを捨てる。route_localnet は使わない(7b.2 節)
			reason = fmt.Sprintf("target %s is a loopback address; kernel mode does not forward to loopback targets, use this host's LAN address", a)
		case a.IsUnspecified():
			// ユーザー空間モードでは 0.0.0.0 への接続はホスト自身に届くので、ループバックと同じく拒む(7b.2 節)
			reason = fmt.Sprintf("target %s is the unspecified address, which reaches this host's loopback; kernel mode does not forward to loopback targets, use this host's LAN address", a)
		default:
			usable = append(usable, a)
		}
	}
	if len(usable) == 0 {
		return nil, reason
	}
	// 選び方を DNS の応答の順によらせない。順が回るたびにテーブルを公開し直さないためである(7b.2 節)
	sort.Slice(usable, func(i, j int) bool { return usable[i].Less(usable[j]) })
	return slices.Compact(usable), ""
}

// errOnlyIPv6 は、ホスト名が IPv6 のアドレスだけに解決されたことを表す。
var errOnlyIPv6 = errors.New("the host has only IPv6 addresses")

// Failed は、名前の解決そのものが失敗したかどうかである。IPv6 のアドレスだけに解決された名前は、
// 解決できたうえで公開できない名前なので含めない。エージェントは、解決が失敗した名前にだけ、直前に
// 解決できたアドレスを使い続ける(7b.2 節)。
func (r Resolution) Failed() bool {
	return r.Err != nil && !errors.Is(r.Err, errOnlyIPv6)
}

// LookupFunc はホスト名のアドレスを引く。net.Resolver.LookupNetIP(ctx, "ip", host) と同じ形である。
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// ResolveAgentTargets は、ルールの宛先のホスト名を DNAT のアドレスへ解決する(7b.2 節の Prepare)。
// IP リテラルの宛先は引かない。無効のルールも引かない。lookup が nil なら net.DefaultResolver を使う。
//
// 使うのは A レコード(IPv4)だけであり、そのすべてを昇順に返す。どのアドレスを使うかは、許可一覧を
// 知る PlanAgent が選ぶ。AAAA レコードだけを持つ名前は、IPv4 の宛先が無いという理由で公開しない。
func ResolveAgentTargets(ctx context.Context, rules []proto.AgentRule, lookup LookupFunc) map[string]Resolution {
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	out := map[string]Resolution{}
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
		if _, done := out[host]; done {
			continue
		}
		out[host] = resolveIPv4(ctx, host, lookup)
	}
	return out
}

func resolveIPv4(ctx context.Context, host string, lookup LookupFunc) Resolution {
	addrs, err := lookup(ctx, host)
	if err != nil {
		return Resolution{Err: err}
	}
	var v4 []netip.Addr
	sawV6 := false
	for _, a := range addrs {
		a = a.Unmap()
		if !a.Is4() {
			sawV6 = true
			continue
		}
		v4 = append(v4, a)
	}
	switch {
	case len(v4) > 0:
		sort.Slice(v4, func(i, j int) bool { return v4[i].Less(v4[j]) })
		return Resolution{Addrs: slices.Compact(v4)}
	case sawV6:
		return Resolution{Err: errOnlyIPv6}
	default:
		return Resolution{Err: fmt.Errorf("host %q resolved to no address", host)}
	}
}
