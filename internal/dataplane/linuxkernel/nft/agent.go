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

	"github.com/rahanahu/wgft/internal/reasontext"
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
	// RefuseTarget は、宛先のアドレスへ転送しない理由を返す。転送してよければ空を返す。エージェントが
	// ブロードキャストとマルチキャストの宛先を拒むために渡す(7 節、7b.2 節)。理由はユーザー空間モードの
	// 中継と同じ文言である。nil なら判定しない。
	RefuseTarget func(netip.Addr) string
	// AllowLoopback は、IPv4 のループバックの宛先を運用者が明示したかの判定である(7b.2 節、
	// allowtargets の AllowsLoopback)。ループバックの宛先には AllowTarget の代わりにこれを使う。nil なら
	// ループバックの宛先へ DNAT を作らない。
	AllowLoopback func(netip.AddrPort) bool
}

// HasLoopback は、公開した DNAT の宛先にループバックのアドレスがあるかどうかである。あれば、エージェントは
// wgft0 の route_localnet を 1 にする(7b.2 節)。
func (p AgentPublication) HasLoopback() bool {
	for _, r := range p.Rules {
		for _, rg := range r.Ranges {
			if rg.Dest.Addr().IsLoopback() {
				return true
			}
		}
	}
	return false
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
	// Prefer は、ルール ID から、そのルールで最も小さいアドレスの代わりに使うアドレスへの対応である
	// (7b.2 節の他のアドレスへの切り替え)。エージェントは、TCP の接続確認で切り替えたアドレスを渡す。
	// 解決の結果に無いアドレスと、ポートの実効宛先を許可一覧が通さないアドレスは使わない。
	Prefer map[string]netip.Addr
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
	// Pinned は、切り替えたアドレスとして使ったアドレスである(AgentInput.Prefer)。そのアドレスを宛先に
	// したポートが 1 つでもあれば持つ。最も小さいアドレスと同じでも持つので、名前を引けない間の再起動で
	// 解決の結果が記録のアドレスだけになっても、切り替えたことが残る。エージェントは再起動の後もこの
	// アドレスを使い続ける(7b.2 節)
	Pinned netip.Addr `json:"pinned,omitzero"`
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
//   - 宛先が未指定のアドレス(0.0.0.0)の場合
//   - 宛先がブロードキャストかマルチキャストのアドレスの場合(cfg.RefuseTarget の判定)
//
// ループバック(127.0.0.0/8)の宛先は、cfg.AllowLoopback が真のポートにだけ DNAT を作る。
// 宛先の許可一覧はポートごとの実効宛先で判定する。ホスト名が複数のアドレスに解決されたときは、ポートごとに
// 一覧が通すアドレスだけを残し、その中で最も小さいアドレスを使う(7b.2 節)。in.Prefer にルールのアドレスが
// あり、一覧がそのポートで通せば、そのアドレスを使う。どのアドレスも通らないポートにだけ DNAT を作らない。
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
		out.Rules = append(out.Rules, planAgentRule(r, in.Resolved, in.Prefer[r.ID], cfg))
	}
	return out
}

func planAgentRule(r proto.AgentRule, resolved map[string]Resolution, prefer netip.Addr, cfg AgentConfig) AgentRuleResult {
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
	addrs, reason := targetAddrs(host, resolved, cfg.RefuseTarget)
	if reason != "" {
		res.Reason = reason
		return res
	}
	// 許可一覧は実効宛先ごとに判定する。ポートごとに、一覧が通すアドレスのうち最も小さいものを使う
	// (7b.2 節)。切り替えたアドレス prefer があり、一覧がそのポートで通せば、そちらを使う。どのアドレスも
	// 通らないポートは作らず、範囲の他のポートは公開する
	if !slices.Contains(addrs, prefer) {
		prefer = netip.Addr{}
	}
	var refused []int // どのアドレスも許可一覧が通さなかったポート
	run := -1         // res.Ranges のうち、伸ばしている最後の範囲。-1 なら無い
	for p := int(r.ListenPort.Lo); p <= int(r.ListenPort.Hi); p++ {
		to := uint16(base + p - int(r.ListenPort.Lo))
		dest, ok := pickDest(addrs, to, cfg)
		if !ok {
			refused = append(refused, p)
			run = -1
			continue
		}
		if pd := netip.AddrPortFrom(prefer, to); prefer.IsValid() && destAllowed(pd, cfg) {
			dest, res.Pinned = pd, prefer
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
		to := uint16(base + refused[0] - int(r.ListenPort.Lo))
		if allLoopback(addrs) {
			res.Reason = loopbackReason(host, addrs)
		} else {
			res.Reason = refusedReason(host, addrs, to, cfg.AllowTargetSource)
		}
		if len(refused) > 1 {
			res.Reason += fmt.Sprintf("; %d of the rule's %d ports are not published", len(refused), r.ListenPort.Len())
		}
	}
	return res
}

// pickDest は、実効宛先のポート to について、許可一覧が通すアドレスのうち最も小さいものを選ぶ。
// addrs は昇順に並んでいる。許可一覧が無ければ最も小さいアドレスである。ループバックのアドレスは、
// 運用者が明示したとき(cfg.AllowLoopback)だけ選ぶ(7b.2 節)。
func pickDest(addrs []netip.Addr, to uint16, cfg AgentConfig) (netip.AddrPort, bool) {
	for _, a := range addrs {
		if d := netip.AddrPortFrom(a, to); destAllowed(d, cfg) {
			return d, true
		}
	}
	return netip.AddrPort{}, false
}

// destAllowed は、実効宛先 d を DNAT の宛先にしてよいかである。ループバックのアドレスは運用者が明示した
// とき(cfg.AllowLoopback)だけ、他のアドレスは許可一覧が通すか一覧が無いときに通す(7b.2 節)。
func destAllowed(d netip.AddrPort, cfg AgentConfig) bool {
	if d.Addr().IsLoopback() {
		return cfg.AllowLoopback != nil && cfg.AllowLoopback(d)
	}
	return cfg.AllowTarget == nil || cfg.AllowTarget(d)
}

// allLoopback は、宛先の候補のアドレスがすべてループバックかどうかである。
func allLoopback(addrs []netip.Addr) bool {
	for _, a := range addrs {
		if !a.IsLoopback() {
			return false
		}
	}
	return len(addrs) > 0
}

// loopbackReason は、ループバックの宛先を運用者が明示していないために DNAT を作らなかった理由である
// (7b.2 節)。server doctor は reasontext.LoopbackUnsupported の句で target_loopback_unsupported に分類する。
// 許可一覧の設定の名前も含むので、doctor はこの句を許可一覧の名前より先に見る。
func loopbackReason(host string, addrs []netip.Addr) string {
	const unless = "kernel mode " + reasontext.LoopbackUnsupported + " unless " + reasontext.AllowTargetsEnv +
		" on the agent host names them with an entry inside 127.0.0.0/8"
	if _, err := netip.ParseAddr(host); err == nil {
		return fmt.Sprintf("target %s is a loopback address; %s", addrs[0], unless)
	}
	return fmt.Sprintf("target host %q resolved to the loopback address %s; %s", host, addrs[0], unless)
}

// refusedReason は、実効宛先のポート to にどのアドレスも使えなかった理由である。文言は中継の拒否
// (internal/dataplane/userspace/relay)と同じ形にする。server doctor は設定の名前か "is not allowed" で
// target_not_allowed に分類する。アドレスは先頭の maxRefusedAddrs 個だけを並べ、残りは "and N more" と書く。
func refusedReason(host string, addrs []netip.Addr, to uint16, source string) string {
	if len(addrs) == 1 {
		d := netip.AddrPortFrom(addrs[0], to)
		if source != "" {
			return fmt.Sprintf("target %s is not in %s", d, source)
		}
		return fmt.Sprintf("target %s "+reasontext.NotAllowed, d)
	}
	shown := addrs[:min(len(addrs), maxRefusedAddrs)]
	list := make([]string, len(shown))
	for i, a := range shown {
		list[i] = a.String()
	}
	resolvedTo := strings.Join(list, ", ")
	if more := len(addrs) - len(shown); more > 0 {
		resolvedTo += fmt.Sprintf(" and %d more", more)
	}
	if source != "" {
		return fmt.Sprintf("target host %q resolved to %s; none of them at port %d is in %s", host, resolvedTo, to, source)
	}
	return fmt.Sprintf("target host %q resolved to %s; each of them at port %d "+reasontext.NotAllowed, host, resolvedTo, to)
}

// maxRefusedAddrs は、refusedReason が理由に並べるアドレスの数である。ホスト名は 253 バイトまで有効で、
// 解決の結果は数十のアドレスになりうる。全部を並べると、hub のハートビートの理由の切り詰め
// (stream.HeartbeatReason、512 バイト)が、server doctor が分類に使う後半(許可一覧の設定の名前か
// "is not allowed")を落とす。4 つなら、253 バイトのホスト名、最長のアドレス、ポートの範囲の
// 追記を合わせても 512 バイトに収まる(internal/agent/kernelmode の reason_roundtrip_linux_test.go が固定する)。
const maxRefusedAddrs = 4

// targetAddrs は宛先のホストを、DNAT に使える IPv4 のアドレスの昇順の並びにする。使えなければ理由を返す。
// ホスト名の解決の結果に未指定、refuse が拒むアドレスが混ざっていれば、それを除いて残りを使う。
// ループバックのアドレスは残す。使うかどうかは、運用者が明示したかを見て pickDest が決める。
func targetAddrs(host string, resolved map[string]Resolution, refuse func(netip.Addr) string) ([]netip.Addr, string) {
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
			return nil, fmt.Sprintf("target host %q has no "+reasontext.NameResolution+" result", host)
		case rs.Err != nil:
			return nil, reasontext.NameResolutionFailed(host, rs.Err)
		}
		cands = rs.Addrs
	}
	var usable []netip.Addr
	reason := ""
	for _, a := range cands {
		a = a.Unmap()
		var refused string
		if refuse != nil {
			refused = refuse(a)
		}
		switch {
		case refused != "":
			// ブロードキャストとマルチキャストは、IPv6 のマルチキャストも含めてユーザー空間モードと同じ理由で
			// 拒む。IPv4 だけの規則より先に見るのはそのためである(7b.2 節)
			reason = refused
		case !a.Is4():
			// カーネルモードは IPv4 の宛先だけを扱う。実装の制限ではなく、モードの機能の違いである(7b.2 節)
			reason = fmt.Sprintf("target %s is an IPv6 address; kernel mode forwards only to IPv4 targets", a)
		case a.IsUnspecified():
			// ユーザー空間モードでは 0.0.0.0 への接続はホスト自身に届く。カーネルモードは DNAT の宛先に
			// できないので拒む(7b.2 節)。server doctor が target_loopback_unsupported に分類できるよう、
			// reasontext.LoopbackUnsupported の句を含める
			reason = fmt.Sprintf("target %s is the unspecified address, which reaches this host's loopback; kernel mode "+reasontext.LoopbackUnsupported+
				" through it; target 127.0.0.1 named in "+reasontext.AllowTargetsEnv+" or this host's LAN address instead", a)
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

// AgentCandidates は、ホスト名 host の解決の結果 addrs のうち、実効宛先のポート to への DNAT に使える
// アドレスを昇順に返す。PlanAgent と同じ規則で、IPv4 でないアドレス、未指定、cfg.RefuseTarget が拒む
// アドレス、許可一覧が通さないアドレス、運用者が明示していないループバックのアドレスを除く。エージェントは、TCP の接続確認に失敗したアドレスの
// 代わりの候補をこれで選ぶ(7b.2 節の他のアドレスへの切り替え)。
func AgentCandidates(host string, addrs []netip.Addr, to uint16, cfg AgentConfig) []netip.Addr {
	usable, reason := targetAddrs(host, map[string]Resolution{host: {Addrs: addrs}}, cfg.RefuseTarget)
	if reason != "" {
		return nil
	}
	var out []netip.Addr
	for _, a := range usable {
		if destAllowed(netip.AddrPortFrom(a, to), cfg) {
			out = append(out, a)
		}
	}
	return out
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
