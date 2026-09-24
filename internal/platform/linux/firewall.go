//go:build linux

// Package linux は、VPS と(将来の Phase 7 の)agent の kernel backend が共通に使う、Linux ホスト側の
// 前段検査と sysctl の読み書きを持つ(設計文書 7a.7 節)。他テーブルの forward/input/DNAT の検査、
// bind 中のポートの検査、ip_forward と conntrack テーブルの sysctl がここに属する。自動では何も
// 書き換えず(ip_forward を除く。EnableIPForward のみ)、拒否か警告と提示に留める。
//
// このパッケージは internal/dataplane/linuxkernel を import しない(その逆に、linuxkernel がこの
// パッケージを import する)。table inet wgft のような、カーネル backend の実装詳細である名前は
// 引数として受け取り、自分では知らない。
package linux

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/proto"
)

// HookForward と HookInput は Finding.Hook の値である。
const (
	HookForward = "forward"
	HookInput   = "input"
)

// Finding は警告 1 件と、管理者に提示する手作業の行。
type Finding struct {
	// Hook は所見が見つかったフックである(HookForward、HookInput)。どちらでもない所見では空である。
	// エージェントは forward の所見だけを、自分の転送の向きに合わせた文言で示す
	Hook    string
	Where   string   // "ip filter FORWARD" のようなチェーンの場所
	Problem string   // 何が起きるか
	Suggest []string // 足す行(コマンドの形)
}

// String は Findings を「どこ: 何が問題か」と提示する行の形にする。
func (f Finding) String() string {
	s := f.Where + ": " + f.Problem
	for _, l := range f.Suggest {
		s += "\n    " + l
	}
	return s
}

// DNAT は他テーブルの nat prerouting にある DNAT 1 件。
type DNAT struct {
	Where string
	Proto proto.Proto     // 不明なら ""
	Ports proto.PortRange // Unknown なら無意味
	// ポートが判定できなかった(無名 set を読めない、式の形が未知)。
	// 衝突の判定では「同じプロトコルなら全ポートと衝突する」扱いにはせず、警告だけにする
	Unknown bool
}

// Report は検査の結果。
type Report struct {
	Findings []Finding
	DNATs    []DNAT
}

// DNATConflicts は (proto, range) に重なる他テーブルの DNAT を返す。ポート不明のものは返さない。
func (r *Report) DNATConflicts(p proto.Proto, pr proto.PortRange) []DNAT {
	var out []DNAT
	for _, d := range r.DNATs {
		if d.Unknown || (d.Proto != "" && d.Proto != p) {
			continue
		}
		if d.Ports.Overlaps(pr) {
			out = append(out, d)
		}
	}
	return out
}

// InputPortSuggestions は、input の base chain が既定で落とす構成で、かつ pr/proto への明示的な
// accept がまだ無いとき、その accept を足す行を提示する。呼び出し元は 3 種類ある。カーネルモードの
// プロキシルール(vpsd 自身が中継で受けるポート。単一ポートに限る。仕様 6.2 節)、ユーザー空間モードの
// 全ルール(範囲を含む。仕様 6.3 節)、vpsd 自身が待ち受ける 2 つのポート(WireGuard の UDP、
// agent API の TCP。仕様 4 節)である。最後のものは実機の Debian 13(input が policy drop で SSH の
// TCP 22 しか accept していない構成)で見つかった。改訂の記録を参照。
// ownTable は自分の table(kernel backend では table inet wgft)の名前で、検査から除く。
func InputPortSuggestions(pr proto.PortRange, p proto.Proto, ownTable string) ([]string, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}
	chains, err := c.ListChains()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ch := range chains {
		if ch.Hooknum == nil || *ch.Hooknum != unix.NF_INET_LOCAL_IN || ch.Type != nftables.ChainTypeFilter || ch.Table.Name == ownTable {
			continue
		}
		rules, err := c.GetRules(ch.Table, ch)
		if err != nil {
			continue
		}
		out = append(out, inputPortSuggestion(ch, rules, pr, p)...)
	}
	return out, nil
}

// inputPortSuggestion は InputPortSuggestions の 1 チェーン分の判定。実の nftables 接続を要らなく
// して、テストが手作りの chain と rules だけで確かめられるように分けてある。
func inputPortSuggestion(ch *nftables.Chain, rules []*nftables.Rule, pr proto.PortRange, p proto.Proto) []string {
	if blocks, _ := blocksByDefault(ch, rules); !blocks {
		return nil
	}
	if acceptsPort(rules, p, pr) {
		return nil
	}
	if iptablesManaged(ch) {
		bin := "iptables"
		if ch.Table.Family == nftables.TableFamilyIPv6 {
			bin = "ip6tables"
		}
		return []string{fmt.Sprintf("%s -I %s -p %s --dport %s -j ACCEPT", bin, ch.Name, p, dportArg(pr, true))}
	}
	return []string{fmt.Sprintf("nft insert rule %s %s %s %s dport %s accept", familyName(ch.Table.Family), ch.Table.Name, ch.Name, p, dportArg(pr, false))}
}

// dportArg は pr を dport の引数の文字列にする。単一ポートはそのまま、範囲は書式が違う。
// nft は "40000-40010"(proto.PortRange.String と同じ)、iptables は "40000:40010" を使う。
func dportArg(pr proto.PortRange, iptablesStyle bool) string {
	if !pr.IsRange() {
		return strconv.Itoa(int(pr.Lo))
	}
	if iptablesStyle {
		return fmt.Sprintf("%d:%d", pr.Lo, pr.Hi)
	}
	return pr.String()
}

// acceptsPort は、rules がすでに proto/pr への明示的な accept(手で足した `tcp dport 8443
// accept` など)を持つかを判定する。持っていれば、二重になる提示を出さない。範囲のルールは、
// 既存の accept の範囲が pr を丸ごと含む場合だけ済んだ扱いにする。一部だけ accept された範囲を
// 済んだ扱いにすると、残りの部分が塞がれたままになるためである。ポートの一致条件が読めない規則は
// 一致とみなさない。読めない規則を「accept 済み」扱いにすると、実際は塞がれている場合に見逃すためである。
// set を使う accept(`tcp dport { 22, 8443 } accept`)も読めない規則として扱う。set の中身を最小から
// 最大の範囲に丸めると、set に無いポートまで accept 済みと判定してしまうためである。
func acceptsPort(rules []*nftables.Rule, p proto.Proto, pr proto.PortRange) bool {
	for _, rl := range rules {
		rp, ports, unknown := matchPorts(nil, nil, rl.Exprs)
		if unknown || rp != p || ports.Lo > pr.Lo || pr.Hi > ports.Hi {
			continue
		}
		if ruleVerdictAccept(rl.Exprs) {
			return true
		}
	}
	return false
}

// ruleVerdictAccept は、exprs の中に accept の verdict があるかを見る(counter や log を挟んでいてもよい)。
func ruleVerdictAccept(exprs []expr.Any) bool {
	for _, e := range exprs {
		if v, ok := e.(*expr.Verdict); ok {
			return v.Kind == expr.VerdictAccept
		}
	}
	return false
}

// Inspect は wgft(または agent の kernel backend)以外の全テーブルの base chain を調べる。
// ownTable は自分の table の名前で、検査から除く。
func Inspect(wgIface, ownTable string) (*Report, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}
	chains, err := c.ListChains()
	if err != nil {
		return nil, fmt.Errorf("listing chains: %w", err)
	}
	rep := &Report{}
	for _, ch := range chains {
		if ch.Hooknum == nil || ch.Table.Name == ownTable {
			continue
		}
		rules, err := c.GetRules(ch.Table, ch)
		if err != nil {
			return nil, fmt.Errorf("rules of %s: %w", where(ch), err)
		}
		switch {
		case *ch.Hooknum == unix.NF_INET_FORWARD && ch.Type == nftables.ChainTypeFilter:
			rep.inspectForward(ch, rules, wgIface)
		case *ch.Hooknum == unix.NF_INET_LOCAL_IN && ch.Type == nftables.ChainTypeFilter:
			rep.inspectInput(ch, rules)
		case *ch.Hooknum == unix.NF_INET_PRE_ROUTING && ch.Type == nftables.ChainTypeNAT:
			rep.collectDNAT(c, ch, rules)
		}
	}
	return rep, nil
}

func where(ch *nftables.Chain) string {
	return fmt.Sprintf("%s %s %s", familyName(ch.Table.Family), ch.Table.Name, ch.Name)
}

func familyName(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	}
	return fmt.Sprintf("family%d", f)
}

// blocksByDefault は「一致しなかったパケットが落ちる」チェーンか。policy drop か、末尾の無条件な drop / reject。
func blocksByDefault(ch *nftables.Chain, rules []*nftables.Rule) (bool, string) {
	if ch.Policy != nil && *ch.Policy == nftables.ChainPolicyDrop {
		return true, "policy drop"
	}
	if n := len(rules); n > 0 {
		if term, how := unconditionalTerminal(rules[n-1].Exprs); term {
			return true, "trailing unconditional " + how
		}
	}
	return false, ""
}

// unconditionalTerminal は、一致条件を持たずに drop / reject する規則か。
func unconditionalTerminal(exprs []expr.Any) (bool, string) {
	how := ""
	for _, e := range exprs {
		switch x := e.(type) {
		case *expr.Counter, *expr.Log:
		case *expr.Reject:
			how = "reject"
		case *expr.Verdict:
			if x.Kind == expr.VerdictDrop {
				how = "drop"
			} else {
				return false, ""
			}
		default:
			return false, ""
		}
	}
	return how != "", how
}

// jumpOnly は一致条件なしで別チェーンへ jump する規則(Docker の `FORWARD -j DOCKER-USER`)の先。
func jumpOnly(exprs []expr.Any) string {
	target := ""
	for _, e := range exprs {
		switch x := e.(type) {
		case *expr.Counter:
		case *expr.Verdict:
			if x.Kind != expr.VerdictJump {
				return ""
			}
			target = x.Chain
		default:
			return ""
		}
	}
	return target
}

// iptablesManaged は iptables-nft が作ったテーブルらしいか(チェーン名が大文字)。提示の形を変える。
func iptablesManaged(ch *nftables.Chain) bool {
	return ch.Name == strings.ToUpper(ch.Name) && (ch.Table.Family == nftables.TableFamilyIPv4 || ch.Table.Family == nftables.TableFamilyIPv6)
}

func (r *Report) inspectForward(ch *nftables.Chain, rules []*nftables.Rule, wg string) {
	blocks, how := blocksByDefault(ch, rules)
	if !blocks {
		return
	}
	// 足す先:一致条件なしの jump があればその先(DOCKER-USER)、なければこのチェーンの先頭
	into := ch.Name
	for _, rl := range rules {
		if t := jumpOnly(rl.Exprs); t != "" {
			into = t
			break
		}
	}
	var suggest []string
	if iptablesManaged(ch) {
		bin := "iptables"
		if ch.Table.Family == nftables.TableFamilyIPv6 {
			bin = "ip6tables"
		}
		suggest = []string{
			fmt.Sprintf("%s -I %s -o %s -j ACCEPT", bin, into, wg),
			fmt.Sprintf("%s -I %s -i %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", bin, into, wg),
		}
	} else {
		fam, tbl := familyName(ch.Table.Family), ch.Table.Name
		suggest = []string{
			fmt.Sprintf(`nft insert rule %s %s %s oifname "%s" accept`, fam, tbl, into, wg),
			fmt.Sprintf(`nft insert rule %s %s %s iifname "%s" ct state established,related accept`, fam, tbl, into, wg),
		}
	}
	r.Findings = append(r.Findings, Finding{
		Hook:    HookForward,
		Where:   where(ch),
		Problem: fmt.Sprintf("forward is %s, so wgft's forwarding is dropped: public IF -> %s and its replies. add these 2 lines once, port-independent", how, wg),
		Suggest: suggest,
	})
}

func (r *Report) inspectInput(ch *nftables.Chain, rules []*nftables.Rule) {
	blocks, how := blocksByDefault(ch, rules)
	if !blocks {
		return
	}
	for _, rl := range rules {
		if acceptsEstablished(rl.Exprs) {
			return
		}
	}
	var suggest []string
	if iptablesManaged(ch) {
		suggest = []string{fmt.Sprintf("iptables -I %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", ch.Name)}
	} else {
		suggest = []string{fmt.Sprintf("nft insert rule %s %s %s ct state established,related accept", familyName(ch.Table.Family), ch.Table.Name, ch.Name)}
	}
	r.Findings = append(r.Findings, Finding{
		Hook:    HookInput,
		Where:   where(ch),
		Problem: fmt.Sprintf("input is %s and has no accept for established; replies to connections the server makes over wg0 are dropped, e.g. proxy-mode relaying and connectivity checks", how),
		Suggest: suggest,
	})
}

// acceptsEstablished は `ct state established[,…] accept` に相当する規則か。
// ネイティブ nft(Bitwise のマスク)、無名 set(Lookup)、iptables-nft(xt conntrack)の 3 系統を見る。
func acceptsEstablished(exprs []expr.Any) bool {
	const established = 0x2 // IP_CT_ESTABLISHED のビット(nft も xt_conntrack も同じ)
	ctState, matches, accept := false, false, false
	for _, e := range exprs {
		switch x := e.(type) {
		case *expr.Ct:
			ctState = x.Key == expr.CtKeySTATE
		case *expr.Bitwise:
			if ctState && len(x.Mask) == 4 && binary.NativeEndian.Uint32(x.Mask)&established != 0 {
				matches = true
			}
		case *expr.Lookup:
			if ctState { // set の中身は読まず、established を含むものとみなす(firewalld の形)
				matches = true
			}
		case *expr.Match:
			if x.Name == "conntrack" {
				var mask uint16
				switch info := x.Info.(type) {
				case *xt.ConntrackMtinfo1:
					mask = uint16(info.StateMask)
				case *xt.ConntrackMtinfo2:
					mask = info.StateMask
				case *xt.ConntrackMtinfo3:
					mask = info.StateMask
				}
				if mask&established != 0 {
					matches = true
				}
			}
		case *expr.Verdict:
			accept = x.Kind == expr.VerdictAccept
		}
	}
	return matches && accept
}

func (r *Report) collectDNAT(c *nftables.Conn, ch *nftables.Chain, rules []*nftables.Rule) {
	for _, rl := range rules {
		if !isDNAT(rl.Exprs) {
			continue
		}
		d := DNAT{Where: where(ch)}
		d.Proto, d.Ports, d.Unknown = matchPorts(c, ch.Table, rl.Exprs)
		r.DNATs = append(r.DNATs, d)
		if d.Unknown {
			// この規則の宛先ポートは読めなかった(multiport、読めない無名 set、未知の式の形)。
			// wgft のルールと重なるかを判定できないので、拒否はせず警告だけにする(仕様 6.1 節)
			desc := "a DNAT rule of unknown protocol"
			if d.Proto != "" {
				desc = "a " + string(d.Proto) + " DNAT rule"
			}
			r.Findings = append(r.Findings, Finding{
				Where:   d.Where,
				Problem: fmt.Sprintf("has %s whose port match could not be read; wgft cannot tell whether it overlaps a wgft rule's port, so check by hand", desc),
			})
		}
	}
}

func isDNAT(exprs []expr.Any) bool {
	for _, e := range exprs {
		switch x := e.(type) {
		case *expr.NAT:
			if x.Type == expr.NATTypeDestNAT {
				return true
			}
		case *expr.Target:
			if x.Name == "DNAT" || x.Name == "REDIRECT" {
				return true
			}
		}
	}
	return false
}

// matchPorts は規則の一致条件から L4 プロトコルと宛先ポートを読む。
// プロトコルは Meta(L4PROTO) + Cmp、ポートは Payload(transport+2, 2) の直後の Cmp eq / Range / Lookup。
func matchPorts(c *nftables.Conn, t *nftables.Table, exprs []expr.Any) (p proto.Proto, ports proto.PortRange, unknown bool) {
	wantL4, wantPort := false, false
	gotPort := false
	for _, e := range exprs {
		switch x := e.(type) {
		case *expr.Meta:
			wantL4 = x.Key == expr.MetaKeyL4PROTO
			wantPort = false
		case *expr.Payload:
			wantPort = x.Base == expr.PayloadBaseTransportHeader && x.Offset == 2 && x.Len == 2
			wantL4 = false
		case *expr.Cmp:
			switch {
			case wantL4 && len(x.Data) == 1:
				switch x.Data[0] {
				case unix.IPPROTO_TCP:
					p = proto.TCP
				case unix.IPPROTO_UDP:
					p = proto.UDP
				}
			case wantPort && len(x.Data) == 2:
				v := binary.BigEndian.Uint16(x.Data)
				switch x.Op {
				case expr.CmpOpEq:
					ports, gotPort = proto.PortRange{Lo: v, Hi: v}, true
				case expr.CmpOpGte:
					ports.Lo, gotPort = v, true
				case expr.CmpOpLte:
					ports.Hi, gotPort = v, true
				}
			}
		case *expr.Range:
			if wantPort && len(x.FromData) == 2 && len(x.ToData) == 2 {
				ports = proto.PortRange{Lo: binary.BigEndian.Uint16(x.FromData), Hi: binary.BigEndian.Uint16(x.ToData)}
				gotPort = true
			}
			wantPort = false
		case *expr.Lookup:
			if wantPort {
				// set の中身を読む接続が無い(acceptsPort のように規則の式だけで判定する)ときは、
				// 読めない一致条件として返す。nil の接続で set を引くと panic する
				if c == nil || t == nil {
					return p, ports, true
				}
				// 無名 set のポート集合。読めれば最小-最大の範囲として扱う(荒いが安全側)
				lo, hi, ok := setPortBounds(c, t, x.SetName)
				if ok {
					ports, gotPort = proto.PortRange{Lo: lo, Hi: hi}, true
				} else {
					return p, ports, true
				}
			}
			wantPort = false
		}
	}
	if !gotPort {
		return p, ports, true
	}
	if ports.Hi == 0 {
		ports.Hi = ports.Lo
	}
	if ports.Lo == 0 {
		ports.Lo = 1
	}
	return p, ports, false
}

func setPortBounds(c *nftables.Conn, t *nftables.Table, name string) (lo, hi uint16, ok bool) {
	s, err := c.GetSetByName(t, name)
	if err != nil {
		return 0, 0, false
	}
	elems, err := c.GetSetElements(s)
	if err != nil || len(elems) == 0 {
		return 0, 0, false
	}
	var vals []uint16
	for _, e := range elems {
		if len(e.Key) == 2 {
			vals = append(vals, binary.BigEndian.Uint16(e.Key))
		}
	}
	if len(vals) == 0 {
		return 0, 0, false
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	return vals[0], vals[len(vals)-1], true
}
