//go:build linux

package nft

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/proto"
)

// DNATKind はエージェントの DNAT の行のコメントの種類である(wgft:<ルール ID>:dnat)。
const DNATKind = "dnat"

// PassKind は、filter_pre で公開したポートの新しい接続を通す行のコメントの種類である(wgft:<ルール ID>:pass)。
const PassKind = "pass"

// agentChain はエージェントの表のチェーンの 1 つである。
type agentChain struct {
	name string
	typ  nftables.ChainType
	hook *nftables.ChainHook
	prio int32
}

// agentChains はエージェントの表のチェーンである(7b.1 節)。filter_pre は conntrack(-200)の後、DNAT
// (nat_pre の dstnat - 1)の前に置く。
var agentChains = []agentChain{
	{"filter_pre", nftables.ChainTypeFilter, nftables.ChainHookPrerouting, -150}, // mangle
	{"nat_pre", nftables.ChainTypeNAT, nftables.ChainHookPrerouting, -101},       // dstnat - 1
	{"input", nftables.ChainTypeFilter, nftables.ChainHookInput, -10},            // filter - 10
	{"forward", nftables.ChainTypeFilter, nftables.ChainHookForward, -10},        // filter - 10
	{"postrouting", nftables.ChainTypeNAT, nftables.ChainHookPostrouting, 100},   // srcnat
}

// agentRow は nat_pre の DNAT の行を除く 1 行である。desc は InspectAgent が欠けた行を示す文言である。
type agentRow struct {
	chain   string
	desc    string
	comment string
	exprs   []expr.Any
}

// StageAgent は table inet wgft_agent の差し替えを組み立てるが、送らない(7a.2 節の Prepare)。
// 送るのは Staged.Flush である。server の Stage と同じく、テーブル全体を 1 つのバッチで差し替える。
func StageAgent(pub AgentPublication, cfg AgentConfig) (*Staged, error) {
	s := &Staged{}
	conn, err := nftables.New(nftables.WithSockOptions(s.sizeSocket))
	if err != nil {
		return nil, fmt.Errorf("cannot connect to nftables: %w", err)
	}
	if err := emitAgent(&sizing{to: conn, size: &s.size}, pub, cfg.WGInterface); err != nil {
		return nil, err
	}
	s.conn = conn
	return s, nil
}

// ApplyAgent は StageAgent と Flush を続けて行う。
func ApplyAgent(pub AgentPublication, cfg AgentConfig) error {
	s, err := StageAgent(pub, cfg)
	if err != nil {
		return err
	}
	return s.Flush()
}

func emitAgent(e emitter, pub AgentPublication, wg string) error {
	if wg == "" {
		return fmt.Errorf("table inet %s: no WireGuard interface name", AgentTableName)
	}
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: AgentTableName}
	e.AddTable(t)
	e.DelTable(t)
	t = e.AddTable(t)

	policy := nftables.ChainPolicyAccept
	chains := map[string]*nftables.Chain{}
	for _, c := range agentChains {
		chains[c.name] = e.AddChain(&nftables.Chain{Name: c.name, Table: t, Type: c.typ, Hooknum: c.hook,
			Priority: nftables.ChainPriorityRef(nftables.ChainPriority(c.prio)), Policy: &policy})
	}
	addRule := func(ch *nftables.Chain, comment string, exprs []expr.Any) {
		r := &nftables.Rule{Table: t, Chain: ch, Exprs: exprs}
		if comment != "" {
			r.UserData = userdata.AppendString(nil, userdata.TypeComment, comment)
		}
		e.AddRule(r)
	}

	fromWG := ifname(expr.MetaKeyIIFNAME, expr.CmpOpEq, wg)
	for _, r := range pub.Rules {
		if len(r.Ranges) == 0 {
			continue
		}
		dnat, err := agentDNAT(e, t, r)
		if err != nil {
			return err
		}
		addRule(chains["nat_pre"], Comment(r.RuleID, DNATKind), concat(fromWG, l4proto(r.Proto), dportIn(r.ListenPort), dnat))
	}
	for _, row := range agentRows(pub, wg) {
		addRule(chains[row.chain], row.comment, row.exprs)
	}
	return nil
}

// agentRows は nat_pre の DNAT の行を除く、表のすべての行である。filter_pre の通す行は公開の結果から
// 決まり、残りの行は公開の結果によらない。
func agentRows(pub AgentPublication, wg string) []agentRow {
	fromWG := ifname(expr.MetaKeyIIFNAME, expr.CmpOpEq, wg)
	toWG := ifname(expr.MetaKeyOIFNAME, expr.CmpOpEq, wg)
	const ipsDstNAT = 0x20 // IPS_DST_NAT:ct status dnat
	drop := []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
	accept := []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
	dnatted := ctBits(expr.CtKeySTATUS, ipsDstNAT)
	established := ctState(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED)
	var rows []agentRow
	add := func(chain, desc, comment string, parts ...[]expr.Any) {
		rows = append(rows, agentRow{chain: chain, desc: desc, comment: comment, exprs: concat(parts...)})
	}

	// filter_pre:wgft0 から入る新しい接続のうち、公開した (プロトコル, ポート) の組だけを DNAT の前で通し、
	// 残りを落とす(7b.1 節)。VPS の側から触れる面を入口で閉じるので、他のテーブルの DNAT(Docker が
	// 公開したポートなど)にも wgft0 からは届かない。成立済みのフローは通す
	add("filter_pre", "filter_pre: accept established and related flows from "+wg, "", fromWG, established, accept)
	for _, r := range pub.Rules {
		for _, rg := range r.Ranges {
			add("filter_pre", fmt.Sprintf("filter_pre: accept %s %s from %s for rule %s", r.Proto, rg.Ports, wg, r.RuleID),
				Comment(r.RuleID, PassKind), fromWG, l4proto(r.Proto), dportIn(rg.Ports), accept)
		}
	}
	add("filter_pre", "filter_pre: drop the rest from "+wg, "", fromWG, drop)

	// input:wgft0 から入る新規の接続のうち、DNAT していないものを落とす(7b.1 節、11 節)。ホスト自身の
	// LAN のアドレスへの DNAT は forward ではなく input を通るので、DNAT したフローは通す(7b.2 節)
	add("input", "input: accept DNATed flows from "+wg, "", fromWG, dnatted, accept)
	add("input", "input: accept established and related flows from "+wg, "", fromWG, established, accept)
	add("input", "input: drop the rest from "+wg, "", fromWG, drop)

	// MSS は wgft0 を通る SYN を両方向で経路の MTU にクランプする(7b.1 節)。片方だけでは他方の向きが止まる
	add("forward", "forward: clamp the MSS of SYNs from "+wg, "", fromWG, mssClamp())
	add("forward", "forward: clamp the MSS of SYNs to "+wg, "", toWG, mssClamp())
	// DNAT したフローとその返りだけを通し、wgft0 が絡む残りの転送を落とす。wgft0 が絡まない転送には触れない
	add("forward", "forward: drop "+wg+" to "+wg, "", fromWG, toWG, drop)
	add("forward", "forward: accept DNATed flows from "+wg, "", fromWG, dnatted, accept)
	add("forward", "forward: accept established and related flows to "+wg, "", toWG, established, accept)
	add("forward", "forward: drop the rest from "+wg, "", fromWG, drop)
	add("forward", "forward: drop the rest to "+wg, "", toWG, drop)

	// MASQUERADE は wgft0 から入って DNAT したフローのうち、wgft0 以外へ出るものに掛ける(7b.1 節)。表を
	// wgft0 の側だけで書くので、LAN のインタフェース名は要らない。iifname が無いと、他のテーブルが DNAT した
	// フロー(Docker が公開したポートなど)の送信元まで書き換える。転送されるパケットの postrouting では、
	// 入力のインタフェースを照合できる
	add("postrouting", "postrouting: masquerade DNATed flows from "+wg+" leaving by another interface", "",
		fromWG, ifname(expr.MetaKeyOIFNAME, expr.CmpOpNeq, wg), dnatted, []expr.Any{&expr.Masq{}})
	return rows
}

// setElemChunk は、set の要素を 1 通の netlink のメッセージに入れる数の上限である。google/nftables
// v0.3.0 は AddSet に渡した要素をすべて 1 つの属性に入れる。属性の長さは 16 ビットなので、map の要素が
// 約 1,800 を超えると長さがあふれ、カーネルは先頭の一部だけを読む(ラボで確かめた。8,001 ポートの範囲で
// 1,857 個だけが入った)。要素をこの数ずつ別のメッセージに分けて送る。
const setElemChunk = 1024

// addSetChunked は set を宣言し、要素を setElemChunk 個ずつ別のメッセージで入れる。どれも同じバッチに
// 入り、set を参照する行より前に送る。無名の set は行に結び付いた後は要素を足せないためである。
func addSetChunked(e emitter, s *nftables.Set, els []nftables.SetElement) error {
	if err := e.AddSet(s, nil); err != nil {
		return err
	}
	for len(els) > 0 {
		n := min(setElemChunk, len(els))
		// google/nftables は無名の set への SetAddElements を拒む。行に結び付く前の同じバッチの中では
		// カーネルは受け付けるので、呼ぶ間だけ印を外す。メッセージは set を ID で指す
		anon := s.Anonymous
		s.Anonymous = false
		err := e.SetAddElements(s, els[:n])
		s.Anonymous = anon
		if err != nil {
			return err
		}
		els = els[n:]
	}
	return nil
}

// agentDNAT は 1 つのルールの DNAT の文である。単一ポートのルールはアドレスとポートを直接書き、範囲の
// ルールは無名の連結 map でポートごとの宛先アドレスとポートを引く(7b.1 節)。範囲のルールで許可一覧が
// 拒んだポートは map に入らないので、そのポートのパケットは DNAT されない。filter_pre が先に落とす。
func agentDNAT(e emitter, t *nftables.Table, r AgentRuleResult) ([]expr.Any, error) {
	if !r.ListenPort.IsRange() {
		d := r.Ranges[0].Dest
		a4 := d.Addr().As4()
		return []expr.Any{
			&expr.Immediate{Register: 1, Data: a4[:]},
			&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(d.Port())},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1, RegProtoMin: 2, Specified: true},
		}, nil
	}
	dataType, err := nftables.ConcatSetType(nftables.TypeIPAddr, nftables.TypeInetService)
	if err != nil {
		return nil, err
	}
	m := &nftables.Set{Table: t, Name: "__map%d", Anonymous: true, Constant: true, IsMap: true,
		KeyType: nftables.TypeInetService, DataType: dataType}
	var elems []nftables.SetElement
	for _, rg := range r.Ranges {
		a4 := rg.Dest.Addr().As4()
		for i := 0; i < rg.Ports.Len(); i++ {
			// 値は連結の各要素を 4 バイトの境界に詰める:アドレス 4 バイト、ポート 2 バイト、詰め物 2 バイト
			val := append(append(append([]byte(nil), a4[:]...), binaryutil.BigEndian.PutUint16(rg.Dest.Port()+uint16(i))...), 0, 0)
			elems = append(elems, nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(rg.Ports.Lo + uint16(i)), Val: val})
		}
	}
	if err := addSetChunked(e, m, elems); err != nil {
		return nil, fmt.Errorf("rule %s: map: %w", r.RuleID, err)
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Lookup{SourceRegister: 1, DestRegister: 1, IsDestRegSet: true, SetName: m.Name, SetID: m.ID},
		// 連結の 2 つ目の要素(ポート)は 32 ビットのレジスタの 2 つ目(NFT_REG32_01 = 9)に入る。
		// nft(8) はこの形では flags を送らない。カーネルはポートのレジスタから PROTO_SPECIFIED を立てる
		&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1, RegProtoMin: unix.NFT_REG32_01},
	}, nil
}

// dportIn は `<proto> dport <range>` のうち宛先ポートの比較の部分。呼び出し側が先に l4proto を置く。
func dportIn(r proto.PortRange) []expr.Any {
	out := []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}}
	if r.Lo == r.Hi {
		return append(out, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(r.Lo)})
	}
	return append(out,
		&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.BigEndian.PutUint16(r.Lo)},
		&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: binaryutil.BigEndian.PutUint16(r.Hi)})
}

// mssClamp は `tcp flags syn / syn,rst tcp option maxseg size set rt mtu`。
// google/nftables v0.3.0 は rt と byteorder の式を読み戻せず、GetRules はこの 2 つを誤りなしに
// 読み飛ばす(Fingerprint の注)。
func mssClamp() []expr.Any {
	const tcpFlagSYN, tcpFlagRST = 0x02, 0x04
	const tcpOptMaxseg = 2
	return concat(l4proto(proto.TCP), []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{tcpFlagSYN | tcpFlagRST}, Xor: []byte{0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{tcpFlagSYN}},
		&expr.Rt{Register: 1, Key: expr.RtTCPMSS},
		&expr.Byteorder{SourceRegister: 1, DestRegister: 1, Op: expr.ByteorderHton, Len: 2, Size: 2},
		&expr.Exthdr{SourceRegister: 1, Type: tcpOptMaxseg, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt},
	})
}
