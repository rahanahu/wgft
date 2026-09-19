// Package nft は、ルール集合から VPS の table inet wgft を組み立てて適用する(仕様 6.1 節)。
//
// nft が暗黙に足す条件(udp dport の前の meta l4proto、ip saddr の前の meta nfproto)を
// 自分で入れ、ポート範囲は nft と同じく gte / lte の 2 つの比較で表す。
// これで生成したテーブルの `nft list` が、同じ内容を `nft -f` で流したものと一致する(実験で確認)。
package nft

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/proto"
)

// TableName は vpsd 専用のテーブル名。他のテーブルには一切触れない。
const TableName = "wgft"

// Config は生成に必要な、ルール以外の情報。
type Config struct {
	WGInterface string                // wg0
	AgentAddr   map[string]netip.Addr // エージェント名 → wg0 上のアドレス
	// UDPPerSourceCap と TCPPerSourceCap は接続元 IP ごとの同時フロー数の上限(仕様 7, 11a 節の
	// 設定値。既に解決済みの具体的な値を受け取り、ここでは既定値を推測しない)。
	// 0 はそのプロトコルの上限を無効にし、対応する set も行も生成しない
	UDPPerSourceCap int
	TCPPerSourceCap int
	// Logf は AgentAddr にないエージェントのルールを飛ばしたときの記録先。nil なら黙って飛ばす
	Logf func(format string, args ...any)
}

// emitter は nftables.Conn のうち生成に使う部分。テストでは記録するだけの実装に差し替える。
type emitter interface {
	AddTable(*nftables.Table) *nftables.Table
	DelTable(*nftables.Table)
	AddSet(*nftables.Set, []nftables.SetElement) error
	AddChain(*nftables.Chain) *nftables.Chain
	AddRule(*nftables.Rule) *nftables.Rule
}

// Apply はテーブル全体を 1 トランザクションで差し替える。
// 「空テーブルの追加 → 削除 → 定義」の順にするので、テーブルがまだない初回でも失敗しない。
// conntrack のエントリは差し替えの影響を受けず、既存のセッションは切れない。
// 生成の途中で失敗すると未送信のメッセージが Conn に残るので、Conn は呼び出しごとに作って捨てる。
func Apply(rules []proto.Rule, cfg Config) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("cannot connect to nftables: %w", err)
	}
	if err := emit(conn, rules, cfg); err != nil {
		return err
	}
	return conn.Flush()
}

// DeleteTable は table inet wgft を削除する。他のテーブルには触れない。
// すでに無ければ何もしない(撤去を手作業の途中からでも走らせられるように)。
func DeleteTable() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("cannot connect to nftables: %w", err)
	}
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("listing tables: %w", err)
	}
	found := false
	for _, t := range tables {
		if t.Name == TableName {
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableName})
	return conn.Flush()
}

// Comment はルールの行に付けるコメント。差し替えのたびにハンドルは振り直されるので、
// カウンタの持ち主はこのコメントで特定する。
func Comment(ruleID, kind string) string { return "wgft:" + ruleID + ":" + kind }

func emit(e emitter, rules []proto.Rule, cfg Config) error {
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
	e.AddTable(t)
	e.DelTable(t)
	t = e.AddTable(t)

	policy := nftables.ChainPolicyAccept
	chain := func(name string, typ nftables.ChainType, hook *nftables.ChainHook, prio int32) *nftables.Chain {
		return e.AddChain(&nftables.Chain{Name: name, Table: t, Type: typ, Hooknum: hook,
			Priority: nftables.ChainPriorityRef(nftables.ChainPriority(prio)), Policy: &policy})
	}
	// 接続元制限とレート制限は nat ではなく filter の prerouting に置く。
	// nat のチェーンはフローの最初のパケットしか通らないので、通信中のフローに効かないため。
	filterPre := chain("filter_pre", nftables.ChainTypeFilter, nftables.ChainHookPrerouting, -150)
	// 既存の nat チェーン(標準の優先度 dstnat = -100)より先に評価されるよう dstnat - 1 にする
	natPre := chain("nat_pre", nftables.ChainTypeNAT, nftables.ChainHookPrerouting, -101)
	input := chain("input", nftables.ChainTypeFilter, nftables.ChainHookInput, -10)
	forward := chain("forward", nftables.ChainTypeFilter, nftables.ChainHookForward, -10)
	post := chain("postrouting", nftables.ChainTypeNAT, nftables.ChainHookPostrouting, 100)

	wg := cfg.WGInterface
	addRule := func(ch *nftables.Chain, comment string, parts ...[]expr.Any) {
		r := &nftables.Rule{Table: t, Chain: ch, Exprs: concat(parts...)}
		if comment != "" {
			r.UserData = userdata.AppendString(nil, userdata.TypeComment, comment)
		}
		e.AddRule(r)
	}

	// 接続元 IP ごとの同時フロー数の上限(仕様 6.1, 7 節)。プロトコルごとに 1 つの動的 set を
	// そのプロトコルの全ルールで共有し、初めてそのプロトコルのルールに出会ったときだけ作る。
	flowSets := map[proto.Proto]*nftables.Set{}

	// カーネルモードで有効なルールだけが行を持つ。set 名はルール ID ではなく連番。
	n := 0
	for i := range rules {
		r := &rules[i]
		if !r.Enabled || r.VPSMode != proto.ModeKernel {
			continue
		}
		// 無効化されたエージェントのルールは行を持たない(テーブル全体が組めなくなるよりよい)
		agent, ok := cfg.AgentAddr[r.Agent]
		if !ok {
			if cfg.Logf != nil {
				cfg.Logf("nftables: rule %s: agent %q is not registered, skipping", r.ID, r.Agent)
			}
			continue
		}
		n++
		from := match(wg, r.Proto, r.ListenPort)

		// 評価順は deny、allow、接続元ごとの meter、接続元ごとの同時フロー数の上限、
		// 新規フローの集約上限、パケットの集約上限。
		// 空の allow に != を書くと全送信元が落ちるので、allow が空なら set も行も作らない。
		if len(r.SourceDeny) > 0 {
			s, err := addIntervalSet(e, t, fmt.Sprintf("deny_%d", n), r.SourceDeny)
			if err != nil {
				return fmt.Errorf("rule %s: %w", r.ID, err)
			}
			addRule(filterPre, Comment(r.ID, "deny"), from, ipv4Saddr(), lookup(s, false), counterDrop())
		}
		if len(r.SourceAllow) > 0 {
			s, err := addIntervalSet(e, t, fmt.Sprintf("allow_%d", n), r.SourceAllow)
			if err != nil {
				return fmt.Errorf("rule %s: %w", r.ID, err)
			}
			addRule(filterPre, Comment(r.ID, "allow"), from, ipv4Saddr(), lookup(s, true), counterDrop())
		}
		if r.PerSourceRate != nil {
			meter := &nftables.Set{Table: t, Name: fmt.Sprintf("meter_%d", n), KeyType: nftables.TypeIPAddr,
				Dynamic: true, HasTimeout: true, Timeout: time.Minute, Size: 65535}
			if err := e.AddSet(meter, nil); err != nil {
				return fmt.Errorf("rule %s: meter: %w", r.ID, err)
			}
			addRule(filterPre, Comment(r.ID, "per_source"), from, ctState(expr.CtStateBitNEW), ipv4Saddr(),
				[]expr.Any{&expr.Dynset{SrcRegKey: 1, SetName: meter.Name, SetID: meter.ID,
					Operation: unix.NFT_DYNSET_OP_ADD, Exprs: []expr.Any{limitOver(*r.PerSourceRate)}}},
				counterDrop())
		}
		if cap := cfg.perSourceCap(r.Proto); cap > 0 {
			if flowSets[r.Proto] == nil {
				s, err := addFlowCapSet(e, t, r.Proto)
				if err != nil {
					return fmt.Errorf("rule %s: %w", r.ID, err)
				}
				flowSets[r.Proto] = s
			}
			fs := flowSets[r.Proto]
			addRule(filterPre, Comment(r.ID, "src_flow"), from, ctState(expr.CtStateBitNEW), ipv4Saddr(),
				[]expr.Any{&expr.Dynset{SrcRegKey: 1, SetName: fs.Name, SetID: fs.ID,
					Operation: unix.NFT_DYNSET_OP_ADD, Exprs: []expr.Any{connlimitOver(uint32(cap))}}},
				counterDrop())
		}
		if r.NewFlowRate != nil {
			addRule(filterPre, Comment(r.ID, "new_flow"), from, ctState(expr.CtStateBitNEW),
				[]expr.Any{limitOver(*r.NewFlowRate)}, counterDrop())
		}
		if r.PacketRate != nil {
			addRule(filterPre, Comment(r.ID, "packet"), from, []expr.Any{limitOver(*r.PacketRate)}, counterDrop())
		}

		// DNAT では宛先アドレスだけを書き換え、ポートは書き換えない。
		// target のポートへの写し替えはエージェント側で行う(仕様 7 節の実効宛先)。
		a4 := agent.As4()
		addRule(natPre, Comment(r.ID, "dnat"), from, []expr.Any{
			&expr.Immediate{Register: 1, Data: a4[:]},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1},
		})
	}

	const ipsDstNAT = 0x20 // IPS_DST_NAT:ct status dnat
	drop := []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
	accept := []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
	// vpsd は wg0 上で待ち受けないので、wg0 から VPS 自身への新規接続を全部落とす
	addRule(input, "", ifname(expr.MetaKeyIIFNAME, expr.CmpOpEq, wg), ctState(expr.CtStateBitNEW), drop)
	// ピア同士の通信を遮断し、DNAT されたフローとその返りだけを通す
	addRule(forward, "", ifname(expr.MetaKeyIIFNAME, expr.CmpOpEq, wg), ifname(expr.MetaKeyOIFNAME, expr.CmpOpEq, wg), drop)
	addRule(forward, "", ifname(expr.MetaKeyOIFNAME, expr.CmpOpEq, wg), ctBits(expr.CtKeySTATUS, ipsDstNAT), accept)
	addRule(forward, "", ifname(expr.MetaKeyIIFNAME, expr.CmpOpEq, wg), ctState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED), accept)
	// wg0 が絡む残りの転送は落とす。wg0 から VPS の他のインタフェース(private NIC、別の VPN)へ出る
	// 新規フローと、他インタフェースから wg0 へ入る DNAT 以外のフローが対象(仕様 6.1 節)
	addRule(forward, "", ifname(expr.MetaKeyIIFNAME, expr.CmpOpEq, wg), drop)
	addRule(forward, "", ifname(expr.MetaKeyOIFNAME, expr.CmpOpEq, wg), drop)
	// masquerade は DNAT された接続に限定し、VPS 自身の通信には触れない
	addRule(post, "", ifname(expr.MetaKeyOIFNAME, expr.CmpOpEq, wg), ctBits(expr.CtKeySTATUS, ipsDstNAT), []expr.Any{&expr.Masq{}})
	return nil
}

// match は `iifname != "wg0" <proto> dport <range>`。
func match(wg string, p proto.Proto, r proto.PortRange) []expr.Any {
	l4 := byte(unix.IPPROTO_UDP)
	if p == proto.TCP {
		l4 = unix.IPPROTO_TCP
	}
	out := concat(ifname(expr.MetaKeyIIFNAME, expr.CmpOpNeq, wg),
		[]expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{l4}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		})
	if r.Lo == r.Hi {
		return append(out, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(r.Lo)})
	}
	return append(out,
		&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.BigEndian.PutUint16(r.Lo)},
		&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: binaryutil.BigEndian.PutUint16(r.Hi)})
}

// ifname はインタフェース名を IFNAMSIZ(16 バイト)に詰めて比較する。
func ifname(key expr.MetaKey, op expr.CmpOp, name string) []expr.Any {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, name)
	return []expr.Any{&expr.Meta{Key: key, Register: 1}, &expr.Cmp{Op: op, Register: 1, Data: b}}
}

// ipv4Saddr は `ip saddr`。inet テーブルなので `meta nfproto ipv4` の比較を先に入れる。
func ipv4Saddr() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
	}
}

func lookup(s *nftables.Set, invert bool) []expr.Any {
	return []expr.Any{&expr.Lookup{SourceRegister: 1, SetName: s.Name, SetID: s.ID, Invert: invert}}
}

func ctState(mask uint32) []expr.Any { return ctBits(expr.CtKeySTATE, mask) }

// ctBits は `ct state new` や `ct status dnat` のような、ビットのどれかが立っているかの判定。
func ctBits(key expr.CtKey, mask uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: key},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(mask), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
	}
}

func counterDrop() []expr.Any {
	return []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}
}

// limitOver は `limit rate over N/unit`。burst は nft の既定値の 5。
func limitOver(r proto.Rate) *expr.Limit {
	units := map[proto.RateUnit]expr.LimitTime{
		proto.PerSecond: expr.LimitTimeSecond, proto.PerMinute: expr.LimitTimeMinute,
		proto.PerHour: expr.LimitTimeHour, proto.PerDay: expr.LimitTimeDay, proto.PerWeek: expr.LimitTimeWeek,
	}
	return &expr.Limit{Type: expr.LimitTypePkts, Rate: r.Count, Over: true, Unit: units[r.Unit], Burst: 5}
}

// flowSetName はプロトコルごとに共有する接続元フロー数の set の名前。ルール ID に依存しない
// 固定名でよい(deny_N や meter_N と違い、プロトコルごとに 1 つしか作らないため)。
func flowSetName(p proto.Proto) string {
	if p == proto.TCP {
		return "flows_tcp"
	}
	return "flows_udp"
}

// perSourceCap は cfg に渡された、接続元 IP ごとの同時フロー数の上限(仕様 7, 11a 節の設定値)。
// 0 はそのプロトコルの上限を無効にする。値の既定はここでは決めない(呼び出し側が解決済みの値を渡す)。
func (cfg Config) perSourceCap(p proto.Proto) int {
	if p == proto.TCP {
		return cfg.TCPPerSourceCap
	}
	return cfg.UDPPerSourceCap
}

// addFlowCapSet は接続元 IP ごとの同時フロー数を数える動的 set を作る。
// ct count は conntrack のエントリの生死で状態が消えるので、meter の set と違い timeout を持たせない
// (timeout を持つ set に ct count を組み合わせると nftables が操作を拒む)。
func addFlowCapSet(e emitter, t *nftables.Table, p proto.Proto) (*nftables.Set, error) {
	s := &nftables.Set{Table: t, Name: flowSetName(p), KeyType: nftables.TypeIPAddr, Dynamic: true, Size: 65535}
	if err := e.AddSet(s, nil); err != nil {
		return nil, fmt.Errorf("flow cap set %s: %w", s.Name, err)
	}
	return s, nil
}

// connlimitOver は `ct count over N`。Flags の NFT_CONNLIMIT_F_INV が「over」に当たる。
func connlimitOver(n uint32) *expr.Connlimit {
	return &expr.Connlimit{Count: n, Flags: expr.NFT_CONNLIMIT_F_INV}
}

func addIntervalSet(e emitter, t *nftables.Table, name string, prefixes []netip.Prefix) (*nftables.Set, error) {
	s := &nftables.Set{Table: t, Name: name, KeyType: nftables.TypeIPAddr, Interval: true}
	if err := e.AddSet(s, intervalElements(prefixes)); err != nil {
		return nil, fmt.Errorf("set %s: %w", name, err)
	}
	return s, nil
}

// intervalElements は CIDR の集合を `flags interval` の set の要素にする。
// nft と同じ形にする:重なりと隣接を併合して昇順に並べ、各区間を「開始」と「終端の次(IntervalEnd)」の組で表す。
// 先頭の区間が 0.0.0.0 から始まらなければ、0.0.0.0 に終端の印を置く。
func intervalElements(prefixes []netip.Prefix) []nftables.SetElement {
	type span struct{ lo, hi uint64 } // hi は排他的
	spans := make([]span, 0, len(prefixes))
	for _, p := range prefixes {
		p = p.Masked()
		lo := uint64(binary.BigEndian.Uint32(p.Addr().AsSlice()))
		spans = append(spans, span{lo, lo + 1<<(32-p.Bits())})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })
	merged := spans[:0]
	for _, s := range spans {
		if n := len(merged); n > 0 && s.lo <= merged[n-1].hi {
			merged[n-1].hi = max(merged[n-1].hi, s.hi)
			continue
		}
		merged = append(merged, s)
	}
	key := func(v uint64) []byte { return binary.BigEndian.AppendUint32(nil, uint32(v)) }
	var out []nftables.SetElement
	if len(merged) > 0 && merged[0].lo != 0 {
		out = append(out, nftables.SetElement{Key: key(0), IntervalEnd: true})
	}
	for _, s := range merged {
		out = append(out, nftables.SetElement{Key: key(s.lo)})
		if s.hi < 1<<32 { // アドレス空間の末尾まで続く区間には終端を置かない
			out = append(out, nftables.SetElement{Key: key(s.hi), IntervalEnd: true})
		}
	}
	return out
}

func concat(parts ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
