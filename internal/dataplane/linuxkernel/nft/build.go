//go:build linux

// Package nft は、Plan から VPS の table inet wgft を組み立てて適用する(仕様 6.1 節、設計文書 7a.2 節)。
// internal/dataplane/linuxkernel の nftables 実装で、internal/vpsd を import しない(設計文書 7a.7 節)。
//
// Apply/emit は internal/planner.Plan と、frontend が実際に待ち受けている Relay ポートの集合
// (design.md 7a.2 節の dataplane.Desired.RelayListening に当たる Runtime 側の入力)だけから組み立てる。
// Plan は無効なルールとエージェントが未登録のルールを既に除いているので、ここでは検査し直さない
// (設計文書 7a.8 節 Phase 3:「ルール集合から nftables を組み立てる」から「Plan から組み立てる」への移行)。
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

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	polnft "github.com/rahanahu/wgft/internal/policy/nftables"
	"github.com/rahanahu/wgft/proto"
)

// TableName は vpsd 専用のテーブル名。他のテーブルには一切触れない。
const TableName = "wgft"

// Config は生成に必要な、Plan 以外の情報。
type Config struct {
	WGInterface string // wg0
}

// emitter は nftables.Conn のうち生成に使う部分。テストでは記録するだけの実装に差し替える。
type emitter interface {
	AddTable(*nftables.Table) *nftables.Table
	DelTable(*nftables.Table)
	AddSet(*nftables.Set, []nftables.SetElement) error
	SetAddElements(*nftables.Set, []nftables.SetElement) error
	AddChain(*nftables.Chain) *nftables.Chain
	AddRule(*nftables.Rule) *nftables.Rule
}

// Apply はテーブル全体を 1 トランザクションで差し替える。
// 「空テーブルの追加 → 削除 → 定義」の順にするので、テーブルがまだない初回でも失敗しない。
// conntrack のエントリは差し替えの影響を受けず、既存のセッションは切れない。
// 生成の途中で失敗すると未送信のメッセージが Conn に残るので、Conn は呼び出しごとに作って捨てる。
//
// relayListening は、vpsd がプロキシモードの待ち受けを実際に開いているポート(design.md 7a.2 節の
// dataplane.Desired.RelayListening)。Relay のルールは、ここにあるポートだけに Admission Policy の
// 行を持つ。bind に失敗したポートでは、同じポートの別のプロセスへの通信に wgft の判定を掛けて
// しまうため(仕様 6.1 節)。nil なら行を持たない。
//
// Apply は Stage と Flush を続けて行う。kernel backend は 2 つを Prepare と Commit に分けて呼ぶ
// (design.md 7a.2 節)。
func Apply(plan planner.Plan, relayListening map[uint16]bool, cfg Config) error {
	s, err := Stage(plan, relayListening, cfg)
	if err != nil {
		return err
	}
	return s.Flush()
}

// Staged は、組み立て終えてまだ送っていないテーブルの差し替え(1 トランザクション分のメッセージ)。
type Staged struct {
	conn *nftables.Conn
	// size は組み立てたバッチの大きさ。Flush がソケットを開くときに、その大きさに合わせた
	// バッファを要求するために使う(batch.go)。
	size batchSize
	// sent は、wgft が要素を書く set(deny_N、allow_N)ごとの送った要素。Flush が差し替えの後に
	// 読み直して比べる(verify.go)。
	sent map[string][]nftables.SetElement
	// readSet は set の要素を読む。nil ならカーネルから読む。単体テストだけが差し替える。
	readSet func(name string) ([]nftables.SetElement, error)
}

// Stage はテーブルの差し替えを組み立てるが、送らない(kernel backend の Prepare。design.md 7a.2 節)。
// 組み立ての誤りはここで返り、何も公開されない。捨てるときは何もしなくてよい(Conn は送るまで
// カーネルに何も書かない)。
func Stage(plan planner.Plan, relayListening map[uint16]bool, cfg Config) (*Staged, error) {
	s := &Staged{}
	// ソケットを開くのは Flush の中なので、ここで渡す設定は組み立ての後に実行される。
	// 大きさの根拠は batch.go にある。
	conn, err := nftables.New(nftables.WithSockOptions(s.sizeSocket))
	if err != nil {
		return nil, fmt.Errorf("cannot connect to nftables: %w", err)
	}
	if err := s.build(conn, plan, relayListening, cfg); err != nil {
		return nil, err
	}
	return s, nil
}

// build は conn の上にテーブルの差し替えを組み立て、バッチの大きさと送る set の要素を s に残す。
func (s *Staged) build(conn *nftables.Conn, plan planner.Plan, relayListening map[uint16]bool, cfg Config) error {
	s.sent = map[string][]nftables.SetElement{}
	if err := emit(&sizing{to: &sentSets{to: conn, elems: s.sent}, size: &s.size}, plan, relayListening, cfg); err != nil {
		return err
	}
	s.conn = conn
	return nil
}

// Flush は組み立てた差し替えを 1 トランザクションで送り、wgft が要素を書く set をカーネルから
// 読み直して、送った要素がそのまま入っているかを確かめる(kernel backend の Commit)。
// カーネル側の差し替え自体は不可分である。ただし、誤りが返ったときに旧いテーブルが残っているとは
// 限らない。カーネルは commit の後に応答を返すので、応答の受信に失敗した場合(ENOBUFS)は、
// テーブルが差し替わった後で誤りが返る。読み直した set が送った要素と一致しない場合も、差し替わった
// 後で誤りが返る。送信が拒まれた場合(EMSGSIZE)とカーネルがバッチを拒んだ場合は、旧いテーブルが
// 残る。実際の状態との食い違いは、reconciler の Observe による drift の検出で収束させる(設計文書
// 6.1 節、7a.3 節)。
func (s *Staged) Flush() error {
	if err := s.conn.Flush(); err != nil {
		return err
	}
	return s.verify()
}

// DeleteTable は table inet wgft を削除する。他のテーブルには触れない。
// すでに無ければ何もしない(撤去を手作業の途中からでも走らせられるように)。
func DeleteTable() error {
	_, err := deleteTableNamed(TableName)
	return err
}

// DeleteAgentTable は table inet wgft_agent を削除し、削除したかどうかを返す(設計文書 10.3 節の
// agent teardown)。他のテーブルには触れない。すでに無ければ何もせず false を返す。
func DeleteAgentTable() (bool, error) { return deleteTableNamed(AgentTableName) }

// AgentTablePresent は table inet wgft_agent があるかどうかを返す。何も変えない。
func AgentTablePresent() (bool, error) {
	conn, err := nftables.New()
	if err != nil {
		return false, fmt.Errorf("cannot connect to nftables: %w", err)
	}
	return tablePresent(conn, AgentTableName)
}

func tablePresent(conn *nftables.Conn, name string) (bool, error) {
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, fmt.Errorf("listing tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == name {
			return true, nil
		}
	}
	return false, nil
}

func deleteTableNamed(name string) (bool, error) {
	conn, err := nftables.New()
	if err != nil {
		return false, fmt.Errorf("cannot connect to nftables: %w", err)
	}
	found, err := tablePresent(conn, name)
	if err != nil || !found {
		return false, err
	}
	conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: name})
	if err := conn.Flush(); err != nil {
		return false, err
	}
	return true, nil
}

// Comment はルールの行に付けるコメント。差し替えのたびにハンドルは振り直されるので、
// カウンタの持ち主はこのコメントで特定する。
// 形式は internal/policy/nftables.Comment が決める。
func Comment(ruleID, kind string) string { return polnft.Comment(ruleID, kind) }

func emit(e emitter, plan planner.Plan, relayListening map[uint16]bool, cfg Config) error {
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
	e.AddTable(t)
	e.DelTable(t)
	t = e.AddTable(t)

	chainPolicy := nftables.ChainPolicyAccept
	chain := func(name string, typ nftables.ChainType, hook *nftables.ChainHook, prio int32) *nftables.Chain {
		return e.AddChain(&nftables.Chain{Name: name, Table: t, Type: typ, Hooknum: hook,
			Priority: nftables.ChainPriorityRef(nftables.ChainPriority(prio)), Policy: &chainPolicy})
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

	// 送信元制限とレートの行は、IR(Plan.Admission)を internal/policy/nftables がコンパイルした
	// 行の列から写す(設計文書 7a.9 節)。判定を付けるポートは、Transparent のポートと、vpsd が
	// 待ち受けを開けている Relay のポートで、どちらも同じ段の行を持つ。bind に失敗した Relay の
	// ポートに行を置くと、同じポートで待ち受ける別のプロセスへの通信に wgft の判定を掛けて
	// しまうため(仕様 6.1 節)。
	//
	// Plan.Ports は無効なルールとエージェントが未登録のルールを既に除き、
	// (Proto, ListenPort.Lo, RuleID) の順に並んでいる(internal/planner.Build)。この順が
	// table の行の順になる(設計文書 7a.8 節 Phase 3)。
	var judged []polnft.Port
	for _, pp := range plan.Ports {
		if pp.Forwarding == model.Relay && !relayListening[pp.ListenPort.Lo] {
			continue
		}
		judged = append(judged, polnft.Port{RuleID: pp.RuleID, Proto: pp.Proto, Ports: pp.ListenPort, Forwarding: pp.Forwarding})
	}
	prog, err := polnft.Compile(plan.Admission, judged)
	if err != nil {
		return err
	}

	// set は、行が初めて参照した時点で宣言する。こうすると set と行を送る順が、ポートごとに
	// set と行を並べて送っていた以前の生成と同じになる。
	sets := map[string]*nftables.Set{}
	setFor := func(ruleID, name string) (*nftables.Set, error) {
		if s := sets[name]; s != nil {
			return s, nil
		}
		decl, ok := prog.Set(name)
		if !ok {
			return nil, fmt.Errorf("rule %s: row refers to undeclared set %s", ruleID, name)
		}
		s, err := addSet(e, t, decl)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", ruleID, err)
		}
		sets[name] = s
		return s, nil
	}

	next := 0 // prog.Rows のうち、まだ写していない最初の行
	for _, pp := range plan.Ports {
		for ; next < len(prog.Rows) && prog.Rows[next].RuleID == pp.RuleID; next++ {
			row := prog.Rows[next]
			from := match(wg, row.Match.Proto, row.Match.Ports)
			var s *nftables.Set
			if row.Stmt.Set != "" {
				if s, err = setFor(row.RuleID, row.Stmt.Set); err != nil {
					return err
				}
			}
			stmt, err := rowStmt(row.Stmt, s)
			if err != nil {
				return fmt.Errorf("rule %s: %w", row.RuleID, err)
			}
			var ct []expr.Any
			if row.Match.CtStateNew {
				ct = ctState(expr.CtStateBitNEW)
			}
			// Admission Policy の行は IPv4 のパケットにだけ一致する(設計文書 7a.9 節)。送信元を読む行は
			// `ip saddr` の前に、読まない集約のレートの行は文の前に `meta nfproto ipv4` を置く
			var v4 []expr.Any
			if row.Match.IPv4 || row.Stmt.UsesSource() {
				v4 = nfprotoIPv4()
			}
			if row.Stmt.UsesSource() {
				v4 = append(v4, ipv4Saddr()...)
			}
			addRule(filterPre, row.Comment, from, ct, v4, stmt, counterDrop())
		}
		if pp.Forwarding == model.Relay {
			// Relay のルールは vpsd が受けて中継する(6.2 節)ので DNAT を持たない
			continue
		}

		// DNAT では宛先アドレスだけを書き換え、ポートは書き換えない。
		// target のポートへの写し替えはエージェント側で行う(仕様 7 節の実効宛先)。
		a4 := pp.AgentAddr.As4()
		addRule(natPre, Comment(pp.RuleID, "dnat"), match(wg, pp.Proto, pp.ListenPort), []expr.Any{
			&expr.Immediate{Register: 1, Data: a4[:]},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1},
		})
	}
	if next != len(prog.Rows) {
		// 行はポートの順に並ぶので、ここに来るのは Plan.Ports に無いルールの行だけである
		return fmt.Errorf("rule %s: admission row does not follow the port order", prog.Rows[next].RuleID)
	}

	const ipsDstNAT = 0x20 // IPS_DST_NAT:ct status dnat
	drop := []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
	accept := []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
	// vpsd は wg0 上で待ち受けないので、wg0 から VPS 自身への新規接続を全部落とす
	addRule(input, "", ifname(expr.MetaKeyIIFNAME, expr.CmpOpEq, wg), ctState(expr.CtStateBitNEW), drop)
	// ピア同士の通信を遮断し、DNAT されたフローとその返りだけを通す
	addRule(forward, "", ifname(expr.MetaKeyIIFNAME, expr.CmpOpEq, wg), ifname(expr.MetaKeyOIFNAME, expr.CmpOpEq, wg), drop)
	addRule(forward, "", ifname(expr.MetaKeyOIFNAME, expr.CmpOpEq, wg), ctBits(expr.CtKeySTATUS, ipsDstNAT), accept)
	// UDP の応答の観測(設計文書 6.1、10.2a 節)。wg0 から戻る DNAT 済みの UDP の応答だけを udp_reply へ
	// 送り、ルールごとの行のカウンタで数える。行の判定は return だけで、転送の結果は変えない。ICMP の誤りは
	// 同じ conntrack のエントリの応答の向きに一致するが、meta l4proto udp で外す。
	// ルールの見分けは応答の送信元ポートで行う。DNAT はポートを書き換えず、応答の向きのパケットは
	// forward の時点でまだ送信元の逆変換(postrouting)を受けていないので、送信元ポートは公開ポートの
	// ままである。`ct original proto-dst` は同じ値を読めるが、google/nftables がその行を読み戻せない
	// (向きの属性の長さの解釈が違い、GetRules が誤りを返す。ラボで確かめた)ので使わない
	if replies := udpReplyPorts(plan); len(replies) > 0 {
		udpReply := e.AddChain(&nftables.Chain{Name: UDPReplyChain, Table: t})
		for _, pp := range replies {
			addRule(udpReply, Comment(pp.RuleID, ReplyKind), l4proto(proto.UDP), sport(pp.ListenPort),
				[]expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictReturn}})
		}
		addRule(forward, "", ifname(expr.MetaKeyIIFNAME, expr.CmpOpEq, wg), l4proto(proto.UDP),
			[]expr.Any{
				&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{ipCtDirReply}},
			},
			ctBits(expr.CtKeySTATUS, ipsDstNAT),
			[]expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: UDPReplyChain}})
	}
	addRule(forward, "", ifname(expr.MetaKeyIIFNAME, expr.CmpOpEq, wg), ctState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED), accept)
	// wg0 が絡む残りの転送は落とす。wg0 から VPS の他のインタフェース(private NIC、別の VPN)へ出る
	// 新規フローと、他インタフェースから wg0 へ入る DNAT 以外のフローが対象(仕様 6.1 節)
	addRule(forward, "", ifname(expr.MetaKeyIIFNAME, expr.CmpOpEq, wg), drop)
	addRule(forward, "", ifname(expr.MetaKeyOIFNAME, expr.CmpOpEq, wg), drop)
	// masquerade は DNAT された接続に限定し、VPS 自身の通信には触れない
	addRule(post, "", ifname(expr.MetaKeyOIFNAME, expr.CmpOpEq, wg), ctBits(expr.CtKeySTATUS, ipsDstNAT), []expr.Any{&expr.Masq{}})
	return nil
}

// UDPReplyChain は UDP の応答を数える通常のチェーンの名前である。行はルールごとに 1 つで、
// コメント wgft:<ルール ID>:reply で持ち主を特定する(ReadReplies)。
const UDPReplyChain = "udp_reply"

// ReplyKind は UDP の応答のカウンタの行のコメントの種類である。drop の種類(ReadDrops)とは
// 別のチェーンに置くので、drop として累積されない。
const ReplyKind = "reply"

// ipCtDirReply は `ct direction reply` の値(IP_CT_DIR_REPLY)。
const ipCtDirReply = 1

// udpReplyPorts は応答を数える UDP のルールである。kernel モードの UDP のルールは常に
// Transparent である(プロキシモードは TCP だけ。5.3 節)。
func udpReplyPorts(plan planner.Plan) []planner.PortPlan {
	var out []planner.PortPlan
	for _, pp := range plan.Ports {
		if pp.Proto == proto.UDP && pp.Forwarding == model.Transparent {
			out = append(out, pp)
		}
	}
	return out
}

// l4proto は `meta l4proto <proto>`。
func l4proto(p proto.Proto) []expr.Any {
	l4 := byte(unix.IPPROTO_UDP)
	if p == proto.TCP {
		l4 = unix.IPPROTO_TCP
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{l4}},
	}
}

// sport は `udp sport <range>` のうち送信元ポートの比較の部分。呼び出し側が先に l4proto を置く。
func sport(r proto.PortRange) []expr.Any {
	out := []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2}}
	if r.Lo == r.Hi {
		return append(out, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(r.Lo)})
	}
	return append(out,
		&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.BigEndian.PutUint16(r.Lo)},
		&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: binaryutil.BigEndian.PutUint16(r.Hi)})
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

// nfprotoIPv4 は `meta nfproto ipv4`。inet テーブルでは `ip saddr` の前にも要る。
func nfprotoIPv4() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
	}
}

// ipv4Saddr は `ip saddr` の読み出し。呼び出し側が先に nfprotoIPv4 を置く。
func ipv4Saddr() []expr.Any {
	return []expr.Any{
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

// limitOver は `limit rate over N/unit burst B packets`。burst は行の列が持つ値
// (policy.TokenBucketBurst。nft の既定値の 5。design.md 7a.9 節「IR の形」の評価の定数)。
func limitOver(r proto.Rate, burst uint32) (*expr.Limit, error) {
	units := map[proto.RateUnit]expr.LimitTime{
		proto.PerSecond: expr.LimitTimeSecond, proto.PerMinute: expr.LimitTimeMinute,
		proto.PerHour: expr.LimitTimeHour, proto.PerDay: expr.LimitTimeDay, proto.PerWeek: expr.LimitTimeWeek,
	}
	u, ok := units[r.Unit]
	if !ok {
		return nil, fmt.Errorf("rate %s has an unknown unit", r)
	}
	return &expr.Limit{Type: expr.LimitTypePkts, Rate: r.Count, Over: true, Unit: u, Burst: burst}, nil
}

// connlimitOver は `ct count over N`。Flags の NFT_CONNLIMIT_F_INV が「over」に当たる。
func connlimitOver(n uint32) *expr.Connlimit {
	return &expr.Connlimit{Count: n, Flags: expr.NFT_CONNLIMIT_F_INV}
}

// rowStmt は行の文を nftables の式へ写す。s は文が参照する set(参照しない文では nil)。
func rowStmt(st polnft.Stmt, s *nftables.Set) ([]expr.Any, error) {
	switch st.Kind {
	case polnft.StmtSourceInSet:
		return lookup(s, false), nil
	case polnft.StmtSourceNotInSet:
		return lookup(s, true), nil
	case polnft.StmtPerSourceLimit:
		l, err := limitOver(st.Rate, st.Burst)
		if err != nil {
			return nil, err
		}
		return dynsetAdd(s, l), nil
	case polnft.StmtPerSourceCtCount:
		return dynsetAdd(s, connlimitOver(st.Count)), nil
	case polnft.StmtLimit:
		l, err := limitOver(st.Rate, st.Burst)
		if err != nil {
			return nil, err
		}
		return []expr.Any{l}, nil
	default:
		return nil, fmt.Errorf("unknown admission statement %d", st.Kind)
	}
}

// dynsetAdd は `add @set { ip saddr <e> }`。キーはレジスタ 1 に読んだ ip saddr である。
func dynsetAdd(s *nftables.Set, e expr.Any) []expr.Any {
	return []expr.Any{&expr.Dynset{SrcRegKey: 1, SetName: s.Name, SetID: s.ID,
		Operation: unix.NFT_DYNSET_OP_ADD, Exprs: []expr.Any{e}}}
}

// addSet は行の列の set の宣言を nftables の set にする。キーはどれも IPv4 の送信元アドレスである。
// 同時フロー数の set(SetFlowCount)は、ct count は conntrack のエントリの生死で状態が消えるので、
// meter の set と違い timeout を持たせない(timeout を持つ set に ct count を組み合わせると
// nftables が操作を拒む)。
func addSet(e emitter, t *nftables.Table, d polnft.Set) (*nftables.Set, error) {
	switch d.Kind {
	case polnft.SetInterval:
		// 宣言を先に送り、要素は 1 通に入る数ずつ分けて足す(batch.go の elemsPerMessage)。
		// 名前付きの set なので SetAddElements で足せる(google/nftables が拒むのは無名の set だけ)。
		// set の大きさ(NFTA_SET_DESC_SIZE)は付けない。付けなければカーネルは要素の数を制限しない
		s := &nftables.Set{Table: t, Name: d.Name, KeyType: nftables.TypeIPAddr, Interval: true}
		if err := e.AddSet(s, nil); err != nil {
			return nil, fmt.Errorf("set %s: %w", d.Name, err)
		}
		for _, els := range elementChunks(intervalElements(d.Elements), elemsPerMessage) {
			if err := e.SetAddElements(s, els); err != nil {
				return nil, fmt.Errorf("set %s: %w", d.Name, err)
			}
		}
		return s, nil
	case polnft.SetMeter:
		s := &nftables.Set{Table: t, Name: d.Name, KeyType: nftables.TypeIPAddr,
			Dynamic: true, HasTimeout: true, Timeout: d.Timeout, Size: uint32(d.Size)}
		if err := e.AddSet(s, nil); err != nil {
			return nil, fmt.Errorf("meter: %w", err)
		}
		return s, nil
	case polnft.SetFlowCount:
		s := &nftables.Set{Table: t, Name: d.Name, KeyType: nftables.TypeIPAddr, Dynamic: true, Size: uint32(d.Size)}
		if err := e.AddSet(s, nil); err != nil {
			return nil, fmt.Errorf("flow cap set %s: %w", d.Name, err)
		}
		return s, nil
	default:
		return nil, fmt.Errorf("set %s: unknown kind %d", d.Name, d.Kind)
	}
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
