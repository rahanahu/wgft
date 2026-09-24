//go:build linux

package nft

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/proto"
)

// AgentInspection は、InspectAgent が読み戻した table inet wgft_agent と、記録した公開との比較である。
type AgentInspection struct {
	// DNATs は nat_pre の wgft の行から読んだ、ルールと連続するポートごとの宛先である。
	// (Proto, Ports.Lo, RuleID) の順。
	DNATs []AgentDNAT
	// Unrecognized は、nat_pre のうち wgft が書く DNAT の形として読めなかった行の数である。外から足された
	// 行か、書き換えられた行である。
	Unrecognized int
	// MissingDNATs は、記録にあって表に無い DNAT である。宛先が違うポートもここに入る。
	MissingDNATs []AgentDNAT
	// ExtraDNATs は、表にあって記録に無い DNAT である。宛先が違うポートもここに入る。
	ExtraDNATs []AgentDNAT
	// Missing は、行とチェーンのうち、記録から組んだ表にあって実際の表に無いものである。nat_pre の DNAT の
	// 行は、map の要素を除いた行の形で比べる。
	// filter_pre、MASQUERADE、forward の通す行のどれかが欠ければ、LAN への転送は止まる。
	Missing []string
	// Unexpected は、実際の表にあって、記録から組んだ表に無い行とチェーンである。
	Unexpected []string
}

// Matches は、表が記録どおりであるかどうかである。
func (i AgentInspection) Matches() bool {
	return i.Unrecognized == 0 && len(i.MissingDNATs) == 0 && len(i.ExtraDNATs) == 0 &&
		len(i.Missing) == 0 && len(i.Unexpected) == 0
}

// InspectAgent は table inet wgft_agent を読み戻し、記録した公開 want から組む表と比べる(7b.4 節。停止中の
// agent doctor が使う)。nat_pre の DNAT はルールとポートごとの宛先と行の形で比べ、残りのチェーンは行の形で比べる。
// wg は WireGuard インタフェースの名前である。テーブルを変えない。present はテーブルがあるかどうかである。
//
// 行の形の比較は、google/nftables が読み戻せない rt と byteorder の式を見ない(Fingerprint の注)。
func InspectAgent(want AgentPublication, wg string) (ins AgentInspection, present bool, err error) {
	c, err := nftables.New()
	if err != nil {
		return AgentInspection{}, false, fmt.Errorf("cannot connect to nftables: %w", err)
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return AgentInspection{}, false, fmt.Errorf("listing tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == AgentTableName {
			present = true
		}
	}
	if !present {
		return AgentInspection{}, false, nil
	}
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: AgentTableName}
	all, err := c.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return AgentInspection{}, true, fmt.Errorf("listing chains: %w", err)
	}
	var chains []chainDump
	for _, ch := range all {
		if ch.Table == nil || ch.Table.Name != AgentTableName {
			continue
		}
		rules, err := c.GetRules(t, &nftables.Chain{Name: ch.Name, Table: t})
		if err != nil {
			return AgentInspection{}, true, fmt.Errorf("listing rules of chain %s: %w", ch.Name, err)
		}
		chains = append(chains, chainDump{chain: ch, rules: rules})
	}
	elems := func(name string) ([]nftables.SetElement, error) {
		return c.GetSetElements(&nftables.Set{Table: t, Name: name})
	}
	ins, err = inspectAgentOf(chains, elems, want, wg)
	return ins, true, err
}

// inspectAgentOf は読み戻したチェーンを記録と比べる。単体テストのために分けてある。
func inspectAgentOf(chains []chainDump, elems func(set string) ([]nftables.SetElement, error), want AgentPublication, wg string) (AgentInspection, error) {
	var ins AgentInspection
	got := map[string]chainDump{}
	for _, cd := range chains {
		got[cd.chain.Name] = cd
	}
	expected, err := expectedAgentRows(want, wg)
	if err != nil {
		return AgentInspection{}, err
	}
	known := map[string]bool{}
	for _, spec := range agentChains {
		known[spec.name] = true
		cd, ok := got[spec.name]
		if !ok {
			ins.Missing = append(ins.Missing, fmt.Sprintf("chain %s is missing", spec.name))
		} else if !chainMatches(cd.chain, spec) {
			ins.Missing = append(ins.Missing, fmt.Sprintf("chain %s is not a %s chain on its hook at priority %d with policy accept", spec.name, spec.typ, spec.prio))
		}
		if spec.name == "nat_pre" {
			tbl, err := agentTableOf(cd.rules, elems)
			if err != nil {
				return AgentInspection{}, err
			}
			ins.DNATs, ins.Unrecognized = tbl.DNATs, tbl.Unrecognized
		}
		missing, unexpected := compareRows(spec.name, expected[spec.name], cd.rules)
		ins.Missing = append(ins.Missing, missing...)
		ins.Unexpected = append(ins.Unexpected, unexpected...)
	}
	for _, cd := range chains {
		if !known[cd.chain.Name] {
			ins.Unexpected = append(ins.Unexpected, fmt.Sprintf("chain %s is not one wgft writes", cd.chain.Name))
		}
	}
	ins.MissingDNATs, ins.ExtraDNATs = diffDNATs(want.DNATs(), ins.DNATs)
	return ins, nil
}

func chainMatches(ch *nftables.Chain, spec agentChain) bool {
	return ch.Type == spec.typ && ch.Hooknum != nil && *ch.Hooknum == *spec.hook &&
		ch.Priority != nil && int32(*ch.Priority) == spec.prio &&
		ch.Policy != nil && *ch.Policy == nftables.ChainPolicyAccept
}

// expectedAgentRows は、記録 want から組む表の行をチェーンごとに返す。nat_pre の DNAT の行も含む。
// map の要素は含まない。要素は DNAT の宛先として別に比べる。
func expectedAgentRows(want AgentPublication, wg string) (map[string][]agentRow, error) {
	c := &rowCollector{rows: map[string][]agentRow{}}
	if err := emitAgent(c, want, wg); err != nil {
		return nil, err
	}
	for _, row := range agentRows(want, wg) {
		for i, r := range c.rows[row.chain] {
			if r.desc == "" && r.comment == row.comment && rowSig(r.comment, r.exprs) == rowSig(row.comment, row.exprs) {
				c.rows[row.chain][i].desc = row.desc
				break
			}
		}
	}
	return c.rows, nil
}

// rowCollector は emitAgent が組む行を集める。netlink には何も送らない。
type rowCollector struct {
	rows map[string][]agentRow
}

func (c *rowCollector) AddTable(t *nftables.Table) *nftables.Table { return t }
func (c *rowCollector) DelTable(*nftables.Table)                   {}
func (c *rowCollector) AddSet(*nftables.Set, []nftables.SetElement) error {
	return nil
}
func (c *rowCollector) SetAddElements(*nftables.Set, []nftables.SetElement) error { return nil }
func (c *rowCollector) AddChain(ch *nftables.Chain) *nftables.Chain               { return ch }
func (c *rowCollector) AddRule(r *nftables.Rule) *nftables.Rule {
	comment, _ := userdata.GetString(r.UserData, userdata.TypeComment)
	row := agentRow{chain: r.Chain.Name, comment: comment, exprs: r.Exprs}
	if r.Chain.Name == "nat_pre" {
		id, _ := parseComment(comment)
		row.desc = "nat_pre: DNAT row of rule " + id
	}
	c.rows[r.Chain.Name] = append(c.rows[r.Chain.Name], row)
	return r
}

// compareRows は、期待する行の列が実際の行の中に同じ順で並んでいるかを見る。見つからない行は missing、
// 期待する行のどれにも当たらない実際の行は unexpected になる。
func compareRows(chain string, want []agentRow, got []*nftables.Rule) (missing, unexpected []string) {
	used := make([]bool, len(got))
	next := 0
	for _, w := range want {
		sig := rowSig(w.comment, w.exprs)
		found := false
		for i := next; i < len(got); i++ {
			comment, _ := userdata.GetString(got[i].UserData, userdata.TypeComment)
			if rowSig(comment, got[i].Exprs) == sig {
				used[i], next, found = true, i+1, true
				break
			}
		}
		if !found {
			missing = append(missing, w.desc)
		}
	}
	for i, u := range used {
		if !u {
			unexpected = append(unexpected, fmt.Sprintf("chain %s: row %d is not one wgft writes", chain, i+1))
		}
	}
	return missing, unexpected
}

// rowSig は行の形を比べるための文字列である。コメントと、式の型と netlink の符号化を並べる。
// google/nftables が読み戻せない rt と byteorder の式は、組んだ側でも数えない。map の名前はカーネルが
// 付けるので見ない。NAT の式は、カーネルが読み戻しで埋める上限のレジスタと PROTO_SPECIFIED をそろえる。
func rowSig(comment string, exprs []expr.Any) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%q|", comment)
	for _, e := range exprs {
		switch x := e.(type) {
		case *expr.Rt, *expr.Byteorder:
			continue
		case *expr.Lookup:
			l := *x
			l.SetName, l.SetID = "", 0
			e = &l
		case *expr.NAT:
			n := *x
			if n.RegAddrMax == 0 {
				n.RegAddrMax = n.RegAddrMin
			}
			if n.RegProtoMax == 0 {
				n.RegProtoMax = n.RegProtoMin
			}
			n.Specified = n.Specified || n.RegProtoMin != 0
			e = &n
		}
		fmt.Fprintf(&b, "%T ", e)
		if m, err := expr.Marshal(byte(unix.NFPROTO_INET), e); err == nil {
			fmt.Fprintf(&b, "%x", m)
		}
		b.WriteByte(';')
	}
	return b.String()
}

// agentTable は nat_pre から読んだ DNAT である。
type agentTable struct {
	DNATs        []AgentDNAT
	Unrecognized int
}

// agentTableOf は nat_pre の行を読む。elems は map の要素を読む。
func agentTableOf(rules []*nftables.Rule, elems func(set string) ([]nftables.SetElement, error)) (agentTable, error) {
	var out agentTable
	var ports []AgentDNAT
	for _, r := range rules {
		d, ok, err := dnatOfRow(r, elems)
		if err != nil {
			return agentTable{}, err
		}
		if !ok {
			out.Unrecognized++
			continue
		}
		ports = append(ports, d...)
	}
	out.DNATs = collapseDNATs(ports)
	return out, nil
}

// collapseDNATs は、ポートごとの DNAT を、同じルールで連続するポートが連続する宛先へ向かう範囲にまとめる。
func collapseDNATs(d []AgentDNAT) []AgentDNAT {
	sort.Slice(d, func(i, j int) bool {
		if d[i].RuleID != d[j].RuleID {
			return d[i].RuleID < d[j].RuleID
		}
		if d[i].Proto != d[j].Proto {
			return d[i].Proto < d[j].Proto
		}
		return d[i].Ports.Lo < d[j].Ports.Lo
	})
	var out []AgentDNAT
	for _, x := range d {
		if n := len(out); n > 0 {
			last := &out[n-1]
			width := int(last.Ports.Hi) - int(last.Ports.Lo) + 1
			if last.RuleID == x.RuleID && last.Proto == x.Proto && int(x.Ports.Lo) == int(last.Ports.Hi)+1 &&
				x.Dest.Addr() == last.Dest.Addr() && int(x.Dest.Port()) == int(last.Dest.Port())+width {
				last.Ports.Hi = x.Ports.Hi
				continue
			}
		}
		out = append(out, x)
	}
	sortDNATs(out)
	return out
}

type dnatKey struct {
	rule  string
	proto proto.Proto
	port  uint16
}

func expandDNATs(d []AgentDNAT) map[dnatKey]netip.AddrPort {
	out := map[dnatKey]netip.AddrPort{}
	for _, x := range d {
		for i := 0; i < x.Ports.Len(); i++ {
			out[dnatKey{x.RuleID, x.Proto, x.Ports.Lo + uint16(i)}] = netip.AddrPortFrom(x.Dest.Addr(), x.Dest.Port()+uint16(i))
		}
	}
	return out
}

// diffDNATs は、want にあって got に無い(宛先の違う)ポートと、その逆を範囲にまとめて返す。
func diffDNATs(want, got []AgentDNAT) (missing, extra []AgentDNAT) {
	w, g := expandDNATs(want), expandDNATs(got)
	pick := func(from, other map[dnatKey]netip.AddrPort) []AgentDNAT {
		var out []AgentDNAT
		for k, dest := range from {
			if o, ok := other[k]; !ok || o != dest {
				out = append(out, AgentDNAT{RuleID: k.rule, Proto: k.proto, Ports: proto.PortRange{Lo: k.port, Hi: k.port}, Dest: dest})
			}
		}
		if len(out) == 0 {
			return nil
		}
		return collapseDNATs(out)
	}
	return pick(w, g), pick(g, w)
}

// dnatOfRow は nat_pre の 1 行を、emitAgent が書く 2 つの形のどちらかとしてポートごとに読む。どちらでも
// なければ ok は偽になる。誤りは map の要素を読めなかった場合だけである。
func dnatOfRow(r *nftables.Rule, elems func(set string) ([]nftables.SetElement, error)) ([]AgentDNAT, bool, error) {
	comment, _ := userdata.GetString(r.UserData, userdata.TypeComment)
	id, kind := parseComment(comment)
	if id == "" || kind != DNATKind {
		return nil, false, nil
	}
	var (
		p        proto.Proto
		port     uint16
		hasPort  bool
		addr     []byte
		toPort   []byte
		setName  string
		sawL4    bool
		sawDNAT  bool
		lastLoad expr.Any
	)
	for _, e := range r.Exprs {
		switch x := e.(type) {
		case *expr.Meta:
			lastLoad = x
		case *expr.Payload:
			lastLoad = x
		case *expr.Cmp:
			switch l := lastLoad.(type) {
			case *expr.Meta:
				if l.Key == expr.MetaKeyL4PROTO && len(x.Data) == 1 && x.Op == expr.CmpOpEq {
					switch x.Data[0] {
					case unix.IPPROTO_TCP:
						p, sawL4 = proto.TCP, true
					case unix.IPPROTO_UDP:
						p, sawL4 = proto.UDP, true
					}
				}
			case *expr.Payload:
				if l.Base == expr.PayloadBaseTransportHeader && l.Offset == 2 && l.Len == 2 && x.Op == expr.CmpOpEq && len(x.Data) == 2 {
					port, hasPort = binaryutil.BigEndian.Uint16(x.Data), true
				}
			}
		case *expr.Immediate:
			switch x.Register {
			case 1:
				addr = x.Data
			case 2:
				toPort = x.Data
			}
		case *expr.Lookup:
			setName = x.SetName
		case *expr.NAT:
			sawDNAT = x.Type == expr.NATTypeDestNAT
		}
	}
	if !sawL4 || !sawDNAT {
		return nil, false, nil
	}
	one := func(port uint16, a []byte, to uint16) AgentDNAT {
		ip, _ := netip.AddrFromSlice(a)
		return AgentDNAT{RuleID: id, Proto: p, Ports: proto.PortRange{Lo: port, Hi: port}, Dest: netip.AddrPortFrom(ip, to)}
	}
	if setName != "" {
		els, err := elems(setName)
		if err != nil {
			return nil, false, fmt.Errorf("reading map %s of rule %s: %w", setName, id, err)
		}
		out := make([]AgentDNAT, 0, len(els))
		for _, el := range els {
			if len(el.Key) < 2 || len(el.Val) < 6 {
				return nil, false, nil
			}
			out = append(out, one(binaryutil.BigEndian.Uint16(el.Key[:2]), el.Val[:4], binaryutil.BigEndian.Uint16(el.Val[4:6])))
		}
		return out, true, nil
	}
	if !hasPort || len(addr) != 4 || len(toPort) < 2 {
		return nil, false, nil
	}
	return []AgentDNAT{one(port, addr, binaryutil.BigEndian.Uint16(toPort[:2]))}, true, nil
}
