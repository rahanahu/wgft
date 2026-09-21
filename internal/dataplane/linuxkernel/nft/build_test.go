//go:build linux

package nft

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

// recorder は emitter を記録するだけの実装。netlink を使わずに生成結果を検査する。
type recorder struct {
	ops    []string // 呼び出しの順序(AddTable / DelTable / ...)
	sets   map[string][]nftables.SetElement
	chains []string
	rules  map[string][]*nftables.Rule // チェーン名 → ルール
}

func newRecorder() *recorder {
	return &recorder{sets: map[string][]nftables.SetElement{}, rules: map[string][]*nftables.Rule{}}
}

func (r *recorder) AddTable(t *nftables.Table) *nftables.Table {
	r.ops = append(r.ops, "AddTable")
	return t
}
func (r *recorder) DelTable(*nftables.Table) { r.ops = append(r.ops, "DelTable") }
func (r *recorder) AddSet(s *nftables.Set, els []nftables.SetElement) error {
	r.ops = append(r.ops, "AddSet "+s.Name)
	r.sets[s.Name] = els
	return nil
}
func (r *recorder) AddChain(c *nftables.Chain) *nftables.Chain {
	r.ops = append(r.ops, "AddChain "+c.Name)
	r.chains = append(r.chains, c.Name)
	return c
}
func (r *recorder) AddRule(rule *nftables.Rule) *nftables.Rule {
	r.ops = append(r.ops, "AddRule "+rule.Chain.Name)
	r.rules[rule.Chain.Name] = append(r.rules[rule.Chain.Name], rule)
	return rule
}

func (r *recorder) comments(chain string) []string {
	var out []string
	for _, rule := range r.rules[chain] {
		c, _ := userdata.GetString(rule.UserData, userdata.TypeComment)
		out = append(out, c)
	}
	return out
}

// row は chain のうち comment に一致する行を返す。emit は Plan.Ports の順(Proto, ListenPort.Lo,
// RuleID)で行を出すので、set の連番と違って個々の行の位置はルール ID から探す方が安定する。
func (r *recorder) row(t *testing.T, chain, comment string) *nftables.Rule {
	t.Helper()
	for _, rule := range r.rules[chain] {
		if c, _ := userdata.GetString(rule.UserData, userdata.TypeComment); c == comment {
			return rule
		}
	}
	t.Fatalf("%s has no row with comment %q", chain, comment)
	return nil
}

// testCfg は wg インタフェース名だけを持つ(接続元 IP ごとの上限は Plan.Admission から、
// エージェントのアドレスと Relay の待ち受けは Plan と relayListening から来る。設計文書 7a.8 節 Phase 3)。
var testCfg = Config{WGInterface: "wg0"}

// testAgentAddr は "home" だけを登録済みにする(testCfg 時代のデフォルトを引き継ぐ)。
var testAgentAddr = map[string]netip.Addr{"home": netip.MustParseAddr("10.200.0.2")}

func rate(s string) *proto.Rate {
	r, err := proto.ParseRate(s)
	if err != nil {
		panic(err)
	}
	return &r
}

// buildTestPlan は、書き込み時の検査を経ずに proto.Rule から直接 Plan を組み立てる
// (internal/vpsd/apply.go の buildPlan と同じ経路。テストの都合で proto.ValidateRules は掛けない)。
func buildTestPlan(t *testing.T, rules []proto.Rule, agentAddr map[string]netip.Addr, limits policy.AdmissionLimits) planner.Plan {
	t.Helper()
	normalized := make([]model.Rule, 0, len(rules))
	for _, r := range rules {
		m, err := model.FromProto(r)
		if err != nil {
			t.Fatalf("model.FromProto(%s): %v", r.ID, err)
		}
		normalized = append(normalized, m)
	}
	agents := make([]planner.Agent, 0, len(agentAddr))
	for name, a := range agentAddr {
		agents = append(agents, planner.Agent{Name: name, Addr: a})
	}
	return planner.Build(planner.Input{Rules: normalized, Limits: limits, Agents: agents})
}

func TestEmitRows(t *testing.T) {
	rules := []proto.Rule{
		{ID: "r_udp", Agent: "home", Proto: proto.UDP, ListenPort: pr(2456, 2457), Target: "192.168.1.20:2456",
			VPSMode: proto.ModeKernel, Enabled: true,
			SourceDeny:  []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
			NewFlowRate: rate("100/second"), PerSourceRate: rate("10/second")},
		{ID: "r_off", Agent: "home", Proto: proto.UDP, ListenPort: pr(3000, 3000), Target: "192.168.1.20:3000",
			VPSMode: proto.ModeKernel, Enabled: false, SourceDeny: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		{ID: "r_proxy", Agent: "home", Proto: proto.TCP, ListenPort: pr(443, 443), Target: "192.168.1.30:443",
			VPSMode: proto.ModeProxy, Enabled: true, SourceAllow: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}},
		{ID: "r_tcp", Agent: "home", Proto: proto.TCP, ListenPort: pr(25565, 25565), Target: "192.168.1.22:25565",
			VPSMode: proto.ModeKernel, Enabled: true,
			SourceAllow: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, PacketRate: rate("5000/second")},
	}
	plan := buildTestPlan(t, rules, testAgentAddr, policy.AdmissionLimits{})
	relayListening := map[uint16]bool{443: true}
	rec := newRecorder()
	if err := emit(rec, plan, relayListening, testCfg); err != nil {
		t.Fatal(err)
	}

	if got := rec.ops[:3]; !reflect.DeepEqual(got, []string{"AddTable", "DelTable", "AddTable"}) {
		t.Errorf("first ops = %v, want add/delete/add", got)
	}
	if want := []string{"filter_pre", "nat_pre", "input", "forward", "postrouting"}; !reflect.DeepEqual(rec.chains, want) {
		t.Errorf("chains = %v, want %v", rec.chains, want)
	}

	// 無効なルールと未登録のエージェントのルールは Plan.Ports に現れないので、set も行も持たない。
	// Relay(プロキシモード)のルールは、待ち受けを開けているポートに Transparent と同じ段の行を
	// 持ち、set 名の連番も進める。Plan.Ports は (Proto, ListenPort.Lo, RuleID) の順なので、行の順は
	// r_proxy(tcp/443) → r_tcp(tcp/25565) → r_udp(udp/2456) になる(設計文書 7a.8 節 Phase 3)。
	var setNames []string
	for _, op := range rec.ops {
		if strings.HasPrefix(op, "AddSet ") {
			setNames = append(setNames, strings.TrimPrefix(op, "AddSet "))
		}
	}
	// flows_udp / flows_tcp は、そのプロトコルの最初の有効なルール(プロキシモードを含む)でだけ作る
	if want := []string{"allow_1", "flows_tcp", "allow_2", "deny_3", "meter_3", "flows_udp"}; !reflect.DeepEqual(setNames, want) {
		t.Errorf("sets = %v, want %v", setNames, want)
	}

	// 行の順序:deny、allow、per_source、src_flow、new_flow、packet。空・未設定のものは出ない。
	// src_flow は接続元 IP ごとの同時フロー数の上限で、プロトコルごとに常に出る。r_tcp は
	// PacketRate を持つが、TCP のルールには packet の行を作らない(設計文書 7a.9 節)。
	wantPre := []string{
		Comment("r_proxy", "allow"), Comment("r_proxy", "src_flow"),
		Comment("r_tcp", "allow"), Comment("r_tcp", "src_flow"),
		Comment("r_udp", "deny"), Comment("r_udp", "per_source"), Comment("r_udp", "src_flow"), Comment("r_udp", "new_flow"),
	}
	if got := rec.comments("filter_pre"); !reflect.DeepEqual(got, wantPre) {
		t.Errorf("filter_pre = %v, want %v", got, wantPre)
	}
	if got, want := rec.comments("nat_pre"), []string{Comment("r_tcp", "dnat"), Comment("r_udp", "dnat")}; !reflect.DeepEqual(got, want) {
		t.Errorf("nat_pre = %v, want %v", got, want)
	}
	for chain, n := range map[string]int{"input": 1, "forward": 5, "postrouting": 1} {
		if got := len(rec.rules[chain]); got != n {
			t.Errorf("%s has %d rules, want %d", chain, got, n)
		}
	}

	// プロキシモードのルールの src_flow は、カーネルモードの TCP のルールと同じ flows_tcp で数える
	// (接続元 IP ごとの上限は全ルールの合計。仕様 7 節)
	tcpFlowLines := 0
	for _, r := range rec.rules["filter_pre"] {
		c, _ := userdata.GetString(r.UserData, userdata.TypeComment)
		if c != Comment("r_proxy", "src_flow") && c != Comment("r_tcp", "src_flow") {
			continue
		}
		tcpFlowLines++
		for _, e := range r.Exprs {
			if d, ok := e.(*expr.Dynset); ok && d.SetName != "flows_tcp" {
				t.Errorf("%s uses set %s, want flows_tcp", c, d.SetName)
			}
		}
	}
	if tcpFlowLines != 2 {
		t.Errorf("found %d TCP src_flow lines, want 2 (r_proxy and r_tcp)", tcpFlowLines)
	}

	// どの Admission Policy の行も IPv4 のパケットにだけ一致する。送信元を読まない集約のレートの行
	// (new_flow、packet)も meta nfproto ipv4 を持つ(設計文書 7a.9 節)
	for _, r := range rec.rules["filter_pre"] {
		c, _ := userdata.GetString(r.UserData, userdata.TypeComment)
		n := 0
		for i, e := range r.Exprs {
			if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeyNFPROTO && i+1 < len(r.Exprs) {
				if cmp, ok := r.Exprs[i+1].(*expr.Cmp); ok && cmp.Op == expr.CmpOpEq && len(cmp.Data) == 1 && cmp.Data[0] == unix.NFPROTO_IPV4 {
					n++
				}
			}
		}
		if n != 1 {
			t.Errorf("%s has %d meta nfproto ipv4 matches, want 1", c, n)
		}
	}

	// allow の lookup は反転(!=)、deny は反転しない
	assertLookupInvert(t, rec.row(t, "filter_pre", Comment("r_udp", "deny")), false)
	assertLookupInvert(t, rec.row(t, "filter_pre", Comment("r_tcp", "allow")), true)

	// DNAT は宛先アドレスだけ(ポートのレジスタは使わない)
	for _, r := range rec.rules["nat_pre"] {
		for _, e := range r.Exprs {
			if nat, ok := e.(*expr.NAT); ok && (nat.RegProtoMin != 0 || nat.Specified) {
				t.Errorf("DNAT rewrites port: %+v", nat)
			}
		}
	}
}

func assertLookupInvert(t *testing.T, r *nftables.Rule, want bool) {
	t.Helper()
	for _, e := range r.Exprs {
		if l, ok := e.(*expr.Lookup); ok {
			if l.Invert != want {
				t.Errorf("lookup %s invert = %v, want %v", l.SetName, l.Invert, want)
			}
			return
		}
	}
	t.Errorf("rule has no lookup")
}

// 接続元 IP ごとの同時フロー数の上限(仕様 6.1, 7 節)は、プロトコルごとに 1 つの set を
// 全ルールで共有し、値は udp 256 / tcp 128 で、ct state new のときだけ効く。
func TestFlowCapSharedAcrossRules(t *testing.T) {
	rules := []proto.Rule{
		{ID: "r_udp1", Agent: "home", Proto: proto.UDP, ListenPort: pr(2456, 2456), Target: "192.168.1.20:2456",
			VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_udp2", Agent: "home", Proto: proto.UDP, ListenPort: pr(2457, 2457), Target: "192.168.1.20:2457",
			VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_tcp", Agent: "home", Proto: proto.TCP, ListenPort: pr(25565, 25565), Target: "192.168.1.22:25565",
			VPSMode: proto.ModeKernel, Enabled: true},
	}
	plan := buildTestPlan(t, rules, testAgentAddr, policy.AdmissionLimits{})
	rec := newRecorder()
	if err := emit(rec, plan, nil, testCfg); err != nil {
		t.Fatal(err)
	}

	var setNames []string
	for _, op := range rec.ops {
		if strings.HasPrefix(op, "AddSet ") {
			setNames = append(setNames, strings.TrimPrefix(op, "AddSet "))
		}
	}
	// flows_udp は 1 回しか作らない(2 つ目の UDP ルールでは作り直さない)。Plan.Ports の順で
	// TCP のルール(25565)が先に来るので、flows_tcp が先にできる
	if want := []string{"flows_tcp", "flows_udp"}; !reflect.DeepEqual(setNames, want) {
		t.Errorf("sets = %v, want %v (must not create flows_udp twice)", setNames, want)
	}

	dyn1 := findDynset(t, rec.row(t, "filter_pre", Comment("r_udp1", "src_flow")))
	dyn2 := findDynset(t, rec.row(t, "filter_pre", Comment("r_udp2", "src_flow")))
	if dyn1.SetName != dyn2.SetName {
		t.Errorf("two udp rules must share one set: %q vs %q", dyn1.SetName, dyn2.SetName)
	}
	if dyn1.SetName != "flows_udp" {
		t.Errorf("set name = %q, want flows_udp", dyn1.SetName)
	}
	if got := connlimitOf(t, dyn1); got.Count != 256 || got.Flags != expr.NFT_CONNLIMIT_F_INV {
		t.Errorf("udp cap = %+v, want count 256 with the over flag", got)
	}

	dyn3 := findDynset(t, rec.row(t, "filter_pre", Comment("r_tcp", "src_flow")))
	if dyn3.SetName != "flows_tcp" {
		t.Errorf("set name = %q, want flows_tcp", dyn3.SetName)
	}
	if got := connlimitOf(t, dyn3); got.Count != 128 || got.Flags != expr.NFT_CONNLIMIT_F_INV {
		t.Errorf("tcp cap = %+v, want count 128 with the over flag", got)
	}

	// 3 行とも ct state new に限る(既存のフローを追い出さない)
	for i, r := range rec.rules["filter_pre"] {
		found := false
		for _, e := range r.Exprs {
			if ct, ok := e.(*expr.Ct); ok && ct.Key == expr.CtKeySTATE {
				found = true
			}
		}
		if !found {
			t.Errorf("filter_pre[%d] has no ct state match", i)
		}
	}
}

func findDynset(t *testing.T, r *nftables.Rule) *expr.Dynset {
	t.Helper()
	for _, e := range r.Exprs {
		if d, ok := e.(*expr.Dynset); ok {
			return d
		}
	}
	t.Fatal("rule has no dynset")
	return nil
}

func connlimitOf(t *testing.T, d *expr.Dynset) *expr.Connlimit {
	t.Helper()
	for _, e := range d.Exprs {
		if c, ok := e.(*expr.Connlimit); ok {
			return c
		}
	}
	t.Fatal("dynset has no connlimit")
	return nil
}

// 0 はそのプロトコルの接続元 IP ごとの上限を無効にし、set も src_flow の行も作らない(仕様 6.1, 7, 11a 節)。
func TestFlowCapZeroDisablesProtocol(t *testing.T) {
	rules := []proto.Rule{
		{ID: "r_udp", Agent: "home", Proto: proto.UDP, ListenPort: pr(2456, 2456), Target: "192.168.1.20:2456",
			VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_tcp", Agent: "home", Proto: proto.TCP, ListenPort: pr(25565, 25565), Target: "192.168.1.22:25565",
			VPSMode: proto.ModeKernel, Enabled: true},
	}
	// TCP は既定のまま(256/128)、UDP だけ外す
	plan := buildTestPlan(t, rules, testAgentAddr, policy.AdmissionLimits{UDPPerSource: policy.PerSourceOff})
	rec := newRecorder()
	if err := emit(rec, plan, nil, testCfg); err != nil {
		t.Fatal(err)
	}

	var setNames []string
	for _, op := range rec.ops {
		if strings.HasPrefix(op, "AddSet ") {
			setNames = append(setNames, strings.TrimPrefix(op, "AddSet "))
		}
	}
	if want := []string{"flows_tcp"}; !reflect.DeepEqual(setNames, want) {
		t.Errorf("sets = %v, want %v (flows_udp must not be created when the cap is 0)", setNames, want)
	}
	if got, want := rec.comments("filter_pre"), []string{Comment("r_tcp", "src_flow")}; !reflect.DeepEqual(got, want) {
		t.Errorf("filter_pre comments = %v, want %v (no src_flow row for udp)", got, want)
	}

	// 両方 0 なら set も行も 1 つも作らない
	plan2 := buildTestPlan(t, rules, testAgentAddr, policy.AdmissionLimits{UDPPerSource: policy.PerSourceOff, TCPPerSource: policy.PerSourceOff})
	rec2 := newRecorder()
	if err := emit(rec2, plan2, nil, testCfg); err != nil {
		t.Fatal(err)
	}
	for _, op := range rec2.ops {
		if strings.HasPrefix(op, "AddSet ") {
			t.Errorf("no set expected when both caps are 0, got %s", op)
		}
	}
	if got := rec2.comments("filter_pre"); len(got) != 0 {
		t.Errorf("no src_flow rows expected when both caps are 0, got %v", got)
	}
}

// カーネルモードも設定値(既定と異なる値)をそのまま使う。
func TestFlowCapCustomValue(t *testing.T) {
	rules := []proto.Rule{
		{ID: "r_udp", Agent: "home", Proto: proto.UDP, ListenPort: pr(2456, 2456), Target: "192.168.1.20:2456",
			VPSMode: proto.ModeKernel, Enabled: true},
	}
	plan := buildTestPlan(t, rules, testAgentAddr, policy.AdmissionLimits{UDPPerSource: 200})
	rec := newRecorder()
	if err := emit(rec, plan, nil, testCfg); err != nil {
		t.Fatal(err)
	}
	dyn := findDynset(t, rec.rules["filter_pre"][0])
	if got := connlimitOf(t, dyn); got.Count != 200 {
		t.Errorf("udp cap = %+v, want count 200", got)
	}
}

func TestIntervalElements(t *testing.T) {
	ip := func(s string) []byte { return netip.MustParseAddr(s).AsSlice() }
	end := func(s string) nftables.SetElement { return nftables.SetElement{Key: ip(s), IntervalEnd: true} }
	start := func(s string) nftables.SetElement { return nftables.SetElement{Key: ip(s)} }
	tests := []struct {
		name string
		in   []string
		want []nftables.SetElement
	}{
		{"1 つの CIDR", []string{"203.0.113.0/24"}, []nftables.SetElement{end("0.0.0.0"), start("203.0.113.0"), end("203.0.114.0")}},
		{"順序を昇順に直す", []string{"203.0.113.0/24", "198.51.100.0/24"},
			[]nftables.SetElement{end("0.0.0.0"), start("198.51.100.0"), end("198.51.101.0"), start("203.0.113.0"), end("203.0.114.0")}},
		{"重なりを併合", []string{"10.0.0.0/8", "10.1.0.0/16"}, []nftables.SetElement{end("0.0.0.0"), start("10.0.0.0"), end("11.0.0.0")}},
		{"隣接を併合", []string{"10.0.0.0/25", "10.0.0.128/25"}, []nftables.SetElement{end("0.0.0.0"), start("10.0.0.0"), end("10.0.1.0")}},
		{"ホストビットを落とす", []string{"203.0.113.77/24"}, []nftables.SetElement{end("0.0.0.0"), start("203.0.113.0"), end("203.0.114.0")}},
		{"0.0.0.0/0 は終端なし", []string{"0.0.0.0/0"}, []nftables.SetElement{start("0.0.0.0")}},
		{"末尾まで続く区間", []string{"255.255.255.0/24"}, []nftables.SetElement{end("0.0.0.0"), start("255.255.255.0")}},
		{"空", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var prefixes []netip.Prefix
			for _, s := range tt.in {
				prefixes = append(prefixes, netip.MustParsePrefix(s))
			}
			got := intervalElements(prefixes)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %s\nwant %s", fmtElems(got), fmtElems(tt.want))
			}
		})
	}
}

func fmtElems(els []nftables.SetElement) string {
	var b strings.Builder
	for _, e := range els {
		a := netip.AddrFrom4([4]byte(e.Key))
		if e.IntervalEnd {
			b.WriteString(a.String() + "(end) ")
		} else {
			b.WriteString(a.String() + " ")
		}
	}
	return b.String()
}

func TestMatchPortForms(t *testing.T) {
	single := match("wg0", proto.TCP, pr(25565, 25565))
	rng := match("wg0", proto.UDP, pr(2456, 2457))
	if len(rng) != len(single)+1 {
		t.Errorf("range should add one more cmp: single=%d range=%d", len(single), len(rng))
	}
	last := single[len(single)-1].(*expr.Cmp)
	if last.Op != expr.CmpOpEq || binary.BigEndian.Uint16(last.Data) != 25565 {
		t.Errorf("single port cmp = %+v", last)
	}
}

func pr(lo, hi uint16) proto.PortRange { return proto.PortRange{Lo: lo, Hi: hi} }

// プロキシモードのルールは、vpsd が待ち受けを開けているポートにだけ接続元 IP ごとの上限の行を持つ。
// bind に失敗したポートに行を残すと、同じポートの別のプロセスへの通信に上限が掛かる(仕様 6.1 節)。
func TestFlowCapProxyOnlyWhenListening(t *testing.T) {
	rules := []proto.Rule{
		{ID: "r_proxy", Agent: "home", Proto: proto.TCP, ListenPort: pr(443, 443), Target: "192.168.1.30:443",
			VPSMode: proto.ModeProxy, Enabled: true},
		{ID: "r_tcp", Agent: "home", Proto: proto.TCP, ListenPort: pr(25565, 25565), Target: "192.168.1.22:25565",
			VPSMode: proto.ModeKernel, Enabled: true},
	}
	plan := buildTestPlan(t, rules, testAgentAddr, policy.AdmissionLimits{})
	for _, listening := range []map[uint16]bool{nil, {}, {8443: true}} {
		rec := newRecorder()
		if err := emit(rec, plan, listening, testCfg); err != nil {
			t.Fatal(err)
		}
		for _, c := range rec.comments("filter_pre") {
			if c == Comment("r_proxy", "src_flow") {
				t.Errorf("relayListening=%v: r_proxy has a src_flow line although its listener is not open", listening)
			}
		}
		// カーネルモードの TCP のルールの行は、プロキシの待ち受けに関係なく残る
		if !slices.Contains(rec.comments("filter_pre"), Comment("r_tcp", "src_flow")) {
			t.Errorf("relayListening=%v: r_tcp lost its src_flow line", listening)
		}
	}
}
