package nft

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"

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

var testCfg = Config{WGInterface: "wg0", AgentAddr: map[string]netip.Addr{"home": netip.MustParseAddr("10.200.0.2")}}

func rate(s string) *proto.Rate {
	r, err := proto.ParseRate(s)
	if err != nil {
		panic(err)
	}
	return &r
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
	rec := newRecorder()
	if err := emit(rec, rules, testCfg); err != nil {
		t.Fatal(err)
	}

	if got := rec.ops[:3]; !reflect.DeepEqual(got, []string{"AddTable", "DelTable", "AddTable"}) {
		t.Errorf("first ops = %v, want add/delete/add", got)
	}
	if want := []string{"filter_pre", "nat_pre", "input", "forward", "postrouting"}; !reflect.DeepEqual(rec.chains, want) {
		t.Errorf("chains = %v, want %v", rec.chains, want)
	}

	// 無効なルールとプロキシモードのルールは set も行も持たない。set 名の連番は有効なカーネルモードのルールで数える
	var setNames []string
	for _, op := range rec.ops {
		if strings.HasPrefix(op, "AddSet ") {
			setNames = append(setNames, strings.TrimPrefix(op, "AddSet "))
		}
	}
	if want := []string{"deny_1", "meter_1", "allow_2"}; !reflect.DeepEqual(setNames, want) {
		t.Errorf("sets = %v, want %v", setNames, want)
	}

	// 行の順序:deny、allow、per_source、new_flow、packet。空・未設定のものは出ない
	wantPre := []string{
		Comment("r_udp", "deny"), Comment("r_udp", "per_source"), Comment("r_udp", "new_flow"),
		Comment("r_tcp", "allow"), Comment("r_tcp", "packet"),
	}
	if got := rec.comments("filter_pre"); !reflect.DeepEqual(got, wantPre) {
		t.Errorf("filter_pre = %v, want %v", got, wantPre)
	}
	if got, want := rec.comments("nat_pre"), []string{Comment("r_udp", "dnat"), Comment("r_tcp", "dnat")}; !reflect.DeepEqual(got, want) {
		t.Errorf("nat_pre = %v, want %v", got, want)
	}
	for chain, n := range map[string]int{"input": 1, "forward": 5, "postrouting": 1} {
		if got := len(rec.rules[chain]); got != n {
			t.Errorf("%s has %d rules, want %d", chain, got, n)
		}
	}

	// allow の lookup は反転(!=)、deny は反転しない
	assertLookupInvert(t, rec.rules["filter_pre"][0], false)
	assertLookupInvert(t, rec.rules["filter_pre"][3], true)

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

func TestEmitUnknownAgent(t *testing.T) {
	rules := []proto.Rule{{ID: "r", Agent: "nobody", Proto: proto.UDP, ListenPort: pr(1, 1),
		Target: "h:1", VPSMode: proto.ModeKernel, Enabled: true}}
	rec := newRecorder()
	var logged string
	cfg := testCfg
	cfg.Logf = func(f string, a ...any) { logged = fmt.Sprintf(f, a...) }
	if err := emit(rec, rules, cfg); err != nil {
		t.Fatal(err)
	}
	if len(rec.rules["nat_pre"]) != 0 || !strings.Contains(logged, "nobody") {
		t.Errorf("unknown agent must be skipped with a log: rows=%d logged=%q", len(rec.rules["nat_pre"]), logged)
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
