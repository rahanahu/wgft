package nftables

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

func rate(s string) *proto.Rate {
	r, err := proto.ParseRate(s)
	if err != nil {
		panic(err)
	}
	return &r
}

func port(id string, p proto.Proto, lo uint16, f model.Forwarding) Port {
	return Port{RuleID: id, Proto: p, Ports: proto.PortRange{Lo: lo, Hi: lo}, Forwarding: f}
}

// fullPolicy は全段を持つ UDP のルールと、Relay の TCP のルールと、Transparent の TCP のルールを持つ。
func fullPolicy() policy.Policy {
	pfx := netip.MustParsePrefix
	return policy.Policy{
		PerSourceFlowCaps: policy.PerSourceFlowCaps{UDP: 256, TCP: 128},
		Rules: []policy.RulePolicy{
			{RuleID: "r_udp", Proto: proto.UDP, SourceDeny: []netip.Prefix{pfx("203.0.113.0/24")},
				SourceAllow:   []netip.Prefix{pfx("198.51.100.0/24")},
				PerSourceRate: rate("10/second"), NewFlowRate: rate("100/second"), PacketRate: rate("5000/second")},
			{RuleID: "r_relay", Proto: proto.TCP, SourceDeny: []netip.Prefix{pfx("203.0.113.0/24")},
				PerSourceRate: rate("1/minute"), NewFlowRate: rate("1/minute")},
			// r_tcp が持つ PacketRate は TCP のルールには効かないので、行を作らないことを確かめる
			// (設計文書 7a.9 節「TCP の packet_rate」)。値そのものは受け付けて保存する。
			{RuleID: "r_tcp", Proto: proto.TCP, SourceAllow: []netip.Prefix{pfx("192.0.2.0/24")}, PacketRate: rate("10/second")},
		},
	}
}

func comments(p Program) []string {
	var out []string
	for _, r := range p.Rows {
		out = append(out, r.Comment)
	}
	return out
}

func setNames(p Program) []string {
	var out []string
	for _, s := range p.Sets {
		out = append(out, s.Name)
	}
	return out
}

func TestCompileRows(t *testing.T) {
	ports := []Port{
		port("r_relay", proto.TCP, 443, model.Relay),
		port("r_tcp", proto.TCP, 25565, model.Transparent),
		port("r_udp", proto.UDP, 2456, model.Transparent),
	}
	prog, err := Compile(fullPolicy(), ports)
	if err != nil {
		t.Fatal(err)
	}
	// Relay のポートも Transparent と同じ段の行を持ち、set の連番を進める。TCP のルール(r_tcp)は
	// PacketRate を持つが、packet の行は作らない(設計文書 7a.9 節「TCP の packet_rate」)。UDP の
	// ルール(r_udp)は変わらず packet の行を持つ。
	want := []string{
		"wgft:r_relay:deny", "wgft:r_relay:per_source", "wgft:r_relay:src_flow", "wgft:r_relay:new_flow",
		"wgft:r_tcp:allow", "wgft:r_tcp:src_flow",
		"wgft:r_udp:deny", "wgft:r_udp:allow", "wgft:r_udp:per_source", "wgft:r_udp:src_flow",
		"wgft:r_udp:new_flow", "wgft:r_udp:packet",
	}
	if got := comments(prog); !reflect.DeepEqual(got, want) {
		t.Errorf("rows = %v\nwant %v", got, want)
	}
	if got, want := setNames(prog), []string{"deny_1", "meter_1", "flows_tcp", "allow_2", "deny_3", "allow_3", "meter_3", "flows_udp"}; !reflect.DeepEqual(got, want) {
		t.Errorf("sets = %v, want %v", got, want)
	}
	// ct state new は送信元ごとの新規フローレート、同時フロー数の上限、集約の新規フローレートの行だけ
	for _, r := range prog.Rows {
		wantNew := r.Kind == "per_source" || r.Kind == "src_flow" || r.Kind == "new_flow"
		if r.Match.CtStateNew != wantNew {
			t.Errorf("%s: ct state new = %v, want %v", r.Comment, r.Match.CtStateNew, wantNew)
		}
		if r.Kind != r.Step.DropKind() || !strings.HasSuffix(r.Comment, ":"+r.Kind) {
			t.Errorf("%s: kind %q does not match step %v", r.Comment, r.Kind, r.Step)
		}
	}
}

// 行の段の順序は policy.Order だけが決める。Order を並べ替えると行の順序も変わる。
func TestCompileFollowsOrder(t *testing.T) {
	saved := policy.Order
	t.Cleanup(func() { policy.Order = saved })
	policy.Order = []policy.Step{
		policy.StepAggregatePacketRate, policy.StepAggregateNewFlowRate, policy.StepPerSourceConcurrentFlows,
		policy.StepPerSourceRate, policy.StepSourceAllow, policy.StepSourceDeny,
	}
	prog, err := Compile(fullPolicy(), []Port{port("r_udp", proto.UDP, 2456, model.Transparent)})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"wgft:r_udp:packet", "wgft:r_udp:new_flow", "wgft:r_udp:src_flow",
		"wgft:r_udp:per_source", "wgft:r_udp:allow", "wgft:r_udp:deny"}
	if got := comments(prog); !reflect.DeepEqual(got, want) {
		t.Errorf("rows = %v, want %v", got, want)
	}
}

func TestCompileOmitsEmptySteps(t *testing.T) {
	pol := policy.Policy{
		PerSourceFlowCaps: policy.PerSourceFlowCaps{UDP: 0, TCP: 128},
		Rules: []policy.RulePolicy{
			{RuleID: "r_udp", Proto: proto.UDP},
			{RuleID: "r_tcp", Proto: proto.TCP},
		},
	}
	prog, err := Compile(pol, []Port{port("r_tcp", proto.TCP, 80, model.Transparent), port("r_udp", proto.UDP, 53, model.Transparent)})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := comments(prog), []string{"wgft:r_tcp:src_flow"}; !reflect.DeepEqual(got, want) {
		t.Errorf("rows = %v, want %v", got, want)
	}
	if got, want := setNames(prog), []string{"flows_tcp"}; !reflect.DeepEqual(got, want) {
		t.Errorf("sets = %v, want %v", got, want)
	}
}

func TestCompileRejectsPortWithoutPolicy(t *testing.T) {
	_, err := Compile(fullPolicy(), []Port{port("r_missing", proto.UDP, 53, model.Transparent)})
	if err == nil {
		t.Fatal("Compile accepted a port whose rule is not in the IR")
	}
	_, err = Compile(fullPolicy(), []Port{port("r_udp", proto.TCP, 53, model.Transparent)})
	if err == nil {
		t.Fatal("Compile accepted a port whose protocol differs from its policy")
	}
}

// どの行も IPv4 のパケットにだけ一致する。送信元を読まない集約のレートの行も含む(設計文書 7a.9 節)。
func TestCompileRowsMatchIPv4Only(t *testing.T) {
	ports := []Port{
		port("r_relay", proto.TCP, 443, model.Relay),
		port("r_tcp", proto.TCP, 25565, model.Transparent),
		port("r_udp", proto.UDP, 2456, model.Transparent),
	}
	prog, err := Compile(fullPolicy(), ports)
	if err != nil {
		t.Fatal(err)
	}
	limits := 0
	for _, r := range prog.Rows {
		if !r.Match.IPv4 {
			t.Errorf("row %s does not match IPv4 only", r.Comment)
		}
		if r.Stmt.Kind == StmtLimit {
			limits++
		}
	}
	if limits == 0 {
		t.Fatal("the policy compiled to no aggregate rate row; the test covers nothing")
	}
}
