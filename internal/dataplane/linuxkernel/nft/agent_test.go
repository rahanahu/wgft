//go:build linux

package nft

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/proto"
)

func agentRule(id string, p proto.Proto, lo, hi uint16, target string) proto.AgentRule {
	return proto.AgentRule{ID: id, Proto: p, ListenPort: pr(lo, hi), Target: target, Enabled: true}
}

func rng(lo, hi uint16, dest string) AgentRange {
	return AgentRange{Ports: pr(lo, hi), Dest: netip.MustParseAddrPort(dest)}
}

// fakeLookup は名前ごとの答えを返す。無い名前は「無い」の誤りにする。
func fakeLookup(answers map[string][]string) LookupFunc {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		as, ok := answers[host]
		if !ok {
			return nil, fmt.Errorf("lookup %s: no such host", host)
		}
		var out []netip.Addr
		for _, a := range as {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
}

// PlanAgent の判定(設計文書 7b.2、7b.3 節):範囲のずらし、許可一覧のポートごとの判定、名前の解決、
// IPv4 の宛先だけを扱うこと、ループバックと未指定のアドレスの拒否。
func TestPlanAgent(t *testing.T) {
	allow, err := allowtargets.Parse("192.168.1.20/31:1-8999,192.168.1.22,192.168.1.30:7000,192.168.1.30:7002,192.168.1.40")
	if err != nil {
		t.Fatal(err)
	}
	cfg := AgentConfig{WGInterface: "wgft0", AllowTarget: allow.Allows, AllowTargetSource: allowtargets.Env}
	open := &AgentConfig{WGInterface: "wgft0"}
	resolved := map[string]Resolution{
		"nas.lan":    {Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.30")}},
		"gone.lan":   {Err: errors.New("lookup gone.lan: no such host")},
		"v6only.lan": {Err: errOnlyIPv6},
		"v6.lan":     {Addrs: []netip.Addr{netip.MustParseAddr("fd00::1")}},
		"mapped.lan": {Addrs: []netip.Addr{netip.MustParseAddr("::ffff:192.168.1.40")}},
	}
	cases := []struct {
		name       string
		rule       proto.AgentRule
		cfg        *AgentConfig // nil なら cfg
		wantRanges []AgentRange
		wantReason string // 部分一致。空なら理由が無いこと
	}{
		{name: "single port rewrites the port", rule: agentRule("r", proto.TCP, 25565, 25565, "192.168.1.22:2000"),
			wantRanges: []AgentRange{rng(25565, 25565, "192.168.1.22:2000")}},
		{name: "range shifts by position", rule: agentRule("r", proto.UDP, 2456, 2458, "192.168.1.20:3000"),
			wantRanges: []AgentRange{rng(2456, 2458, "192.168.1.20:3000")}},
		{name: "host name uses its resolution", rule: agentRule("r", proto.UDP, 7000, 7000, "nas.lan:7000"),
			wantRanges: []AgentRange{rng(7000, 7000, "192.168.1.30:7000")}},
		{name: "IPv4-mapped resolution is unmapped", rule: agentRule("r", proto.TCP, 80, 80, "mapped.lan:80"),
			wantRanges: []AgentRange{rng(80, 80, "192.168.1.40:80")}},
		{name: "allowlist refuses one port of a range", rule: agentRule("r", proto.UDP, 7000, 7002, "nas.lan:7000"),
			wantRanges: []AgentRange{rng(7000, 7000, "192.168.1.30:7000"), rng(7002, 7002, "192.168.1.30:7002")},
			wantReason: "target 192.168.1.30:7001 is not in " + allowtargets.Env},
		{name: "allowlist is judged on the effective target port", rule: agentRule("r", proto.UDP, 8998, 9001, "192.168.1.20:8998"),
			wantRanges: []AgentRange{rng(8998, 8999, "192.168.1.20:8998")},
			wantReason: "target 192.168.1.20:9000 is not in " + allowtargets.Env + "; 2 of the rule's 4 ports are not published"},
		{name: "allowlist refuses a whole rule", rule: agentRule("r", proto.TCP, 22, 22, "10.0.0.1:22"),
			wantReason: "target 10.0.0.1:22 is not in " + allowtargets.Env},
		{name: "allowlist without a source name", rule: agentRule("r", proto.TCP, 22, 22, "10.0.0.1:22"),
			cfg:        &AgentConfig{WGInterface: "wgft0", AllowTarget: allow.Allows},
			wantReason: "target 10.0.0.1:22 is not allowed"},
		{name: "no allowlist allows everything", rule: agentRule("r", proto.TCP, 22, 22, "10.0.0.1:22"),
			cfg: open, wantRanges: []AgentRange{rng(22, 22, "10.0.0.1:22")}},
		{name: "full-width range is one range", rule: agentRule("r", proto.UDP, 1, 65535, "10.0.0.1:1"),
			cfg: open, wantRanges: []AgentRange{rng(1, 65535, "10.0.0.1:1")}},
		{name: "loopback is refused", rule: agentRule("r", proto.TCP, 8080, 8080, "127.0.0.1:80"),
			wantReason: "loopback"},
		{name: "any 127/8 address is loopback", rule: agentRule("r", proto.TCP, 8080, 8080, "127.1.2.3:80"),
			cfg: open, wantReason: "loopback"},
		{name: "unspecified address is refused", rule: agentRule("r", proto.TCP, 8080, 8080, "0.0.0.0:80"),
			cfg: open, wantReason: "unspecified"},
		{name: "IPv6 literal target is refused", rule: agentRule("r", proto.TCP, 80, 80, "[fd00::1]:80"),
			cfg: open, wantReason: "target fd00::1 is an IPv6 address; kernel mode forwards only to IPv4 targets"},
		{name: "name with only IPv6 addresses is refused", rule: agentRule("r", proto.TCP, 80, 80, "v6only.lan:80"),
			cfg: open, wantReason: "target host \"v6only.lan\" has only IPv6 addresses; kernel mode forwards only to IPv4 targets"},
		{name: "IPv6 resolution given directly is refused", rule: agentRule("r", proto.TCP, 80, 80, "v6.lan:80"),
			cfg: open, wantReason: "only to IPv4"},
		{name: "resolution error", rule: agentRule("r", proto.TCP, 80, 80, "gone.lan:80"),
			wantReason: "name resolution of target host \"gone.lan\" failed: lookup gone.lan: no such host"},
		{name: "no resolution result", rule: agentRule("r", proto.TCP, 80, 80, "unknown.lan:80"),
			wantReason: "name resolution"},
		{name: "range past 65535", rule: agentRule("r", proto.UDP, 100, 102, "192.168.1.20:65534"),
			cfg: open, wantReason: "exceeds 65535"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			if tc.cfg != nil {
				c = *tc.cfg
			}
			pub := PlanAgent(AgentInput{Rules: []proto.AgentRule{tc.rule}, Resolved: resolved}, c)
			if len(pub.Rules) != 1 {
				t.Fatalf("got %d results, want 1", len(pub.Rules))
			}
			got := pub.Rules[0]
			if !reflect.DeepEqual(got.Ranges, tc.wantRanges) {
				t.Errorf("ranges = %v, want %v", got.Ranges, tc.wantRanges)
			}
			switch {
			case tc.wantReason == "" && got.Reason != "":
				t.Errorf("reason = %q, want none", got.Reason)
			case !strings.Contains(got.Reason, tc.wantReason):
				t.Errorf("reason = %q, want it to contain %q", got.Reason, tc.wantReason)
			}
			if got.RuleID != tc.rule.ID || got.Proto != tc.rule.Proto || got.ListenPort != tc.rule.ListenPort || got.Target != tc.rule.Target {
				t.Errorf("result does not carry the declaration: %+v", got)
			}
		})
	}
}

// 名前は A レコードだけを使う(7b.2 節)。AAAA だけの名前は IPv4 の宛先が無いという理由で公開しない。
// A レコードはすべてを昇順に返し、どれを使うかは PlanAgent が選ぶ。IP リテラルと無効のルールは引かない。
func TestResolveAgentTargets(t *testing.T) {
	var asked []string
	base := fakeLookup(map[string][]string{
		"multi.lan":  {"fd00::9", "192.168.1.9", "192.168.1.3"},
		"v6only.lan": {"fd00::1", "fd00::2"},
		"mapped.lan": {"::ffff:192.168.1.40"},
		"empty.lan":  {},
	})
	lookup := func(ctx context.Context, host string) ([]netip.Addr, error) {
		asked = append(asked, host)
		return base(ctx, host)
	}
	off := agentRule("r_off", proto.TCP, 10, 10, "off.lan:80")
	off.Enabled = false
	rules := []proto.AgentRule{
		agentRule("r_multi", proto.TCP, 80, 80, "multi.lan:80"),
		agentRule("r_multi2", proto.UDP, 80, 80, "multi.lan:81"),
		agentRule("r_v6", proto.TCP, 81, 81, "v6only.lan:80"),
		agentRule("r_mapped", proto.TCP, 82, 82, "mapped.lan:80"),
		agentRule("r_empty", proto.TCP, 83, 83, "empty.lan:80"),
		agentRule("r_gone", proto.TCP, 84, 84, "gone.lan:80"),
		agentRule("r_lit", proto.TCP, 85, 85, "192.168.1.5:80"),
		agentRule("r_lit6", proto.TCP, 86, 86, "[fd00::5]:80"),
		off,
	}
	res := ResolveAgentTargets(context.Background(), rules, lookup)
	if want := []string{"multi.lan", "v6only.lan", "mapped.lan", "empty.lan", "gone.lan"}; !reflect.DeepEqual(asked, want) {
		t.Errorf("looked up %v, want %v", asked, want)
	}
	if got := res["multi.lan"]; got.Err != nil || !reflect.DeepEqual(got.Addrs, []netip.Addr{netip.MustParseAddr("192.168.1.3"), netip.MustParseAddr("192.168.1.9")}) {
		t.Errorf("multi.lan = %+v, want its IPv4 addresses in ascending order", got)
	}
	if got := res["mapped.lan"]; got.Err != nil || !reflect.DeepEqual(got.Addrs, []netip.Addr{netip.MustParseAddr("192.168.1.40")}) {
		t.Errorf("mapped.lan = %+v, want 192.168.1.40", got)
	}
	if got := res["v6only.lan"]; !errors.Is(got.Err, errOnlyIPv6) || got.Failed() {
		t.Errorf("v6only.lan = %+v failed=%v, want the only-IPv6 error, which is not a failed lookup", got, got.Failed())
	}
	if got := res["empty.lan"]; got.Err == nil || !got.Failed() {
		t.Errorf("empty.lan = %+v, want a failed lookup", got)
	}
	if got := res["multi.lan"]; got.Failed() {
		t.Error("a resolved name counts as failed")
	}
	pub := PlanAgent(AgentInput{Rules: rules, Resolved: res}, AgentConfig{WGInterface: "wgft0"})
	reasons := map[string]string{}
	for _, r := range pub.Rules {
		reasons[r.RuleID] = r.Reason
	}
	for id, want := range map[string]string{
		"r_multi": "", "r_multi2": "", "r_mapped": "", "r_lit": "",
		"r_v6":    "has only IPv6 addresses; kernel mode forwards only to IPv4 targets",
		"r_lit6":  "is an IPv6 address; kernel mode forwards only to IPv4 targets",
		"r_gone":  "name resolution of target host \"gone.lan\" failed",
		"r_empty": "resolved to no address",
	} {
		got, ok := reasons[id]
		if !ok || (want == "" && got != "") || !strings.Contains(got, want) {
			t.Errorf("%s reason = %q, want %q", id, got, want)
		}
	}
}

// ホスト名が複数の A レコードに解決されたときは、許可一覧が通すアドレスだけを残し、その中で最も小さい
// アドレスを使う(7b.2 節)。どれも通らなければルールを公開しない。選ぶアドレスは応答の順によらない。
func TestPlanAgentMultipleAddresses(t *testing.T) {
	a := netip.MustParseAddr
	allow, err := allowtargets.Parse("192.168.1.9,192.168.1.12,192.168.1.3:7001")
	if err != nil {
		t.Fatal(err)
	}
	cfg := AgentConfig{WGInterface: "wgft0", AllowTarget: allow.Allows, AllowTargetSource: allowtargets.Env}
	resolved := map[string]Resolution{
		"svc.lan":  {Addrs: []netip.Addr{a("192.168.1.3"), a("192.168.1.9"), a("192.168.1.12")}},
		"none.lan": {Addrs: []netip.Addr{a("10.0.0.1"), a("10.0.0.2")}},
		"loop.lan": {Addrs: []netip.Addr{a("127.0.0.1"), a("192.168.1.12")}},
	}
	plan := func(rule proto.AgentRule, res map[string]Resolution, c AgentConfig) AgentRuleResult {
		t.Helper()
		pub := PlanAgent(AgentInput{Rules: []proto.AgentRule{rule}, Resolved: res}, c)
		if len(pub.Rules) != 1 {
			t.Fatalf("got %d results", len(pub.Rules))
		}
		return pub.Rules[0]
	}

	t.Run("the smallest refused, a larger one allowed", func(t *testing.T) {
		got := plan(agentRule("r", proto.TCP, 80, 80, "svc.lan:80"), resolved, cfg)
		if want := []AgentRange{rng(80, 80, "192.168.1.9:80")}; !reflect.DeepEqual(got.Ranges, want) || got.Reason != "" {
			t.Errorf("result = %+v, want 192.168.1.9:80, the smallest allowed address, and no reason", got)
		}
	})
	t.Run("without an allowlist the smallest", func(t *testing.T) {
		got := plan(agentRule("r", proto.TCP, 80, 80, "svc.lan:80"), resolved, AgentConfig{WGInterface: "wgft0"})
		if want := []AgentRange{rng(80, 80, "192.168.1.3:80")}; !reflect.DeepEqual(got.Ranges, want) {
			t.Errorf("ranges = %v, want %v", got.Ranges, want)
		}
	})
	t.Run("per port on a range", func(t *testing.T) {
		// 7001 だけは最も小さい 192.168.1.3 を一覧が通す
		got := plan(agentRule("r", proto.UDP, 7000, 7002, "svc.lan:7000"), resolved, cfg)
		want := []AgentRange{rng(7000, 7000, "192.168.1.9:7000"), rng(7001, 7001, "192.168.1.3:7001"), rng(7002, 7002, "192.168.1.9:7002")}
		if !reflect.DeepEqual(got.Ranges, want) || got.Reason != "" {
			t.Errorf("result = %+v, want %v", got, want)
		}
	})
	t.Run("all refused", func(t *testing.T) {
		got := plan(agentRule("r", proto.TCP, 80, 81, "none.lan:80"), resolved, cfg)
		want := `target host "none.lan" resolved to 10.0.0.1, 10.0.0.2; none of them at port 80 is in ` + allowtargets.Env +
			"; 2 of the rule's 2 ports are not published"
		if len(got.Ranges) != 0 || got.Reason != want {
			t.Errorf("result = %+v, want no ranges and the reason %q", got, want)
		}
		got = plan(agentRule("r", proto.TCP, 80, 80, "none.lan:80"), resolved, AgentConfig{WGInterface: "wgft0", AllowTarget: allow.Allows})
		if !strings.Contains(got.Reason, "is not allowed") {
			t.Errorf("reason without a source name = %q, want it to contain \"is not allowed\"", got.Reason)
		}
	})
	t.Run("loopback among the answers is skipped", func(t *testing.T) {
		got := plan(agentRule("r", proto.TCP, 80, 80, "loop.lan:80"), resolved, AgentConfig{WGInterface: "wgft0"})
		if want := []AgentRange{rng(80, 80, "192.168.1.12:80")}; !reflect.DeepEqual(got.Ranges, want) || got.Reason != "" {
			t.Errorf("result = %+v, want %v", got, want)
		}
	})
	t.Run("answer order does not matter", func(t *testing.T) {
		orders := [][]string{
			{"192.168.1.12", "192.168.1.3", "192.168.1.9"},
			{"192.168.1.9", "192.168.1.12", "192.168.1.3"},
			{"192.168.1.3", "192.168.1.9", "192.168.1.12"},
		}
		for _, order := range orders {
			// PlanAgent に渡る順を崩しても、ResolveAgentTargets を通しても、同じアドレスを選ぶ
			var shuffled []netip.Addr
			for _, s := range order {
				shuffled = append(shuffled, a(s))
			}
			direct := plan(agentRule("r", proto.TCP, 80, 80, "svc.lan:80"), map[string]Resolution{"svc.lan": {Addrs: shuffled}}, cfg)
			rules := []proto.AgentRule{agentRule("r", proto.TCP, 80, 80, "svc.lan:80")}
			res := ResolveAgentTargets(context.Background(), rules, fakeLookup(map[string][]string{"svc.lan": order}))
			resolvedOnce := plan(rules[0], res, AgentConfig{WGInterface: "wgft0"})
			if want := []AgentRange{rng(80, 80, "192.168.1.9:80")}; !reflect.DeepEqual(direct.Ranges, want) {
				t.Errorf("order %v with the allowlist: %v, want %v", order, direct.Ranges, want)
			}
			if want := []AgentRange{rng(80, 80, "192.168.1.3:80")}; !reflect.DeepEqual(resolvedOnce.Ranges, want) {
				t.Errorf("order %v through ResolveAgentTargets: %v, want %v", order, resolvedOnce.Ranges, want)
			}
		}
	})
}

// 拒んだルールは他のルールを止めず、無効なルールは結果にも表にも出ない。結果は (Proto, Lo, ID) の順。
// 世代は記録に写る。
func TestPlanAgentOrderAndIsolation(t *testing.T) {
	off := agentRule("r_off", proto.UDP, 9000, 9000, "192.168.1.20:9000")
	off.Enabled = false
	pub := PlanAgent(AgentInput{Generation: 42, Rules: []proto.AgentRule{
		agentRule("r_udp", proto.UDP, 2456, 2457, "192.168.1.20:2456"),
		agentRule("r_loop", proto.TCP, 8080, 8080, "127.0.0.1:80"),
		off,
		agentRule("r_tcp_b", proto.TCP, 25565, 25565, "192.168.1.22:25565"),
		agentRule("r_tcp_a", proto.TCP, 25565, 25565, "192.168.1.23:25565"),
	}}, AgentConfig{WGInterface: "wgft0"})
	if pub.Generation != 42 {
		t.Errorf("generation = %d, want 42", pub.Generation)
	}
	var ids []string
	for _, r := range pub.Rules {
		ids = append(ids, r.RuleID)
	}
	if want := []string{"r_loop", "r_tcp_a", "r_tcp_b", "r_udp"}; !reflect.DeepEqual(ids, want) {
		t.Errorf("order = %v, want %v", ids, want)
	}
	if pub.Rules[0].Reason == "" || len(pub.Rules[0].Ranges) != 0 {
		t.Errorf("loopback rule = %+v, want a reason and no ranges", pub.Rules[0])
	}
	want := []AgentDNAT{
		{RuleID: "r_tcp_a", Proto: proto.TCP, Ports: pr(25565, 25565), Dest: netip.MustParseAddrPort("192.168.1.23:25565")},
		{RuleID: "r_tcp_b", Proto: proto.TCP, Ports: pr(25565, 25565), Dest: netip.MustParseAddrPort("192.168.1.22:25565")},
		{RuleID: "r_udp", Proto: proto.UDP, Ports: pr(2456, 2457), Dest: netip.MustParseAddrPort("192.168.1.20:2456")},
	}
	if got := pub.DNATs(); !reflect.DeepEqual(got, want) {
		t.Errorf("DNATs = %v, want %v", got, want)
	}
}

// 記録は範囲ごとに持つので、ポートの数に比例して大きくならない。
func TestAgentPublicationRecordStaysSmall(t *testing.T) {
	pub := PlanAgent(AgentInput{Generation: 7, Rules: []proto.AgentRule{
		agentRule("r_wide", proto.UDP, 1000, 60999, "192.168.1.20:1000"),
	}}, AgentConfig{WGInterface: "wgft0"})
	b, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 512 {
		t.Errorf("a 60000-port rule records %d bytes: %s", len(b), b)
	}
	var back AgentPublication
	if err := json.Unmarshal(b, &back); err != nil || !reflect.DeepEqual(back, pub) {
		t.Errorf("record does not round-trip: %v\n got %+v\nwant %+v", err, back, pub)
	}
}

// agentRecorder は recorder に、無名の map に別々の名前を付ける働きと、チェーンそのものを残す働きを足す。
// google/nftables の Conn は名前の "%d" をカーネルに埋めさせるので、記録するだけの実装では map が同じ
// 名前で重なるため。
type agentRecorder struct {
	*recorder
	maps       int
	chainObjs  []*nftables.Chain
	elemChunks []int // SetAddElements の 1 回ごとの要素の数
}

func (r *agentRecorder) AddSet(s *nftables.Set, els []nftables.SetElement) error {
	if s.Anonymous {
		s.Name = fmt.Sprintf("__map%d", r.maps)
		r.maps++
	}
	return r.recorder.AddSet(s, els)
}

func (r *agentRecorder) SetAddElements(s *nftables.Set, els []nftables.SetElement) error {
	r.elemChunks = append(r.elemChunks, len(els))
	return r.recorder.SetAddElements(s, els)
}

func (r *agentRecorder) AddChain(c *nftables.Chain) *nftables.Chain {
	r.chainObjs = append(r.chainObjs, c)
	return r.recorder.AddChain(c)
}

func emitAgentForTest(t *testing.T, pub AgentPublication) *agentRecorder {
	t.Helper()
	rec := &agentRecorder{recorder: newRecorder()}
	if err := emitAgent(rec, pub, "wgft0"); err != nil {
		t.Fatal(err)
	}
	return rec
}

// dumps は記録した表を、InspectAgent が読み戻す形にする。
func (r *agentRecorder) dumps() []chainDump {
	var out []chainDump
	for _, c := range r.chainObjs {
		out = append(out, chainDump{chain: c, rules: append([]*nftables.Rule(nil), r.rules[c.Name]...)})
	}
	return out
}

func (r *agentRecorder) elems(name string) ([]nftables.SetElement, error) {
	els, ok := r.sets[name]
	if !ok {
		return nil, fmt.Errorf("no set %s", name)
	}
	return els, nil
}

func testAgentPublication() AgentPublication {
	return PlanAgent(AgentInput{Rules: []proto.AgentRule{
		agentRule("r_mc", proto.TCP, 25565, 25565, "192.168.1.22:25566"),
		agentRule("r_valheim", proto.UDP, 2456, 2458, "192.168.1.20:3000"),
		agentRule("r_partial", proto.UDP, 7000, 7002, "192.168.1.30:7000"),
		agentRule("r_loop", proto.TCP, 8080, 8080, "127.0.0.1:80"),
	}}, AgentConfig{WGInterface: "wgft0",
		AllowTarget: func(ap netip.AddrPort) bool { return ap != netip.MustParseAddrPort("192.168.1.30:7001") }})
}

func hasExpr[T expr.Any](exprs []expr.Any) (T, bool) {
	for _, e := range exprs {
		if x, ok := e.(T); ok {
			return x, true
		}
	}
	var zero T
	return zero, false
}

func verdicts(rows []*nftables.Rule) []expr.VerdictKind {
	var out []expr.VerdictKind
	for _, r := range rows {
		v, _ := hasExpr[*expr.Verdict](r.Exprs)
		if v == nil {
			out = append(out, -99)
			continue
		}
		out = append(out, v.Kind)
	}
	return out
}

// dportCmps は行の宛先ポートの比較の値である。
func dportCmps(r *nftables.Rule) [][]byte {
	var out [][]byte
	for _, e := range r.Exprs {
		if c, ok := e.(*expr.Cmp); ok && len(c.Data) == 2 {
			out = append(out, c.Data)
		}
	}
	return out
}

// テーブルの形(7b.1 節):チェーンと優先度、filter_pre の入口の守り、DNAT の 2 つの形、input の守り、
// 両方向の MSS、forward、wgft0 から入り wgft0 以外へ出る DNAT のフローだけの MASQUERADE。
func TestEmitAgentTable(t *testing.T) {
	rec := emitAgentForTest(t, testAgentPublication())
	if want := []string{"filter_pre", "nat_pre", "input", "forward", "postrouting"}; !reflect.DeepEqual(rec.chains, want) {
		t.Fatalf("chains = %v, want %v", rec.chains, want)
	}
	if want := []string{"AddTable", "DelTable", "AddTable"}; !reflect.DeepEqual(rec.ops[:3], want) {
		t.Errorf("first ops = %v, want the table replaced as a whole: %v", rec.ops[:3], want)
	}
	for _, c := range rec.chainObjs {
		if c.Name == "filter_pre" && (*c.Priority != -150 || *c.Hooknum != *nftables.ChainHookPrerouting || c.Type != nftables.ChainTypeFilter) {
			t.Errorf("filter_pre = %+v, want a filter prerouting chain at -150, after conntrack and before DNAT", c)
		}
	}

	// filter_pre:成立済みのフローを通し、公開した (プロトコル, ポート) だけを通し、残りを落とす。
	// 許可一覧が拒んだ 7001 は通さない
	fp := rec.rules["filter_pre"]
	if got, want := verdicts(fp), []expr.VerdictKind{expr.VerdictAccept, expr.VerdictAccept, expr.VerdictAccept, expr.VerdictAccept, expr.VerdictAccept, expr.VerdictDrop}; !reflect.DeepEqual(got, want) {
		t.Fatalf("filter_pre verdicts = %v, want %v", got, want)
	}
	if ct, _ := hasExpr[*expr.Ct](fp[0].Exprs); ct == nil || ct.Key != expr.CtKeySTATE {
		t.Errorf("filter_pre's first row = %+v, want ct state established,related accept", fp[0].Exprs)
	}
	if got, want := rec.comments("filter_pre"), []string{"", Comment("r_mc", PassKind), Comment("r_valheim", PassKind),
		Comment("r_partial", PassKind), Comment("r_partial", PassKind), ""}; !reflect.DeepEqual(got, want) {
		t.Errorf("filter_pre comments = %v, want %v", got, want)
	}
	if got, want := [][][]byte{dportCmps(fp[1]), dportCmps(fp[2]), dportCmps(fp[3]), dportCmps(fp[4])},
		[][][]byte{{{0x63, 0xdd}}, {{0x09, 0x98}, {0x09, 0x9a}}, {{0x1b, 0x58}}, {{0x1b, 0x5a}}}; !reflect.DeepEqual(got, want) {
		t.Errorf("filter_pre ports = %v, want 25565, 2456-2458, 7000, 7002", got)
	}
	// 成立済みの行は ESTABLISHED と RELATED の両方(ct state のビット 2 と 4)を通す
	if bw, _ := hasExpr[*expr.Bitwise](fp[0].Exprs); bw == nil || !reflect.DeepEqual(bw.Mask, binaryutil.NativeEndian.PutUint32(0x02|0x04)) {
		t.Errorf("filter_pre's first row mask = %+v, want established,related", bw)
	}
	// 通す行はルールのプロトコルで照合する(meta l4proto の比較の値:tcp 6、udp 17)
	for i, want := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP, unix.IPPROTO_UDP, unix.IPPROTO_UDP} {
		var l4 []byte
		for _, e := range fp[i+1].Exprs {
			if c, ok := e.(*expr.Cmp); ok && len(c.Data) == 1 {
				l4 = c.Data
			}
		}
		if !reflect.DeepEqual(l4, []byte{want}) {
			t.Errorf("filter_pre row %d matches l4proto %v, want %d", i+1, l4, want)
		}
	}
	if len(fp[5].Exprs) != 3 { // iifname の 2 つと drop
		t.Errorf("filter_pre's last row = %+v, want iifname wgft0 drop", fp[5].Exprs)
	}

	// nat_pre:DNAT を公開しないルール(r_loop)は行を持たない
	if got, want := rec.comments("nat_pre"), []string{Comment("r_mc", "dnat"), Comment("r_valheim", "dnat"), Comment("r_partial", "dnat")}; !reflect.DeepEqual(got, want) {
		t.Errorf("nat_pre comments = %v, want %v", got, want)
	}
	single := rec.row(t, "nat_pre", Comment("r_mc", "dnat"))
	if nat, ok := hasExpr[*expr.NAT](single.Exprs); !ok || nat.RegAddrMin != 1 || nat.RegProtoMin != 2 || !nat.Specified || nat.Type != expr.NATTypeDestNAT {
		t.Errorf("single-port DNAT = %+v, want dnat ip to addr:port from registers 1 and 2", nat)
	}
	if _, ok := hasExpr[*expr.Lookup](single.Exprs); ok {
		t.Error("single-port rule uses a map")
	}
	var imm []*expr.Immediate
	for _, e := range single.Exprs {
		if x, ok := e.(*expr.Immediate); ok {
			imm = append(imm, x)
		}
	}
	if len(imm) != 2 || !reflect.DeepEqual(imm[0].Data, []byte{192, 168, 1, 22}) || !reflect.DeepEqual(imm[1].Data, []byte{0x63, 0xde}) {
		t.Errorf("single-port immediates = %+v, want 192.168.1.22 and port 25566", imm)
	}

	partial := rec.row(t, "nat_pre", Comment("r_partial", "dnat"))
	lk, ok := hasExpr[*expr.Lookup](partial.Exprs)
	if !ok || !lk.IsDestRegSet || lk.DestRegister != 1 {
		t.Fatalf("range rule lookup = %+v, want a map lookup into register 1", lk)
	}
	if nat, _ := hasExpr[*expr.NAT](partial.Exprs); nat == nil || nat.RegAddrMin != 1 || nat.RegProtoMin != unix.NFT_REG32_01 {
		t.Errorf("range DNAT = %+v, want address from register 1 and port from NFT_REG32_01", nat)
	}
	// 範囲の行は宣言の範囲で照合し、map には許可一覧が通したポートだけが入る
	if got := dportCmps(partial); !reflect.DeepEqual(got, [][]byte{{0x1b, 0x58}, {0x1b, 0x5a}}) {
		t.Errorf("range match = %v, want 7000-7002", got)
	}
	wantEls := []nftables.SetElement{
		{Key: []byte{0x1b, 0x58}, Val: []byte{192, 168, 1, 30, 0x1b, 0x58, 0, 0}},
		{Key: []byte{0x1b, 0x5a}, Val: []byte{192, 168, 1, 30, 0x1b, 0x5a, 0, 0}},
	}
	if els := rec.sets[lk.SetName]; !reflect.DeepEqual(els, wantEls) {
		t.Errorf("map elements = %+v, want %+v", els, wantEls)
	}

	// input:DNAT したフローと成立済みのフローを通し、wgft0 からの残りを落とす
	in := rec.rules["input"]
	if got, want := verdicts(in), []expr.VerdictKind{expr.VerdictAccept, expr.VerdictAccept, expr.VerdictDrop}; !reflect.DeepEqual(got, want) {
		t.Errorf("input verdicts = %v, want %v", got, want)
	}
	if ct, _ := hasExpr[*expr.Ct](in[0].Exprs); ct == nil || ct.Key != expr.CtKeySTATUS {
		t.Errorf("input's first row = %+v, want ct status dnat accept", in[0].Exprs)
	}

	// forward:MSS のクランプが両方向に、判定の行より前にある
	fw := rec.rules["forward"]
	if len(fw) != 7 {
		t.Fatalf("forward has %d rows, want 7", len(fw))
	}
	for i, key := range []expr.MetaKey{expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME} {
		m, _ := hasExpr[*expr.Meta](fw[i].Exprs)
		rt, okRt := hasExpr[*expr.Rt](fw[i].Exprs)
		ex, okEx := hasExpr[*expr.Exthdr](fw[i].Exprs)
		if m == nil || m.Key != key || !okRt || rt.Key != expr.RtTCPMSS || !okEx || ex.Op != expr.ExthdrOpTcpopt || ex.SourceRegister != 1 {
			t.Errorf("forward row %d = %+v, want the MSS clamp to rt mtu on %v", i, fw[i].Exprs, key)
		}
		if _, isVerdict := hasExpr[*expr.Verdict](fw[i].Exprs); isVerdict {
			t.Errorf("forward row %d has a verdict; the MSS clamp must let the packet continue", i)
		}
	}
	if got, want := verdicts(fw[2:]), []expr.VerdictKind{expr.VerdictDrop, expr.VerdictAccept, expr.VerdictAccept, expr.VerdictDrop, expr.VerdictDrop}; !reflect.DeepEqual(got, want) {
		t.Errorf("forward verdicts = %v, want %v", got, want)
	}

	// postrouting:wgft0 から入り wgft0 以外へ出る DNAT のフローだけを MASQUERADE する。iifname が無いと
	// 他のテーブルが DNAT したフローにも掛かる
	post := rec.rules["postrouting"]
	if len(post) != 1 {
		t.Fatalf("postrouting has %d rows, want 1", len(post))
	}
	var metas []expr.MetaKey
	var ops []expr.CmpOp
	for _, e := range post[0].Exprs {
		switch x := e.(type) {
		case *expr.Meta:
			metas = append(metas, x.Key)
		case *expr.Cmp:
			if len(x.Data) == unix.IFNAMSIZ {
				ops = append(ops, x.Op)
			}
		}
	}
	if _, ok := hasExpr[*expr.Masq](post[0].Exprs); !ok ||
		!reflect.DeepEqual(metas, []expr.MetaKey{expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME}) ||
		!reflect.DeepEqual(ops, []expr.CmpOp{expr.CmpOpEq, expr.CmpOpNeq}) {
		t.Errorf("postrouting = %+v, want iifname wgft0 oifname != wgft0 ct status dnat masquerade", post[0].Exprs)
	}
	if ct, _ := hasExpr[*expr.Ct](post[0].Exprs); ct == nil || ct.Key != expr.CtKeySTATUS {
		t.Errorf("postrouting does not require ct status dnat: %+v", post[0].Exprs)
	}
	// 表は wgft0 の名前だけを使い、他のインタフェースの名前を持たない
	for chain, rows := range rec.rules {
		for _, r := range rows {
			for _, e := range r.Exprs {
				if c, ok := e.(*expr.Cmp); ok && len(c.Data) == unix.IFNAMSIZ && !strings.HasPrefix(string(c.Data), "wgft0\x00") {
					t.Errorf("%s compares an interface other than wgft0: %q", chain, c.Data)
				}
			}
		}
	}
}

// 公開するルールが無くても、入口の守り、input の守り、MSS の行、MASQUERADE は置く。filter_pre は
// wgft0 からの新しい接続をすべて落とす。
func TestEmitAgentEmpty(t *testing.T) {
	rec := emitAgentForTest(t, AgentPublication{})
	if n := len(rec.rules["nat_pre"]); n != 0 {
		t.Errorf("nat_pre has %d rows, want none", n)
	}
	if got, want := verdicts(rec.rules["filter_pre"]), []expr.VerdictKind{expr.VerdictAccept, expr.VerdictDrop}; !reflect.DeepEqual(got, want) {
		t.Errorf("filter_pre verdicts = %v, want established accept then drop", got)
	}
	if len(rec.rules["input"]) != 3 || len(rec.rules["forward"]) != 7 || len(rec.rules["postrouting"]) != 1 {
		t.Errorf("rows = input %d, forward %d, postrouting %d; want 3, 7, 1",
			len(rec.rules["input"]), len(rec.rules["forward"]), len(rec.rules["postrouting"]))
	}
	if err := emitAgent(newRecorder(), AgentPublication{}, ""); err == nil {
		t.Error("emitAgent without an interface name succeeded")
	}
}

// 大きな map は要素を setElemChunk 個ずつ別のメッセージで送る。google/nftables v0.3.0 は AddSet に渡した
// 要素を 1 つの属性に入れ、約 1,800 個を超えると長さがあふれるため。どのメッセージも map を参照する行より
// 前に送る。
func TestEmitAgentChunksLargeMaps(t *testing.T) {
	for _, width := range []int{8001, 65535} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			lo := uint16(1)
			if width < 65535 {
				lo = 20000
			}
			pub := PlanAgent(AgentInput{Rules: []proto.AgentRule{
				agentRule("r_wide", proto.UDP, lo, lo+uint16(width-1), "192.168.1.20:1"),
				agentRule("r_tcp", proto.TCP, 25565, 25565, "192.168.1.22:25565"),
			}}, AgentConfig{WGInterface: "wgft0"})
			rec := emitAgentForTest(t, pub)
			// 1 通の要素の属性の長さは 16 ビットに収まらなければならない。map の要素 1 つは netlink で
			// 最大 40 バイト程度になる(入れ子の見出しとキー 4 バイト、アドレスとポートの値 8 バイト)。
			// ラボでは 1 通に 1,857 個を超えて入れると長さがあふれた
			const maxAttr, elemEncoded = 65535, 40
			total := 0
			for _, n := range rec.elemChunks {
				if n*elemEncoded > maxAttr {
					t.Errorf("one message carries %d elements, about %d bytes; over the 16-bit attribute length", n, n*elemEncoded)
				}
				total += n
			}
			if total != width || len(rec.sets["__map0"]) != width {
				t.Errorf("sent %d elements, map holds %d; want %d", total, len(rec.sets["__map0"]), width)
			}
			// map を参照する行は nat_pre の 2 行目(tcp の行の次)である
			addSet, lastElems, wideRule, natRows := -1, -1, -1, 0
			for i, op := range rec.ops {
				switch op {
				case "AddSet __map0":
					addSet = i
				case "SetAddElements __map0":
					lastElems = i
				case "AddRule nat_pre":
					if natRows++; natRows == 2 {
						wideRule = i
					}
				}
			}
			if rec.comments("nat_pre")[1] != Comment("r_wide", DNATKind) || !(addSet >= 0 && addSet < lastElems && lastElems < wideRule) {
				t.Errorf("ops order: AddSet %d, last SetAddElements %d, the map's rule %d; want the elements before the rule", addSet, lastElems, wideRule)
			}
			ins, err := inspectAgentOf(rec.dumps(), rec.elems, pub, "wgft0")
			if err != nil || !ins.Matches() {
				t.Errorf("inspection of the emitted table: %v, %+v", err, ins)
			}
		})
	}
}

// InspectAgent の比較は、emitAgent が書いた表を記録どおりと判定し、欠けた行とチェーン、足された行、
// 欠けたり宛先の違ったりする DNAT を示す。
func TestInspectAgentOf(t *testing.T) {
	pub := testAgentPublication()
	fresh := func() *agentRecorder { return emitAgentForTest(t, pub) }
	inspect := func(rec *agentRecorder) AgentInspection {
		t.Helper()
		ins, err := inspectAgentOf(rec.dumps(), rec.elems, pub, "wgft0")
		if err != nil {
			t.Fatal(err)
		}
		return ins
	}
	if ins := inspect(fresh()); !ins.Matches() || !reflect.DeepEqual(ins.DNATs, pub.DNATs()) {
		t.Fatalf("fresh table does not match its record: %+v\nwant DNATs %v", ins, pub.DNATs())
	}

	t.Run("missing masquerade", func(t *testing.T) {
		rec := fresh()
		rec.rules["postrouting"] = nil
		ins := inspect(rec)
		if len(ins.Missing) != 1 || !strings.Contains(ins.Missing[0], "masquerade") {
			t.Errorf("missing = %v, want the masquerade row", ins.Missing)
		}
	})
	t.Run("missing forward accept", func(t *testing.T) {
		rec := fresh()
		fw := rec.rules["forward"]
		rec.rules["forward"] = append(append([]*nftables.Rule(nil), fw[:3]...), fw[4:]...)
		ins := inspect(rec)
		if len(ins.Missing) != 1 || ins.Missing[0] != "forward: accept DNATed flows from wgft0" {
			t.Errorf("missing = %v, want the forward accept of DNATed flows", ins.Missing)
		}
	})
	t.Run("missing filter_pre chain", func(t *testing.T) {
		rec := fresh()
		var kept []*nftables.Chain
		for _, c := range rec.chainObjs {
			if c.Name != "filter_pre" {
				kept = append(kept, c)
			}
		}
		rec.chainObjs = kept
		ins := inspect(rec)
		if len(ins.Missing) == 0 || ins.Missing[0] != "chain filter_pre is missing" || ins.Matches() {
			t.Errorf("missing = %v, want the filter_pre chain and its rows", ins.Missing)
		}
	})
	t.Run("filter_pre pass row missing", func(t *testing.T) {
		rec := fresh()
		fp := rec.rules["filter_pre"]
		rec.rules["filter_pre"] = append(append([]*nftables.Rule(nil), fp[:1]...), fp[2:]...)
		ins := inspect(rec)
		if len(ins.Missing) != 1 || ins.Missing[0] != "filter_pre: accept tcp 25565 from wgft0 for rule r_mc" {
			t.Errorf("missing = %v, want the pass row of r_mc", ins.Missing)
		}
	})
	t.Run("chain with another priority", func(t *testing.T) {
		rec := fresh()
		for _, c := range rec.chainObjs {
			if c.Name == "forward" {
				c.Priority = nftables.ChainPriorityRef(0)
			}
		}
		if ins := inspect(rec); len(ins.Missing) != 1 || !strings.HasPrefix(ins.Missing[0], "chain forward is not") {
			t.Errorf("missing = %v, want the forward chain's header", ins.Missing)
		}
	})
	t.Run("added rows and chains", func(t *testing.T) {
		rec := fresh()
		rec.rules["forward"] = append([]*nftables.Rule{{Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}}}, rec.rules["forward"]...)
		rec.chainObjs = append(rec.chainObjs, &nftables.Chain{Name: "extra"})
		rec.rules["nat_pre"] = append(rec.rules["nat_pre"], &nftables.Rule{Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}})
		ins := inspect(rec)
		if !reflect.DeepEqual(ins.Unexpected, []string{"chain nat_pre: row 4 is not one wgft writes", "chain forward: row 1 is not one wgft writes", "chain extra is not one wgft writes"}) ||
			ins.Unrecognized != 1 || len(ins.ExtraDNATsInPlace) != 0 || len(ins.Missing) != 0 || len(ins.Moved) != 0 {
			t.Errorf("inspection = %+v, want the added row, chain and nat_pre row", ins)
		}
	})
	t.Run("rows in another order", func(t *testing.T) {
		rec := fresh()
		fw := append([]*nftables.Rule(nil), rec.rules["forward"]...)
		fw[2], fw[3] = fw[3], fw[2] // accept of DNATed flows before the wgft0-to-wgft0 drop
		rec.rules["forward"] = fw
		ins := inspect(rec)
		// 位置が違うだけの行は欠けでも加わった行でもなく、位置の違いとして示す(10.2c 節)
		// 隣り合う 2 行を入れ替えた表では、どちらを移したとも言えるので、どちらか 1 行を名指せばよい
		if len(ins.Missing) != 0 || len(ins.Unexpected) != 0 || len(ins.Moved) != 1 || ins.Matches() ||
			(ins.Moved[0] != "forward: accept DNATed flows from wgft0, now at row 3" && ins.Moved[0] != "forward: drop wgft0 to wgft0, now at row 4") {
			t.Errorf("missing %v unexpected %v moved %v; want the swapped row reported as moved", ins.Missing, ins.Unexpected, ins.Moved)
		}
	})
	// DNAT の行は、宛先を読めても形が違えば記録どおりではない
	t.Run("DNAT row without iifname", func(t *testing.T) {
		rec := fresh()
		row := rec.row(t, "nat_pre", Comment("r_mc", "dnat"))
		row.Exprs = row.Exprs[2:] // iifname の読み出しと比較を外す
		ins := inspect(rec)
		if !reflect.DeepEqual(ins.Missing, []string{"nat_pre: DNAT row of rule r_mc"}) || len(ins.Unexpected) != 1 || len(ins.MissingDNATs) != 0 {
			t.Errorf("inspection = %+v, want the r_mc DNAT row reported although its destination reads the same", ins)
		}
	})
	t.Run("DNAT row with a narrowed port match", func(t *testing.T) {
		rec := fresh()
		row := rec.row(t, "nat_pre", Comment("r_valheim", "dnat"))
		exprs := append([]expr.Any(nil), row.Exprs...)
		for i, e := range exprs {
			if c, ok := e.(*expr.Cmp); ok && c.Op == expr.CmpOpLte {
				exprs[i] = &expr.Cmp{Op: expr.CmpOpLte, Register: c.Register, Data: []byte{0x09, 0x99}} // 2458 -> 2457
			}
		}
		row.Exprs = exprs
		ins := inspect(rec)
		if !reflect.DeepEqual(ins.Missing, []string{"nat_pre: DNAT row of rule r_valheim"}) || ins.Matches() {
			t.Errorf("inspection = %+v, want the narrowed r_valheim row reported", ins)
		}
	})
	// カーネルは読み戻しで NAT の式の上限のレジスタと PROTO_SPECIFIED を埋める。組んだ式と形が違っても
	// 記録どおりである
	t.Run("DNAT rows in the read-back form", func(t *testing.T) {
		rec := fresh()
		for _, row := range rec.rules["nat_pre"] {
			exprs := append([]expr.Any(nil), row.Exprs...)
			for i, e := range exprs {
				if n, ok := e.(*expr.NAT); ok {
					back := *n
					back.RegAddrMax, back.RegProtoMax, back.Specified = n.RegAddrMin, n.RegProtoMin, true
					exprs[i] = &back
				}
			}
			row.Exprs = exprs
		}
		if ins := inspect(rec); !ins.Matches() {
			t.Errorf("inspection of the read-back form = %+v, want it to match", ins)
		}
	})
	// map の DNAT がポートを読むレジスタを誤ると、宛先は同じに読めても転送は壊れる
	t.Run("map DNAT with the wrong port register", func(t *testing.T) {
		rec := fresh()
		row := rec.row(t, "nat_pre", Comment("r_valheim", "dnat"))
		exprs := append([]expr.Any(nil), row.Exprs...)
		for i, e := range exprs {
			if n, ok := e.(*expr.NAT); ok {
				if n.RegProtoMin != unix.NFT_REG32_01 {
					t.Fatalf("the map row's port register is %d, want %d", n.RegProtoMin, unix.NFT_REG32_01)
				}
				wrong := *n
				wrong.RegProtoMin = 2
				exprs[i] = &wrong
			}
		}
		row.Exprs = exprs
		ins := inspect(rec)
		if !reflect.DeepEqual(ins.Missing, []string{"nat_pre: DNAT row of rule r_valheim"}) || len(ins.MissingDNATs) != 0 {
			t.Errorf("inspection = %+v, want the r_valheim row reported although its destinations read the same", ins)
		}
	})
	t.Run("map element missing and changed", func(t *testing.T) {
		rec := fresh()
		lk, _ := hasExpr[*expr.Lookup](rec.row(t, "nat_pre", Comment("r_valheim", "dnat")).Exprs)
		els := rec.sets[lk.SetName]
		// 2457 を消し、2458 の宛先のポートを変える
		rec.sets[lk.SetName] = []nftables.SetElement{els[0], {Key: els[2].Key, Val: []byte{192, 168, 1, 20, 0x0b, 0xff, 0, 0}}}
		ins := inspect(rec)
		wantMissing := []AgentDNAT{{RuleID: "r_valheim", Proto: proto.UDP, Ports: pr(2457, 2458), Dest: netip.MustParseAddrPort("192.168.1.20:3001")}}
		wantExtra := []AgentDNAT{{RuleID: "r_valheim", Proto: proto.UDP, Ports: pr(2458, 2458), Dest: netip.MustParseAddrPort("192.168.1.20:3071")}}
		if !reflect.DeepEqual(ins.MissingDNATs, wantMissing) || !reflect.DeepEqual(ins.ExtraDNATs, wantExtra) {
			t.Errorf("missing %v extra %v; want %v and %v", ins.MissingDNATs, ins.ExtraDNATs, wantMissing, wantExtra)
		}
	})
	t.Run("rows without a wgft comment in nat_pre", func(t *testing.T) {
		rec := fresh()
		rec.rules["nat_pre"] = append(rec.rules["nat_pre"],
			&nftables.Rule{UserData: userdata.AppendString(nil, userdata.TypeComment, Comment("r_x", "dnat")),
				Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}})
		if ins := inspect(rec); ins.Unrecognized != 1 {
			t.Errorf("unrecognized = %d, want 1", ins.Unrecognized)
		}
	})
	t.Run("map read failure", func(t *testing.T) {
		rec := fresh()
		if _, err := inspectAgentOf(rec.dumps(), func(string) ([]nftables.SetElement, error) { return nil, errors.New("boom") }, pub, "wgft0"); err == nil {
			t.Error("a failed map read did not surface")
		}
	})
}

// rowGuards は、名前の付いた守りの行である(設計文書 10.2c 節の「dataplane.table の判定」)。何が開くかは、
// 欠けた行の組み合わせで読み手が決める。
var rowGuards = map[string]string{
	"filter_pre: drop the rest from wgft0":      GuardPreDrop,
	"input: drop the rest from wgft0":           GuardInputDrop,
	"forward: clamp the MSS of SYNs from wgft0": GuardMSS,
	"forward: clamp the MSS of SYNs to wgft0":   GuardMSS,
	"forward: drop wgft0 to wgft0":              GuardHairpinDrop,
	"forward: drop the rest from wgft0":         GuardForwardFromDrop,
	"forward: drop the rest to wgft0":           GuardForwardToDrop,
}

// 欠けた行とチェーンの役割は、欠けたときに転送が止まるかどうかで決まる(設計文書 10.2c 節の
// 「dataplane.table の判定」)。表はラボで行を 1 種類ずつ消して確かめた結果である。通す行は、同じ
// チェーンでそれが通さなければ落とす drop の行も欠けていれば、転送を止めない。
func TestInspectAgentRowRoles(t *testing.T) {
	pub := testAgentPublication()
	rows := agentRows(pub, "wgft0")
	drop := func(rec *agentRecorder, descs ...string) {
		t.Helper()
		for _, desc := range descs {
			var want agentRow
			for _, r := range rows {
				if r.desc == desc {
					want = r
				}
			}
			if want.desc == "" {
				t.Fatalf("no row %q", desc)
			}
			got := rec.rules[want.chain]
			for i, r := range got {
				comment, _ := userdata.GetString(r.UserData, userdata.TypeComment)
				if rowSig(comment, r.Exprs) == rowSig(want.comment, want.exprs) {
					rec.rules[want.chain] = append(append([]*nftables.Rule(nil), got[:i]...), got[i+1:]...)
					break
				}
			}
		}
	}
	dropChain := func(rec *agentRecorder, name string) {
		var kept []*nftables.Chain
		for _, c := range rec.chainObjs {
			if c.Name != name {
				kept = append(kept, c)
			}
		}
		rec.chainObjs = kept
	}
	type want map[string]RowRole
	for _, tc := range []struct {
		name  string
		edit  func(rec *agentRecorder)
		roles want
	}{
		{"filter_pre drop", func(r *agentRecorder) { drop(r, "filter_pre: drop the rest from wgft0") },
			want{"filter_pre: drop the rest from wgft0": RoleGuard}},
		{"filter_pre established", func(r *agentRecorder) { drop(r, "filter_pre: accept established and related flows from wgft0") },
			want{"filter_pre: accept established and related flows from wgft0": RoleGuard}},
		{"a pass row", func(r *agentRecorder) { drop(r, "filter_pre: accept tcp 25565 from wgft0 for rule r_mc") },
			want{"filter_pre: accept tcp 25565 from wgft0 for rule r_mc": RoleCarry}},
		{"a pass row and the drop", func(r *agentRecorder) {
			drop(r, "filter_pre: accept tcp 25565 from wgft0 for rule r_mc", "filter_pre: drop the rest from wgft0")
		}, want{"filter_pre: accept tcp 25565 from wgft0 for rule r_mc": RoleGuard, "filter_pre: drop the rest from wgft0": RoleGuard}},
		{"the filter_pre chain", func(r *agentRecorder) { dropChain(r, "filter_pre") },
			want{"chain filter_pre is missing": RoleGuard, "filter_pre: accept tcp 25565 from wgft0 for rule r_mc": RoleGuard}},
		{"input DNAT accept", func(r *agentRecorder) { drop(r, "input: accept DNATed flows from wgft0") },
			want{"input: accept DNATed flows from wgft0": RoleCarrySelf}},
		{"input DNAT accept and the drop", func(r *agentRecorder) {
			drop(r, "input: accept DNATed flows from wgft0", "input: drop the rest from wgft0")
		}, want{"input: accept DNATed flows from wgft0": RoleGuard, "input: drop the rest from wgft0": RoleGuard}},
		{"input established", func(r *agentRecorder) { drop(r, "input: accept established and related flows from wgft0") },
			want{"input: accept established and related flows from wgft0": RoleGuard}},
		{"the MSS rows", func(r *agentRecorder) {
			drop(r, "forward: clamp the MSS of SYNs from wgft0", "forward: clamp the MSS of SYNs to wgft0")
		}, want{"forward: clamp the MSS of SYNs from wgft0": RoleGuard, "forward: clamp the MSS of SYNs to wgft0": RoleGuard}},
		{"every guard drop", func(r *agentRecorder) {
			drop(r, "input: drop the rest from wgft0", "forward: drop the rest to wgft0", "filter_pre: drop the rest from wgft0")
		}, want{"input: drop the rest from wgft0": RoleGuard, "forward: drop the rest to wgft0": RoleGuard}},
		{"forward wgft0 to wgft0 drop", func(r *agentRecorder) { drop(r, "forward: drop wgft0 to wgft0") },
			want{"forward: drop wgft0 to wgft0": RoleGuard}},
		{"forward DNAT accept", func(r *agentRecorder) { drop(r, "forward: accept DNATed flows from wgft0") },
			want{"forward: accept DNATed flows from wgft0": RoleCarryLAN}},
		{"forward DNAT accept and its drop", func(r *agentRecorder) {
			drop(r, "forward: accept DNATed flows from wgft0", "forward: drop the rest from wgft0")
		}, want{"forward: accept DNATed flows from wgft0": RoleGuard, "forward: drop the rest from wgft0": RoleGuard}},
		{"forward established", func(r *agentRecorder) { drop(r, "forward: accept established and related flows to wgft0") },
			want{"forward: accept established and related flows to wgft0": RoleCarryLAN}},
		{"forward established and its drop", func(r *agentRecorder) {
			drop(r, "forward: accept established and related flows to wgft0", "forward: drop the rest to wgft0")
		}, want{"forward: accept established and related flows to wgft0": RoleGuard, "forward: drop the rest to wgft0": RoleGuard}},
		{"the forward chain", func(r *agentRecorder) { dropChain(r, "forward") },
			want{"chain forward is missing": RoleGuard, "forward: accept DNATed flows from wgft0": RoleGuard}},
		{"the masquerade", func(r *agentRecorder) {
			drop(r, "postrouting: masquerade DNATed flows from wgft0 leaving by another interface")
		}, want{"postrouting: masquerade DNATed flows from wgft0 leaving by another interface": RoleCarryLAN}},
		{"the postrouting chain", func(r *agentRecorder) { dropChain(r, "postrouting") },
			want{"chain postrouting is missing": RoleCarryLAN, "postrouting: masquerade DNATed flows from wgft0 leaving by another interface": RoleCarryLAN}},
		{"the nat_pre chain", func(r *agentRecorder) { dropChain(r, "nat_pre") },
			want{"chain nat_pre is missing": RoleCarry, "nat_pre: DNAT row of rule r_mc": RoleCarry}},
		// map から要素が消えた範囲のルールは、行があっても DNAT が欠けている
		{"a map element", func(r *agentRecorder) { r.sets["__map0"] = r.sets["__map0"][1:] },
			want{"DNAT udp 2456 of rule r_valheim to 192.168.1.20:3000": RoleCarry}},
		{"a chain with another priority", func(r *agentRecorder) {
			for _, c := range r.chainObjs {
				if c.Name == "input" {
					c.Priority = nftables.ChainPriorityRef(0)
				}
			}
		}, want{"chain input is not a filter chain on its hook at priority -10 with policy accept": RoleCarry}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := emitAgentForTest(t, pub)
			tc.edit(rec)
			ins, err := inspectAgentOf(rec.dumps(), rec.elems, pub, "wgft0")
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]RowRole{}
			for _, m := range ins.MissingItems {
				got[m.Desc] = m.Role
			}
			for _, m := range ins.MissingItems {
				if m.Guard != rowGuards[m.Desc] {
					t.Errorf("%q: guard %q, want %q", m.Desc, m.Guard, rowGuards[m.Desc])
				}
			}
			for desc, role := range tc.roles {
				if r, ok := got[desc]; !ok || r != role {
					t.Errorf("%q: role %d (present %v), want %d; all: %v", desc, r, ok, role, ins.MissingItems)
				}
			}
			if len(ins.MissingItems) < len(ins.Missing) {
				t.Errorf("%d missing items for %d missing rows", len(ins.MissingItems), len(ins.Missing))
			}
		})
	}
}

// 期待する行が同じチェーンの別の位置にあれば、欠けたのではなく位置が違う(設計文書 10.2c 節)。drop の行を
// チェーンの先頭へ移した表は、欠けた行を持たず、位置の違う行を持つ。
func TestInspectAgentMovedRows(t *testing.T) {
	pub := testAgentPublication()
	for _, tc := range []struct {
		chain, desc string
	}{
		{"filter_pre", "filter_pre: drop the rest from wgft0"},
		{"forward", "forward: drop the rest from wgft0"},
		{"input", "input: drop the rest from wgft0"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			rec := emitAgentForTest(t, pub)
			rows := rec.rules[tc.chain]
			var want agentRow
			for _, r := range agentRows(pub, "wgft0") {
				if r.desc == tc.desc {
					want = r
				}
			}
			moved := false
			for i, r := range rows {
				comment, _ := userdata.GetString(r.UserData, userdata.TypeComment)
				if rowSig(comment, r.Exprs) == rowSig(want.comment, want.exprs) {
					rest := append(append([]*nftables.Rule(nil), rows[:i]...), rows[i+1:]...)
					rec.rules[tc.chain] = append([]*nftables.Rule{r}, rest...)
					moved = true
					break
				}
			}
			if !moved {
				t.Fatalf("no row %q", tc.desc)
			}
			ins, err := inspectAgentOf(rec.dumps(), rec.elems, pub, "wgft0")
			if err != nil {
				t.Fatal(err)
			}
			if len(ins.Missing) != 0 || len(ins.MissingItems) != 0 || len(ins.Unexpected) != 0 {
				t.Errorf("missing %v, unexpected %v; want none for a row that only moved", ins.Missing, ins.Unexpected)
			}
			if len(ins.Moved) != 1 || !strings.HasPrefix(ins.Moved[0], tc.desc+", now at row 1") || ins.Matches() {
				t.Errorf("moved = %v, want %q at row 1", ins.Moved, tc.desc)
			}
		})
	}
}

// map に加わった要素は、wgft が書いた形の行から読んだ DNAT として ExtraDNATsInPlace に入る。加わった行が
// 同時にあっても消えない。加わった DNAT の行から読んだ DNAT は入らない。
func TestInspectAgentExtraDNATsInPlace(t *testing.T) {
	full := testAgentPublication()
	// 記録は r_partial の 7002 を持たず、表の map には 7002 の要素がある
	want := testAgentPublication()
	for i, r := range want.Rules {
		if r.RuleID == "r_partial" {
			want.Rules[i].Ranges = r.Ranges[:1]
		}
	}
	rec := emitAgentForTest(t, full)
	rec.rules["nat_pre"] = append(rec.rules["nat_pre"], &nftables.Rule{Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}})
	ins, err := inspectAgentOf(rec.dumps(), rec.elems, want, "wgft0")
	if err != nil {
		t.Fatal(err)
	}
	if len(ins.ExtraDNATsInPlace) != 1 || ins.ExtraDNATsInPlace[0].Ports.Lo != 7002 || !slices.Contains(ins.Unexpected, "chain nat_pre: row 4 is not one wgft writes") {
		t.Errorf("extra in place %v, unexpected %v; want the 7002 element and the added row", ins.ExtraDNATsInPlace, ins.Unexpected)
	}

	// 加わった DNAT の行は Unexpected に入り、その DNAT は ExtraDNATsInPlace に入らない
	extraRule := AgentPublication{Rules: []AgentRuleResult{{RuleID: "r_extra", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 9999, Hi: 9999},
		Target: "192.168.1.9:9999", Ranges: []AgentRange{{Ports: proto.PortRange{Lo: 9999, Hi: 9999}, Dest: netip.MustParseAddrPort("192.168.1.9:9999")}}}}}
	withExtra := testAgentPublication()
	withExtra.Rules = append(withExtra.Rules, extraRule.Rules...)
	rec = emitAgentForTest(t, withExtra)
	ins, err = inspectAgentOf(rec.dumps(), rec.elems, full, "wgft0")
	if err != nil {
		t.Fatal(err)
	}
	if len(ins.ExtraDNATs) == 0 || len(ins.ExtraDNATsInPlace) != 0 || len(ins.Unexpected) == 0 {
		t.Errorf("extra %v, in place %v, unexpected %v; want the added row's DNAT only in ExtraDNATs", ins.ExtraDNATs, ins.ExtraDNATsInPlace, ins.Unexpected)
	}
}

// 1 行を移しただけの表では、動いていない行ではなく移した行を、位置の違う行として名指す(最長共通部分列の
// 照合)。filter_pre の成立済みのフローを通す行を末尾へ移すと、名指されるのはその行だけである。
func TestInspectAgentNamesTheRowThatMoved(t *testing.T) {
	pub := testAgentPublication()
	rec := emitAgentForTest(t, pub)
	rows := rec.rules["filter_pre"]
	rec.rules["filter_pre"] = append(append([]*nftables.Rule(nil), rows[1:]...), rows[0])
	ins, err := inspectAgentOf(rec.dumps(), rec.elems, pub, "wgft0")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("filter_pre: accept established and related flows from wgft0, now at row %d", len(rows))
	if !reflect.DeepEqual(ins.Moved, []string{want}) || len(ins.Missing) != 0 || len(ins.Unexpected) != 0 {
		t.Errorf("moved %v missing %v unexpected %v; want only %q", ins.Moved, ins.Missing, ins.Unexpected, want)
	}
}

// 表が大きすぎて最長共通部分列を取らないチェーンでは、先頭から順の照合に切り替える。並びが同じなら
// すべて対応し、先頭の行を末尾へ移した場合は、先頭の行だけが末尾に対応して残りは対応しない。移した行の
// 名指しが粗くなるだけで、欠けと位置の違いの区別は保たれる。
func TestAlignRowsFallsBackForLargeChains(t *testing.T) {
	big := make([]string, 3000)
	for i := range big {
		big[i] = fmt.Sprint(i)
	}
	same := alignRows(big, big)
	for i, j := range same {
		if j != i {
			t.Fatalf("identical chains: row %d aligned to %d", i, j)
		}
	}
	got := append(append([]string(nil), big[1:]...), big[0])
	out := alignRows(big, got)
	if out[0] != len(big)-1 || out[1] != -1 {
		t.Errorf("greedy fallback = %v...", out[:3])
	}
	small := alignRows([]string{"a", "b", "c", "d"}, []string{"b", "c", "d", "a"})
	if !reflect.DeepEqual(small, []int{-1, 0, 1, 2}) {
		t.Errorf("alignment = %v, want a moved to the end and the rest in order", small)
	}
}

// DNAT の行が欠けたルールの宛先は、その行の欠けとして 1 件に数える。行が無ければ宛先も必ず無いためである。
func TestInspectAgentCountsAMissingDNATRowOnce(t *testing.T) {
	pub := testAgentPublication()
	rec := emitAgentForTest(t, pub)
	var kept []*nftables.Rule
	for _, r := range rec.rules["nat_pre"] {
		comment, _ := userdata.GetString(r.UserData, userdata.TypeComment)
		if comment != Comment("r_mc", DNATKind) {
			kept = append(kept, r)
		}
	}
	rec.rules["nat_pre"] = kept
	ins, err := inspectAgentOf(rec.dumps(), rec.elems, pub, "wgft0")
	if err != nil {
		t.Fatal(err)
	}
	if len(ins.MissingItems) != 1 || ins.MissingItems[0].Desc != "nat_pre: DNAT row of rule r_mc" || len(ins.MissingDNATs) != 1 {
		t.Errorf("missing items %v, missing DNATs %v; want the row once, and the DNAT kept for Matches", ins.MissingItems, ins.MissingDNATs)
	}
}
