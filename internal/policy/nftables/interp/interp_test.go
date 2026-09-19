package interp

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/policy"
	polnft "github.com/rahanahu/wgft/internal/policy/nftables"
	"github.com/rahanahu/wgft/proto"
)

// 共有 fixture が覆わない、meter の期限と set の大きさを、手で組んだ行の列で確かめる。

func udpRow(kind string, ctNew bool, st polnft.Stmt) polnft.Row {
	return polnft.Row{RuleID: "r", Kind: kind, Comment: polnft.Comment("r", kind),
		Match: polnft.Match{Proto: proto.UDP, Ports: proto.PortRange{Lo: 53, Hi: 53}, CtStateNew: ctNew}, Stmt: st}
}

func pkt(src, flow string) Packet {
	return Packet{Proto: proto.UDP, DstPort: 53, Src: netip.MustParseAddr(src), Flow: flow}
}

func mustEval(t *testing.T, in *Interpreter, now time.Duration, p Packet) bool {
	t.Helper()
	v, err := in.Eval(now, p)
	if err != nil {
		t.Fatal(err)
	}
	return v.Dropped
}

// meter の要素は add で作った時点から timeout で消え、消えた後は満杯のバケットで作り直される。
func TestMeterElementExpires(t *testing.T) {
	r := proto.Rate{Count: 1, Unit: proto.PerHour}
	prog := polnft.Program{
		Sets: []polnft.Set{{Name: "meter_1", Kind: polnft.SetMeter, Timeout: policy.PerSourceTableTTL, Size: 10}},
		Rows: []polnft.Row{udpRow("per_source", true, polnft.Stmt{Kind: polnft.StmtPerSourceLimit, Set: "meter_1", Rate: r, Burst: 2})},
	}
	in, err := New(prog)
	if err != nil {
		t.Fatal(err)
	}
	src := "198.51.100.1"
	if mustEval(t, in, 0, pkt(src, "f1")) || mustEval(t, in, 0, pkt(src, "f2")) {
		t.Fatal("the first two flows must pass (burst 2)")
	}
	if !mustEval(t, in, 59*time.Second, pkt(src, "f3")) {
		t.Fatal("a third flow within the element's lifetime must be dropped")
	}
	if mustEval(t, in, 60*time.Second, pkt(src, "f4")) {
		t.Fatal("after the timeout the element is recreated with a full bucket")
	}
}

// set が size まで埋まると新しい送信元の add が失敗し、その行は一致しない(制限が外れる)。
func TestFullSetsStopMatching(t *testing.T) {
	r := proto.Rate{Count: 1, Unit: proto.PerHour}
	prog := polnft.Program{
		Sets: []polnft.Set{
			{Name: "meter_1", Kind: polnft.SetMeter, Timeout: time.Minute, Size: 1},
			{Name: "flows_udp", Kind: polnft.SetFlowCount, Size: 1},
		},
		Rows: []polnft.Row{
			udpRow("per_source", true, polnft.Stmt{Kind: polnft.StmtPerSourceLimit, Set: "meter_1", Rate: r, Burst: 1}),
			udpRow("src_flow", true, polnft.Stmt{Kind: polnft.StmtPerSourceCtCount, Set: "flows_udp", Count: 1}),
		},
	}
	in, err := New(prog)
	if err != nil {
		t.Fatal(err)
	}
	if mustEval(t, in, 0, pkt("198.51.100.1", "a1")) {
		t.Fatal("first flow must pass")
	}
	if !mustEval(t, in, 0, pkt("198.51.100.1", "a2")) {
		t.Fatal("second flow of the same source must be dropped by per_source")
	}
	// 別の送信元は、どちらの set にも入れないので、どちらの行にも一致しない
	for i := range 3 {
		if mustEval(t, in, 0, pkt("198.51.100.2", fmt.Sprintf("b%d", i))) {
			t.Fatalf("flow b%d: a source that cannot be added to a full set must not be limited", i)
		}
	}
}

// 集約の limit は nft_limit と同じ整数のナノ秒で補充する。
func TestBucketRefill(t *testing.T) {
	b, err := newBucket(proto.Rate{Count: 3, Unit: proto.PerSecond}, 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if b.over(0) {
			t.Fatalf("packet %d within the burst was over", i)
		}
	}
	if !b.over(0) {
		t.Fatal("the sixth packet at t=0 must be over")
	}
	// 費用は 1e9/3 = 333333333ns。その 1ns 前は足りず、ちょうどで足りる
	if !b.over(333333332) {
		t.Fatal("one token is not refilled 1ns before the cost")
	}
	if b.over(333333333) {
		t.Fatal("one token is refilled after exactly the cost")
	}
}

// meta nfproto ipv4 を持つ集約の limit の行は IPv6 のパケットに一致せず、トークンを使わない。
// 持たない行は IPv6 のパケットにも一致する(inet のテーブルの挙動)。
func TestIPv4MatchKeepsIPv6OffAggregateLimits(t *testing.T) {
	r := proto.Rate{Count: 1, Unit: proto.PerHour}
	for _, v4 := range []bool{true, false} {
		row := udpRow("new_flow", true, polnft.Stmt{Kind: polnft.StmtLimit, Rate: r, Burst: 1})
		row.Match.IPv4 = v4
		in, err := New(polnft.Program{Rows: []polnft.Row{row}})
		if err != nil {
			t.Fatal(err)
		}
		v6 := Packet{Proto: proto.UDP, DstPort: 53, Src: netip.MustParseAddr("2001:db8::1"), Flow: "v6"}
		if mustEval(t, in, 0, v6) {
			t.Fatalf("IPv4=%v: the IPv6 packet was dropped before the bucket was spent", v4)
		}
		// burst 1:IPv6 のパケットがトークンを使っていなければ、IPv4 のフローが通る
		if got := mustEval(t, in, 0, pkt("198.51.100.1", "a1")); got != !v4 {
			t.Errorf("IPv4=%v: the IPv4 flow after an IPv6 one dropped = %v, want %v", v4, got, !v4)
		}
	}
}
