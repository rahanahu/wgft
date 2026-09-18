package proto

import (
	"net/netip"
	"testing"
)

// TestRuleSplit は分割の境界条件と、実効宛先が変わらないことを確かめる(仕様 5.4、7 節)。
func TestRuleSplit(t *testing.T) {
	r := validRule() // UDP 2456-2457 -> 192.168.1.20:2456

	head, tail, err := r.Split(PortRange{2457, 2457}, "r_tail")
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if head.ID != r.ID || head.ListenPort != (PortRange{2456, 2456}) || head.Target != r.Target {
		t.Errorf("head = %+v", head)
	}
	if tail.ID != "r_tail" || tail.ListenPort != (PortRange{2457, 2457}) || tail.Target != "192.168.1.20:2457" {
		t.Errorf("tail = %+v", tail)
	}

	for _, tt := range []struct {
		name string
		at   PortRange
	}{
		{"範囲でなく単一ポート", PortRange{2457, 2458}},
		{"先頭ポートそのもの", PortRange{2456, 2456}},
		{"範囲の外", PortRange{2458, 2458}},
	} {
		if _, _, err := r.Split(tt.at, "r_tail"); err == nil {
			t.Errorf("%s: Split(%v) succeeded, want error", tt.name, tt.at)
		}
	}
}

// TestRuleSplitProxyRange は、vps_mode=proxy のルールの分割が、両側とも単一ポートになる
// 場合(2 ポートの範囲を境界で割る)だけ受け付け、片側でも範囲が残る分割(3 ポート以上の
// 範囲。単一ポート運用にする前から保存されていた既存データとしてしか存在しえない)は
// 拒否することを確かめる(5.4 節)。
func TestRuleSplitProxyRange(t *testing.T) {
	twoWide := validRule()
	twoWide.Proto, twoWide.VPSMode = TCP, ModeProxy
	twoWide.ListenPort, twoWide.Target = PortRange{443, 444}, "192.168.1.20:443"

	head, tail, err := twoWide.Split(PortRange{444, 444}, "r_tail")
	if err != nil {
		t.Fatalf("splitting a 2-wide proxy range at its only valid point must succeed: %v", err)
	}
	if head.ListenPort.IsRange() || tail.ListenPort.IsRange() {
		t.Errorf("both pieces must be single ports: head=%v tail=%v", head.ListenPort, tail.ListenPort)
	}

	threeWide := validRule()
	threeWide.Proto, threeWide.VPSMode = TCP, ModeProxy
	threeWide.ListenPort, threeWide.Target = PortRange{443, 445}, "192.168.1.20:443"

	for _, at := range []PortRange{{444, 444}, {445, 445}} {
		if _, _, err := threeWide.Split(at, "r_tail"); err == nil {
			t.Errorf("splitting a 3-wide proxy range at %v must fail (one side would stay a range)", at)
		}
	}
}

// TestMerge は統合が self の ID・その他の項目を保ち、listen_port と実効宛先だけを広げることを
// 確かめる。id1/id2 のどちらが下位ポートかに関わらず self が残る(仕様 10.1、10.2 節)。
func TestMerge(t *testing.T) {
	a := validRule() // r_1, UDP 2456-2457 -> 192.168.1.20:2456
	a.Group, a.Note = "valheim", "weekend"
	b := a
	b.ID, b.ListenPort, b.Target = "r_2", PortRange{2458, 2459}, "192.168.1.20:2458"

	merged, err := Merge(a, b)
	if err != nil {
		t.Fatalf("Merge(a, b): %v", err)
	}
	if merged.ID != a.ID || merged.Group != a.Group || merged.Note != a.Note {
		t.Errorf("merged identity = %+v, want a's", merged)
	}
	if merged.ListenPort != (PortRange{2456, 2459}) || merged.Target != a.Target {
		t.Errorf("merged range/target = %v %q, want 2456-2459 / %q", merged.ListenPort, merged.Target, a.Target)
	}

	// 順序を逆にしても、self(この場合は b)の ID が残る。
	merged, err = Merge(b, a)
	if err != nil {
		t.Fatalf("Merge(b, a): %v", err)
	}
	if merged.ID != b.ID {
		t.Errorf("Merge(b, a).ID = %q, want %q", merged.ID, b.ID)
	}
	if merged.ListenPort != (PortRange{2456, 2459}) || merged.Target != a.Target {
		t.Errorf("merged range/target = %v %q, want 2456-2459 / %q (the lower rule's)", merged.ListenPort, merged.Target, a.Target)
	}
}

// TestFindMergeBlocker は、統合できない理由の判定を、CLI が古くから見ていた核の条件
// (エージェント、プロトコル、方式、隣接、実効宛先の連続)と、Web UI が候補を絞るために
// 追加で見る項目(proxy_protocol、拒否/許可リスト、レート、enabled)の両方について確かめる。
// 各ケースは validRule() から作った、隙間なく揃った a・b の組を、b だけ 1 項目変えて使う
// (a を直接書き換えると次のケースに漏れるため)。
func TestFindMergeBlocker(t *testing.T) {
	pair := func() (a, b Rule) {
		a = validRule() // r_1, UDP 2456-2457 -> 192.168.1.20:2456
		b = a
		b.ID, b.ListenPort, b.Target = "r_2", PortRange{2458, 2459}, "192.168.1.20:2458"
		return a, b
	}

	a, b := pair()
	if blk := FindMergeBlocker(a, b); blk != BlockNone {
		t.Errorf("matching neighbor: FindMergeBlocker = %q, want BlockNone", blk)
	}

	cases := []struct {
		name   string
		mutate func(a, b *Rule)
		want   MergeBlocker
	}{
		{"agent が違う", func(a, b *Rule) { b.Agent = "office" }, BlockAgent},
		{"proto が違う", func(a, b *Rule) { b.Proto = TCP }, BlockProto},
		{"vps_mode が違う(TCP の組で proxy/kernel を混ぜる)", func(a, b *Rule) {
			a.Proto, b.Proto = TCP, TCP
			b.VPSMode = ModeProxy
		}, BlockMode},
		{"隣接していない", func(a, b *Rule) { b.ListenPort = PortRange{2470, 2471} }, BlockNotAdjacent},
		{"実効宛先が連続していない", func(a, b *Rule) { b.Target = "192.168.1.20:9999" }, BlockTargetGap},
		// vps_mode=proxy はどんな 2 つの組でも統合できない(統合すると必ず範囲になり、
		// proxy は単一ポート運用のため)。この組み合わせは差がある値(旧テストは
		// proxy_protocol)を問わず BlockProxyRange が先に返る。proxy_protocol は
		// vps_mode=proxy でしか立てられない(Rule.Validate)ので、BlockProxyProtocol は
		// 有効なルールの組では実質到達しない
		{"proxy はどんな組でも統合できない(TCP proxy の組で片方だけ proxy_protocol を付ける)", func(a, b *Rule) {
			a.Proto, b.Proto = TCP, TCP
			a.VPSMode, b.VPSMode = ModeProxy, ModeProxy
			b.ProxyProtocol = true
		}, BlockProxyRange},
		{"proxy はどんな組でも統合できない(他の値がすべて揃っていても)", func(a, b *Rule) {
			a.Proto, b.Proto = TCP, TCP
			a.VPSMode, b.VPSMode = ModeProxy, ModeProxy
		}, BlockProxyRange},
		{"拒否リストが違う", func(a, b *Rule) { b.SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")} }, BlockDenyList},
		{"許可リストが違う", func(a, b *Rule) { b.SourceAllow = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")} }, BlockAllowList},
		// 旧い CLI が許していた重複エントリがあっても、長さだけでなく重複を払った内容で比べる
		// (a は同じ CIDR を 2 度、b は別の CIDR を含むので、実際には異なる集合)。
		{"拒否リストに重複があり、長さは同じでも内容が違う", func(a, b *Rule) {
			a.SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("203.0.113.0/24")}
			b.SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("198.51.100.0/24")}
		}, BlockDenyList},
		{"レートが違う", func(a, b *Rule) { r := Rate{Count: 10, Unit: PerSecond}; b.NewFlowRate = &r }, BlockRates},
		{"enabled が違う", func(a, b *Rule) { b.Enabled = false }, BlockEnabled},
	}
	for _, tt := range cases {
		a, b := pair()
		tt.mutate(&a, &b)
		if got := FindMergeBlocker(a, b); got != tt.want {
			t.Errorf("%s: FindMergeBlocker(a, b) = %q, want %q", tt.name, got, tt.want)
		}
		if got := FindMergeBlocker(b, a); got != tt.want {
			t.Errorf("%s (順序を逆に): FindMergeBlocker(b, a) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// TestMergeRejectsBlocked は、FindMergeBlocker が理由を返す組み合わせで Merge も
// 誤りを返すこと(統合の実行そのものが、Web UI が候補を絞る条件と同じ集合で守られること)を確かめる。
func TestMergeRejectsBlocked(t *testing.T) {
	a := validRule()
	b := a
	b.ID, b.ListenPort, b.Target = "r_2", PortRange{2458, 2459}, "192.168.1.20:2458"
	b.SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}

	if _, err := Merge(a, b); err == nil {
		t.Fatal("Merge with a differing deny list succeeded, want an error naming the reason")
	}
}
