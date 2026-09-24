//go:build lab && linux

package nft

// 大きな送信元の一覧の set をカーネルに載せるテスト(設計文書 6.1 節)。ラボの vps ns で root として
// 実行する(lab/lab test internal/dataplane/linuxkernel/nft vps -test.run TestLabSourceList)。
// 送信元の一覧は 100.64.0.0/10 の中に 4 つおきに並べた /32 で、隣り合わないので区間 1 つが /32 1 つになる。
// 通信の確かめには、使い捨ての netns を veth でつなぎ、一覧のアドレスを実際に持たせて UDP を 1 つ送る。

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"

	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

const (
	probeNS       = "wgftsetprobe"
	probeHostIF   = "vsetprobe0"
	probePeerIF   = "vsetprobe1"
	probeHostAddr = "100.127.255.254" // 一覧(100.64.0.0 から 4 つおき)に入らない
)

var labListBase = netip.MustParseAddr("100.64.0.0")

func requireRootAndNft(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root が必要")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft がない")
	}
}

// sourceListPlan は、送信元の一覧 prefixes を deny か allow に持つ UDP のルール 1 本の Plan である。
func sourceListPlan(t *testing.T, kind string, prefixes []netip.Prefix, port uint16) planner.Plan {
	t.Helper()
	r := proto.Rule{ID: "r_list", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: port, Hi: port},
		Target: "192.168.1.20:9999", VPSMode: proto.ModeKernel, Enabled: true}
	if kind == "deny" {
		r.SourceDeny = prefixes
	} else {
		r.SourceAllow = prefixes
	}
	return planFromRules(t, []proto.Rule{r}, map[string]netip.Addr{"home": netip.MustParseAddr("10.200.0.2")}, policy.AdmissionLimits{})
}

// kernelSetElements は set の要素をカーネルから読む(google/nftables の GetSetElements)。
func kernelSetElements(t *testing.T, name string) []nftables.SetElement {
	t.Helper()
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	els, err := c.GetSetElements(&nftables.Set{Table: &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}, Name: name})
	if err != nil {
		t.Fatalf("GetSetElements %s: %v", name, err)
	}
	return els
}

// nftSetCount は `nft -j list set` が示す set の要素の数(nft は区間 1 つを 1 要素として示す)。
func nftSetCount(t *testing.T, name string) int {
	t.Helper()
	out, err := exec.Command("nft", "-j", "list", "set", "inet", TableName, name).CombinedOutput()
	if err != nil {
		t.Fatalf("nft -j list set %s: %v\n%.2000s", name, err, out)
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("nft -j list set %s: %v", name, err)
	}
	for _, item := range doc.Nftables {
		raw, ok := item["set"]
		if !ok {
			continue
		}
		var set struct {
			Elem []json.RawMessage `json:"elem"`
		}
		if err := json.Unmarshal(raw, &set); err != nil {
			t.Fatal(err)
		}
		return len(set.Elem)
	}
	t.Fatalf("nft -j list set %s: no set in the output", name)
	return 0
}

// rowPackets は filter_pre のうちコメントが comment の行のカウンタの値である。
func rowPackets(t *testing.T, comment string) uint64 {
	t.Helper()
	out, err := exec.Command("nft", "-j", "list", "chain", "inet", TableName, "filter_pre").CombinedOutput()
	if err != nil {
		t.Fatalf("nft -j list chain filter_pre: %v\n%s", err, out)
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	for _, item := range doc.Nftables {
		raw, ok := item["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Comment string                       `json:"comment"`
			Expr    []map[string]json.RawMessage `json:"expr"`
		}
		if err := json.Unmarshal(raw, &rule); err != nil {
			t.Fatal(err)
		}
		if rule.Comment != comment {
			continue
		}
		for _, e := range rule.Expr {
			if c, ok := e["counter"]; ok {
				var counter struct {
					Packets uint64 `json:"packets"`
				}
				if err := json.Unmarshal(c, &counter); err != nil {
					t.Fatal(err)
				}
				return counter.Packets
			}
		}
	}
	t.Fatalf("filter_pre has no row with comment %q", comment)
	return 0
}

func mustRun(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// probeLink は、使い捨ての netns を veth でこの netns につなぐ。100.64.0.0/10 を両端に置くので、
// 一覧のどのアドレスを持たせても、この netns の probeHostAddr へ直接届く。
func probeLink(t *testing.T) {
	t.Helper()
	cleanup := func() {
		_ = exec.Command("ip", "netns", "del", probeNS).Run()
		_ = exec.Command("ip", "link", "del", probeHostIF).Run()
	}
	cleanup()
	t.Cleanup(cleanup)
	mustRun(t, "ip", "netns", "add", probeNS)
	mustRun(t, "ip", "link", "add", probeHostIF, "type", "veth", "peer", "name", probePeerIF)
	mustRun(t, "ip", "link", "set", probePeerIF, "netns", probeNS)
	mustRun(t, "ip", "addr", "add", probeHostAddr+"/10", "dev", probeHostIF)
	mustRun(t, "ip", "link", "set", probeHostIF, "up")
	mustRun(t, "ip", "netns", "exec", probeNS, "ip", "link", "set", probePeerIF, "up")
}

// sendFrom は、使い捨ての netns のアドレスを from に置き換えて、probeHostAddr の port へ UDP を 1 つ送る。
// 送信元のアドレスは偽装ではなく、そのインタフェースが実際に持つアドレスである。
func sendFrom(t *testing.T, from netip.Addr, port uint16) {
	t.Helper()
	mustRun(t, "ip", "netns", "exec", probeNS, "ip", "addr", "flush", "dev", probePeerIF)
	mustRun(t, "ip", "netns", "exec", probeNS, "ip", "addr", "add", from.String()+"/10", "dev", probePeerIF)
	send := fmt.Sprintf("exec 3<>/dev/udp/%s/%d; echo probe >&3; exec 3>&-", probeHostAddr, port)
	mustRun(t, "ip", "netns", "exec", probeNS, "bash", "-c", send)
	time.Sleep(200 * time.Millisecond)
}

// dropped は、from から送った UDP が行 comment に落とされたか(行のカウンタが進んだか)を返す。
func dropped(t *testing.T, comment string, from netip.Addr, port uint16) bool {
	t.Helper()
	before := rowPackets(t, comment)
	sendFrom(t, from, port)
	return rowPackets(t, comment) > before
}

// 送信元の一覧が netlink の属性の 16 ビットの長さを超える大きさでも、set は一覧のすべてを持ち、
// 一覧の最後のアドレスからのパケットは deny なら落ち、allow なら通る。一覧に無いアドレスは逆になる
// (対照)。以前は 1638 個で set が空、1700 個で 62 要素になり、5000 個でバッチ全体が拒まれた。
func TestLabSourceListSizes(t *testing.T) {
	requireRootAndNft(t)
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		t.Logf("kernel %s", strings.TrimSpace(string(out)))
	}
	probeLink(t)
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", TableName).Run() })
	for _, kind := range []string{"deny", "allow"} {
		for _, n := range []int{1637, 1638, 1700, 5000, 20000} {
			t.Run(fmt.Sprintf("%s_%d", kind, n), func(t *testing.T) {
				port := uint16(21000 + n%10000)
				prefixes := spreadPrefixes(labListBase, n)
				plan := sourceListPlan(t, kind, prefixes, port)
				start := time.Now()
				if err := Apply(plan, nil, Config{WGInterface: "wg0"}); err != nil {
					t.Fatalf("Apply: %v", err)
				}
				t.Logf("Apply of %d prefixes took %v", n, time.Since(start))
				set := kind + "_1"
				if got, want := len(kernelSetElements(t, set)), len(intervalElements(prefixes)); got != want {
					t.Errorf("GetSetElements %s: %d elements, want %d", set, got, want)
				}
				if got := nftSetCount(t, set); got != n {
					t.Errorf("nft -j list set %s: %d elements, want %d", set, got, n)
				}
				comment := Comment("r_list", kind)
				last := prefixes[n-1].Addr()
				unlisted := last.Next() // 4 つおきなので一覧に無い
				if got, want := dropped(t, comment, last, port), kind == "deny"; got != want {
					t.Errorf("a packet from %s, the last listed address: dropped by the %s row = %v, want %v", last, kind, got, want)
				}
				if got, want := dropped(t, comment, unlisted, port), kind == "allow"; got != want {
					t.Errorf("a packet from %s, not listed: dropped by the %s row = %v, want %v", unlisted, kind, got, want)
				}
			})
		}
	}
}

// withoutChunks は、要素を 1 通にまとめて送る以前の組み立てを、テストの間だけ再現する。
func withoutChunks(t *testing.T) {
	t.Helper()
	saved := elemsPerMessage
	elemsPerMessage = 1 << 30
	t.Cleanup(func() { elemsPerMessage = saved })
}

// 以前の組み立て(要素を 1 通にまとめて送る)で set の要素が黙って欠けると、Flush の読み直しが
// それを見つけて誤りを返す。カーネルは誤りを返さずに差し替えを受け入れるので、この検査が無ければ
// Apply は成功していた。
func TestLabVerifyCatchesDroppedElements(t *testing.T) {
	requireRootAndNft(t)
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", TableName).Run() })
	withoutChunks(t)
	for _, kind := range []string{"deny", "allow"} {
		for _, n := range []int{1638, 1700} {
			t.Run(fmt.Sprintf("%s_%d", kind, n), func(t *testing.T) {
				_ = exec.Command("nft", "delete", "table", "inet", TableName).Run()
				prefixes := spreadPrefixes(labListBase, n)
				err := Apply(sourceListPlan(t, kind, prefixes, 22000), nil, Config{WGInterface: "wg0"})
				if err == nil || !strings.Contains(err.Error(), "does not hold what was sent") {
					t.Fatalf("Apply without chunks: %v, want the read-back to report missing elements", err)
				}
				t.Logf("Apply without chunks: %v", err)
				t.Logf("the kernel holds %d elements of %s_1 after the failed Apply", len(kernelSetElements(t, kind+"_1")), kind)
			})
		}
	}
}

// 差し替えが失敗しても、直前に公開した良いテーブルが残る。失敗は、以前の組み立てで 5000 個の
// 一覧を 1 通にまとめて送り、カーネルにバッチ全体を拒ませて起こす。
func TestLabFailedUpdateKeepsTheTable(t *testing.T) {
	requireRootAndNft(t)
	probeLink(t)
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", TableName).Run() })
	const port = 23000
	good := spreadPrefixes(labListBase, 10)
	if err := Apply(sourceListPlan(t, "deny", good, port), nil, Config{WGInterface: "wg0"}); err != nil {
		t.Fatalf("Apply of the good table: %v", err)
	}
	before, present, err := Fingerprint()
	if err != nil || !present {
		t.Fatalf("Fingerprint of the good table: %v, present=%v", err, present)
	}

	withoutChunks(t)
	bad := spreadPrefixes(netip.MustParseAddr("100.80.0.0"), 5000)
	err = Apply(sourceListPlan(t, "deny", bad, port+1), nil, Config{WGInterface: "wg0"})
	if err == nil {
		t.Fatal("Apply of 5000 prefixes in one message succeeded; this test no longer provokes a refused batch")
	}
	if strings.Contains(err.Error(), "does not hold what was sent") {
		t.Fatalf("Apply failed on the read-back, so the kernel took the batch: %v", err)
	}
	t.Logf("Apply of the refused batch: %v", err)

	after, present, err := Fingerprint()
	if err != nil || !present {
		t.Fatalf("Fingerprint after the failed update: %v, present=%v", err, present)
	}
	if after != before {
		t.Errorf("the table changed although the update failed\n%s", nftList(t))
	}
	if got, want := len(kernelSetElements(t, "deny_1")), len(intervalElements(good)); got != want {
		t.Errorf("deny_1 holds %d elements after the failed update, want %d", got, want)
	}
	if !dropped(t, Comment("r_list", "deny"), good[9].Addr(), port) {
		t.Error("a packet from a denied address passes after the failed update")
	}
}

// 区間の形の端の場合も、読み直しの検査を通り、set が送った要素をすべて持つ。0.0.0.0 から始まる区間
// (先頭の終端の印が無い)、アドレス空間の末尾まで続く区間(終端の印が無い)、併合される隣接、
// ちょうど 1 通に収まる要素の数(1365)と 1 通をわずかに超える数(1367)、両端に触れる区間を混ぜた
// 大きな一覧を、テーブルが無い状態からと、同じテーブルの差し替えの 2 回で確かめる。
func TestLabEdgeShapes(t *testing.T) {
	requireRootAndNft(t)
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", TableName).Run() })
	p := netip.MustParsePrefix
	spread := func(n int) []netip.Prefix { return spreadPrefixes(labListBase, n) }
	for _, tc := range []struct {
		name        string
		deny, allow []netip.Prefix
	}{
		{"deny 0.0.0.0/0", []netip.Prefix{p("0.0.0.0/0")}, nil},
		{"allow 0.0.0.0/0", nil, []netip.Prefix{p("0.0.0.0/0")}},
		{"deny 255.255.255.255/32", []netip.Prefix{p("255.255.255.255/32")}, nil},
		{"deny both ends /32", []netip.Prefix{p("0.0.0.0/32"), p("255.255.255.255/32")}, nil},
		{"deny 0/8 and 240/4, allow 128/1", []netip.Prefix{p("0.0.0.0/8"), p("240.0.0.0/4")}, []netip.Prefix{p("128.0.0.0/1")}},
		{"deny adjacent that merge", []netip.Prefix{p("10.0.0.0/25"), p("10.0.0.128/25"), p("10.0.1.0/24")}, nil},
		{"682 prefixes, 1365 elements", spread(682), spread(682)},
		{"683 prefixes, 1367 elements", spread(683), spread(683)},
		{"3000 prefixes and the top /24", append(spread(3000), p("255.255.255.0/24")), append(spread(3000), p("0.0.0.0/8"))},
		{"3000 prefixes and both ends", append(append(spread(3000), p("0.0.0.0/8")), p("224.0.0.0/3")), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_ = exec.Command("nft", "delete", "table", "inet", TableName).Run()
			r := proto.Rule{ID: "r_edge", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 4000, Hi: 4000},
				Target: "192.168.1.20:9999", VPSMode: proto.ModeKernel, Enabled: true, SourceDeny: tc.deny, SourceAllow: tc.allow}
			plan := planFromRules(t, []proto.Rule{r}, map[string]netip.Addr{"home": netip.MustParseAddr("10.200.0.2")}, policy.AdmissionLimits{})
			for i, when := range []string{"fresh", "replacing"} {
				if err := Apply(plan, nil, Config{WGInterface: "wg0"}); err != nil {
					t.Fatalf("Apply #%d, %s: %v", i+1, when, err)
				}
				for set, list := range map[string][]netip.Prefix{"deny_1": tc.deny, "allow_1": tc.allow} {
					if len(list) == 0 {
						continue
					}
					if got, want := len(kernelSetElements(t, set)), len(intervalElements(list)); got != want {
						t.Errorf("Apply #%d, %s: %s holds %d set elements, want %d", i+1, when, set, got, want)
					}
				}
			}
		})
	}
}
