//go:build lab && linux

package nft

// ゴールデンテスト。ラボの vps ns で root として実行する(lab/lab test internal/dataplane/linuxkernel/nft)。
// testdata/<case>.json のルールから生成したテーブルの `nft list` が、
// testdata/<case>.nft を `nft -f` で流したものと一致することを確かめる。

import (
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

// planFromRules は、書き込み時と同じ検査を経て proto.Rule から Plan を組み立てる(internal/vpsd/apply.go
// の buildPlan と同じ経路)。limits のゼロ値は接続元 IP ごとの上限の既定値(UDP 256、TCP 128。仕様 7 節)
// を使う(internal/policy.Build の約束)。
func planFromRules(t *testing.T, rules []proto.Rule, agentAddr map[string]netip.Addr, limits policy.AdmissionLimits) planner.Plan {
	t.Helper()
	normalized, err := model.NormalizeRules(rules, nil)
	if err != nil {
		t.Fatalf("model.NormalizeRules: %v", err)
	}
	agents := make([]planner.Agent, 0, len(agentAddr))
	for name, a := range agentAddr {
		agents = append(agents, planner.Agent{Name: name, Addr: a})
	}
	return planner.Build(planner.Input{Rules: normalized, Limits: limits, Agents: agents})
}

var counterRe = regexp.MustCompile(`counter packets \d+ bytes \d+`)

func nftList(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "table", "inet", TableName).CombinedOutput()
	if err != nil {
		t.Fatalf("nft list: %v\n%s", err, out)
	}
	return counterRe.ReplaceAllString(string(out), "counter")
}

func nftFile(t *testing.T, path string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 生成側と同じ「空テーブル追加 → 削除 → 定義」で流す
	script := "table inet " + TableName + " {}\ndelete table inet " + TableName + "\n" + string(body)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f %s: %v\n%s", path, err, out)
	}
}

func TestGolden(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root が必要")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft がない")
	}
	t.Cleanup(func() { exec.Command("nft", "delete", "table", "inet", TableName).Run() })

	cfg := Config{WGInterface: "wg0"}
	agentAddr := map[string]netip.Addr{"home": netip.MustParseAddr("10.200.0.2"), "office": netip.MustParseAddr("10.200.0.3")}
	// basic.json の r_proxy(tcp/443)は、待ち受けを開けている前提にする(仕様 6.1 節)。
	relayListening := map[uint16]bool{443: true}
	cases, _ := filepath.Glob("testdata/*.json")
	if len(cases) == 0 {
		t.Fatal("testdata がない")
	}
	for _, jsonPath := range cases {
		name := strings.TrimSuffix(filepath.Base(jsonPath), ".json")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(jsonPath)
			if err != nil {
				t.Fatal(err)
			}
			var rules []proto.Rule
			if err := json.Unmarshal(raw, &rules); err != nil {
				t.Fatal(err)
			}
			plan := planFromRules(t, rules, agentAddr, policy.AdmissionLimits{})

			nftFile(t, strings.TrimSuffix(jsonPath, ".json")+".nft")
			want := nftList(t)

			if err := Apply(plan, relayListening, cfg); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			got := nftList(t)
			if got != want {
				t.Errorf("nft list differs\n--- want (nft -f)\n%s\n--- got (google/nftables)\n%s", want, got)
			}
			// wgft 自身が google/nftables で読み戻せること(Observe の指紋と UDP の応答のカウンタ)。
			// nft list の一致だけでは、google/nftables が解釈できない属性を持つ行を見落とす
			if _, _, err := Fingerprint(TableName); err != nil {
				t.Errorf("Fingerprint: %v", err)
			}
			if udpReplyPorts(plan) != nil {
				replies, err := ReadReplies()
				if err != nil {
					t.Errorf("ReadReplies: %v", err)
				}
				for _, pp := range udpReplyPorts(plan) {
					if v, ok := replies[pp.RuleID]; !ok || v != 0 {
						t.Errorf("ReadReplies[%s] = %d, %v; want 0 on a fresh table", pp.RuleID, v, ok)
					}
				}
			}
			// もう一度適用しても同じ(テーブルがある状態からの差し替え)
			if err := Apply(plan, relayListening, cfg); err != nil {
				t.Fatalf("Apply again: %v", err)
			}
			if again := nftList(t); again != want {
				t.Errorf("second Apply differs\n%s", again)
			}
		})
	}
}

// 他のテーブルには一切触れないこと(仕様 1 節「既存の nftables ルールを壊さない」)。
func TestLeavesOtherTablesAlone(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root が必要")
	}
	const other = `table ip lab_other {
  set s { type ipv4_addr; elements = { 192.0.2.1 } }
  chain FORWARD {
    type filter hook forward priority filter; policy drop;
    ip saddr @s counter accept
  }
  chain nat_pre {
    type nat hook prerouting priority dstnat; policy accept;
    udp dport 9999 dnat to 192.0.2.9
  }
}
`
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(other)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		exec.Command("nft", "delete", "table", "ip", "lab_other").Run()
		exec.Command("nft", "delete", "table", "inet", TableName).Run()
	})
	list := func() string {
		out, err := exec.Command("nft", "-a", "list", "table", "ip", "lab_other").CombinedOutput()
		if err != nil {
			t.Fatalf("nft list: %v\n%s", err, out)
		}
		return string(out)
	}
	before := list()
	rules := []proto.Rule{{ID: "r", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 9999, Hi: 9999},
		Target: "192.168.1.1:9999", VPSMode: proto.ModeKernel, Enabled: true}}
	plan := planFromRules(t, rules, map[string]netip.Addr{"home": netip.MustParseAddr("10.200.0.2")}, policy.AdmissionLimits{})
	cfg := Config{WGInterface: "wg0"}
	for i := 0; i < 2; i++ {
		if err := Apply(plan, nil, cfg); err != nil {
			t.Fatal(err)
		}
	}
	if after := list(); after != before {
		t.Errorf("other table changed (handles included)\n--- before\n%s\n--- after\n%s", before, after)
	}
}

// forward の取りこぼしが無いこと(仕様 6.1 節):wg インタフェースから VPS の他のインタフェースへ
// 出る新規フローは、既存ファイアウォールの policy に関係なく wgft のテーブルで落ちる。
// ラボの vps ns で、home 側に向いた pub1 を wg インタフェースに見立ててテーブルを適用し、
// home ns から client ns への ping(pub1 → pub0 の転送)が止まること、テーブルを消すと戻ることを見る。
func TestForwardDropsFromWG(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root が必要")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft がない")
	}
	ping := func() bool {
		return exec.Command("ip", "netns", "exec", "home", "ping", "-c1", "-W1", "198.51.100.2").Run() == nil
	}
	if !ping() {
		t.Skip("home から client に届かない(ラボのトポロジが無い)")
	}
	t.Cleanup(func() { exec.Command("nft", "delete", "table", "inet", TableName).Run() })
	cfg := Config{WGInterface: "pub1"}
	if err := Apply(planner.Plan{}, nil, cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if ping() {
		t.Fatalf("home -> client still passes through the vps forward chain with the wgft table applied\n%s", nftList(t))
	}
	if err := exec.Command("nft", "delete", "table", "inet", TableName).Run(); err != nil {
		t.Fatal(err)
	}
	if !ping() {
		t.Fatal("home -> client does not recover after deleting the table")
	}
}
