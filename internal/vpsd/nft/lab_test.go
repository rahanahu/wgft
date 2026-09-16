//go:build lab

package nft

// ゴールデンテスト。ラボの vps ns で root として実行する(lab/lab test internal/vpsd/nft)。
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

	"github.com/rahanahu/wgft/proto"
)

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

	cfg := Config{WGInterface: "wg0", AgentAddr: map[string]netip.Addr{
		"home": netip.MustParseAddr("10.200.0.2"), "office": netip.MustParseAddr("10.200.0.3")}}
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
			if err := proto.ValidateRules(rules, nil); err != nil {
				t.Fatal(err)
			}
			nftFile(t, strings.TrimSuffix(jsonPath, ".json")+".nft")
			want := nftList(t)

			if err := Apply(rules, cfg); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			got := nftList(t)
			if got != want {
				t.Errorf("nft list differs\n--- want (nft -f)\n%s\n--- got (google/nftables)\n%s", want, got)
			}
			// もう一度適用しても同じ(テーブルがある状態からの差し替え)
			if err := Apply(rules, cfg); err != nil {
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
	cfg := Config{WGInterface: "wg0", AgentAddr: map[string]netip.Addr{"home": netip.MustParseAddr("10.200.0.2")}}
	for i := 0; i < 2; i++ {
		if err := Apply(rules, cfg); err != nil {
			t.Fatal(err)
		}
	}
	if after := list(); after != before {
		t.Errorf("other table changed (handles included)\n--- before\n%s\n--- after\n%s", before, after)
	}
}
