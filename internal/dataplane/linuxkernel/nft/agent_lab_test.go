//go:build lab && linux

package nft

// エージェントの table inet wgft_agent のゴールデンテスト。ラボの vps ns で root として実行する
// (lab/lab test internal/dataplane/linuxkernel/nft)。testdata/agent/<case>.nft を `nft -f` で流した表と、
// google/nftables で組んだ表の `nft list` が一致し、google/nftables で読み戻せることを確かめる。

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

func agentNftList(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "table", "inet", AgentTableName).CombinedOutput()
	if err != nil {
		t.Fatalf("nft list: %v\n%s", err, out)
	}
	return string(out)
}

// agentNetlinkList は `nft --debug=netlink list` の式の列である。`nft list` の表示は式の一部を
// 映さない。例えば map の DNAT のポートを読むレジスタを誤っても、表示は同じで、転送だけが壊れる
// (ラボで確かめた)。map の要素の並びは読むたびに変わりうるので、set ごとに並べ替える。チェーンの
// 見出しの handle は落とす。
func agentNetlinkList(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("nft", "--debug=netlink", "list", "table", "inet", AgentTableName).CombinedOutput()
	if err != nil {
		t.Fatalf("nft --debug=netlink list: %v\n%s", err, out)
	}
	var lines, elems []string
	flush := func() {
		sort.Strings(elems)
		lines = append(lines, elems...)
		elems = nil
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "\telement ") {
			elems = append(elems, l)
			continue
		}
		flush()
		lines = append(lines, chainHeaderRe.ReplaceAllString(l, "$1"))
	}
	flush()
	return strings.Join(lines, "\n")
}

var chainHeaderRe = regexp.MustCompile(`^(inet ` + AgentTableName + ` [a-z_]+)( \d+)+$`)

func agentNftFile(t *testing.T, path string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := "table inet " + AgentTableName + " {}\ndelete table inet " + AgentTableName + "\n" + string(body)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f %s: %v\n%s", path, err, out)
	}
}

// agentGoldenCases は testdata/agent/<name>.nft に対応する入力である。
var agentGoldenCases = map[string]struct {
	in  AgentInput
	cfg AgentConfig
}{
	"basic": {
		in: AgentInput{
			Rules: []proto.AgentRule{
				{ID: "r_valheim", Proto: proto.UDP, ListenPort: pr(2456, 2458), Target: "192.168.1.20:3000", Enabled: true},
				{ID: "r_mc", Proto: proto.TCP, ListenPort: pr(25565, 25565), Target: "192.168.1.22:25566", Enabled: true},
				// 7001 だけを許可一覧が拒む。ホスト名は解決の結果で判定する
				{ID: "r_partial", Proto: proto.UDP, ListenPort: pr(7000, 7002), Target: "nas.lan:7000", Enabled: true},
				// 以下は DNAT を作らない
				{ID: "r_loop", Proto: proto.TCP, ListenPort: pr(8080, 8080), Target: "127.0.0.1:80", Enabled: true},
				{ID: "r_unresolved", Proto: proto.TCP, ListenPort: pr(8081, 8081), Target: "gone.lan:80", Enabled: true},
				{ID: "r_off", Proto: proto.UDP, ListenPort: pr(9000, 9000), Target: "192.168.1.20:9000", Enabled: false},
			},
			Resolved: map[string]Resolution{
				"nas.lan":  {Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.30")}},
				"gone.lan": {Err: errors.New("lookup gone.lan: no such host")},
			},
		},
		cfg: AgentConfig{WGInterface: "wgft0", AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
			AllowTarget: func(ap netip.AddrPort) bool { return ap != netip.MustParseAddrPort("192.168.1.30:7001") }},
	},
	"empty": {cfg: AgentConfig{WGInterface: "wgft0"}},
}

func TestAgentGolden(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root が必要")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft がない")
	}
	t.Cleanup(func() { exec.Command("nft", "delete", "table", "inet", AgentTableName).Run() })
	for name, tc := range agentGoldenCases {
		t.Run(name, func(t *testing.T) {
			agentNftFile(t, "testdata/agent/"+name+".nft")
			want, wantNL := agentNftList(t), agentNetlinkList(t)

			pub := PlanAgent(tc.in, tc.cfg)
			if err := ApplyAgent(pub, tc.cfg); err != nil {
				t.Fatalf("ApplyAgent: %v", err)
			}
			got := agentNftList(t)
			if got != want {
				t.Errorf("nft list differs\n--- want (nft -f)\n%s\n--- got (google/nftables)\n%s", want, got)
			}
			if gotNL := agentNetlinkList(t); gotNL != wantNL {
				t.Errorf("nft --debug=netlink list differs\n--- want (nft -f)\n%s\n--- got (google/nftables)\n%s", wantNL, gotNL)
			}
			// google/nftables で読み戻せること。指紋は全チェーンの行と static な set を読む。nft list の
			// 一致だけでは、google/nftables が解釈できない属性を持つ行を見落とす
			fp, present, err := Fingerprint(AgentTableName)
			if err != nil || !present {
				t.Fatalf("Fingerprint(%s) = %q, %v, %v", AgentTableName, fp, present, err)
			}
			if again, _, err := Fingerprint(AgentTableName); err != nil || again != fp {
				t.Errorf("a second read gives another fingerprint: %q, %v; want %q", again, err, fp)
			}
			// 読み戻した表は、記録どおり。DNAT は公開の結果と同じ
			ins, present, err := InspectAgent(pub, tc.cfg.WGInterface)
			if err != nil || !present {
				t.Fatalf("InspectAgent: present %v, %v", present, err)
			}
			if !ins.Matches() {
				t.Errorf("InspectAgent does not match the record: %+v", ins)
			}
			if !reflect.DeepEqual(ins.DNATs, pub.DNATs()) {
				t.Errorf("InspectAgent DNATs\n got %v\nwant %v", ins.DNATs, pub.DNATs())
			}
			// もう一度適用しても同じ(テーブルがある状態からの差し替え)
			if err := ApplyAgent(pub, tc.cfg); err != nil {
				t.Fatalf("ApplyAgent again: %v", err)
			}
			if again := agentNftList(t); again != want {
				t.Errorf("second ApplyAgent differs\n%s", again)
			}
		})
	}
}

// 外から行を足された表では、InspectAgent は wgft の行だけを読み、残りを数える。指紋は変わる。
func TestAgentInspectForeignRow(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root が必要")
	}
	t.Cleanup(func() { exec.Command("nft", "delete", "table", "inet", AgentTableName).Run() })
	tc := agentGoldenCases["basic"]
	pub := PlanAgent(tc.in, tc.cfg)
	if err := ApplyAgent(pub, tc.cfg); err != nil {
		t.Fatal(err)
	}
	before, _, err := Fingerprint(AgentTableName)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("nft", "add", "rule", "inet", AgentTableName, "nat_pre",
		"iifname", "wgft0", "tcp", "dport", "22", "dnat", "ip", "to", "192.168.1.1:22").CombinedOutput(); err != nil {
		t.Fatalf("nft add rule: %v\n%s", err, out)
	}
	ins, _, err := InspectAgent(pub, tc.cfg.WGInterface)
	if err != nil {
		t.Fatal(err)
	}
	if ins.Unrecognized != 1 || !reflect.DeepEqual(ins.DNATs, pub.DNATs()) || ins.Matches() {
		t.Errorf("InspectAgent = %+v; want the published DNATs and 1 unrecognized row", ins)
	}
	// 外から MASQUERADE の行を消すと、欠けた行として示す
	out, err := exec.Command("nft", "flush", "chain", "inet", AgentTableName, "postrouting").CombinedOutput()
	if err != nil {
		t.Fatalf("nft flush chain: %v\n%s", err, out)
	}
	if ins, _, err = InspectAgent(pub, tc.cfg.WGInterface); err != nil || len(ins.Missing) != 1 || !strings.Contains(ins.Missing[0], "masquerade") {
		t.Errorf("InspectAgent after flushing postrouting = %+v, %v; want the masquerade row missing", ins.Missing, err)
	}
	if after, _, err := Fingerprint(AgentTableName); err != nil || after == before {
		t.Errorf("fingerprint after adding a row = %q, %v; want it to change from %q", after, err, before)
	}
}

// エージェントの表は他のテーブルに一切触れない。server の table inet wgft が同じホストにあっても同じ
// (7b.1 節)。
func TestAgentLeavesOtherTablesAlone(t *testing.T) {
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
	nftFile(t, "testdata/empty.nft") // server の table inet wgft
	t.Cleanup(func() {
		exec.Command("nft", "delete", "table", "ip", "lab_other").Run()
		exec.Command("nft", "delete", "table", "inet", TableName).Run()
		exec.Command("nft", "delete", "table", "inet", AgentTableName).Run()
	})
	list := func(family, name string) string {
		out, err := exec.Command("nft", "-a", "list", "table", family, name).CombinedOutput()
		if err != nil {
			t.Fatalf("nft list %s %s: %v\n%s", family, name, err, out)
		}
		return string(out)
	}
	beforeOther, beforeServer := list("ip", "lab_other"), list("inet", TableName)
	tc := agentGoldenCases["basic"]
	for i := 0; i < 2; i++ {
		if err := ApplyAgent(PlanAgent(tc.in, tc.cfg), tc.cfg); err != nil {
			t.Fatal(err)
		}
	}
	if after := list("ip", "lab_other"); after != beforeOther {
		t.Errorf("other table changed (handles included)\n--- before\n%s\n--- after\n%s", beforeOther, after)
	}
	if after := list("inet", TableName); after != beforeServer {
		t.Errorf("server table changed (handles included)\n--- before\n%s\n--- after\n%s", beforeServer, after)
	}
}
