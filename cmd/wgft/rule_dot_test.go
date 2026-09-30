package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// TestRuleCLIRefusesDotNames は、`rule add` と `rule import` が、agent か ID が `.` か `..` のルールを
// サーバに送る前に拒むことを確かめる(design.md 10.2 節)。
// 変異の確認:Rule.Validate の `.` と `..` の検査を外すと、どちらもバッチまで進んで落ちる。
func TestRuleCLIRefusesDotNames(t *testing.T) {
	for _, agent := range []string{".", ".."} {
		adminURL, _, backend := newRuleCLITestServerWithAgents(t, agent)
		_, _, err := runRuleCmd(t, adminURL, "add", "--agent", agent, "--udp", "3001", "--to", "192.168.1.20:3001")
		if err == nil || !strings.Contains(err.Error(), "is not allowed") {
			t.Errorf("rule add --agent %s = %v, want it refused", agent, err)
		}
		if backend.batchCalls != 0 {
			t.Errorf("rule add --agent %s reached the server's batch", agent)
		}
	}
	for _, id := range []string{".", ".."} {
		adminURL, st, _ := newRuleCLITestServerWithAgents(t, "home")
		b, _ := json.Marshal([]proto.Rule{{ID: id, Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 3001, Hi: 3001},
			Target: "192.168.1.20:3001", VPSMode: proto.ModeKernel, Enabled: true}})
		path := filepath.Join(t.TempDir(), "rules.json")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := runRuleCmd(t, adminURL, "import", path)
		if err == nil || !strings.Contains(err.Error(), "is not allowed") {
			t.Errorf("rule import with id %q = %v, want it refused", id, err)
		}
		if rules, _ := st.Rules(); len(rules) != 0 {
			t.Errorf("rule import with id %q stored %+v", id, rules)
		}
	}
}
