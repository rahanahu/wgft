package main

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// storedBadIDRule は、ID の検査(design.md 5.3 節)の前に保存された行を模した、改行を含む ID の
// ルールである。
var storedBadIDRule = proto.Rule{ID: "r_legacy\nforged", Agent: "home", Proto: proto.UDP,
	ListenPort: proto.PortRange{Lo: 3002, Hi: 3003}, Target: "192.168.1.20:3002", VPSMode: proto.ModeKernel, Enabled: true}

// newRuleCLITestServerWithStoredBadID は、storedBadIDRule を検査を通さずに SQL で直接書いたサーバを
// 立てる。
func newRuleCLITestServerWithStoredBadID(t *testing.T) (string, *store.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.sqlite")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	js, _ := json.Marshal(storedBadIDRule)
	if _, err := db.Exec("INSERT INTO rules (id, position, json) VALUES (?, 0, ?)", storedBadIDRule.ID, string(js)); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(admin.New(&fakeRuleBackend{st: st, agentNames: []string{"home"}}))
	t.Cleanup(srv.Close)
	return srv.URL, st
}

func writeRulesFile(t *testing.T, rules []proto.Rule) string {
	t.Helper()
	b, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRuleCLIRuleIDLimits は、CLI の経路で、ID の検査と保存済みの行の扱い(design.md 5.4 節)を
// 確かめる。`rule import` は新しい違反の ID を拒み、保存済みの行をそのまま戻す読み込みは通す。
// `rule disable`、`rule set`、`rule split` は保存済みの行を同じ ID のまま変えるので拒まれ、`rule rm` は
// ID の先頭で指して消せる。
// 変異の確認:Rule.Validate から ID の検査を外すと、新しい違反の ID の読み込みと、`rule disable`、
// `rule set`、`rule split` が通って落ちる。
func TestRuleCLIRuleIDLimits(t *testing.T) {
	adminURL, st := newRuleCLITestServerWithStoredBadID(t)

	_, _, err := runRuleCmd(t, adminURL, "import", writeRulesFile(t, []proto.Rule{storedBadIDRule, {ID: strings.Repeat("y", 129),
		Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 3003, Hi: 3003}, Target: "192.168.1.20:3003",
		VPSMode: proto.ModeKernel, Enabled: true}}))
	if err == nil || !strings.Contains(err.Error(), "id is 129 bytes long; the limit is 128 bytes") {
		t.Errorf("rule import adding a 129-byte id = %v, want it refused", err)
	}

	if _, _, err := runRuleCmd(t, adminURL, "import", writeRulesFile(t, []proto.Rule{storedBadIDRule})); err != nil {
		t.Errorf("rule import of the stored set unchanged = %v, want it to work", err)
	}

	if _, _, err := runRuleCmd(t, adminURL, "disable", "r_legacy"); err == nil || !strings.Contains(err.Error(), "id contains U+000A") {
		t.Errorf("rule disable of the stored row = %v, want it refused for its id", err)
	}
	if _, _, err := runRuleCmd(t, adminURL, "set", "r_legacy", "--note", "x"); err == nil || !strings.Contains(err.Error(), "id contains U+000A") {
		t.Errorf("rule set of the stored row = %v, want it refused for its id", err)
	}
	if _, _, err := runRuleCmd(t, adminURL, "split", "r_legacy", "3003"); err == nil || !strings.Contains(err.Error(), "id contains U+000A") {
		t.Errorf("rule split of the stored row = %v, want it refused for its id", err)
	}
	if rules, _ := st.Rules(); len(rules) != 1 || !rules[0].Enabled || rules[0].Note != "" || rules[0].ListenPort.Hi != 3003 {
		t.Fatalf("a refused change altered the rules: %+v", rules)
	}

	if _, _, err := runRuleCmd(t, adminURL, "rm", "r_legacy"); err != nil {
		t.Errorf("rule rm of the stored row by its prefix = %v, want it to work", err)
	}
	if rules, _ := st.Rules(); len(rules) != 0 {
		t.Errorf("rules after rule rm = %+v, want none", rules)
	}
}

// TestRuleCLIMergeStoredBadID は、保存済みの違反の ID の行を `rule merge` で扱う 2 つの向きを確かめる。
// 統合した行は 1 つ目の ID を保つので、違反の行を 1 つ目にすると拒まれ、2 つ目にすると違反の行が
// 消えて通る。無関係な `rule add` は保存済みの行に妨げられない。
func TestRuleCLIMergeStoredBadID(t *testing.T) {
	adminURL, st := newRuleCLITestServerWithStoredBadID(t)
	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "3004", "--to", "192.168.1.20:3004"); err != nil {
		t.Fatalf("an unrelated rule add = %v, want it to work", err)
	}
	var added string
	rules, _ := st.Rules()
	for _, r := range rules {
		if r.ID != storedBadIDRule.ID {
			added = r.ID
		}
	}
	if len(rules) != 2 || added == "" {
		t.Fatalf("rules after rule add = %+v", rules)
	}
	if _, _, err := runRuleCmd(t, adminURL, "merge", "r_legacy", added); err == nil || !strings.Contains(err.Error(), "id contains U+000A") {
		t.Errorf("rule merge keeping the stored id = %v, want it refused for its id", err)
	}
	if _, _, err := runRuleCmd(t, adminURL, "merge", added, "r_legacy"); err != nil {
		t.Errorf("rule merge into the valid id = %v, want it to work", err)
	}
	if rules, _ := st.Rules(); len(rules) != 1 || rules[0].ID != added || rules[0].ListenPort != (proto.PortRange{Lo: 3002, Hi: 3004}) {
		t.Errorf("rules after the merge = %+v, want only %s covering 3002-3004", rules, added)
	}
}
