package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// countRule は、agent を持ち主とする UDP の単一ポートのルールである。target のポートを listen_port と
// そろえるので、隣り合う 2 本は統合できる。
func countRule(id, agent string, port uint16) proto.Rule {
	return proto.Rule{ID: id, Agent: agent, Proto: proto.UDP, ListenPort: proto.PortRange{Lo: port, Hi: port},
		Target: fmt.Sprintf("192.168.1.20:%d", port), VPSMode: proto.ModeKernel, Enabled: true}
}

// homeRules は home の n 本のルールを、ID r_c0000 から、ポート 10000 から作る。
func homeRules(n int) []proto.Rule {
	out := make([]proto.Rule, n)
	for i := range out {
		out[i] = countRule(fmt.Sprintf("r_c%04d", i), "home", uint16(10000+i))
	}
	return out
}

// newRuleCountTestServer は、home と other を登録したサーバを立てる。stored の行は、上限の検査の前に
// 保存されたデータを模して、検査を通さずに SQL で直接書く。
func newRuleCountTestServer(t *testing.T, stored []proto.Rule) (string, *store.Store) {
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
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range stored {
		js, _ := json.Marshal(r)
		if _, err := tx.Exec("INSERT INTO rules (id, position, json) VALUES (?, ?, ?)", r.ID, i, string(js)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(admin.New(&fakeRuleBackend{st: st, agentNames: []string{"home", "other"}}))
	t.Cleanup(srv.Close)
	return srv.URL, st
}

func countOf(t *testing.T, st *store.Store, agent string) int {
	t.Helper()
	rules, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	return proto.RuleCountsByAgent(rules)[agent]
}

const limitMsg = "over the limit of 512 rules per agent"

// TestRuleCLIAgentRuleLimit は、CLI の経路で、エージェントあたりのルールの数の上限(design.md 5.3、
// 5.4 節)を確かめる。512 本のエージェントへの `rule add` と `rule split` は拒まれ、`--dry-run` も
// 受理されない見込みとして失敗する。本数を変えない `rule disable` と、`rule rm` の後の `rule add` は
// 通る。別のエージェントへの `rule add` は妨げられない。
// 変異の確認:ValidateUpsert から数の判定を外すと、`rule add`、`--dry-run`、`rule split` が通って落ちる。
func TestRuleCLIAgentRuleLimit(t *testing.T) {
	rules := homeRules(512)
	// 下の split 用に、1 本を 2 ポートの範囲にする
	rules[0] = countRule("r_c0000", "home", 9000)
	rules[0].ListenPort = proto.PortRange{Lo: 9000, Hi: 9001}
	adminURL, st := newRuleCountTestServer(t, rules)

	_, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "3000", "--to", "192.168.1.20:3000")
	if err == nil || !strings.Contains(err.Error(), `agent "home" would have 513 rules, `+limitMsg) {
		t.Errorf("rule add of the 513th rule = %v, want it refused", err)
	}
	stdout, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "3000", "--to", "192.168.1.20:3000", "--dry-run")
	if err == nil || !strings.Contains(stdout, `agent "home" would have 513 rules`) {
		t.Errorf("rule add --dry-run of the 513th rule = %v, stdout %q; want the issue", err, stdout)
	}
	if _, _, err := runRuleCmd(t, adminURL, "split", "r_c0000", "9001"); err == nil || !strings.Contains(err.Error(), limitMsg) {
		t.Errorf("rule split at the limit = %v, want it refused", err)
	}
	if got := countOf(t, st, "home"); got != 512 {
		t.Fatalf("home has %d rules after refused changes, want 512", got)
	}
	if _, _, err := runRuleCmd(t, adminURL, "disable", "r_c0001"); err != nil {
		t.Errorf("rule disable at the limit = %v, want it to work", err)
	}
	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "other", "--udp", "3000", "--to", "192.168.1.20:3000"); err != nil {
		t.Errorf("rule add to another agent = %v, want it to work", err)
	}
	if _, _, err := runRuleCmd(t, adminURL, "rm", "r_c0002"); err != nil {
		t.Errorf("rule rm at the limit = %v, want it to work", err)
	}
	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "3001", "--to", "192.168.1.20:3001"); err != nil {
		t.Errorf("rule add of the 512th rule = %v, want it to work", err)
	}
	if got := countOf(t, st, "home"); got != 512 {
		t.Errorf("home has %d rules, want 512", got)
	}
}

// TestRuleCLIOverLimitData は、上限の導入の前に 512 本を超えて保存されたエージェント(design.md 5.4 節)を、
// CLI で減らせることを確かめる。`rule ls` は全部を示す。`rule add` と、本数を増やす `rule import` は
// 拒まれる。`rule rm`、`rule merge`、同じ本数を別の ID で置き換える `rule import`、別のエージェントへ
// 移す `rule import` は通る。そのエージェントへ移す `rule import` は拒まれる。
// 変異の確認:判定を「後の本数 > 上限」だけにすると、rm、merge、同じ本数の import、移し替えが落ちる。
func TestRuleCLIOverLimitData(t *testing.T) {
	adminURL, st := newRuleCountTestServer(t, homeRules(600))

	stdout, _, err := runRuleCmd(t, adminURL, "ls", "--json")
	if err != nil {
		t.Fatalf("rule ls = %v", err)
	}
	var list admin.BatchResponse
	if err := json.Unmarshal([]byte(stdout), &list); err != nil || len(list.Rules) != 600 {
		t.Fatalf("rule ls --json = %d rules, %v; want 600", len(list.Rules), err)
	}
	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "3000", "--to", "192.168.1.20:3000"); err == nil || !strings.Contains(err.Error(), `would have 601 rules`) {
		t.Errorf("rule add over the limit = %v, want it refused", err)
	}
	if _, _, err := runRuleCmd(t, adminURL, "rm", "r_c0599"); err != nil {
		t.Errorf("rule rm over the limit = %v, want it to work", err)
	}
	if _, _, err := runRuleCmd(t, adminURL, "merge", "r_c0000", "r_c0001"); err != nil {
		t.Errorf("rule merge over the limit = %v, want it to work", err)
	}
	if got := countOf(t, st, "home"); got != 598 {
		t.Fatalf("home has %d rules after rm and merge, want 598", got)
	}

	// 598 本を別の ID とポートで置き換える
	repl := make([]proto.Rule, 598)
	for i := range repl {
		repl[i] = countRule(fmt.Sprintf("r_n%04d", i), "home", uint16(20000+i))
	}
	if _, _, err := runRuleCmd(t, adminURL, "import", writeRulesFile(t, repl)); err != nil {
		t.Errorf("rule import replacing 598 rules with 598 = %v, want it to work", err)
	}
	// 1 本を other へ移す
	moved := append([]proto.Rule(nil), repl...)
	moved[0].Agent = "other"
	if _, _, err := runRuleCmd(t, adminURL, "import", writeRulesFile(t, moved)); err != nil {
		t.Errorf("rule import moving one rule to other = %v, want it to work", err)
	}
	if got := countOf(t, st, "home"); got != 597 {
		t.Fatalf("home has %d rules after the move, want 597", got)
	}
	// other から home へ戻すと home が増える
	if _, _, err := runRuleCmd(t, adminURL, "import", writeRulesFile(t, repl)); err == nil || !strings.Contains(err.Error(), `agent "home" would have 598 rules`) {
		t.Errorf("rule import moving a rule back to home = %v, want it refused", err)
	}
	if _, _, err := runRuleCmd(t, adminURL, "import", writeRulesFile(t, append(moved, countRule("r_extra", "home", 30000)))); err == nil || !strings.Contains(err.Error(), limitMsg) {
		t.Errorf("rule import adding a rule to home = %v, want it refused", err)
	}
	if got := countOf(t, st, "home"); got != 597 {
		t.Errorf("home has %d rules after refused imports, want 597", got)
	}
}

// TestRuleCLITargetLimit は、`rule add` が 260 バイトの target を拒み、259 バイトを受けることを確かめる
// (design.md 5.3 節)。
func TestRuleCLITargetLimit(t *testing.T) {
	adminURL, st := newRuleCountTestServer(t, nil)
	long := strings.Repeat("a", 254) + ":65535"
	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "3000", "--to", long); err == nil || !strings.Contains(err.Error(), "target is 260 bytes long; the limit is 259 bytes") {
		t.Errorf("rule add with a 260-byte target = %v, want it refused", err)
	}
	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "3000", "--to", long[1:]); err != nil {
		t.Errorf("rule add with a 259-byte target = %v, want it to work", err)
	}
	if rules, _ := st.Rules(); len(rules) != 1 || len(rules[0].Target) != 259 {
		t.Errorf("rules = %+v, want the one 259-byte target", rules)
	}
}
