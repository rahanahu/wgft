package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
)

// このファイルは `rule add` と `rule set` の `--dry-run`(design.md 11a 節)を確かめる。
// --dry-run は Batch を一度も呼ばず、管理用 API から観測できる範囲で実際の Batch が保存前に
// 行う判定と一致させる。GET /api/v1/agents によるエージェントの登録の確認と、GET
// /api/v1/server から組み立てた予約ポートを渡した proto.ValidateUpsert(ID の重複・予約ポート・
// listen_port の重なり)である。行の形(proto.Rule.Validate)は、`rule add`/`rule set` の RunE が
// runRuleDryRun を呼ぶ前に共通で検査しており、runRuleDryRun はこの検査をし直さない。

// TestRuleAddDryRunNeverCallsBatch は、--dry-run を付けた `rule add` が誤りの有無に関わらず
// Batch を一度も呼ばないこと(受け入れの条件)を、fakeRuleBackend.batchCalls で直接確かめる。
func TestRuleAddDryRunNeverCallsBatch(t *testing.T) {
	adminURL, _, backend := newRuleCLITestServerWithAgents(t, "home")

	// 誤りが無い場合
	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "2456", "--to", "192.168.1.20:2456", "--dry-run"); err != nil {
		t.Fatalf("dry-run add with no issues must not fail: %v", err)
	}
	// 誤りがある場合(未登録のエージェント)
	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "ghost", "--udp", "2500", "--to", "192.168.1.20:2500", "--dry-run"); err == nil {
		t.Fatal("dry-run add with an unregistered agent must fail")
	}
	if backend.batchCalls != 0 {
		t.Fatalf("Batch must never be called by --dry-run, got %d call(s)", backend.batchCalls)
	}
	rules, err := backend.st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("--dry-run must not save anything, got %d saved rule(s)", len(rules))
	}
}

// TestRuleAddDryRunNoIssues は、誤りの無い `rule add --dry-run` が終了コード 0 に当たる
// nil を返し、出力が「保存すれば通る見込み」であることと「何も保存されていない」ことを
// 明示することを確かめる。
func TestRuleAddDryRunNoIssues(t *testing.T) {
	adminURL, _, _ := newRuleCLITestServerWithAgents(t, "home")

	stdout, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "2456", "--to", "192.168.1.20:2456", "--dry-run")
	if err != nil {
		t.Fatalf("dry-run add with no issues must not fail: %v", err)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout must say no issues were found: %q", stdout)
	}
	if !strings.Contains(stdout, "Nothing was saved") {
		t.Errorf("stdout must state that nothing was saved: %q", stdout)
	}
	if !strings.Contains(stdout, "UDP 2456") {
		t.Errorf("stdout must show the rule that would be added: %q", stdout)
	}
}

// TestRuleAddDryRunUnregisteredAgent は、GET /api/v1/agents に無い --agent を、
// 未登録のエージェントとして検出することを確かめる。
func TestRuleAddDryRunUnregisteredAgent(t *testing.T) {
	adminURL, _, _ := newRuleCLITestServerWithAgents(t, "home") // "ghost" is not registered

	stdout, stderr, err := runRuleCmd(t, adminURL, "add", "--agent", "ghost", "--udp", "2456", "--to", "192.168.1.20:2456", "--dry-run")
	if err == nil {
		t.Fatal("dry-run add with an unregistered agent must fail")
	}
	if !strings.Contains(stdout, `agent "ghost" is not registered`) {
		t.Errorf("stdout must report the unregistered agent: %q", stdout)
	}
	if !strings.Contains(stderr, "issue") {
		t.Errorf("stderr must report the failure: %q", stderr)
	}
}

// TestRuleAddDryRunOverlappingPort は、既存のルールと listen_port が重なる追加を検出する
// ことを確かめる。proto.ValidateUpsert が全体の重なりを見る経路(importIssues と同じ順序の
// 3 番目の検査)を通る。
func TestRuleAddDryRunOverlappingPort(t *testing.T) {
	adminURL, _, backend := newRuleCLITestServerWithAgents(t, "home")

	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "2450-2460", "--to", "192.168.1.20:2450"); err != nil {
		t.Fatalf("rule add: %v", err)
	}
	if backend.batchCalls != 1 {
		t.Fatalf("the real add above must call Batch exactly once, got %d", backend.batchCalls)
	}

	stdout, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "2455-2465", "--to", "192.168.1.21:2455", "--dry-run")
	if err == nil {
		t.Fatal("dry-run add with an overlapping listen_port must fail")
	}
	if !strings.Contains(stdout, "overlaps") {
		t.Errorf("stdout must report the overlap: %q", stdout)
	}
	if backend.batchCalls != 1 {
		t.Fatalf("the failing dry-run must not call Batch, got %d total call(s)", backend.batchCalls)
	}
}

// TestRuleAddDryRunShapeErrorNeverReachesAdminAPI は、行ごとの形の誤り(proto.Rule.Validate)を
// `rule add` が --dry-run の有無に関わらず、runRuleDryRun を呼ぶ前に検査することを確かめる
// (design.md 11a 節)。この理由から --group "bad group" は Batch はもちろん、admin API に
// 一度も触れずに失敗するので、この失敗を確かめるのに fakeRuleBackend の Agents()/ServerInfo()
// が何を返すかは無関係である。以前このテストは名前が示す経路(runRuleDryRun/ruleDryRunIssues
// の内部での形の検査)を検査していなかった。実際にはそちらに同じ検査は無い。
// ruleDryRunIssues はその分岐を持たない。理由は cmd/wgft/rule.go の runRuleDryRun のコメントに
// ある。proto.Rule.Validate 自体の検査内容は proto パッケージの単体テストが確かめている。
func TestRuleAddDryRunShapeErrorNeverReachesAdminAPI(t *testing.T) {
	adminURL, _, backend := newRuleCLITestServerWithAgents(t, "home")

	_, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "2456", "--to", "192.168.1.20:2456", "--group", "bad group", "--dry-run")
	if err == nil {
		t.Fatal("dry-run add with an invalid group must fail")
	}
	if exitCode(err) != 1 {
		t.Fatalf("a shape error caught before the dry run begins must still exit 1, got %d: %v", exitCode(err), err)
	}
	// The name and this comment claim the admin API is never reached at all, not merely that
	// Batch is not called, so every endpoint the fake backend can count is checked, not just
	// batchCalls: findRule (rule set's shared helper) is not on rule add's path either, but a
	// future refactor could route rule add through GET /api/v1/rules by mistake, and only
	// checking batchCalls would not catch that.
	if backend.batchCalls != 0 || backend.rulesCalls != 0 || backend.agentsCalls != 0 || backend.serverInfoCalls != 0 {
		t.Fatalf("no admin API endpoint may be reached, got batch=%d rules=%d agents=%d server=%d",
			backend.batchCalls, backend.rulesCalls, backend.agentsCalls, backend.serverInfoCalls)
	}
}

// TestRuleSetDryRunNoIssues は、誤りの無い `rule set --dry-run` が保存せずに成功することを
// 確かめる。
func TestRuleSetDryRunNoIssues(t *testing.T) {
	adminURL, _, backend := newRuleCLITestServerWithAgents(t, "home")
	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "2456", "--to", "192.168.1.20:2456"); err != nil {
		t.Fatalf("rule add: %v", err)
	}
	id := firstRuleID(t, adminURL)
	callsBefore := backend.batchCalls

	stdout, _, err := runRuleCmd(t, adminURL, "set", id, "--note", "game server", "--dry-run")
	if err != nil {
		t.Fatalf("dry-run set with no issues must not fail: %v", err)
	}
	if !strings.Contains(stdout, "no issues found") || !strings.Contains(stdout, "Nothing was saved") {
		t.Errorf("stdout must say no issues were found and nothing was saved: %q", stdout)
	}
	if backend.batchCalls != callsBefore {
		t.Fatalf("dry-run set must not call Batch, went from %d to %d", callsBefore, backend.batchCalls)
	}
	rules, err := backend.st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].Note != "" {
		t.Errorf("dry-run set must not save the new note, got %q", rules[0].Note)
	}
}

// TestRuleSetDryRunUnregisteredAgent は、既存ルールの所有エージェントが登録されていない
// 場合に、group/note だけの変更でも --dry-run がそれを検出することを確かめる
// (importIssues と同じく、変わった行の agent 存在は無条件に見る)。
func TestRuleSetDryRunUnregisteredAgent(t *testing.T) {
	// "home" だけを登録し、"ghost" の名前でルールを作る(fakeRuleBackend.Batch はサーバー側の
	// 登録確認を行わないので、テストの下準備として作れる)。
	adminURL, _, backend := newRuleCLITestServerWithAgents(t, "home")
	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "ghost", "--udp", "2456", "--to", "192.168.1.20:2456"); err != nil {
		t.Fatalf("rule add: %v", err)
	}
	id := firstRuleID(t, adminURL)
	callsBefore := backend.batchCalls

	stdout, _, err := runRuleCmd(t, adminURL, "set", id, "--note", "x", "--dry-run")
	if err == nil {
		t.Fatal("dry-run set on a rule owned by an unregistered agent must fail")
	}
	if !strings.Contains(stdout, `agent "ghost" is not registered`) {
		t.Errorf("stdout must report the unregistered agent: %q", stdout)
	}
	if backend.batchCalls != callsBefore {
		t.Fatalf("dry-run set must not call Batch, went from %d to %d", callsBefore, backend.batchCalls)
	}
}

// The following three tests fix, on the same fixture, the defect an independent review found:
// --dry-run passed nil as proto.ValidateUpsert's reserved argument, so a rule overlapping a port
// the server has reserved for itself (WireGuard, the admin API, or the agent API) printed
// "accepted" while the real Batch that store.ApplyBatch runs (with the server's actual
// proto.Reserved) refused it. Each test sets fakeRuleBackend.serverInfo to make one of those
// three ports collide with the rule under test, then checks both sides against that same
// serverInfo value: --dry-run must exit 1, and a real "rule add" (no --dry-run) against the
// same backend must refuse the batch too. Checking only one side would not pin down that the
// two judgments agree; the pair is the point (design.md 11a 節, revised).

// TestRuleAddDryRunWireGuardPortConflict は、GET /api/v1/server の wg_port と重なる
// listen_port を --dry-run が拒むこと、同じ fixture への実 Batch も拒むことを確かめる。
func TestRuleAddDryRunWireGuardPortConflict(t *testing.T) {
	adminURL, _, backend := newRuleCLITestServerWithAgents(t, "home")
	backend.serverInfo = admin.ServerInfo{WGPort: 51820}

	stdout, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "51820", "--to", "192.168.1.20:51820", "--dry-run")
	if err == nil {
		t.Fatal("dry-run add on the server's WireGuard port must fail")
	}
	if !strings.Contains(stdout, "WireGuard") {
		t.Errorf("stdout must name WireGuard as the reason: %q", stdout)
	}
	if backend.batchCalls != 0 {
		t.Fatalf("the failing dry-run must not call Batch, got %d call(s)", backend.batchCalls)
	}

	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "51820", "--to", "192.168.1.20:51820"); err == nil {
		t.Fatal("the real add on the same port must be refused too, matching the dry-run's judgment")
	}
	if backend.batchCalls != 1 {
		t.Fatalf("the refused real add must still call Batch exactly once, got %d", backend.batchCalls)
	}
}

// TestRuleAddDryRunAgentAPIPortConflict は agent_api_port との重なりを同様に確かめる。
func TestRuleAddDryRunAgentAPIPortConflict(t *testing.T) {
	adminURL, _, backend := newRuleCLITestServerWithAgents(t, "home")
	backend.serverInfo = admin.ServerInfo{AgentAPIPort: "9443"}

	stdout, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "9443", "--to", "192.168.1.20:9443", "--dry-run")
	if err == nil {
		t.Fatal("dry-run add on the server's agent API port must fail")
	}
	if !strings.Contains(stdout, "agent API") {
		t.Errorf("stdout must name the agent API as the reason: %q", stdout)
	}
	if backend.batchCalls != 0 {
		t.Fatalf("the failing dry-run must not call Batch, got %d call(s)", backend.batchCalls)
	}

	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "9443", "--to", "192.168.1.20:9443"); err == nil {
		t.Fatal("the real add on the same port must be refused too, matching the dry-run's judgment")
	}
	if backend.batchCalls != 1 {
		t.Fatalf("the refused real add must still call Batch exactly once, got %d", backend.batchCalls)
	}
}

// TestRuleAddDryRunAdminPortConflict は admin_addr(host:port の形のとき)との重なりを
// 同様に確かめる。
func TestRuleAddDryRunAdminPortConflict(t *testing.T) {
	adminURL, _, backend := newRuleCLITestServerWithAgents(t, "home")
	backend.serverInfo = admin.ServerInfo{AdminAddr: "10.0.0.5:8443"}

	stdout, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--tcp", "8443", "--to", "192.168.1.20:8443", "--dry-run")
	if err == nil {
		t.Fatal("dry-run add on the server's admin API port must fail")
	}
	if !strings.Contains(stdout, "admin API") {
		t.Errorf("stdout must name the admin API as the reason: %q", stdout)
	}
	if backend.batchCalls != 0 {
		t.Fatalf("the failing dry-run must not call Batch, got %d call(s)", backend.batchCalls)
	}

	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--tcp", "8443", "--to", "192.168.1.20:8443"); err == nil {
		t.Fatal("the real add on the same port must be refused too, matching the dry-run's judgment")
	}
	if backend.batchCalls != 1 {
		t.Fatalf("the refused real add must still call Batch exactly once, got %d", backend.batchCalls)
	}
}

// TestRuleAddDryRunServerInfoUnavailable は、GET /api/v1/server が読めない場合(この節点を
// 持たない旧い server を想定する)、--dry-run が「予約ポート無し」に読み替えて続行せず、
// server doctor と同じ終了コード 2(unavailable)で止まることを確かめる(design.md 11a 節)。
// この応答は admin.New が組む本物のルーティングを経由しないので、backend の ServerInfo() が
// 何を返すかは無関係である。
func TestRuleAddDryRunServerInfoUnavailable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(ts.Close)

	_, _, err := runRuleCmd(t, ts.URL, "add", "--agent", "home", "--udp", "2456", "--to", "192.168.1.20:2456", "--dry-run")
	if err == nil {
		t.Fatal("dry-run must fail when GET /api/v1/server cannot be read")
	}
	if code := exitCode(err); code != exitUnavailable {
		t.Fatalf("dry-run must exit %d (unavailable) when server info cannot be read, got %d: %v", exitUnavailable, code, err)
	}
}

// selectiveFailureAdminServer serves valid, empty answers for GET /api/v1/server, /api/v1/rules
// and /api/v1/agents, except for the one path named by fail, which 404s the way an admin API too
// old to have that endpoint would (the same stand-in TestRuleAddDryRunServerInfoUnavailable uses
// for GET /api/v1/server, generalized to the other two reads runRuleDryRun makes). It pins
// runRuleDryRun's unavailable(...) wrapping around its own second and third reads: a mutation
// test changing either of those two wraps to return the bare error instead left every existing
// test passing, since TestRuleAddDryRunServerInfoUnavailable only ever fails the first read.
func selectiveFailureAdminServer(t *testing.T, fail string) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == fail {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/server":
			fmt.Fprint(w, `{}`)
		case "/api/v1/rules":
			fmt.Fprint(w, `{"rules":[],"generation":0}`)
		case "/api/v1/agents":
			fmt.Fprint(w, `[]`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// TestRuleAddDryRunRulesUnavailable pins runRuleDryRun's own "reading rules" unavailable(...)
// wrap (cmd/wgft/rule.go): GET /api/v1/server succeeds, but GET /api/v1/rules does not.
func TestRuleAddDryRunRulesUnavailable(t *testing.T) {
	adminURL := selectiveFailureAdminServer(t, "/api/v1/rules")

	_, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "2456", "--to", "192.168.1.20:2456", "--dry-run")
	if err == nil {
		t.Fatal("dry-run must fail when GET /api/v1/rules cannot be read")
	}
	if code := exitCode(err); code != exitUnavailable {
		t.Fatalf("dry-run must exit %d (unavailable) when rules cannot be read, got %d: %v", exitUnavailable, code, err)
	}
}

// TestRuleAddDryRunAgentsUnavailable pins runRuleDryRun's own "reading agents" unavailable(...)
// wrap (cmd/wgft/rule.go): GET /api/v1/server and GET /api/v1/rules succeed, but GET
// /api/v1/agents does not.
func TestRuleAddDryRunAgentsUnavailable(t *testing.T) {
	adminURL := selectiveFailureAdminServer(t, "/api/v1/agents")

	_, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "2456", "--to", "192.168.1.20:2456", "--dry-run")
	if err == nil {
		t.Fatal("dry-run must fail when GET /api/v1/agents cannot be read")
	}
	if code := exitCode(err); code != exitUnavailable {
		t.Fatalf("dry-run must exit %d (unavailable) when agents cannot be read, got %d: %v", exitUnavailable, code, err)
	}
}

// TestRuleSetDryRunAdminAPIUnreachable fixes the defect an independent review found: rule set's
// RunE calls findRule, which reads GET /api/v1/rules, ahead of runRuleDryRun's own reads and
// outside any unavailable(...) wrap, so whether an unreachable admin API exited 1 or 2 depended
// on which of findRule's or runRuleDryRun's own GET /api/v1/rules call happened to fail first.
// docs/design.md 11a 節, helptext.go's "rule set" Long and this feature's own commit message all
// promise exit 2 for every read --dry-run needs, matching "rule add". Here the admin API answers
// nothing at all, so findRule's own read is the one that fails, and that alone must still give
// exit 2 for --dry-run.
func TestRuleSetDryRunAdminAPIUnreachable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(ts.Close)

	_, _, err := runRuleCmd(t, ts.URL, "set", "r_01M2R009", "--note", "x", "--dry-run")
	if err == nil {
		t.Fatal("dry-run set must fail when the admin API cannot be reached")
	}
	if code := exitCode(err); code != exitUnavailable {
		t.Fatalf("dry-run set must exit %d (unavailable) when the admin API cannot be reached, got %d: %v", exitUnavailable, code, err)
	}
}

// TestRuleSetNoDryRunAdminAPIUnreachableStillExitsOne pins the shared behavior
// TestRuleSetDryRunAdminAPIUnreachable must not change: findRule's failure, used directly by
// rule rm/enable/disable and by rule set without --dry-run, keeps exit code 1 for all of them,
// exactly as before this fix.
func TestRuleSetNoDryRunAdminAPIUnreachableStillExitsOne(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(ts.Close)

	_, _, err := runRuleCmd(t, ts.URL, "set", "r_01M2R009", "--note", "x")
	if err == nil {
		t.Fatal("rule set must fail when the admin API cannot be reached")
	}
	if code := exitCode(err); code != 1 {
		t.Fatalf("rule set without --dry-run must keep exit code 1 when the admin API cannot be reached, got %d: %v", code, err)
	}
}

// disposableRuleIDPattern matches a rule ID's shape (newRuleID()'s "r_" + a 26-character ULID),
// used below to check a --dry-run issue message for a throwaway ID it must not print.
var disposableRuleIDPattern = regexp.MustCompile(`\br_[0-9A-Za-z]{26}\b`)

// TestRuleAddDryRunReservedPortConflictNoThrowawayID fixes the second place an independent
// review found the same defect in: dryRunRuleLabel already kept a new row's disposable per-run ID
// (newRuleID()'s ULID, never the ID a real "rule add" would go on to save) out of the "agent not
// registered" issue, but the reserved-port-collision, ID-duplicate and listen_port-overlap issues
// come from proto.ValidateUpsert's own error text instead, which still printed that disposable ID
// verbatim. The reserved-port collision checked here is this revision's headline judgment and the
// most likely path to hit the defect.
func TestRuleAddDryRunReservedPortConflictNoThrowawayID(t *testing.T) {
	adminURL, _, backend := newRuleCLITestServerWithAgents(t, "home")
	backend.serverInfo = admin.ServerInfo{WGPort: 51820}

	stdout, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "51820", "--to", "192.168.1.20:51820", "--dry-run")
	if err == nil {
		t.Fatal("dry-run add on the server's WireGuard port must fail")
	}
	if disposableRuleIDPattern.MatchString(stdout) {
		t.Errorf("stdout must not print the disposable ID rule add generated for this run alone: %q", stdout)
	}
	if !strings.Contains(stdout, "new rule (") {
		t.Errorf("stdout must identify the new row by its summary instead of an ID: %q", stdout)
	}
}

// TestRuleAddDryRunOverlappingPortNoThrowawayID is like
// TestRuleAddDryRunReservedPortConflictNoThrowawayID for the listen_port-overlap issue, which
// names two rows: the existing rule (a real, saved ID, which may legitimately appear) and the new
// one under dry run (a disposable ID, which may not).
func TestRuleAddDryRunOverlappingPortNoThrowawayID(t *testing.T) {
	adminURL, _, _ := newRuleCLITestServerWithAgents(t, "home")
	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "2450-2460", "--to", "192.168.1.20:2450"); err != nil {
		t.Fatalf("rule add: %v", err)
	}
	existingID := firstRuleID(t, adminURL)

	stdout, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "2455-2465", "--to", "192.168.1.21:2455", "--dry-run")
	if err == nil {
		t.Fatal("dry-run add with an overlapping listen_port must fail")
	}
	for _, id := range disposableRuleIDPattern.FindAllString(stdout, -1) {
		if id != existingID {
			t.Errorf("stdout must not print a disposable rule ID, found %q which is not the existing rule's own %q: %q", id, existingID, stdout)
		}
	}
	if !strings.Contains(stdout, "new rule (") {
		t.Errorf("stdout must identify the new row by its summary instead of an ID: %q", stdout)
	}
}

// TestReservedFromServerInfoDelegates confirms that reservedFromServerInfo forwards to
// admin.ReservedFromServerInfo unchanged (a straight dereference-and-call, cmd/wgft/rule.go).
//
// The full rule this delegates to -- WireGuard always reserved, admin API only when AdminAddr
// parses as host:port, agent API from the already-split AgentAPIPort -- used to be pinned by a
// larger table test here, duplicating a copy of the same logic that lived in
// admin.ReservedFromServerInfo. Now that reservedFromServerInfo is only a delegation, that table
// belongs with the function it actually tests: internal/vpsd/admin's own
// TestReservedFromServerInfo (reserved_test.go) pins the rule itself, including the cases (a
// Unix socket AdminAddr, an AdminAddr that fails to parse for some other reason, an empty
// AgentAPIPort) that matter for not silently reserving a placeholder port. Keeping a second full
// copy of that table here would let the two drift out of sync with no test catching it; this
// smaller test only guards that the one-line delegation itself does not regress, for example by
// someone re-inlining the old logic and returning something else.
func TestReservedFromServerInfoDelegates(t *testing.T) {
	cases := []struct {
		name string
		info admin.ServerInfo
	}{
		{name: "TCP admin_addr reserves its port", info: admin.ServerInfo{WGPort: 51820, AdminAddr: "10.0.0.5:8443", AgentAPIPort: "9443"}},
		{name: "unix socket admin_addr reserves no port", info: admin.ServerInfo{WGPort: 51820, AdminAddr: "unix:///run/wgft/admin.sock", AgentAPIPort: "9443"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reservedFromServerInfo(&tc.info)
			want := admin.ReservedFromServerInfo(tc.info)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("reservedFromServerInfo(%+v) = %v, want %v (admin.ReservedFromServerInfo's own answer)", tc.info, got, want)
			}
		})
	}
}
