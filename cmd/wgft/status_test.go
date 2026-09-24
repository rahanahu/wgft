package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは `wgft status`(設計文書 10.2b 節)の判定を、合成した管理用 API の応答に
// 対して確かめる。at、u64、doctorNow は doctor_test.go のものをそのまま使う。

// wallNow は、実時刻の time.Now() から見て d 前の時刻を返す。at は doctorNow(固定の偽の
// 「今」)から見た相対時刻を作るが、runStatusCmd を経由する RunE の試験は cmd.Execute() が
// status.go の RunE をそのまま呼ぶため、比較の基準は doctorNow ではなく実際の time.Now() に
// なる(status.go:154)。buildStatusReport を直に呼ぶ試験は Now: doctorNow を明示して渡すので
// at() で足りるが、この経路の「doctorNow から 5 秒前」は、実時刻が doctorNow を過ぎた分だけ
// 古い時刻になり、鮮度の判定(targetReportStale は 90 秒、handshakeStale は 3 分)を外れて
// 落ちる。RunE を通す試験のうち、鮮度が結果を左右するものはこちらを使う。
func wallNow(d time.Duration) string { return time.Now().Add(-d).Format(time.RFC3339) }

func rulesFixture() []proto.Rule {
	mk := func(id, target string, enabled bool) proto.Rule {
		return proto.Rule{
			ID: id, Agent: "home", Proto: proto.TCP, Enabled: enabled,
			ListenPort: proto.PortRange{Lo: 2000, Hi: 2000}, Target: target,
			SourceAllow: []netip.Prefix{}, SourceDeny: []netip.Prefix{},
		}
	}
	rules := []proto.Rule{mk("r_disabled0001", "192.168.1.9:2000", false)}
	for i := 0; i < 8; i++ {
		id := "r_0" + string(rune('1'+i)) + "healthy00"
		rules = append(rules, mk(id, "192.168.1.10:2000", true))
	}
	return rules
}

// healthyStatusInput は、健全な行が 1 つも崩れていない証拠一式である(第 1 の例、design.md
// 10.2b 節)。無効なルールを 1 本混ぜて、総数に数えないことも併せて確かめる。有効な各ルールは、
// server の apply_state が active であることに加え、そのルールの持ち主(home)からの鮮度のある
// agent_rule_states の ok も持つ。2026-09-22 の改訂以降、この両方が揃って初めて active と数える
// (この節の先頭のコメントと rulesStatusOf を見よ)。
func healthyStatusInput() statusInput {
	rules := rulesFixture()
	states := map[string]admin.RuleApply{}
	agentStates := map[string]admin.AgentRuleStatus{}
	for _, r := range rules {
		if r.Enabled {
			states[r.ID] = admin.RuleApply{ApplyState: admin.ApplyActive}
			agentStates[r.ID] = admin.AgentRuleStatus{Agent: r.Agent, State: proto.StatusOK, Connected: true, At: at(5 * time.Second)}
		} else {
			states[r.ID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: "disabled"}
		}
	}
	return statusInput{
		Now: doctorNow,
		Rules: &admin.BatchResponse{
			Rules: rules, DesiredGeneration: u64(9), ActiveGeneration: u64(9), RuleStates: states, AgentRuleStates: agentStates,
		},
		Agents: []admin.AgentInfo{
			{Name: "home", Connected: true, LastHeartbeat: at(5 * time.Second), LastHandshake: at(5 * time.Second)},
			{Name: "home2", Connected: true, LastHeartbeat: at(5 * time.Second), LastHandshake: at(5 * time.Second)},
		},
	}
}

func TestBuildStatusReportHealthy(t *testing.T) {
	rep := buildStatusReport(healthyStatusInput())

	if rep.Server.Status != serverHealthy || rep.Server.Detail != "" {
		t.Errorf("server = %+v, want healthy with no detail", rep.Server)
	}
	if rep.Agents.Healthy != 2 || rep.Agents.Total != 2 || rep.Agents.Detail != "" {
		t.Errorf("agents = %+v, want 2/2 healthy with no detail", rep.Agents)
	}
	// The disabled rule must not count toward the total (design.md 10.2b 節).
	if rep.Rules.Active != 8 || rep.Rules.Degraded != 0 || rep.Rules.Unknown != 0 || rep.Rules.Total != 8 || rep.Rules.Detail != "" {
		t.Errorf("rules = %+v, want 8/8 active with no detail", rep.Rules)
	}
	if rep.Warnings.Count != 0 || rep.Warnings.Detail != "" {
		t.Errorf("warnings = %+v, want none", rep.Warnings)
	}

	var buf bytes.Buffer
	writeStatusReport(&buf, rep)
	want := "Server        healthy\n" +
		"Agents        2 / 2 healthy\n" +
		"Rules         8 active\n" +
		"Warnings      none\n"
	if got := buf.String(); got != want {
		t.Errorf("writeStatusReport =\n%s\nwant\n%s", got, want)
	}

	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	want2 := `{"server":{"status":"healthy"},"agents":{"healthy":2,"degraded":0,"unknown":0,"disabled":0,"total":2},"rules":{"active":8,"degraded":0,"unknown":0,"agent_disabled":0,"total":8},"warnings":{"count":0}}`
	if string(data) != want2 {
		t.Errorf("json = %s, want %s", data, want2)
	}

	if err := statusExit(rep); err != nil {
		t.Errorf("a fully healthy report must exit 0, got %v", err)
	}
}

// statusExampleInput は design.md 10.2b 節の第 2 の例(健全でない 3 行)を再現する。ID は実際に
// newRuleID (cmd/wgft/rule.go) が作る "r_" + 26 文字の ULID の形(28 文字)にしてある。short()
// (cmd/wgft/rule.go)は 12 文字を超えたものだけを 12 文字 + "…" に詰めるので、この長さでないと
// "…" を経由する表示を確かめられない(レビューの指摘)。
func statusExampleInput() statusInput {
	rules := rulesFixture()
	states := map[string]admin.RuleApply{}
	agentStates := map[string]admin.AgentRuleStatus{}
	for i, r := range rules {
		if !r.Enabled {
			states[r.ID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: "disabled"}
			continue
		}
		if i == 1 { // the first enabled rule stands in for r_01M335HMABBS0HAXB58DE7QSTR
			continue
		}
		states[r.ID] = admin.RuleApply{ApplyState: admin.ApplyActive}
		agentStates[r.ID] = admin.AgentRuleStatus{Agent: r.Agent, State: proto.StatusOK, Connected: true, At: at(5 * time.Second)}
	}
	rules[1].ID = "r_01M335HMABBS0HAXB58DE7QSTR"
	states[rules[1].ID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: "bind failed: address already in use"}

	return statusInput{
		Now: doctorNow,
		Rules: &admin.BatchResponse{
			Rules: rules, DesiredGeneration: u64(9), ActiveGeneration: u64(9), RuleStates: states, AgentRuleStates: agentStates,
		},
		Agents: []admin.AgentInfo{
			{Name: "home", Connected: true, LastHeartbeat: at(5 * time.Second), LastHandshake: at(5 * time.Second)},
			{Name: "home2", Connected: false, LastHeartbeat: at(4*time.Minute + 12*time.Second)},
		},
		Warnings: []admin.Warning{{Agent: "home", Kind: "ip-flapping", Detail: "returned to an earlier value", At: at(time.Minute)}},
	}
}

// TestBuildStatusReportProblems は、健全でない行が degraded として数えられ(証拠のある apply
// 失敗であって unknown ではない)、終了コードが 1 になることを確かめる(design.md 10.2b 節)。
func TestBuildStatusReportProblems(t *testing.T) {
	rep := buildStatusReport(statusExampleInput())

	if rep.Server.Status != serverHealthy {
		t.Errorf("server = %+v, want healthy (this scenario does not touch generations or apply_error)", rep.Server)
	}
	if rep.Agents.Healthy != 1 || rep.Agents.Total != 2 {
		t.Errorf("agents = %+v, want 1/2", rep.Agents)
	}
	if want := "home2 last seen 4m12s ago"; rep.Agents.Detail != want {
		t.Errorf("agents.detail = %q, want %q", rep.Agents.Detail, want)
	}
	if rep.Rules.Active != 7 || rep.Rules.Degraded != 1 || rep.Rules.Unknown != 0 || rep.Rules.Total != 8 {
		t.Errorf("rules = %+v, want 7 active, 1 degraded, 0 unknown, 8 total", rep.Rules)
	}
	if want := "r_01M335HMAB… bind failed: address already in use"; rep.Rules.Detail != want {
		t.Errorf("rules.detail = %q, want %q", rep.Rules.Detail, want)
	}
	if rep.Warnings.Count != 1 {
		t.Errorf("warnings.count = %d, want 1", rep.Warnings.Count)
	}
	if want := "ip-flapping on home, 1m0s ago"; rep.Warnings.Detail != want {
		t.Errorf("warnings.detail = %q, want %q", rep.Warnings.Detail, want)
	}

	var buf bytes.Buffer
	writeStatusReport(&buf, rep)
	want := "Server        healthy\n" +
		"Agents        1 healthy, 1 degraded / 2   home2 last seen 4m12s ago\n" +
		"Rules         7 active, 1 degraded / 8   r_01M335HMAB… bind failed: address already in use\n" +
		"Warnings      1              ip-flapping on home, 1m0s ago\n"
	if got := buf.String(); got != want {
		t.Errorf("writeStatusReport =\n%s\nwant\n%s", got, want)
	}

	err := statusExit(rep)
	if err == nil {
		t.Fatal("a degraded rule, a disconnected agent and an open warning must exit non-zero")
	}
	if code := exitCode(err); code != 1 {
		t.Errorf("a degraded item exits 1, got %d", code)
	}
}

// The four tests below each break exactly one of the four causes statusExit reads, leaving the
// other three healthy. TestBuildStatusReportProblems alone breaks three causes at once, so an
// independent review found that mutating any one of statusExit's four sections (or dropping a
// single cause) still left err != nil and went undetected. These tests close that gap: each one
// fails on its own if the matching section of statusExit is removed.

// TestStatusExitServerDegradedOnly は、Server 行だけが degraded なら終了コードが 1 になり、
// 他の 3 行は健全なままであることを確かめる。
func TestStatusExitServerDegradedOnly(t *testing.T) {
	in := healthyStatusInput()
	in.Rules.ApplyError = "backend closed"
	rep := buildStatusReport(in)

	if rep.Server.Status != serverDegraded {
		t.Fatalf("server = %+v, want degraded", rep.Server)
	}
	if rep.Rules.Degraded != 0 || rep.Rules.Unknown != 0 {
		t.Errorf("rules must stay healthy, got %+v", rep.Rules)
	}
	if rep.Agents.Healthy != rep.Agents.Total {
		t.Errorf("agents must stay healthy, got %+v", rep.Agents)
	}
	if rep.Warnings.Count != 0 {
		t.Errorf("warnings must stay healthy, got %+v", rep.Warnings)
	}
	if err := statusExit(rep); err == nil {
		t.Fatal("a degraded server alone must exit non-zero")
	} else if code := exitCode(err); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// TestStatusExitRulesDegradedOnly は、Rules 行だけに degraded なルールが 1 本あれば終了コードが
// 1 になり、他の 3 行は健全なままであることを確かめる。
func TestStatusExitRulesDegradedOnly(t *testing.T) {
	in := healthyStatusInput()
	var oneID string
	for _, r := range in.Rules.Rules {
		if r.Enabled {
			oneID = r.ID
			break
		}
	}
	in.Rules.RuleStates[oneID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: "bind failed"}
	rep := buildStatusReport(in)

	if rep.Server.Status != serverHealthy {
		t.Errorf("server must stay healthy, got %+v", rep.Server)
	}
	if rep.Rules.Degraded != 1 {
		t.Fatalf("rules.degraded = %d, want 1", rep.Rules.Degraded)
	}
	if rep.Agents.Healthy != rep.Agents.Total {
		t.Errorf("agents must stay healthy, got %+v", rep.Agents)
	}
	if rep.Warnings.Count != 0 {
		t.Errorf("warnings must stay healthy, got %+v", rep.Warnings)
	}
	if err := statusExit(rep); err == nil {
		t.Fatal("a degraded rule alone must exit non-zero")
	} else if code := exitCode(err); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// TestStatusExitAgentDisconnectedOnly は、Agents 行だけが 1 台切れていれば終了コードが 1 に
// なり、他の 3 行は健全なままであることを確かめる。
func TestStatusExitAgentDisconnectedOnly(t *testing.T) {
	in := healthyStatusInput()
	in.Agents[0].Connected = false
	in.Agents[0].LastHeartbeat = at(90 * time.Second)
	rep := buildStatusReport(in)

	if rep.Server.Status != serverHealthy {
		t.Errorf("server must stay healthy, got %+v", rep.Server)
	}
	if rep.Rules.Degraded != 0 || rep.Rules.Unknown != 0 {
		t.Errorf("rules must stay healthy, got %+v", rep.Rules)
	}
	if rep.Agents.Healthy != rep.Agents.Total-1 {
		t.Fatalf("agents = %+v, want one fewer healthy than total", rep.Agents)
	}
	if rep.Warnings.Count != 0 {
		t.Errorf("warnings must stay healthy, got %+v", rep.Warnings)
	}
	if err := statusExit(rep); err == nil {
		t.Fatal("a disconnected agent alone must exit non-zero")
	} else if code := exitCode(err); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// TestStatusExitWarningsOnly は、Warnings 行だけに開いている警告が 1 件あれば終了コードが 1 に
// なり、他の 3 行は健全なままであることを確かめる。
func TestStatusExitWarningsOnly(t *testing.T) {
	in := healthyStatusInput()
	in.Warnings = []admin.Warning{{Agent: "home", Kind: "ip-flapping", Detail: "returned to an earlier value", At: at(time.Minute)}}
	rep := buildStatusReport(in)

	if rep.Server.Status != serverHealthy {
		t.Errorf("server must stay healthy, got %+v", rep.Server)
	}
	if rep.Rules.Degraded != 0 || rep.Rules.Unknown != 0 {
		t.Errorf("rules must stay healthy, got %+v", rep.Rules)
	}
	if rep.Agents.Healthy != rep.Agents.Total {
		t.Errorf("agents must stay healthy, got %+v", rep.Agents)
	}
	if rep.Warnings.Count != 1 {
		t.Fatalf("warnings.count = %d, want 1", rep.Warnings.Count)
	}
	if err := statusExit(rep); err == nil {
		t.Fatal("an open warning alone must exit non-zero")
	} else if code := exitCode(err); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// --- Agents 行のトンネルの健全さ: 所有者の決定(2026-09-22)の試験 ---
//
// 以下は、独立レビューが挙げた最も重い欠陥をそのまま再現する。トンネルが死んでいて制御ストリーム
// だけ生きている配置で、Agents 行が Connected しか見なければ「1 / 1 healthy」と言い、終了コードは
// 0 のままになる。`server doctor` は同じ入力に対して exit 1 を返す。agentHealthOf(status.go)は
// doctor.go の tunnelHealth(`tunnel.handshake`、10.2a 節、handshakeStale=3 分)をそのまま呼び、
// この食い違いを閉じる。

// TestAgentHealthOfTunnelDeadButControlAliveIsDegraded は、独立レビューの指摘そのものを
// agentHealthOf 単体で確かめる。制御ストリームは繋がっている(Connected: true)が、最終
// ハンドシェイクが一度も観測されていない、つまりトンネルは死んでいる。
func TestAgentHealthOfTunnelDeadButControlAliveIsDegraded(t *testing.T) {
	a := admin.AgentInfo{Name: "home", Connected: true, LastHeartbeat: at(5 * time.Second)}
	status, detail := agentHealthOf(a, doctorNow)
	if status != serverDegraded {
		t.Fatalf("status = %q, want %q: a dead tunnel behind a live control stream must not read healthy", status, serverDegraded)
	}
	if !strings.Contains(detail, "home") || !strings.Contains(detail, "tunnel") {
		t.Errorf("detail = %q, want it to name the agent and the tunnel", detail)
	}
}

// TestAgentHealthOfStaleHandshakeIsDegraded は、一度は観測されたが古くなったハンドシェイクも
// degraded にすることを確かめる。前のテスト(ハンドシェイクを一度も観測していない場合)だけでは、
// tunnelHealth の古さの確認(`now.Sub(hs) > handshakeStale`)を丸ごと落として「一度も観測して
// いない場合だけ」に狭める変異を見逃す。
func TestAgentHealthOfStaleHandshakeIsDegraded(t *testing.T) {
	a := admin.AgentInfo{Name: "home", Connected: true, LastHeartbeat: at(5 * time.Second), LastHandshake: at(9 * time.Minute)}
	status, detail := agentHealthOf(a, doctorNow)
	if status != serverDegraded {
		t.Fatalf("status = %q, want %q: a handshake 9 minutes old is well past handshakeStale (3m)", status, serverDegraded)
	}
	if !strings.Contains(detail, "ago") {
		t.Errorf("detail = %q, want it to carry the handshake's age", detail)
	}
}

// TestStatusRunEDegradedWhenTunnelIsDeadButControlIsAlive is the direct RunE-level regression test
// for the defect an independent review found: with a control stream up but no tunnel handshake
// ever observed, `wgft status` used to print "1 / 1 healthy" and exit 0 while `server doctor` on
// the same input already exits 1. It must now print the agent as degraded and exit 1 too.
func TestStatusRunEDegradedWhenTunnelIsDeadButControlIsAlive(t *testing.T) {
	b := degradedStatusBackend()
	// Isolate this one cause: make every rule and warning healthy, keep only the agent whose
	// control stream is alive but whose tunnel has no handshake at all.
	rules := rulesFixture()
	states := map[string]admin.RuleApply{}
	agentStates := map[string]admin.AgentRuleStatus{}
	for _, r := range rules {
		if !r.Enabled {
			states[r.ID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: "disabled"}
			continue
		}
		states[r.ID] = admin.RuleApply{ApplyState: admin.ApplyActive}
		agentStates[r.ID] = admin.AgentRuleStatus{Agent: r.Agent, State: proto.StatusOK, Connected: true, At: at(5 * time.Second)}
	}
	b.rules = rules
	b.apply = admin.ApplyStatus{DesiredGeneration: 9, ActiveGeneration: 9, Rules: states}
	b.agentRuleStates = agentStates
	b.agents = []admin.AgentInfo{{Name: "home", Connected: true, LastHeartbeat: at(5 * time.Second)}} // no LastHandshake at all
	b.warnings = nil

	srv := httptest.NewServer(admin.New(b))
	defer srv.Close()

	stdout, err := runStatusCmd(t, srv.URL)
	if strings.Contains(stdout, "1 / 1 healthy") {
		t.Errorf("a dead tunnel behind a live control stream must not read healthy, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "degraded") {
		t.Errorf("stdout must show the agent degraded, got:\n%s", stdout)
	}
	if err == nil {
		t.Fatal("a dead tunnel behind a live control stream must make status exit non-zero, matching server doctor")
	}
	if code := exitCode(err); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// TestAgentHealthOfTunnelErrorIsDegraded は、制御ストリームが繋がっていて最終ハンドシェイクも
// 新しいが、エージェント自身がトンネルを error と報告している場合を確かめる。tunnelHealth
// (doctor.go)の failed をそのまま degraded に写す。
func TestAgentHealthOfTunnelErrorIsDegraded(t *testing.T) {
	a := admin.AgentInfo{
		Name: "home", Connected: true, LastHeartbeat: at(5 * time.Second), LastHandshake: at(5 * time.Second),
		Tunnel: admin.TunnelStatus{State: proto.StatusError, Reason: "handshake not established"},
	}
	status, detail := agentHealthOf(a, doctorNow)
	if status != serverDegraded {
		t.Fatalf("status = %q, want %q", status, serverDegraded)
	}
	if !strings.Contains(detail, "handshake not established") {
		t.Errorf("detail = %q, want it to carry the agent's own reason", detail)
	}
}

// TestAgentHealthOfUnknownTunnelStateIsUnknown は、tunnelHealth の unknown 側の分岐(この版の
// 知らないトンネルの状態、7a.11 節の開いた集合)を、degraded ではなく unknown に写すことを
// 確かめる。
func TestAgentHealthOfUnknownTunnelStateIsUnknown(t *testing.T) {
	a := admin.AgentInfo{
		Name: "home", Connected: true, LastHeartbeat: at(5 * time.Second), LastHandshake: at(5 * time.Second),
		Tunnel: admin.TunnelStatus{State: "handshaking"},
	}
	status, _ := agentHealthOf(a, doctorNow)
	if status != statusUnknown {
		t.Fatalf("status = %q, want %q: an unrecognized tunnel state must not be treated as a fault", status, statusUnknown)
	}
}

// TestStatusExitUnknownTunnelStateAloneExitsZero は、上の unknown な分類が終了コードを動かさ
// ないことを確かめる。unknown は degraded と違い、故障を観測してはいない(design.md 10.2b 節)。
func TestStatusExitUnknownTunnelStateAloneExitsZero(t *testing.T) {
	in := healthyStatusInput()
	in.Agents[0].Tunnel = admin.TunnelStatus{State: "handshaking"}
	rep := buildStatusReport(in)

	if rep.Agents.Degraded != 0 {
		t.Fatalf("agents = %+v, want 0 degraded", rep.Agents)
	}
	if rep.Agents.Unknown != 1 {
		t.Fatalf("agents = %+v, want 1 unknown", rep.Agents)
	}
	if err := statusExit(rep); err != nil {
		t.Errorf("an unrecognized tunnel state alone must exit 0, got %v", err)
	}
}

// TestServerStatusOfGenerationGap は、Server 行が世代の遅れを検出することを確かめる。優先順位
// は doctor.go の dataplaneCheck と同じで、世代の遅れがあれば apply_error より先に報告する。
func TestServerStatusOfGenerationGap(t *testing.T) {
	res := &admin.BatchResponse{DesiredGeneration: u64(10), ActiveGeneration: u64(9), ApplyError: "backend closed"}
	st := serverStatusOf(res)
	if st.Status != serverDegraded {
		t.Fatalf("a generation gap must be degraded, got %+v", st)
	}
	if st.Detail == "" {
		t.Error("detail must not be empty")
	}
}

// TestServerStatusOfApplyError は、世代が揃っていても apply_error が残っていれば健全でない
// ことを確かめる(戻れない地点の後の修復の失敗、design.md 7a.3 節)。
func TestServerStatusOfApplyError(t *testing.T) {
	res := &admin.BatchResponse{DesiredGeneration: u64(9), ActiveGeneration: u64(9), ApplyError: "repair failed"}
	st := serverStatusOf(res)
	if st.Status != serverDegraded {
		t.Fatalf("a lingering apply_error must be degraded, got %+v", st)
	}
}

// TestServerStatusOfNoEvidence は、報告を持たない Backend(世代も apply_error も無い)を unknown
// として扱うことを確かめる。故障を観測してはいないが、健全だという証拠も無いので、healthy とは
// 別の状態にする(design.md 10.2b 節)。旧い版の server にこの版の CLI を向けたとき、フィールドが
// まだ返らないだけで "Server healthy" と誤って言ってしまうことを防ぐための決定である。
func TestServerStatusOfNoEvidence(t *testing.T) {
	st := serverStatusOf(&admin.BatchResponse{})
	if st.Status != statusUnknown {
		t.Errorf("no evidence of failure must read unknown, not healthy, got %+v", st)
	}
	if st.Detail == "" {
		t.Error("unknown must still say why, detail is empty")
	}
}

// TestServerStatusOfApplyErrorWithoutGenerations は、apply_error だけが証拠にある場合(世代の
// フィールドは無い)、それでも degraded にすることを確かめる。apply_error は世代とは別の証拠で
// あり、これが有る以上「証拠が無い」とは言えない(design.md 10.2b 節)。
func TestServerStatusOfApplyErrorWithoutGenerations(t *testing.T) {
	st := serverStatusOf(&admin.BatchResponse{ApplyError: "backend closed"})
	if st.Status != serverDegraded {
		t.Errorf("an apply_error without generations must still be degraded, got %+v", st)
	}
}

// TestAgentsStatusOfNeverConnected は、ハートビートを一度も送っていないエージェントの文言を
// 確かめる。
func TestAgentsStatusOfNeverConnected(t *testing.T) {
	st := agentsStatusOf([]admin.AgentInfo{{Name: "home3", Connected: false}}, doctorNow)
	if st.Healthy != 0 || st.Degraded != 1 || st.Unknown != 0 || st.Total != 1 {
		t.Fatalf("st = %+v", st)
	}
	if want := "home3 never connected"; st.Detail != want {
		t.Errorf("detail = %q, want %q", st.Detail, want)
	}
}

// TestStatusJSONRoundTrip は、健全でない場合の --json の形が design.md 10.2b 節の例と一致
// することを確かめる。3 つの状態(healthy・degraded・unknown)は、Server は文字列の "status" で、
// Rules は active・degraded・unknown の 3 つの数え分けで、それぞれ区別できる。
func TestStatusJSONRoundTrip(t *testing.T) {
	rep := buildStatusReport(statusExampleInput())
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var back statusReport
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back != rep {
		t.Errorf("round trip mismatch: got %+v, want %+v", back, rep)
	}
	for _, want := range []string{
		`"server":{"status":"healthy"}`,
		`"agents":{"healthy":1,"degraded":1,"unknown":0,"disabled":0,"total":2,"detail":"home2 last seen 4m12s ago"}`,
		`"rules":{"active":7,"degraded":1,"unknown":0,"agent_disabled":0,"total":8,"detail":"r_01M335HMAB… bind failed: address already in use"}`,
		`"warnings":{"count":1,"detail":"ip-flapping on home, 1m0s ago"}`,
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("json = %s, want it to contain %s", data, want)
		}
	}
}

// TestBuildStatusReportVersionMismatch は所有者のレビューが挙げた場合を再現する。世代のフィールド
// を返さず、rule_states も空の旧い版の server に対しては、Server が unknown になり、Rules も
// unknown を含む形になる。証拠が無いことを健全と数えていた誤りの直接の再現であり、直った後は
// 終了コードが 0 のままであること(unknown は非 0 にしない)も併せて確かめる(design.md 10.2b 節)。
func TestBuildStatusReportVersionMismatch(t *testing.T) {
	rules := rulesFixture()
	in := statusInput{
		Now: doctorNow,
		Rules: &admin.BatchResponse{
			Rules: rules, // no DesiredGeneration, no ActiveGeneration, no ApplyError, no RuleStates
		},
		Agents: []admin.AgentInfo{
			{Name: "home", Connected: true, LastHeartbeat: at(5 * time.Second), LastHandshake: at(5 * time.Second)},
		},
	}
	rep := buildStatusReport(in)

	if rep.Server.Status != statusUnknown {
		t.Errorf("server = %+v, want unknown", rep.Server)
	}
	if rep.Server.Detail == "" {
		t.Error("an unknown server must still say why")
	}
	// The 8 enabled rules (the disabled one is excluded) must all read unknown, not active:
	// a Backend that reports nothing has given no evidence that any of them is being forwarded.
	if rep.Rules.Active != 0 || rep.Rules.Degraded != 0 || rep.Rules.Unknown != 8 || rep.Rules.Total != 8 {
		t.Errorf("rules = %+v, want 0 active, 0 degraded, 8 unknown, 8 total", rep.Rules)
	}
	if rep.Rules.Detail == "" {
		t.Error("unknown rules must still say that apply state is unavailable")
	}

	if err := statusExit(rep); err != nil {
		t.Errorf("unknown alone must exit 0, matching server doctor's own UNKNOWN, got %v", err)
	}
}

// TestWriteStatusReportRulesUnknown は、Rules 行の unknown 側の枝(rulesValue の数え分けの形と、
// unknown の内訳を添える detail の文言)を writeStatusReport を通して確かめる。design.md の
// 改訂の記録は、この枝を writeStatusReport で確かめたと述べていたが、実際にはそのテストが無かった
// (レビューの指摘)。
func TestWriteStatusReportRulesUnknown(t *testing.T) {
	rep := buildStatusReport(statusInput{
		Now: doctorNow,
		Rules: &admin.BatchResponse{
			Rules: rulesFixture(), // no DesiredGeneration, no ActiveGeneration, no ApplyError, no RuleStates
		},
		Agents: []admin.AgentInfo{{Name: "home", Connected: true, LastHeartbeat: at(5 * time.Second), LastHandshake: at(5 * time.Second)}},
	})

	if got := rulesValue(rep.Rules); got != "0 active, 8 unknown / 8" {
		t.Errorf("rulesValue = %q, want %q", got, "0 active, 8 unknown / 8")
	}

	var buf bytes.Buffer
	writeStatusReport(&buf, rep)
	got := buf.String()
	if !strings.Contains(got, "0 active, 8 unknown / 8") {
		t.Errorf("writeStatusReport must print the per-state counts, got:\n%s", got)
	}
	if !strings.Contains(got, "apply state is unavailable for 8 rules") {
		t.Errorf("writeStatusReport must name the unknown rules, got:\n%s", got)
	}
}

// TestRulesStatusOfUnknownApplyStateValue は、この版が知らない apply_state の値(将来の版の
// server が足しうる値、例えば "retiring")を、故障ではなく unknown に数え、終了コードを 0 の
// ままにすることを確かめる。apply_state は増えうる開いた集合であり、知らない値を失敗にしては
// ならないという約束(design.md 7a.11 節)を、この版から知る値だけを degraded に数える形で守る。
// かつての default 節は、active 以外を丸ごと degraded に数えており、新しい版の server に古い CLI
// を向けたとき、まだ知らない値だけで誤って壊れていると報告していた。
func TestRulesStatusOfUnknownApplyStateValue(t *testing.T) {
	rules := rulesFixture()
	states := map[string]admin.RuleApply{}
	agentStates := map[string]admin.AgentRuleStatus{}
	for _, r := range rules {
		if !r.Enabled {
			states[r.ID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: "disabled"}
			continue
		}
		states[r.ID] = admin.RuleApply{ApplyState: admin.ApplyActive}
		agentStates[r.ID] = admin.AgentRuleStatus{Agent: r.Agent, State: proto.StatusOK, Connected: true, At: at(5 * time.Second)}
	}
	// One enabled rule reports a value this build has never heard of.
	var oneID string
	for _, r := range rules {
		if r.Enabled {
			oneID = r.ID
			break
		}
	}
	states[oneID] = admin.RuleApply{ApplyState: "retiring"}

	in := statusInput{
		Now: doctorNow,
		Rules: &admin.BatchResponse{
			Rules: rules, DesiredGeneration: u64(9), ActiveGeneration: u64(9), RuleStates: states, AgentRuleStates: agentStates,
		},
		Agents: []admin.AgentInfo{{Name: "home", Connected: true, LastHeartbeat: at(5 * time.Second), LastHandshake: at(5 * time.Second)}},
	}
	rep := buildStatusReport(in)

	if rep.Rules.Active != 7 || rep.Rules.Degraded != 0 || rep.Rules.Unknown != 1 || rep.Rules.Total != 8 {
		t.Errorf("rules = %+v, want 7 active, 0 degraded, 1 unknown, 8 total", rep.Rules)
	}
	if err := statusExit(rep); err != nil {
		t.Errorf("an unknown apply_state value alone must exit 0, got %v", err)
	}
	if want := "apply state is an unrecognized value for 1 rule"; !strings.Contains(rep.Rules.Detail, want) {
		t.Errorf("rules.detail = %q, want it to contain %q (not \"unavailable\": a value did arrive)", rep.Rules.Detail, want)
	}
}

// TestRulesStatusOfFreshUnknownAgentStateIsUnknownNotActive は、レビューが入れた変異
// (`case fresh && ars.State == proto.StatusOK:` を `case fresh:` に変える)が生き残っていた穴を
// 固定する。server は apply_state を active と報告し、そのルールの持ち主のエージェントの報告も
// 鮮度があるが、State がこの版の知らない値(将来の agent が足しうる値、例えば "starting")なら、
// active ではなく unknown に数える。7a.11 節は agent_rule_states の state も apply_state と同じ
// 開いた集合と定めており、エージェント側だけをこの約束の外に置いてはならない。
func TestRulesStatusOfFreshUnknownAgentStateIsUnknownNotActive(t *testing.T) {
	in := healthyStatusInput()
	var oneID string
	for _, r := range in.Rules.Rules {
		if r.Enabled {
			oneID = r.ID
			break
		}
	}
	in.Rules.AgentRuleStates[oneID] = admin.AgentRuleStatus{
		Agent: "home", State: "starting", Connected: true, At: at(5 * time.Second),
	}
	rep := buildStatusReport(in)

	if rep.Rules.Active != 7 || rep.Rules.Degraded != 0 || rep.Rules.Unknown != 1 || rep.Rules.Total != 8 {
		t.Fatalf("rules = %+v, want 7 active, 0 degraded, 1 unknown, 8 total", rep.Rules)
	}
	if err := statusExit(rep); err != nil {
		t.Errorf("an unrecognized agent-side state alone must exit 0, got %v", err)
	}
}

// TestStatusWrongArgumentCountExitsUnavailable は、`server doctor` と同じ扱い(design.md
// 10.2b 節)で、引数の誤りが終了コード 2 になることを確かめる。
func TestStatusWrongArgumentCountExitsUnavailable(t *testing.T) {
	err := newStatusCmd().Args(nil, []string{"one"})
	if err == nil {
		t.Fatal("an argument must be rejected; status takes none")
	}
	var un *unavailableError
	if !errors.As(err, &un) {
		t.Errorf("the argument error must be an *unavailableError so it exits %d, got %T: %v", exitUnavailable, err, err)
	}
	if code := exitCode(err); code != exitUnavailable {
		t.Errorf("exit code = %d, want %d", code, exitUnavailable)
	}
	if err := newStatusCmd().Args(nil, nil); err != nil {
		t.Errorf("no argument is valid, got %v", err)
	}
}

// TestStatusUnknownFlagExitsUnavailable は、フラグの誤りも終了コード 2 になることを確かめる。
func TestStatusUnknownFlagExitsUnavailable(t *testing.T) {
	cmd := newStatusCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--bogus"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("an unknown flag must be rejected")
	}
	var un *unavailableError
	if !errors.As(err, &un) {
		t.Errorf("the flag error must be an *unavailableError so it exits %d, got %T: %v", exitUnavailable, err, err)
	}
	if code := exitCode(err); code != exitUnavailable {
		t.Errorf("exit code = %d, want %d", code, exitUnavailable)
	}
}

// --- RunE 経由の試験 ---
//
// buildStatusReport や statusExit を直接呼ぶ上のテストは、cmd/wgft/status.go の RunE 自身を
// 一度も通さない。独立レビューが見つけた最も重い欠陥(--json の経路が enc.Encode の戻り値をそのまま
// 返し、statusExit まで届かないので degraded でも終了コード 0 になっていた)は、この経路にしか
// 現れなかった。fakeStatusBackend は internal/vpsd/admin の内部専用の fakeBackend を cmd/wgft から
// 使えないので同じ形で持つ最小限の Backend 実装であり、rule_test.go の fakeRuleBackend と同じ理由
// で存在する。

type fakeStatusBackend struct {
	rules    []proto.Rule
	agents   []admin.AgentInfo
	warnings []admin.Warning
	apply    admin.ApplyStatus
	// agentRuleStates, when non-nil, makes this backend implement admin.AgentRuleStatusBackend (see
	// AgentRuleStatuses below), so a rule ApplyActive without a matching entry here reads as no
	// fresh agent evidence (unknown), and a matching entry drives the active/degraded split
	// (design.md 10.2b 節, 2026-09-22).
	agentRuleStates map[string]admin.AgentRuleStatus
	// rulesErr, agentsErr and warningsErr, when set, make the matching method fail so the admin
	// HTTP layer answers 500 and internal/vpsd/admin.Client's call returns a non-nil error. Used to
	// confirm `wgft status` wraps every admin API failure as *unavailableError (exit 2), not just
	// the one from GET /api/v1/rules (an independent review found the Agents/Warnings failures were
	// never separately tested).
	rulesErr, agentsErr, warningsErr error
}

func (b *fakeStatusBackend) Rules() ([]proto.Rule, error)            { return b.rules, b.rulesErr }
func (b *fakeStatusBackend) Generation() (uint64, error)             { return b.apply.DesiredGeneration, nil }
func (b *fakeStatusBackend) AgentState(string) (*proto.State, error) { return &proto.State{}, nil }
func (b *fakeStatusBackend) Agents() ([]admin.AgentInfo, error)      { return b.agents, b.agentsErr }
func (b *fakeStatusBackend) RuleDrops() (map[string]uint64, error)   { return nil, nil }
func (b *fakeStatusBackend) JoinString(string) (admin.JoinStringResponse, error) {
	return admin.JoinStringResponse{}, nil
}
func (b *fakeStatusBackend) Revoke(string) error { return nil }
func (b *fakeStatusBackend) DisableAgent(string) (admin.AgentDisabledResponse, error) {
	return admin.AgentDisabledResponse{}, nil
}
func (b *fakeStatusBackend) EnableAgent(string) (admin.AgentDisabledResponse, error) {
	return admin.AgentDisabledResponse{}, nil
}
func (b *fakeStatusBackend) Warnings() ([]admin.Warning, error) {
	return b.warnings, b.warningsErr
}
func (b *fakeStatusBackend) DismissWarning(string, string, string) error { return nil }
func (b *fakeStatusBackend) IPMismatchAcks() ([]store.Ack, error)        { return nil, nil }
func (b *fakeStatusBackend) CheckConnectivity(string) (admin.ConnCheck, error) {
	return admin.ConnCheck{}, nil
}
func (b *fakeStatusBackend) ServerInfo() (admin.ServerInfo, error) { return admin.ServerInfo{}, nil }
func (b *fakeStatusBackend) Batch(admin.BatchRequest) (*store.BatchResult, error) {
	return nil, nil
}
func (b *fakeStatusBackend) ApplyStatus() (admin.ApplyStatus, bool) { return b.apply, true }

// AgentRuleStatuses implements admin.AgentRuleStatusBackend (internal/vpsd/admin/agent_rule_status.go).
func (b *fakeStatusBackend) AgentRuleStatuses(rules []proto.Rule) map[string]admin.AgentRuleStatus {
	return b.agentRuleStates
}

// degradedStatusBackend は、健全な行が 1 つも無い応答を返す(design.md 10.2b 節の第 2 の例と
// 同じ組み合わせ:degraded なルールが 1 本、切断したエージェントが 1 台、開いている警告が 1 件)。
func degradedStatusBackend() *fakeStatusBackend {
	rules := rulesFixture()
	states := map[string]admin.RuleApply{}
	for i, r := range rules {
		if !r.Enabled {
			states[r.ID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: "disabled"}
			continue
		}
		state := admin.ApplyActive
		if i == 1 {
			state = admin.ApplyNotActive
		}
		states[r.ID] = admin.RuleApply{ApplyState: state, Reason: "bind failed: address already in use"}
	}
	return &fakeStatusBackend{
		rules: rules,
		agents: []admin.AgentInfo{
			{Name: "home", Connected: true, LastHeartbeat: at(5 * time.Second), LastHandshake: at(5 * time.Second)},
			{Name: "home2", Connected: false, LastHeartbeat: at(4*time.Minute + 12*time.Second)},
		},
		warnings: []admin.Warning{{Agent: "home", Kind: "ip-flapping", Detail: "returned to an earlier value", At: at(time.Minute)}},
		apply:    admin.ApplyStatus{DesiredGeneration: 9, ActiveGeneration: 9, Rules: states},
	}
}

// runStatusCmd executes `wgft status` against a fake admin server through cmd.Execute (not
// buildStatusReport/statusExit directly), the way a real invocation would. It runs the bare
// status command rather than the root command, as the other RunE-path tests in this file do, so
// stderr is captured separately: run through the root command, a RunE error also prints cobra's
// own "Error: ..." and usage text, which would otherwise land inside the --json stdout capture.
func runStatusCmd(t *testing.T, adminURL string, args ...string) (stdout string, err error) {
	t.Helper()
	cmd := newStatusCmd()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs(append([]string{"--admin", adminURL}, args...))
	err = cmd.Execute()
	return out.String(), err
}

// TestStatusRunEExitsNonZeroOnDegradedText は、`wgft status`(テキスト出力)の RunE 自身を通し、
// degraded な応答に対して終了コード 1 になることを確かめる。以前はこの経路を試すテストが
// 1 つも無かった。
func TestStatusRunEExitsNonZeroOnDegradedText(t *testing.T) {
	srv := httptest.NewServer(admin.New(degradedStatusBackend()))
	defer srv.Close()

	stdout, err := runStatusCmd(t, srv.URL)
	if !strings.Contains(stdout, "Server") || !strings.Contains(stdout, "Rules") {
		t.Errorf("stdout must hold the four-line report, got:\n%s", stdout)
	}
	if err == nil {
		t.Fatal("a degraded deployment must make status exit non-zero")
	}
	if code := exitCode(err); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// TestStatusRunEExitsNonZeroOnDegradedJSON は、上と同じ degraded な応答に対して、`--json` の
// 経路でも終了コードが 1 になることを確かめる。この経路は、enc.Encode の戻り値をそのまま返して
// いたために statusExit へ届かず、degraded でも終了コード 0 になっていた欠陥そのものの再現である
// (レビューの指摘)。
func TestStatusRunEExitsNonZeroOnDegradedJSON(t *testing.T) {
	srv := httptest.NewServer(admin.New(degradedStatusBackend()))
	defer srv.Close()

	stdout, err := runStatusCmd(t, srv.URL, "--json")
	var rep statusReport
	if jerr := json.Unmarshal([]byte(stdout), &rep); jerr != nil {
		t.Fatalf("--json output is not valid JSON: %v\n%s", jerr, stdout)
	}
	if rep.Rules.Degraded == 0 && rep.Agents.Healthy == rep.Agents.Total && rep.Warnings.Count == 0 {
		t.Fatalf("the fixture must be degraded, got %+v", rep)
	}
	if err == nil {
		t.Fatal("a degraded deployment must make status --json exit non-zero too")
	}
	if code := exitCode(err); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// --- agent_rule_states: 所有者の決定(2026-09-22)の試験 ---
//
// 以下は、Rules 行が server 側の apply_state だけでなくエージェント側の agent_rule_states も
// 読むという、この節の中心の変更を確かめる。独立レビューの指摘そのままの場合(server が 8 本を
// きれいに公開できていても、エージェントが target を拒んでいれば 0 バイトも転送されていない)を
// 再現し、`server doctor` と `status` が食い違わないことを確かめる。

// agentSideFailureStatusBackend は、独立レビューが指摘した場合をそのまま再現する。server は
// 8 本の有効なルールをすべて apply_state active で公開できているが、エージェント自身がどの
// target への到達も拒んでいる(WGFT_AGENT_ALLOW_TARGETS など)。この変更の前は、rulesStatusOf が
// apply_state だけを見ていたので "8 active" と報告し、終了コード 0 で終わっていた。`server doctor`
// は同じ入力から "8 of 8 rules not carrying traffic"(終了コード 1)を返す。
func agentSideFailureStatusBackend() *fakeStatusBackend {
	rules := rulesFixture()
	states := map[string]admin.RuleApply{}
	agentStates := map[string]admin.AgentRuleStatus{}
	for _, r := range rules {
		if !r.Enabled {
			states[r.ID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: "disabled"}
			continue
		}
		states[r.ID] = admin.RuleApply{ApplyState: admin.ApplyActive}
		agentStates[r.ID] = admin.AgentRuleStatus{
			Agent: r.Agent, State: proto.StatusError, Reason: "target not allowed", Connected: true, At: wallNow(5 * time.Second),
		}
	}
	return &fakeStatusBackend{
		rules:           rules,
		agents:          []admin.AgentInfo{{Name: "home", Connected: true, LastHeartbeat: wallNow(5 * time.Second), LastHandshake: wallNow(5 * time.Second)}},
		apply:           admin.ApplyStatus{DesiredGeneration: 9, ActiveGeneration: 9, Rules: states},
		agentRuleStates: agentStates,
	}
}

// TestStatusRunEDegradedWhenAgentRefusesForwarding is the direct regression test for the defect an
// independent review found: rulesStatusOf only read rule_states[].apply_state, so a cleanly
// published rule set whose agent refuses every target still read "8 active" and exited 0. It must
// now read degraded, and status must exit 1, matching `server doctor`'s own failure on the same
// input (design.md 10.2b 節、2026-09-22 の所有者の決定).
func TestStatusRunEDegradedWhenAgentRefusesForwarding(t *testing.T) {
	srv := httptest.NewServer(admin.New(agentSideFailureStatusBackend()))
	defer srv.Close()

	stdout, err := runStatusCmd(t, srv.URL)
	if strings.Contains(stdout, "8 active") {
		t.Errorf("every rule is degraded on the agent side; stdout must not call them active, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "8 degraded") {
		t.Errorf("stdout must show all 8 rules degraded, got:\n%s", stdout)
	}
	if err == nil {
		t.Fatal("an agent that refuses every target must make status exit non-zero, matching server doctor")
	}
	if code := exitCode(err); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// TestRulesStatusOfAgentSideErrorIsDegraded は buildStatusReport を直接通し、上と同じ場合(server
// は active、エージェントの鮮度のある報告は error)が 1 本のルールだけで起きても degraded に数え、
// active には数えないことを確かめる。
func TestRulesStatusOfAgentSideErrorIsDegraded(t *testing.T) {
	in := healthyStatusInput()
	var oneID string
	for _, r := range in.Rules.Rules {
		if r.Enabled {
			oneID = r.ID
			break
		}
	}
	in.Rules.AgentRuleStates[oneID] = admin.AgentRuleStatus{
		Agent: "home", State: proto.StatusError, Reason: "target not allowed", Connected: true, At: at(5 * time.Second),
	}
	rep := buildStatusReport(in)

	if rep.Rules.Active != 7 || rep.Rules.Degraded != 1 || rep.Rules.Unknown != 0 || rep.Rules.Total != 8 {
		t.Fatalf("rules = %+v, want 7 active, 1 degraded, 0 unknown, 8 total", rep.Rules)
	}
	if !strings.Contains(rep.Rules.Detail, "target not allowed") {
		t.Errorf("rules.detail = %q, want it to name the agent's own reason", rep.Rules.Detail)
	}
	if err := statusExit(rep); err == nil {
		t.Error("an agent-side forwarding failure alone must exit non-zero")
	}
}

// TestRulesStatusOfStaleAgentReportIsUnknown は、5.2 節の禁止(切断中のエージェントの最後の報告を
// 今の状態として描いてはならない)を rulesStatusOf が守ることを確かめる。server の apply_state は
// active のままで、エージェントの agent_rule_states の報告だけが古くなった 2 通り(stream が
// 切れた、報告そのものが targetReportStale を超えて古い)を確かめ、どちらも degraded にも active
// にも数えず unknown に落ちることを確かめる。ここが degraded のまま残ると、stream が切れている間
// ずっと壊れていると報告し続けることになり、逆に active のまま残ると、古い ok を今の健全と
// 偽ることになる。
func TestRulesStatusOfStaleAgentReportIsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state admin.AgentRuleStatus
	}{
		{
			"stream disconnected, last report was error",
			admin.AgentRuleStatus{Agent: "home", State: proto.StatusError, Reason: "target not allowed", Connected: false, At: at(5 * time.Second)},
		},
		{
			"stream disconnected, last report was ok",
			admin.AgentRuleStatus{Agent: "home", State: proto.StatusOK, Connected: false, At: at(5 * time.Second)},
		},
		{
			"connected, but the report is older than targetReportStale",
			admin.AgentRuleStatus{Agent: "home", State: proto.StatusError, Reason: "target not allowed", Connected: true, At: at(2 * time.Minute)},
		},
		{
			"connected, ok, but older than targetReportStale",
			admin.AgentRuleStatus{Agent: "home", State: proto.StatusOK, Connected: true, At: at(2 * time.Minute)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := healthyStatusInput()
			var oneID string
			for _, r := range in.Rules.Rules {
				if r.Enabled {
					oneID = r.ID
					break
				}
			}
			in.Rules.AgentRuleStates[oneID] = tc.state
			rep := buildStatusReport(in)

			if rep.Rules.Active != 7 || rep.Rules.Degraded != 0 || rep.Rules.Unknown != 1 || rep.Rules.Total != 8 {
				t.Fatalf("rules = %+v, want 7 active, 0 degraded, 1 unknown, 8 total", rep.Rules)
			}
			if err := statusExit(rep); err != nil {
				t.Errorf("a stale agent report alone must not raise the exit code, got %v", err)
			}
		})
	}
}

// TestRulesStatusOfApplyPendingIsDegraded は、admin.ApplyPending(admin.ApplyNotActive の姉妹の
// 既知の値)も degraded に数えることを確かめる。既存の試験はどれも ApplyNotActive しか使っておらず、
// rulesStatusOf の case 節から ApplyPending を落とす変異が検出されずに残っていた(レビューの
// 指摘)。
func TestRulesStatusOfApplyPendingIsDegraded(t *testing.T) {
	in := healthyStatusInput()
	var oneID string
	for _, r := range in.Rules.Rules {
		if r.Enabled {
			oneID = r.ID
			break
		}
	}
	in.Rules.RuleStates[oneID] = admin.RuleApply{ApplyState: admin.ApplyPending, Reason: "nftables: transaction failed"}
	rep := buildStatusReport(in)

	if rep.Rules.Active != 7 || rep.Rules.Degraded != 1 || rep.Rules.Unknown != 0 || rep.Rules.Total != 8 {
		t.Fatalf("rules = %+v, want 7 active, 1 degraded, 0 unknown, 8 total", rep.Rules)
	}
	if err := statusExit(rep); err == nil {
		t.Error("a pending rule alone must exit non-zero")
	}
}

// --- 管理用 API への到達失敗の試験 ---
//
// 独立レビューは、c.Rules()・c.Warnings()・c.Agents() のどの失敗も、包まずそのまま返す変異
// (unavailable(err) を err に変える)が生き残ることを指摘した。以下は、RunE を通してこの 3 つを
// それぞれ確かめる。

// TestStatusRunEAdminUnreachableExitsUnavailable は、管理用 API がまったく応答しない場合(閉じた
// httptest サーバ)、c.Rules() の失敗が終了コード 2 になることを確かめる。unavailable(err) を
// err に変える変異が入ると、この場合の終了コードは 1 になる。
func TestStatusRunEAdminUnreachableExitsUnavailable(t *testing.T) {
	srv := httptest.NewServer(admin.New(degradedStatusBackend()))
	srv.Close() // close before use: every request now fails to connect

	_, err := runStatusCmd(t, srv.URL)
	if err == nil {
		t.Fatal("an unreachable admin API must make status exit non-zero")
	}
	if code := exitCode(err); code != exitUnavailable {
		t.Errorf("exit code = %d, want %d (not 1: this is not a degraded report, it is no report at all)", code, exitUnavailable)
	}
}

// TestStatusRunEAgentsFetchFailureExitsUnavailable は、GET /api/v1/rules は答えるが
// GET /api/v1/agents だけが失敗する場合を確かめる。c.Rules() だけを試す試験では、c.Agents() の
// unavailable(err) を err に変える変異を見逃す。
func TestStatusRunEAgentsFetchFailureExitsUnavailable(t *testing.T) {
	b := degradedStatusBackend()
	b.agentsErr = errors.New("backend closed")
	srv := httptest.NewServer(admin.New(b))
	defer srv.Close()

	_, err := runStatusCmd(t, srv.URL)
	if err == nil {
		t.Fatal("a failing GET /api/v1/agents must make status exit non-zero")
	}
	if code := exitCode(err); code != exitUnavailable {
		t.Errorf("exit code = %d, want %d", code, exitUnavailable)
	}
}

// TestStatusRunEWarningsFetchFailureExitsUnavailable is the same guard for GET /api/v1/warnings.
func TestStatusRunEWarningsFetchFailureExitsUnavailable(t *testing.T) {
	b := degradedStatusBackend()
	b.warningsErr = errors.New("backend closed")
	srv := httptest.NewServer(admin.New(b))
	defer srv.Close()

	_, err := runStatusCmd(t, srv.URL)
	if err == nil {
		t.Fatal("a failing GET /api/v1/warnings must make status exit non-zero")
	}
	if code := exitCode(err); code != exitUnavailable {
		t.Errorf("exit code = %d, want %d", code, exitUnavailable)
	}
}

// failWriter is an io.Writer that always fails, standing in for a full disk or a closed pipe on
// stdout.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// TestStatusRunEJSONEncodeFailureExitsUnavailable は、`--json` の出力先への書き込みそのものが
// 失敗した場合を確かめる。独立レビューは、enc.Encode の失敗を包む unavailable(err) を err に
// 変える変異が生き残ることを指摘した。その変異が入ると、この場合の終了コードは 1 になる。
func TestStatusRunEJSONEncodeFailureExitsUnavailable(t *testing.T) {
	srv := httptest.NewServer(admin.New(degradedStatusBackend()))
	defer srv.Close()

	cmd := newStatusCmd()
	cmd.SetOut(failWriter{})
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--admin", srv.URL, "--json"})
	err := cmd.Execute()

	if err == nil {
		t.Fatal("a write failure on --json output must make status exit non-zero")
	}
	if code := exitCode(err); code != exitUnavailable {
		t.Errorf("exit code = %d, want %d (not 1: the report itself could not be delivered)", code, exitUnavailable)
	}
}
