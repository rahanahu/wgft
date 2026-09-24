package admin

import (
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、ダッシュボードのルール一覧の診断の印(設計文書 10.1、10.2d 節)を確かめる。
// 印は診断の画面と同じ判定と図(doctor.BuildReport、doctorPath)から選ぶだけであり、ヘッダの
// 全体ヘルスとグループの見出しの error の件数も、同じ印から数える。

// markFixture は、印のそれぞれの形と、適用状態のバッジと印が食い違う行を 1 本ずつ持つ。
//
//	g1:        r_ok(✓)、r_err(✕ listener / target、バッジは Error)、
//	           r_hs(✕ WireGuard、バッジは Applied。ハンドシェイクだけが古い)
//	g2:        r_stale(? agent、バッジは Error。ハートビートが古い)、r_deg(? agent、切断していて
//	           ハンドシェイクは新しい)、r_late(? listener / target、まだ報告されていない)、
//	           r_dis(無効なルール、灰色)、r_gone(持ち主のエージェントが未登録、灰色)
//	           r_paused(無効なエージェントのルール、灰色。server は not_active を報告する)
//	その他:    r_down(✕ WireGuard、バッジは Agent offline)
//
// バッジの色から数えると g1 は 1 件、g2 は 1 件、その他は 0 件、全体は 2 件になる。印から数えると
// g1 は 2 件、g2 は 0 件、その他は 1 件、全体は 3 件である。
func markFixture(t *testing.T) (*countingBackend, *Server) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rule := func(id, agent, group string, p proto.Proto, port uint16, enabled bool) proto.Rule {
		return proto.Rule{ID: id, Agent: agent, Group: group, Proto: p, ListenPort: proto.PortRange{Lo: port, Hi: port},
			Target: fmt.Sprintf("192.168.1.20:%d", port), VPSMode: proto.ModeKernel, Enabled: enabled}
	}
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules,
			rule("r_ok", "home", "g1", proto.TCP, 1001, true),
			rule("r_err", "home", "g1", proto.TCP, 1002, true),
			rule("r_hs", "edge", "g1", proto.TCP, 1003, true),
			rule("r_stale", "quiet", "g2", proto.TCP, 1004, true),
			rule("r_deg", "lan", "g2", proto.TCP, 1005, true),
			rule("r_late", "home", "g2", proto.TCP, 1006, true),
			rule("r_dis", "home", "g2", proto.TCP, 1007, false),
			rule("r_gone", "ghost", "g2", proto.TCP, 1008, true),
			rule("r_paused", "paused", "g2", proto.TCP, 1010, true),
			rule("r_down", "down", "", proto.TCP, 1009, true),
		), nil
	}); err != nil {
		t.Fatal(err)
	}
	gen, err := st.Generation()
	if err != nil {
		t.Fatal(err)
	}
	ago := func(d time.Duration) string { return time.Now().Add(-d).Format(time.RFC3339) }
	ok := TunnelStatus{State: proto.StatusOK}
	agents := []AgentInfo{
		{Name: "home", Connected: true, Generation: gen, LastHeartbeat: ago(10 * time.Second), LastHandshake: ago(30 * time.Second), Tunnel: ok,
			Rules: []proto.RuleStatus{
				{ID: "r_ok", State: proto.StatusOK},
				{ID: "r_err", State: proto.StatusError, Reason: "tcp/1002: dial tcp 192.168.1.20:1002: connect: connection refused"},
				{ID: "r_dis", State: proto.StatusOK},
			}},
		{Name: "edge", Connected: true, Generation: gen, LastHeartbeat: ago(10 * time.Second), LastHandshake: ago(10 * time.Minute), Tunnel: ok,
			Rules: []proto.RuleStatus{{ID: "r_hs", State: proto.StatusOK}}},
		{Name: "quiet", Connected: true, Generation: gen, LastHeartbeat: ago(2 * time.Minute), LastHandshake: ago(30 * time.Second), Tunnel: ok,
			Rules: []proto.RuleStatus{{ID: "r_stale", State: proto.StatusError, Reason: "tcp/1004: stale failure"}}},
		{Name: "lan", Connected: false, Generation: gen, LastHeartbeat: ago(3 * time.Minute), LastHandshake: ago(30 * time.Second), Tunnel: ok},
		{Name: "paused", Disabled: true, Connected: true, Generation: gen, LastHeartbeat: ago(10 * time.Second), LastHandshake: ago(30 * time.Second), Tunnel: ok},
		{Name: "down", Connected: false, Generation: gen, LastHeartbeat: ago(time.Hour), LastHandshake: ago(time.Hour), Tunnel: ok},
	}
	b := &countingBackend{fakeBackend: fakeBackend{st: st, agents: agents, warnings: []Warning{}}}
	return b, New(b)
}

// markWant は 1 本のルールの印の期待である。node が空なら語を添えない。
type markWant struct {
	state, symbol, node, word, badge string
}

var markWants = map[string]markWant{
	"r_ok":     {state: nodeOK, symbol: "✓", word: "OK", badge: "success"},
	"r_err":    {state: nodeFailed, symbol: "✕", node: "listener / target", word: "FAILED", badge: "danger"},
	"r_hs":     {state: nodeFailed, symbol: "✕", node: "WireGuard", word: "FAILED", badge: "success"},
	"r_stale":  {state: nodeUnknown, symbol: "?", node: "agent", word: "UNKNOWN", badge: "danger"},
	"r_deg":    {state: nodeUnknown, symbol: "?", node: "agent", word: "UNKNOWN", badge: "neutral"},
	"r_late":   {state: nodeUnknown, symbol: "?", node: "listener / target", word: "UNKNOWN", badge: "warning"},
	"r_dis":    {state: nodeSkipped, word: "SKIPPED", badge: "neutral"},
	"r_paused": {state: nodeSkipped, word: "SKIPPED", badge: "neutral"},
	"r_down":   {state: nodeFailed, symbol: "✕", node: "WireGuard", word: "FAILED", badge: "neutral"},
}

// ruleRow は一覧の中の 1 本のルールの行を返す。行は詳細ページへのリンクで見分ける。
func ruleRow(t *testing.T, body, id string) string {
	t.Helper()
	for _, row := range strings.Split(body, `<tr class="rule-row"`)[1:] {
		if end := strings.Index(row, "</tr>"); end >= 0 {
			row = row[:end]
		}
		if strings.Contains(row, `href="/ui/rules/`+id+`"`) {
			return row
		}
	}
	t.Fatalf("no row for %s in:\n%s", id, body)
	return ""
}

// stateCell は行の状態の列の中身(バッジと印)を返す。
func stateCell(t *testing.T, body, id string) string {
	t.Helper()
	row := ruleRow(t, body, id)
	i := strings.Index(row, `<div class="state-cell">`)
	if i < 0 {
		t.Fatalf("%s: no state cell in row:\n%s", id, row)
	}
	j := strings.Index(row[i:], "</div>")
	return row[i : i+j]
}

// TestDashboardMarkPerState は、状態ごとの印の形、記号、添える節点の名前、読み上げの文、リンクを
// 確かめる。FAILED は止まった節点の名前を、UNKNOWN は図の上で最初の UNKNOWN の節点の名前を添える。
// 無効なルールと、持ち主のエージェントが未登録のルールは灰色で、赤にしない。
func TestDashboardMarkPerState(t *testing.T) {
	_, s := markFixture(t)
	srv := httptest.NewServer(s)
	defer srv.Close()

	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/?lang="+lang)
		for id, w := range markWants {
			cell := stateCell(t, body, id)
			alt := w.word
			if w.node != "" {
				alt += " at " + w.node
			}
			alt = fmt.Sprintf(T(lang, "dashDiagAlt"), alt)
			for _, want := range []string{
				`<span class="badge ` + w.badge + `">`,
				`<a class="diag-mark ` + w.state + `" href="/ui/doctor/` + id + `" title="` + alt + `">`,
				`<span class="node ` + w.state + ` node-inline"><span class="node-mark" aria-hidden="true">` + w.symbol + `</span></span>`,
				`<span class="sr-only">` + alt + `</span>`,
			} {
				if !strings.Contains(cell, want) {
					t.Errorf("%s %s: the state cell is missing %q:\n%s", lang, id, want, cell)
				}
			}
			node := `<span class="diag-node" aria-hidden="true">`
			switch {
			case w.node == "" && strings.Contains(cell, node):
				t.Errorf("%s %s: a %s mark must not name a node:\n%s", lang, id, w.word, cell)
			case w.node != "" && !strings.Contains(cell, node+w.node+`</span>`):
				t.Errorf("%s %s: the mark must name the node %q:\n%s", lang, id, w.node, cell)
			}
		}

		// 持ち主のエージェントが未登録のルールは、診断では FAILED だが、Web UI では灰色の
		// 「エージェント未登録」にする(設計文書 5.1、10.1 節)。
		gone := stateCell(t, body, "r_gone")
		unreg := T(lang, "dashDiagUnregistered")
		for _, want := range []string{
			`<a class="diag-mark skipped" href="/ui/doctor/r_gone"`,
			`<span class="node skipped node-inline"><span class="node-mark" aria-hidden="true"></span></span>`,
			`<span class="diag-node" aria-hidden="true">` + unreg + `</span>`,
			`<span class="sr-only">` + fmt.Sprintf(T(lang, "dashDiagAlt"), unreg) + `</span>`,
		} {
			if !strings.Contains(gone, want) {
				t.Errorf("%s r_gone: the state cell is missing %q:\n%s", lang, want, gone)
			}
		}
		for _, id := range []string{"r_dis", "r_gone"} {
			cell := stateCell(t, body, id)
			for _, red := range []string{"failed", "danger"} {
				if strings.Contains(cell, red) {
					t.Errorf("%s %s: a grey row must carry nothing red (%q):\n%s", lang, id, red, cell)
				}
			}
		}
	}
}

// TestDashboardGreyRowsForAgentsNotForwarding は、持ち主のエージェントが無効か未登録のルールを、
// 適用状態のバッジも診断の印も灰色で示し、エラーに数えないことを確かめる(設計文書 5.1、10.1 節)。
// 無効なエージェントのルールは、server が not_active を報告していても赤にせず、転送していないので
// 緑の ✓ にもしない。件数に入らないことは TestDashboardCountsFollowTheMarks が g2 の 0 件で確かめる。
func TestDashboardGreyRowsForAgentsNotForwarding(t *testing.T) {
	_, s := markFixture(t)
	srv := httptest.NewServer(s)
	defer srv.Close()

	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/?lang="+lang)
		for id, label := range map[string]string{"r_paused": T(lang, "agentDisabled"), "r_gone": T(lang, "agentUnregistered")} {
			cell := stateCell(t, body, id)
			for _, want := range []string{
				`<span class="badge neutral">● ` + label + `</span>`,
				`<a class="diag-mark skipped" href="/ui/doctor/` + id + `"`,
			} {
				if !strings.Contains(cell, want) {
					t.Errorf("%s %s: the state cell is missing %q:\n%s", lang, id, want, cell)
				}
			}
			for _, wrong := range []string{"danger", "failed", "success", "warning", "unknown", "✓", "✕"} {
				if strings.Contains(cell, wrong) {
					t.Errorf("%s %s: a rule whose agent does not forward must be grey only, but its cell has %q:\n%s", lang, id, wrong, cell)
				}
			}
		}
	}
}

// TestDashboardMarkSymbolsAreHidden は、印の記号が aria-hidden の .node-mark の中にだけあり、
// 意味は .sr-only の文が担うことを確かめる(経路の図の TestDoctorPathIsNotDrawnWithText と同じ形)。
func TestDashboardMarkSymbolsAreHidden(t *testing.T) {
	_, s := markFixture(t)
	srv := httptest.NewServer(s)
	defer srv.Close()

	hidden := regexp.MustCompile(`<span class="node-mark" aria-hidden="true">[^<]*</span>`)
	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/?lang="+lang)
		for id := range markWants {
			cell := stateCell(t, body, id)
			if n := strings.Count(cell, `class="sr-only"`); n != 1 {
				t.Errorf("%s %s: the mark has %d .sr-only sentence(s), want 1:\n%s", lang, id, n, cell)
			}
			rest := hidden.ReplaceAllString(cell, "")
			for _, sym := range []string{"✓", "✕", "?", "\u2014"} {
				if strings.Contains(rest, sym) {
					t.Errorf("%s %s: %q is drawn outside the aria-hidden mark:\n%s", lang, id, sym, cell)
				}
			}
		}
	}
}

// TestDashboardMarkNamesTheDiagnosisStop は、FAILED の印が添える節点が、診断の判定の StoppedAt が
// 入る節点、つまり診断の画面が止まった位置として描く節点と同じであることを、判定そのものから
// 期待を組み立てて確かめる。
func TestDashboardMarkNamesTheDiagnosisStop(t *testing.T) {
	_, s := markFixture(t)
	srv := httptest.NewServer(s)
	defer srv.Close()

	in, err := doctor.Read(doctorEvidence{s}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rep := doctor.BuildReport(in.Rules.Rules, in)
	body := getBody(t, srv.URL+"/?lang=en")
	failed := 0
	for _, rr := range rep.Rules {
		if rr.Status != doctor.StatusFailed || rr.Agent == "ghost" {
			continue
		}
		failed++
		i := doctorNodeIndex(rr.StoppedAt)
		if i < 0 {
			t.Fatalf("%s: StoppedAt %q is in no node", rr.RuleID, rr.StoppedAt)
		}
		want := `<span class="diag-node" aria-hidden="true">` + doctorNodeDefs[i].Name + `</span>`
		if cell := stateCell(t, body, rr.RuleID); !strings.Contains(cell, want) {
			t.Errorf("%s: StoppedAt %s is in %q, but the mark does not name it:\n%s", rr.RuleID, rr.StoppedAt, doctorNodeDefs[i].Name, cell)
		}
	}
	if failed != 3 {
		t.Errorf("the fixture has %d failed rules besides the unregistered one, want 3; the test would not see what it claims", failed)
	}
}

// groupErrSpan は、グループの見出しの error の件数の札を拾う。
var groupErrSpan = regexp.MustCompile(`<span class="count danger">([^<]*)</span>`)

// TestDashboardCountsFollowTheMarks は、ヘッダの全体ヘルスとグループの見出しの error の件数が、
// 適用状態のバッジではなく診断の印から数えられることを確かめる。バッジが Applied の行でも ✕ なら
// 数え、バッジが Error の行でも ? なら数えない。未登録のエージェントのルールは数えない。
func TestDashboardCountsFollowTheMarks(t *testing.T) {
	_, s := markFixture(t)
	srv := httptest.NewServer(s)
	defer srv.Close()

	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/?lang="+lang)

		// どのグループでも、見出しの件数と、そのグループの赤い ✕ の行の数が一致する。
		groups := strings.Split(body, `<tr class="group-row">`)[1:]
		if len(groups) != 3 {
			t.Fatalf("%s: %d groups, want 3", lang, len(groups))
		}
		wantPerGroup := map[string]int{"g1": 2, "g2": 0, T(lang, "ungrouped"): 1}
		total := 0
		for _, g := range groups {
			name := regexp.MustCompile(`<span class="group-name">([^<]*)</span>`).FindStringSubmatch(g)[1]
			marks := strings.Count(g, `class="diag-mark failed"`)
			total += marks
			label := ""
			if m := groupErrSpan.FindStringSubmatch(g); m != nil {
				label = m[1]
			}
			want := ""
			if marks == 1 {
				want = fmt.Sprintf(T(lang, "groupErrN1"), marks)
			} else if marks > 1 {
				want = fmt.Sprintf(T(lang, "groupErrN"), marks)
			}
			if label != want {
				t.Errorf("%s group %s: the heading says %q, but the group has %d red mark(s)", lang, name, label, marks)
			}
			if marks != wantPerGroup[name] {
				t.Errorf("%s group %s: %d red mark(s), want %d", lang, name, marks, wantPerGroup[name])
			}
		}

		// ヘッダの全体ヘルスは、一覧全体の赤い ✕ の数を言う。
		if total != 3 {
			t.Fatalf("%s: %d red marks in the list, want 3", lang, total)
		}
		summary := fmt.Sprintf(T(lang, "summaryErr"), 4, 6, 10, total)
		if !strings.Contains(body, summary) {
			t.Errorf("%s: the header health summary is not %q:\n%s", lang, summary, body)
		}
		health := getBody(t, srv.URL+"/ui/health?lang="+lang)
		if !strings.Contains(health, summary) {
			t.Errorf("%s: the /ui/health fragment is not %q:\n%s", lang, summary, health)
		}
	}
}

// readCountingBackend は、ダッシュボードが Backend をいくつ読んだかを数える。埋め込んだ
// countingBackend の加算の報告(ApplyStatus など)はそのまま使う。
type readCountingBackend struct {
	*countingBackend
	rules, agents, gens, drops, applies atomic.Int64
}

func (b *readCountingBackend) ApplyStatus() (ApplyStatus, bool) {
	b.applies.Add(1)
	return b.countingBackend.ApplyStatus()
}

func (b *readCountingBackend) Rules() ([]proto.Rule, error) {
	b.rules.Add(1)
	return b.countingBackend.Rules()
}

func (b *readCountingBackend) Agents() ([]AgentInfo, error) {
	b.agents.Add(1)
	return b.countingBackend.Agents()
}

func (b *readCountingBackend) Generation() (uint64, error) {
	b.gens.Add(1)
	return b.countingBackend.Generation()
}

func (b *readCountingBackend) RuleDrops() (map[string]uint64, error) {
	b.drops.Add(1)
	return b.countingBackend.RuleDrops()
}

// TestDashboardReadsOnce は、印を出すために読み取りを増やさないことを確かめる。ページ全体と
// 4 つの部分更新は、どれもルール、エージェント、世代、拒否数、server の適用状態をそれぞれ 1 回だけ
// 読み、疎通の確認を呼ばない。バッジと印と件数は、この 1 回の読み取りから作られる。
func TestDashboardReadsOnce(t *testing.T) {
	base, _ := markFixture(t)
	b := &readCountingBackend{countingBackend: base}
	srv := httptest.NewServer(New(b))
	defer srv.Close()

	for _, path := range []string{"/", "/ui/rules", "/ui/health", "/ui/agents", "/ui/warnings"} {
		b.rules.Store(0)
		b.agents.Store(0)
		b.gens.Store(0)
		b.drops.Store(0)
		b.applies.Store(0)
		getBody(t, srv.URL+path)
		for name, n := range map[string]int64{"Rules": b.rules.Load(), "Agents": b.agents.Load(), "Generation": b.gens.Load(), "RuleDrops": b.drops.Load(), "ApplyStatus": b.applies.Load()} {
			if n != 1 {
				t.Errorf("GET %s read %s %d time(s), want exactly 1", path, name, n)
			}
		}
		if n := b.checks.Load(); n != 0 {
			t.Fatalf("GET %s dialled %d time(s); the dashboard must never run the probe", path, n)
		}
	}
}

// TestDashboardLeavesTheLongErrorToOtherPages は、エージェントが報告した理由の長い文が一覧から
// 外れ、ルールの詳細ページと診断の画面には残ることを確かめる(設計文書 10.1 節)。
func TestDashboardLeavesTheLongErrorToOtherPages(t *testing.T) {
	_, s := markFixture(t)
	srv := httptest.NewServer(s)
	defer srv.Close()

	const reason = "connect: connection refused"
	for _, path := range []string{"/?lang=en", "/ui/rules?lang=en"} {
		if body := getBody(t, srv.URL+path); strings.Contains(body, reason) {
			t.Errorf("GET %s still carries the long error text %q", path, reason)
		}
	}
	for _, path := range []string{"/ui/rules/r_err?lang=en", "/ui/doctor/r_err?lang=en"} {
		if body := getBody(t, srv.URL+path); !strings.Contains(body, reason) {
			t.Errorf("GET %s lost the error text %q", path, reason)
		}
	}
}

// TestDashMarksMatchChecksOf は、dashMarks がルールごとの検査を 1 回で振り分けても、ルールごとに
// rep.ChecksOf を呼んだ場合と同じ印になることを確かめる。振り分けは費用のための近道であり、
// 印を変えてはならない。
func TestDashMarksMatchChecksOf(t *testing.T) {
	_, s := markFixture(t)
	in, err := doctor.Read(doctorEvidence{s}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, lang := range []string{"ja", "en"} {
		got := dashMarks(in.Rules.Rules, in, lang)
		rep := doctor.BuildReport(in.Rules.Rules, in)
		if len(got) != len(rep.Rules) || len(got) == 0 {
			t.Fatalf("%s: %d marks for %d rules", lang, len(got), len(rep.Rules))
		}
		for _, rr := range rep.Rules {
			checks := rep.ChecksOf(rr.RuleID)
			want := doctorMark(rr, checks, doctorPath(rr, checks, in.Now, lang), lang)
			if got[rr.RuleID] != want {
				t.Errorf("%s %s: mark %+v, want %+v", lang, rr.RuleID, got[rr.RuleID], want)
			}
		}
	}
}

// TestChecksByRuleKeepsInterleavedChecks は、同じルールの検査が離れて現れても、振り分けがどれも
// 落とさず、元の順のまま継ぎ足すことを確かめる。今の BuildReport は 1 本のルールの検査を続けて
// 並べるが、振り分けはその並びに頼って検査を落としてはならない。
func TestChecksByRuleKeepsInterleavedChecks(t *testing.T) {
	c := func(rule, id string) doctor.Check { return doctor.Check{RuleID: rule, ID: id} }
	checks := []doctor.Check{
		c("a", doctor.CheckEnabled), c("a", doctor.CheckPublicPort),
		c("b", doctor.CheckEnabled),
		c("", doctor.CheckDataplane),
		c("a", doctor.CheckTarget),
		c("b", doctor.CheckTarget),
	}
	got := checksByRule(checks)
	want := map[string][]string{
		"a": {doctor.CheckEnabled, doctor.CheckPublicPort, doctor.CheckTarget},
		"b": {doctor.CheckEnabled, doctor.CheckTarget},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rules, want %d: %v", len(got), len(want), got)
	}
	for rule, ids := range want {
		var gotIDs []string
		for _, ch := range got[rule] {
			gotIDs = append(gotIDs, ch.ID)
		}
		if strings.Join(gotIDs, ",") != strings.Join(ids, ",") {
			t.Errorf("rule %s: checks %v, want %v", rule, gotIDs, ids)
		}
	}
	// 連続した区間を指したまま継ぎ足しても、元の並びを書き換えない。
	if checks[2].RuleID != "b" || checks[2].ID != doctor.CheckEnabled {
		t.Errorf("checksByRule wrote into its input: %+v", checks[2])
	}
}
