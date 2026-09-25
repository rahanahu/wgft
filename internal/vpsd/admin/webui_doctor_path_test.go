package admin

import (
	"html"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは診断の画面の経路の図(webui_doctor_path.go、設計文書 10.2d 節の改訂の記録)を
// 仕様の形で確かめる。入力は判定そのもの(doctor.BuildReport)であり、図は判定を作り直さずに
// 写すだけであることを、判定の値から期待を組み立てることで固定する。

var pathNow = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

func pathAt(d time.Duration) string { return pathNow.Add(-d).Format(time.RFC3339) }

func pathU64(v uint64) *uint64 { return &v }

func pathRule(id string, p proto.Proto) proto.Rule {
	r := proto.Rule{
		ID: id, Agent: "home", Proto: p, ListenPort: proto.PortRange{Lo: 25565, Hi: 25565},
		Target: "192.168.1.20:25565", VPSMode: proto.ModeKernel, Enabled: true,
	}
	if p == proto.UDP {
		r.ListenPort, r.Target = proto.PortRange{Lo: 2456, Hi: 2457}, "192.168.1.20:2456"
	}
	return r
}

// pathInput は、壊れた検査が 1 つも無い証拠一式である。各場合はこれを 1 点だけ崩す。
func pathInput(rules ...proto.Rule) doctor.Input {
	in := doctor.Input{
		Now: pathNow,
		Rules: &BatchResponse{
			Generation: 12, Rules: rules,
			DesiredGeneration: pathU64(12), ActiveGeneration: pathU64(12),
			RuleStates: map[string]RuleApply{}, Drift: &Drift{},
			ResourceRefusals: map[string]map[string]uint64{},
			FlowBudget:       map[proto.Proto]FlowBudget{proto.TCP: {InUse: 1, Limit: 2048}},
			AgentRuleStates:  map[string]AgentRuleStatus{},
		},
		Agents: []AgentInfo{{
			Name: "home", Address: "10.200.0.2", Connected: true, StreamFrom: "203.0.113.9:51234",
			LastHeartbeat: pathAt(10 * time.Second), Generation: 12,
			Tunnel:        TunnelStatus{State: proto.StatusOK, LastHandshake: pathAt(30 * time.Second)},
			LastHandshake: pathAt(30 * time.Second),
		}},
		Probes: map[string]doctor.ProbeResult{},
	}
	for _, r := range rules {
		in.Rules.RuleStates[r.ID] = RuleApply{ApplyState: ApplyActive, ActiveGeneration: pathU64(12)}
		in.Rules.AgentRuleStates[r.ID] = AgentRuleStatus{Agent: "home", State: proto.StatusOK, At: pathAt(10 * time.Second), Connected: true}
	}
	return in
}

// staleTunnel はトンネルの最終ハンドシェイクを 3m41s 前にする。
func staleTunnel(in *doctor.Input) {
	in.Agents[0].LastHandshake = pathAt(3*time.Minute + 41*time.Second)
	in.Agents[0].Tunnel.LastHandshake = in.Agents[0].LastHandshake
}

type pathCase struct {
	name  string
	rules []proto.Rule
	edit  func(in *doctor.Input)
}

func pathCases() []pathCase {
	tcp := pathRule("r_tcp", proto.TCP)
	udp := pathRule("r_udp", proto.UDP)
	off := pathRule("r_off", proto.TCP)
	off.Enabled = false
	// named は宛先がホスト名のルールである。カーネルモードのエージェントは、名前の解決に失敗すると
	// 直前の解決の結果で転送を続け、そのことを理由に書く(設計文書 7b.2 節)。
	named := pathRule("r_named", proto.TCP)
	named.Target = "game.lan:25565"
	stale := `name resolution of target host "game.lan" failed: lookup game.lan: no such host; still forwarding to 192.168.1.30 from the last successful resolution`
	return []pathCase{
		{"name fails, still forwarding", []proto.Rule{named}, func(in *doctor.Input) {
			in.Rules.AgentRuleStates["r_named"] = AgentRuleStatus{Agent: "home", State: proto.StatusError,
				Reason: stale, At: pathAt(10 * time.Second), Connected: true}
		}},
		{"name fails, the old address refuses", []proto.Rule{named}, func(in *doctor.Input) {
			in.Rules.AgentRuleStates["r_named"] = AgentRuleStatus{Agent: "home", State: proto.StatusError,
				Reason: stale + "; target 192.168.1.30:25565: dial tcp 192.168.1.30:25565: connect: connection refused",
				At:     pathAt(10 * time.Second), Connected: true}
		}},
		{"healthy TCP", []proto.Rule{tcp}, nil},
		{"UDP rule without probe", []proto.Rule{udp}, nil},
		{"stop at WireGuard", []proto.Rule{tcp}, staleTunnel},
		{"stop at WireGuard with the stream down too", []proto.Rule{tcp}, func(in *doctor.Input) {
			staleTunnel(in)
			in.Agents[0].Connected = false
			st := in.Rules.AgentRuleStates["r_tcp"]
			st.Connected = false
			in.Rules.AgentRuleStates["r_tcp"] = st
		}},
		{"stop at target", []proto.Rule{tcp}, func(in *doctor.Input) {
			in.Rules.AgentRuleStates["r_tcp"] = AgentRuleStatus{Agent: "home", State: proto.StatusError,
				Reason: "tcp/25565: dial tcp 192.168.1.20:25565: connect: connection refused", At: pathAt(10 * time.Second), Connected: true}
		}},
		{"probe failed at target", []proto.Rule{tcp}, func(in *doctor.Input) {
			in.Probed = true
			in.Probes["r_tcp"] = doctor.ProbeResult{Check: &ConnCheck{Reach: "agent", Detail: "connection refused"}}
		}},
		{"probe did not reach the listener", []proto.Rule{tcp}, func(in *doctor.Input) {
			in.Probed = true
			in.Probes["r_tcp"] = doctor.ProbeResult{Check: &ConnCheck{Reach: "none", Detail: "i/o timeout"}}
		}},
		{"probe reached the target", []proto.Rule{tcp}, func(in *doctor.Input) {
			in.Probed = true
			in.Probes["r_tcp"] = doctor.ProbeResult{Check: &ConnCheck{OK: true, Reach: "target", Detail: "ok"}}
		}},
		{"stream down, tunnel alive", []proto.Rule{tcp}, func(in *doctor.Input) {
			in.Agents[0].Connected = false
			st := in.Rules.AgentRuleStates["r_tcp"]
			st.Connected = false
			in.Rules.AgentRuleStates["r_tcp"] = st
		}},
		{"disabled rule", []proto.Rule{off}, nil},
		{"disabled agent", []proto.Rule{tcp}, func(in *doctor.Input) {
			in.Agents[0].Disabled = true
			in.Rules.RuleStates["r_tcp"] = RuleApply{ApplyState: ApplyNotActive, Reason: `agent "home" is disabled`}
			delete(in.Rules.AgentRuleStates, "r_tcp")
		}},
		{"unregistered agent", []proto.Rule{tcp}, func(in *doctor.Input) { in.Agents = nil }},
		{"public port not served", []proto.Rule{tcp}, func(in *doctor.Input) {
			in.Rules.RuleStates["r_tcp"] = RuleApply{ApplyState: ApplyNotActive, Reason: "bind failed"}
		}},
		{"dataplane behind", []proto.Rule{tcp}, func(in *doctor.Input) { in.Rules.ActiveGeneration = pathU64(11) }},
	}
}

// buildPath は場合 1 つの判定と図を組み立てる。
func buildPath(t *testing.T, c pathCase) (doctor.Report, []doctorPathView) {
	t.Helper()
	in := pathInput(c.rules...)
	if c.edit != nil {
		c.edit(&in)
	}
	rep := doctor.BuildReport(c.rules, in)
	var paths []doctorPathView
	for _, rr := range rep.Rules {
		paths = append(paths, doctorPath(rr, rep.ChecksOf(rr.RuleID), in.Now, "en"))
	}
	return rep, paths
}

func nodeStates(p doctorPathView) []string {
	var out []string
	for _, n := range p.Nodes {
		out = append(out, n.State)
	}
	return out
}

// TestDoctorPathFollowsTheVerdict は、図の規則を判定の値から書いた仕様として確かめる。
//   - StoppedAt がある行では、その検査が入る節点だけが ✕ で、後ろの節点はすべて「届いていない」
//   - StoppedAt より手前の節点は ✕ にならない
//   - UNKNOWN の行には ✕ が無く、? が 1 つ以上ある
//   - OK の行には ✕ も ? も無い
//   - 無効なルールの行は、すべての節点が「届いていない」で、✕ が無い
func TestDoctorPathFollowsTheVerdict(t *testing.T) {
	// 前提: 各場合が仕様のどの分岐を通るかを、判定の値で先に確かめる。
	wantStatus := map[string]string{
		"healthy TCP": "ok", "UDP rule without probe": "ok", "stop at WireGuard": "failed",
		"stop at WireGuard with the stream down too": "failed", "stop at target": "failed",
		"probe failed at target": "failed", "probe did not reach the listener": "failed",
		"probe reached the target": "ok", "stream down, tunnel alive": "unknown", "disabled rule": "skipped", "disabled agent": "skipped",
		"unregistered agent": "failed", "public port not served": "failed", "dataplane behind": "ok",
		"name fails, still forwarding": "unknown", "name fails, the old address refuses": "failed",
	}
	for _, c := range pathCases() {
		t.Run(c.name, func(t *testing.T) {
			rep, paths := buildPath(t, c)
			if got := rep.Rules[0].Status; got != wantStatus[c.name] {
				t.Fatalf("precondition: the verdict is %s, want %s", got, wantStatus[c.name])
			}
			for i, rr := range rep.Rules {
				p := paths[i]
				states := nodeStates(p)
				if len(p.Nodes) != len(doctorNodeDefs) {
					t.Fatalf("path has %d nodes, want %d", len(p.Nodes), len(doctorNodeDefs))
				}
				count := func(s string) int {
					n := 0
					for _, v := range states {
						if v == s {
							n++
						}
					}
					return n
				}
				switch {
				case !rr.Enabled:
					for j, n := range p.Nodes {
						if n.State != nodeUnreached {
							t.Errorf("a disabled rule's node %d (%s) is %s, want not reached", j, n.Name, n.State)
						}
					}
					if p.Caption != "enabled / rule_disabled" {
						t.Errorf("a disabled rule's caption = %q, want the enabled check's label and reason", p.Caption)
					}
				case rep.RuleAgentDisabled(rr.RuleID):
					// 持ち主のエージェントが無効なルールも、無効なルールと同じく宣言どおりの状態で
					// ある。故障の色(✕ と ?)を使わず、すべての節点を「届いていない」で描く。
					for j, n := range p.Nodes {
						if n.State != nodeUnreached {
							t.Errorf("a disabled agent's rule: node %d (%s) is %s, want not reached", j, n.Name, n.State)
						}
						if !strings.Contains(n.Alt, T("en", "doctorAgentDisabledAlt")) {
							t.Errorf("node %d alt %q does not say the agent is disabled", j, n.Alt)
						}
					}
					if p.Caption != "agent enabled / agent_disabled" || p.Nodes[0].Stop != p.Caption {
						t.Errorf("a disabled agent's rule: caption = %q, stop = %q", p.Caption, p.Nodes[0].Stop)
					}
				case rr.StoppedAt != "":
					k := doctorNodeIndex(rr.StoppedAt)
					if k < 0 {
						t.Fatalf("StoppedAt %s is in no node", rr.StoppedAt)
					}
					for j, n := range p.Nodes {
						switch {
						case j < k && n.State == nodeFailed:
							t.Errorf("node %d (%s) before the stop is drawn failed: %v", j, n.Name, states)
						case j == k && (n.State != nodeFailed || n.Symbol != "✕"):
							t.Errorf("the stopped node %d (%s) is %s %q, want failed ✕: %v", j, n.Name, n.State, n.Symbol, states)
						case j > k && (n.State != nodeUnreached || !n.AfterStop):
							t.Errorf("node %d (%s) after the stop is %s, want not reached: %v", j, n.Name, n.State, states)
						}
					}
				case rr.Status == doctor.StatusUnknown:
					if count(nodeFailed) != 0 || count(nodeUnknown) == 0 {
						t.Errorf("an UNKNOWN row must have no ✕ and at least one ?, got %v", states)
					}
				case rr.Status == doctor.StatusOK:
					if count(nodeFailed) != 0 || count(nodeUnknown) != 0 {
						t.Errorf("an OK row must have neither ✕ nor ?, got %v", states)
					}
				}
			}
		})
	}
}

// TestDoctorPathShapes は、場合ごとの図の形そのものを固定する。上の仕様が同じでも、節点の
// 割り当てがずれると止まる位置が変わるので、代表の場合は形まで書く。
func TestDoctorPathShapes(t *testing.T) {
	want := map[string]string{
		"healthy TCP":                      "untested ok ok ok",
		"UDP rule without probe":           "untested ok ok untested",
		"stop at WireGuard":                "untested failed unreached unreached",
		"stop at target":                   "untested ok ok failed",
		"probe failed at target":           "untested ok ok failed",
		"probe did not reach the listener": "untested ok ok failed",
		"probe reached the target":         "untested ok ok ok",
		"disabled rule":                    "unreached unreached unreached unreached",
		"disabled agent":                   "unreached unreached unreached unreached",
		"unregistered agent":               "untested skipped failed unreached",
		"public port not served":           "failed unreached unreached unreached",
		"dataplane behind":                 "untested ok ok ok",
		// 名前の解決に失敗しても直前の解決の結果で転送を続けているなら、宛先の節点は ? であって
		// ✕ ではない(設計文書 10.2a 節)。直前のアドレスの宛先も拒めば、そこで止まる。
		"name fails, still forwarding":        "untested ok ok unknown",
		"name fails, the old address refuses": "untested ok ok failed",
	}
	for _, c := range pathCases() {
		w, ok := want[c.name]
		if !ok {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			_, paths := buildPath(t, c)
			if got := strings.Join(nodeStates(paths[0]), " "); got != w {
				t.Errorf("path = %s, want %s", got, w)
			}
		})
	}
}

// TestDoctorPathStopLabel は、止まった節点の札が検査の見出し、reason、経過の時間から作られる
// ことを確かめる。新しい短文の表を持たないためである。
func TestDoctorPathStopLabel(t *testing.T) {
	for _, c := range pathCases() {
		if c.name != "stop at WireGuard" {
			continue
		}
		_, paths := buildPath(t, c)
		p := paths[0]
		if p.Nodes[1].Stop != "WireGuard / no_recent_handshake · 3m41s" {
			t.Errorf("stop label = %q, want %q", p.Nodes[1].Stop, "WireGuard / no_recent_handshake · 3m41s")
		}
		if p.Caption != p.Nodes[1].Stop {
			t.Errorf("the summary caption %q must repeat the stopped node's label %q", p.Caption, p.Nodes[1].Stop)
		}
		for j, n := range p.Nodes {
			if j != 1 && n.Stop != "" {
				t.Errorf("node %d (%s) carries a stop label %q; only the stopped node does", j, n.Name, n.Stop)
			}
		}
	}
}

// TestDoctorPathUnreachedNodesKeepTheOriginalStatus は、「届いていない」として描いた節点の
// 代替テキストが、止まった後ろであることと中の検査の元の状態を持つことを確かめる。図が判定を
// 隠さないためである。
func TestDoctorPathUnreachedNodesKeepTheOriginalStatus(t *testing.T) {
	for _, c := range pathCases() {
		if c.name != "stop at WireGuard with the stream down too" {
			continue
		}
		rep, paths := buildPath(t, c)
		p := paths[0]
		for _, idx := range []int{2, 3} {
			n := p.Nodes[idx]
			if !strings.Contains(n.Alt, T("en", "doctorAfterStopAlt")) {
				t.Errorf("node %s: alt %q does not say it is after the stop", n.Name, n.Alt)
			}
			for _, id := range doctorNodeDefs[idx].IDs {
				for _, ch := range rep.ChecksOf("r_tcp") {
					if ch.ID == id && !strings.Contains(n.Alt, doctorCheckWord(ch)) {
						t.Errorf("node %s: alt %q is missing the original status %q", n.Name, n.Alt, doctorCheckWord(ch))
					}
				}
			}
		}
		// 元の状態の少なくとも 1 つは OK ではない。そうでなければこの場合は仕様を確かめていない。
		if !strings.Contains(p.Nodes[3].Alt, "UNKNOWN / stale_report") {
			t.Errorf("the target node's alt must carry UNKNOWN / stale_report, got %q", p.Nodes[3].Alt)
		}
	}
}

// TestDoctorPathDoesNotDrawAUDPTargetAsVerified は、UDP のルールの宛先の節点を ✓ にしない
// ことを確かめる。UDP のエージェントの ok はリスナーが開いたことしか意味せず、判定そのものが
// `rule.target` を not_tested(udp_listener_only)にする。図はそれを読み替えずに写し、代替テキスト
// にも判定と同じ NOT TESTED が入る(設計文書 10.2a 節、2026-09-24 の改訂の記録)。
func TestDoctorPathDoesNotDrawAUDPTargetAsVerified(t *testing.T) {
	for _, c := range pathCases() {
		if c.name != "UDP rule without probe" {
			continue
		}
		rep, paths := buildPath(t, c)
		if rep.Rules[0].Status != doctor.StatusOK {
			t.Fatalf("precondition: a healthy UDP rule reads %s, want ok", rep.Rules[0].Status)
		}
		n := paths[0].Nodes[3]
		if n.State == nodeOK || n.Symbol == "✓" {
			t.Errorf("a UDP target node must not read OK: %+v", n)
		}
		if n.Word != "NOT TESTED" || n.Note != T("en", "doctorUDPTargetNote") {
			t.Errorf("a UDP target node must read NOT TESTED with the listener note, got %q / %q", n.Word, n.Note)
		}
		// 節点の語も読み替えではなく判定から来るので、節点の状態に判定の reason が付く。
		if !strings.HasPrefix(n.Alt, "listener / target: NOT TESTED / udp_listener_only") {
			t.Errorf("the node's own state must carry the check's reason, got %q", n.Alt)
		}
		if !strings.Contains(n.Alt, "target NOT TESTED / udp_listener_only") {
			t.Errorf("the alt must carry the check's own NOT TESTED and reason, got %q", n.Alt)
		}
		if strings.Contains(n.Alt, "target OK") {
			t.Errorf("the alt must not call the UDP target OK, got %q", n.Alt)
		}
	}
}

// TestDoctorPathUDPTargetNoteFollowsTheCheck は、宛先の節点に添える「リスナーは開いているが
// UDP の宛先は試していない」旨の 1 文が、判定が not_tested(udp_listener_only)を返したときだけ
// 出ることを確かめる。健全な TCP のルールの宛先と、報告の古い UDP のルールの宛先には出さない。
// 後者はリスナーが今開いているとは言えないためである。
func TestDoctorPathUDPTargetNoteFollowsTheCheck(t *testing.T) {
	udp := pathRule("r_udp", proto.UDP)
	cases := []struct {
		name     string
		c        pathCase
		wantNote bool
		wantWord string
	}{
		{"healthy UDP", pathCase{"healthy UDP", []proto.Rule{udp}, nil}, true, "NOT TESTED"},
		{"healthy TCP", pathCase{"healthy TCP", []proto.Rule{pathRule("r_tcp", proto.TCP)}, nil}, false, "OK"},
		{"UDP with a stale report", pathCase{"UDP with a stale report", []proto.Rule{udp}, func(in *doctor.Input) {
			st := in.Rules.AgentRuleStates["r_udp"]
			st.At = pathAt(doctor.TargetReportStale + time.Second)
			in.Rules.AgentRuleStates["r_udp"] = st
		}}, false, "UNKNOWN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, paths := buildPath(t, tc.c)
			n := paths[0].Nodes[3]
			if got := n.Note != ""; got != tc.wantNote {
				t.Errorf("note = %q, want one: %v", n.Note, tc.wantNote)
			}
			if n.Word != tc.wantWord {
				t.Errorf("word = %q, want %q", n.Word, tc.wantWord)
			}
		})
	}
}

// TestDoctorPathSameAgentStopsAtTheSameNode は、同じエージェントの複数のルールが同じ原因で
// 止まるとき、どの行も同じ節点で同じ札になることを確かめる。行を並べ替えなくても同じ原因と
// 読めるようにするためである。
func TestDoctorPathSameAgentStopsAtTheSameNode(t *testing.T) {
	a, b, u := pathRule("r_a", proto.TCP), pathRule("r_b", proto.TCP), pathRule("r_u", proto.UDP)
	b.ListenPort, b.Target = proto.PortRange{Lo: 8080, Hi: 8080}, "192.168.1.30:8080"
	c := pathCase{"three rules", []proto.Rule{a, b, u}, staleTunnel}
	_, paths := buildPath(t, c)
	for i, p := range paths {
		if got := strings.Join(nodeStates(p), " "); got != "untested failed unreached unreached" {
			t.Errorf("rule %d: path = %s, want the stop at WireGuard", i, got)
		}
		if p.Caption != paths[0].Caption || p.Caption == "" {
			t.Errorf("rule %d: caption %q differs from %q", i, p.Caption, paths[0].Caption)
		}
	}
}

// TestDoctorPathKeepsDataplaneOutOfTheNodes は、server.dataplane を節点に入れないことを
// 確かめる。ルールの検査ではないので、入れると行の状態と図が食い違う。
func TestDoctorPathKeepsDataplaneOutOfTheNodes(t *testing.T) {
	if i := doctorNodeIndex(doctor.CheckDataplane); i >= 0 {
		t.Errorf("server.dataplane is in node %d; it belongs to the banner", i)
	}
	for _, id := range []string{doctor.CheckCredentials, doctor.CheckFlowBudget} {
		if i := doctorNodeIndex(id); i >= 0 {
			t.Errorf("off-path check %s is in node %d", id, i)
		}
	}
	// 経路の上の検査はすべて、どれかの節点に入る。入らない検査は図から黙って落ちる。
	for _, id := range doctor.CheckOrder() {
		switch id {
		case doctor.CheckDataplane, doctor.CheckCredentials, doctor.CheckFlowBudget:
			continue
		}
		if doctorNodeIndex(id) < 0 {
			t.Errorf("on-path check %s is in no node", id)
		}
	}
}

// TestDoctorAgentPathShowsTheStatusAsIs は、エージェントの行が tunnel、stream、rules の順で、
// 状態をそのまま出すことを確かめる。エージェントには StoppedAt が無いので、「届いていない」への
// 置き換えをしない。
func TestDoctorAgentPathShowsTheStatusAsIs(t *testing.T) {
	c := pathCase{"stale tunnel and stream down", []proto.Rule{pathRule("r_tcp", proto.TCP)}, func(in *doctor.Input) {
		staleTunnel(in)
		in.Agents[0].Connected = false
	}}
	rep, _ := buildPath(t, c)
	p, _ := doctorAgentPath("home", rep, "en")
	var names []string
	for _, n := range p.Nodes {
		names = append(names, n.Name)
		if n.State == nodeUnreached {
			t.Errorf("agent node %s is drawn not reached; the agent row shows statuses as is", n.Name)
		}
	}
	if strings.Join(names, " ") != "tunnel stream rules" {
		t.Errorf("agent row order = %v, want tunnel stream rules", names)
	}
	if p.Nodes[0].State != nodeFailed {
		t.Errorf("a stale tunnel must read failed in the agent row, got %s", p.Nodes[0].State)
	}
}

// TestDoctorAgentPathPrefersAnEnabledRule は、無効なルールを先に持つエージェントでも、行の
// 状態を有効なルールの検査から採ることを確かめる。無効なルールの検査は rule_disabled の
// skipped で、エージェントの状態を述べない。
func TestDoctorAgentPathPrefersAnEnabledRule(t *testing.T) {
	off := pathRule("r_a_off", proto.TCP)
	off.Enabled = false
	on := pathRule("r_b_on", proto.TCP)
	c := pathCase{"disabled first", []proto.Rule{off, on}, nil}
	rep, _ := buildPath(t, c)
	p, checks := doctorAgentPath("home", rep, "en")
	if got := strings.Join(nodeStates(p), " "); got != "ok ok ok" {
		t.Errorf("agent row = %s, want ok ok ok", got)
	}
	// 画面の行と CLI の Agents の行は、同じ検査を読む。
	sum := rep.AgentSummaries()
	if len(checks) != 3 || len(sum) != 1 || checks[1].Status != sum[0].Status || checks[1].Reason != sum[0].Reason {
		t.Errorf("the page's stream node %+v and the CLI's agent line %+v must read the same check", checks, sum)
	}
}

// TestDoctorPathAltCarriesTheEnglishStatusWord は、どの節点の代替テキストも、状態の語を英語で
// 持つことを確かめる。記号は aria-hidden なので、読み上げはこの文だけが担う。
func TestDoctorPathAltCarriesTheEnglishStatusWord(t *testing.T) {
	words := []string{"OK", "FAILED", "UNKNOWN", "DEGRADED", "NOT TESTED", "SKIPPED"}
	for _, c := range pathCases() {
		t.Run(c.name, func(t *testing.T) {
			_, paths := buildPath(t, c)
			for _, n := range paths[0].Nodes {
				found := false
				for _, w := range words {
					if strings.Contains(n.Alt, w) {
						found = true
					}
				}
				if !found {
					t.Errorf("node %s: alt %q carries no English status word", n.Name, n.Alt)
				}
			}
		})
	}
}

// newBannerTestServer は、server の転送が今のルールに追いついていない管理 API サーバーを立てる。
type behindBackend struct{ *countingBackend }

func (b behindBackend) ApplyStatus() (ApplyStatus, bool) {
	st, ok := b.countingBackend.ApplyStatus()
	behind := st.DesiredGeneration - 1
	st.ActiveGeneration = behind
	return st, ok
}

// TestDoctorRulePageShowsTheDataplaneBannerOnlyWhenNotOK は、server.dataplane を図の上の帯に
// 出すのが OK でないときだけであることを確かめる。
func TestDoctorRulePageShowsTheDataplaneBannerOnlyWhenNotOK(t *testing.T) {
	srv, _ := newDoctorTestServer(t)
	ok := getBody(t, srv.URL+"/ui/doctor/r_ok?lang=en")
	if strings.Contains(ok, `class="doctor-banner`) || strings.Contains(ok, html.EscapeString(T("en", "doctorBanner"))) {
		t.Errorf("a healthy dataplane must not raise the banner:\n%s", ok)
	}

	_, b := newDoctorTestServer(t)
	behind := httptest.NewServer(New(behindBackend{b}))
	t.Cleanup(behind.Close)
	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, behind.URL+"/ui/doctor/r_ok?lang="+lang)
		if !strings.Contains(body, `class="doctor-banner`) || !strings.Contains(body, html.EscapeString(T(lang, "doctorBanner"))) {
			t.Errorf("%s: a dataplane that is not OK must raise the banner:\n%s", lang, body)
		}
		// 帯は図の上にある。
		if strings.Index(body, `class="doctor-banner`) > strings.Index(body, `class="path full"`) {
			t.Errorf("%s: the banner must sit above the diagram", lang)
		}
	}
}

// TestDoctorPagesDrawThePathInBothLocales は、一覧の画面と 1 本のルールの画面が、両方の
// ロケールで図を描くことを確かめる。節点の名前と状態の語は英語のままで、枠の語だけが変わる。
func TestDoctorPagesDrawThePathInBothLocales(t *testing.T) {
	srv, _ := newDoctorTestServer(t)
	for _, lang := range []string{"ja", "en"} {
		list := getBody(t, srv.URL+"/ui/doctor?lang="+lang)
		if n := strings.Count(list, `<ol class="path mini" aria-label="`+T(lang, "doctorPathAria")+`"`); n != 3 {
			t.Errorf("%s: the summary draws %d rule paths, want one per rule (3)", lang, n)
		}
		if !strings.Contains(list, "public port - WireGuard - agent - listener / target") {
			t.Errorf("%s: the summary must name the stages once in the header", lang)
		}
		// 行の図は 1 本のルールの画面へのリンクである。
		if !strings.Contains(list, `<a class="path-link" href="/ui/doctor/r_off">`) {
			t.Errorf("%s: a row's path must link to the rule's own page", lang)
		}

		// r_off のエージェントはハンドシェイクを 1 度もしていないので、WireGuard で止まる。
		rule := getBody(t, srv.URL+"/ui/doctor/r_off?lang="+lang)
		if !strings.Contains(rule, `<ol class="path full" aria-label="`+T(lang, "doctorPathAria")+`"`) {
			t.Errorf("%s: the rule page does not draw the path:\n%s", lang, rule)
		}
		for _, want := range []string{
			`<span class="node-name">public port</span>`, `<span class="node-name">WireGuard</span>`,
			`<span class="node-name">agent</span>`, `<span class="node-name">listener / target</span>`,
			`<span class="node-word">FAILED</span>`, `<span class="node-word">` + T(lang, "doctorNotReached") + `</span>`,
			T(lang, "doctorAfterStopAlt"),
		} {
			if !strings.Contains(rule, want) {
				t.Errorf("%s: the rule page is missing %q", lang, want)
			}
		}
		// 止まった節点の折りたたみは既定で開く。
		if !regexpOpenWireGuard.MatchString(rule) {
			t.Errorf("%s: the stopped node's details must be open by default:\n%s", lang, rule)
		}
	}
}

var regexpOpenWireGuard = regexp.MustCompile(`<details class="node-detail" open>\s*<summary>\s*<span class="node failed node-inline"><span class="node-mark" aria-hidden="true">✕</span></span>\s*<strong>WireGuard</strong>`)

// TestDoctorPathIsNotDrawnWithText は、図を文字の罫線で描かないことを確かめる。図は CSS の
// 図形と線で描き、記号は aria-hidden にして、読み上げは .sr-only の文が担う。
func TestDoctorPathIsNotDrawnWithText(t *testing.T) {
	srv, _ := newDoctorTestServer(t)
	for _, path := range []string{"/ui/doctor", "/ui/doctor/r_ok", "/ui/doctor/r_err", "/ui/doctor/r_off"} {
		for _, lang := range []string{"ja", "en"} {
			body := getBody(t, srv.URL+path+"?lang="+lang)
			for _, r := range body {
				if r >= 0x2500 && r <= 0x257F {
					t.Errorf("%s %s: the page uses the box-drawing character %q", path, lang, r)
					break
				}
			}
			for _, s := range []string{"◌", "─", "--o--", "-+-"} {
				if strings.Contains(body, s) {
					t.Errorf("%s %s: the page draws the path with text %q", path, lang, s)
				}
			}
			// 記号はすべて aria-hidden の中にある。
			for _, sym := range []string{"✓", "✕"} {
				if strings.Count(body, sym) != strings.Count(body, `aria-hidden="true">`+sym) {
					t.Errorf("%s %s: every %s must sit in an aria-hidden mark", path, lang, sym)
				}
			}
		}
	}
}

// TestDoctorNodeTakesTheWorstStatus は、節点の状態が中の検査の最も悪いものであることを、
// 並びの順に依らずに確かめる。順序は failed > unknown > skipped > not_tested > ok である。
func TestDoctorNodeTakesTheWorstStatus(t *testing.T) {
	def := doctorNodeDefs[3]
	chk := func(id, status, reason string) doctor.Check {
		return doctor.Check{ID: id, RuleID: "r", Label: id, Status: status, Reason: reason}
	}
	cases := []struct {
		name       string
		checks     []doctor.Check
		want, word string
		reason     string
	}{
		{"unknown after skipped and not_tested", []doctor.Check{
			chk(doctor.CheckTargetResolve, doctor.StatusSkipped, "agent_not_registered"),
			chk(doctor.CheckTarget, doctor.StatusNotTested, "resolved_by_agent"),
			chk(doctor.CheckProbe, doctor.StatusUnknown, "not_reported"),
		}, nodeUnknown, "UNKNOWN", "not_reported"},
		{"unknown before skipped and not_tested", []doctor.Check{
			chk(doctor.CheckTargetResolve, doctor.StatusUnknown, "stale_report"),
			chk(doctor.CheckTarget, doctor.StatusSkipped, "agent_not_registered"),
			chk(doctor.CheckProbe, doctor.StatusNotTested, "resolved_by_agent"),
		}, nodeUnknown, "UNKNOWN", "stale_report"},
		{"skipped over not_tested", []doctor.Check{
			chk(doctor.CheckTargetResolve, doctor.StatusNotTested, "resolved_by_agent"),
			chk(doctor.CheckTarget, doctor.StatusSkipped, "agent_not_registered"),
		}, nodeSkipped, "SKIPPED", "agent_not_registered"},
		{"not_tested over ok", []doctor.Check{
			chk(doctor.CheckTargetResolve, doctor.StatusOK, ""),
			chk(doctor.CheckTarget, doctor.StatusNotTested, "resolved_by_agent"),
		}, nodeUntested, "NOT TESTED", "resolved_by_agent"},
		{"failed over unknown", []doctor.Check{
			chk(doctor.CheckTargetResolve, doctor.StatusUnknown, "stale_report"),
			chk(doctor.CheckTarget, doctor.StatusFailed, "connection_refused"),
		}, nodeFailed, "FAILED", "connection_refused"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			byID := map[string]doctor.Check{}
			for _, ch := range c.checks {
				byID[ch.ID] = ch
			}
			n, _ := doctorNode(def, byID, doctor.RuleReport{RuleID: "r", Proto: "tcp", Enabled: true}, pathNow, "en")
			if n.State != c.want || n.Word != c.word {
				t.Errorf("node = %s %s, want %s %s", n.State, n.Word, c.want, c.word)
			}
			// 代替テキストの先頭は、最も悪い検査の状態と reason である。
			if head := def.Name + ": " + c.word + " / " + c.reason; !strings.HasPrefix(n.Alt, head) {
				t.Errorf("alt %q must start with %q", n.Alt, head)
			}
		})
	}
}

// TestDoctorPathOpensUnknownNodes は、UNKNOWN の節点の折りたたみを既定で開くことを確かめる。
// 止まった節点と同じく、運用者が次に読む場所だからである。
func TestDoctorPathOpensUnknownNodes(t *testing.T) {
	for _, c := range pathCases() {
		if c.name != "stream down, tunnel alive" {
			continue
		}
		_, paths := buildPath(t, c)
		for _, n := range paths[0].Nodes {
			if (n.State == nodeUnknown) != n.Open {
				t.Errorf("node %s is %s with open=%v; exactly the UNKNOWN nodes open here", n.Name, n.State, n.Open)
			}
		}
		if !strings.HasPrefix(paths[0].Nodes[2].Alt, "agent: DEGRADED / agent_disconnected") {
			t.Errorf("the agent node's alt must lead with its worst check, got %q", paths[0].Nodes[2].Alt)
		}
	}

	srv, b := newDoctorTestServer(t)
	agents, _ := b.Agents()
	agents[0].Connected = false
	b.agents = agents
	body := getBody(t, srv.URL+"/ui/doctor/r_ok?lang=en")
	if !regexp.MustCompile(`<details class="node-detail" open>\s*<summary>\s*<span class="node unknown node-inline">[^\n]*\s*<strong>agent</strong>`).MatchString(body) {
		t.Errorf("the UNKNOWN agent node's details must be open on the page:\n%s", body)
	}
}

var (
	reNodeLI   = regexp.MustCompile(`<li class="node [^"]*"`)
	reNodeA11y = regexp.MustCompile(`(?s)<li class="node [^"]*" title="([^"]+)">.*?<span class="sr-only">([^<]+)</span>`)
)

// TestDoctorPathNodesCarryTextAlternatives は、描いた画面の上で、縮めた図と 1 本のルールの図の
// どの節点にも title と .sr-only の文があり、英語の状態の語か「届いていない」を持つことを
// 確かめる。
func TestDoctorPathNodesCarryTextAlternatives(t *testing.T) {
	srv, _ := newDoctorTestServer(t)
	for _, path := range []string{"/ui/doctor", "/ui/doctor/r_ok", "/ui/doctor/r_err", "/ui/doctor/r_off"} {
		for _, lang := range []string{"ja", "en"} {
			body := getBody(t, srv.URL+path+"?lang="+lang)
			lis := len(reNodeLI.FindAllString(body, -1))
			ms := reNodeA11y.FindAllStringSubmatch(body, -1)
			if lis == 0 || len(ms) != lis {
				t.Errorf("%s %s: %d nodes but %d carry a title and .sr-only text", path, lang, lis, len(ms))
			}
			for _, m := range ms {
				ok := false
				for _, w := range []string{"OK", "FAILED", "UNKNOWN", "DEGRADED", "NOT TESTED", "SKIPPED"} {
					if strings.Contains(m[2], w) {
						ok = true
					}
				}
				if !ok || !strings.Contains(m[1], m[2][:strings.Index(m[2], ":")]) {
					t.Errorf("%s %s: node text %q / title %q lacks the English status word", path, lang, m[2], m[1])
				}
			}
		}
	}
}

// TestDoctorPagesMarkTheStopAndLinkTheRows は、一覧の画面と 1 本のルールの画面の、止まった位置の
// 印を確かめる。止まった後ろの節点は after-stop で線を点線にし、一覧の行は止まった節点の札と、
// ルールの画面へのリンクを持つ。
func TestDoctorPagesMarkTheStopAndLinkTheRows(t *testing.T) {
	srv, _ := newDoctorTestServer(t)
	list := getBody(t, srv.URL+"/ui/doctor?lang=en")
	row := doctorRuleRow(t, list, "r_off")
	if !strings.Contains(row, `<span class="path-caption mono">WireGuard / `) {
		t.Errorf("a stopped row must carry the stopped node's label, row:\n%s", row)
	}
	if n := strings.Count(row, `class="node unreached after-stop"`); n != 2 {
		t.Errorf("the row stopped at WireGuard has %d after-stop nodes, want the 2 after it", n)
	}
	for _, id := range []string{"r_ok", "r_err", "r_off"} {
		if !strings.Contains(list, `<a class="rule-link" href="/ui/doctor/`+id+`">`) {
			t.Errorf("the row of %s must link to its rule page", id)
		}
	}
	if okRow := doctorRuleRow(t, list, "r_ok"); strings.Contains(okRow, "path-caption") {
		t.Errorf("a healthy row carries no stop label, row:\n%s", okRow)
	}
	rule := getBody(t, srv.URL+"/ui/doctor/r_off?lang=en")
	if n := strings.Count(rule, `class="node unreached after-stop"`); n != 2 {
		t.Errorf("the rule page stopped at WireGuard has %d after-stop nodes, want 2", n)
	}
	css := getBody(t, srv.URL+"/static/styles.css")
	for _, want := range []string{
		".path.mini .node.after-stop::before { border-top-style: dashed; }",
		".path.full .node.after-stop::before { border-top-style: dashed; }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("styles.css must draw the line after the stop dashed: %q", want)
		}
	}
}

// TestDoctorOffPathChecksOpenWithTheBanner は、経路の外の検査の折りたたみを、dataplane の帯が
// 出ているときだけ既定で開くことを確かめる。帯の検査の詳細がそこにあるためである。
func TestDoctorOffPathChecksOpenWithTheBanner(t *testing.T) {
	re := regexp.MustCompile(`<details class="node-detail" open>\s*<summary><strong>` + regexp.QuoteMeta(T("en", "doctorOffPathHead")))
	srv, b := newDoctorTestServer(t)
	if re.MatchString(getBody(t, srv.URL+"/ui/doctor/r_ok?lang=en")) {
		t.Errorf("the off-path checks must stay closed while dataplane is OK")
	}
	behind := httptest.NewServer(New(behindBackend{b}))
	t.Cleanup(behind.Close)
	if !re.MatchString(getBody(t, behind.URL+"/ui/doctor/r_ok?lang=en")) {
		t.Errorf("the off-path checks must open when the dataplane banner shows")
	}
}

// TestDoctorAgentRowsKeepCausesAndNext は、一覧の画面のエージェントの行が、検査の Causes と
// 次に見るものを行ごとの折りたたみに持ち、OK でない行だけを既定で開くことを確かめる。ルールが
// WireGuard で止まると 1 本のルールの画面の agent の節点は「届いていない」で閉じるので、次の
// 一手はここで読めなければならない。
func TestDoctorAgentRowsKeepCausesAndNext(t *testing.T) {
	srv, _ := newDoctorTestServer(t)
	body := getBody(t, srv.URL+"/ui/doctor?lang=en")
	rows := map[string]string{}
	for _, r := range strings.Split(body, "<tr>") {
		for _, a := range []string{"home", "office"} {
			if strings.Contains(r, `<span class="check-label">`+a+`</span>`) {
				rows[a] = r
			}
		}
	}
	off := rows["office"]
	if !strings.Contains(off, `<details class="row-finding agent-finding" open>`) {
		t.Errorf("a failing agent row's checks must be open, row:\n%s", off)
	}
	for _, want := range []string{"Check:", "the agent is not running, or holds a different key", T("en", "doctorInternalHead")} {
		if !strings.Contains(off, want) {
			t.Errorf("the office row is missing %q, row:\n%s", want, off)
		}
	}
	if home := rows["home"]; !strings.Contains(home, `<details class="row-finding agent-finding">`) {
		t.Errorf("a healthy agent row keeps its checks closed, row:\n%s", home)
	}
}

// TestDoctorPathStaleResolutionReadsDegraded は、名前の解決に失敗して直前の解決の結果で転送を続けて
// いるルールを、画面が「止まった」と描かないことを確かめる(設計文書 10.2a 節)。宛先の節点は
// DEGRADED の ? で、ダッシュボードの印はエラーに数えず、結論は転送を続けていることを述べる。
func TestDoctorPathStaleResolutionReadsDegraded(t *testing.T) {
	found := false
	for _, c := range pathCases() {
		if c.name != "name fails, still forwarding" {
			continue
		}
		found = true
		rep, paths := buildPath(t, c)
		rr := rep.Rules[0]
		node := paths[0].Nodes[doctorNodeIndex(doctor.CheckTargetResolve)]
		if node.State != nodeUnknown || node.Word != "DEGRADED" || node.Stop != "" {
			t.Errorf("target node = %s %q stop %q, want unknown DEGRADED with no stop", node.State, node.Word, node.Stop)
		}
		m := doctorMark(rr, rep.ChecksOf(rr.RuleID), paths[0], "en")
		if m.Failed || m.State != nodeUnknown || m.Node != node.Name {
			t.Errorf("dashboard mark = %+v, want an unknown mark at %q that is not counted as an error", m, node.Name)
		}
		line := doctorResultLine(rr, rep)
		if !strings.Contains(line, "still forwarding to 192.168.1.30") || !strings.Contains(line, "fix name resolution") {
			t.Errorf("result line = %q, want it to say the rule still forwards and to fix name resolution", line)
		}
	}
	if !found {
		t.Fatal("the case is missing from pathCases")
	}
}

// 前の解決の結果で転送を続けるルールの経路に別の UNKNOWN もあれば、画面の結論も両方を述べる。
// CLI の Result: の行と同じ文である。
func TestDoctorResultLineStaleResolutionKeepsOtherUnknowns(t *testing.T) {
	for _, c := range pathCases() {
		if c.name != "name fails, still forwarding" {
			continue
		}
		edit := c.edit
		c.edit = func(in *doctor.Input) {
			edit(in)
			in.Agents[0].Generation = 11
			in.Agents[0].GenerationBehindSince = pathAt(5 * time.Second)
		}
		rep, _ := buildPath(t, c)
		line := doctorResultLine(rep.Rules[0], rep)
		for _, want := range []string{"still forwarding to 192.168.1.30", "other evidence above is also stale or untested"} {
			if !strings.Contains(line, want) {
				t.Errorf("result line = %q, want it to hold %q", line, want)
			}
		}
		return
	}
	t.Fatal("the case is missing from pathCases")
}
