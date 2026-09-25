package main

import (
	"bytes"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent"
	"github.com/rahanahu/wgft/internal/flock"
	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/proto"
)

// collectStrings walks v (a pointer to a struct) with reflect and returns every string value it
// finds, however deeply nested. It mirrors textsafe.SanitizeStrings' own walk so this test can
// check every field classifyDoctorReply's textsafe.SanitizeStrings call is supposed to cover,
// without listing agent.DoctorResponse's fields by hand here too.
func collectStrings(t *testing.T, v any) []string {
	t.Helper()
	var out []string
	var walk func(reflect.Value)
	walk = func(rv reflect.Value) {
		switch rv.Kind() {
		case reflect.Ptr, reflect.Interface:
			if !rv.IsNil() {
				walk(rv.Elem())
			}
		case reflect.Struct:
			for i := 0; i < rv.NumField(); i++ {
				if f := rv.Field(i); f.CanInterface() {
					walk(f)
				}
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < rv.Len(); i++ {
				walk(rv.Index(i))
			}
		case reflect.String:
			out = append(out, rv.String())
		}
	}
	walk(reflect.ValueOf(v))
	return out
}

// このファイルは、agent が信頼の境界の外にあるという design.md 11 節の前提から来る、CLI の表示
// 無害化のテストである。`wgft agent doctor` が制御ソケットの応答を読む経路(agentdoctorlive.go)を
// 対象にする。`agent ls`・`rule ls`・`status`・`server doctor` の側は、それぞれの表示関数の単体
// テストとして別ファイルに置く。

// TestClassifyDoctorReplySanitizesEveryStringField は、稼働中の(乗っ取られたと想定する)agent が
// 返す doctor 応答のどの文字列も、classifyDoctorReply を通った後は端末の制御文字を持たないことを
// 確かめる(design.md 11 節)。textsafe.SanitizeStrings が構造体を再帰的に歩く実装なので、個々の
// フィールドを列挙する代わりに reflect で全文字列を集めて調べる。
func TestClassifyDoctorReplySanitizesEveryStringField(t *testing.T) {
	resp := runtimeResponse(func(st *agent.DoctorRuntimeState) {
		st.Tunnel.Reason = "hijacked\x1b[2Jreason"
		st.Tunnel.Endpoint = "10.0.0.1:1\x07234"
		st.Rules = []agent.DoctorRule{{
			ID:          "r_evil\x1b]0;pwned\x07",
			State:       proto.StatusError,
			Reason:      "bad\rCR",
			BindError:   "esc\x1bhere",
			TargetError: "c1\x9bcontrol",
		}}
		st.PublishError = "pub\x00lish"
	})
	live := classifyDoctorReply("/tmp/does-not-matter.sock", liveReply(resp))
	if live.Kind != liveOK {
		t.Fatalf("Kind = %v, want liveOK", live.Kind)
	}
	for _, s := range collectStrings(t, live.Resp) {
		if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) }) {
			t.Errorf("classifyDoctorReply left a raw control byte in a string field: %q", s)
		}
	}
}

// TestClassifyDoctorReplySanitizesTheUnsupportedReply confirms the "it replied ..." text
// agentControlCheck shows for a legacy/unsupported reply (agentdoctorlive.go's liveUnsupported
// branch, live.Reply) is also sanitized: this field is set directly, bypassing
// textsafe.SanitizeStrings' struct walk over agent.DoctorResponse.
func TestClassifyDoctorReplySanitizesTheUnsupportedReply(t *testing.T) {
	live := classifyDoctorReply("/tmp/does-not-matter.sock", "not json at all \x1b[31m\n")
	if live.Kind != liveReplyUnreadable {
		t.Fatalf("Kind = %v, want liveReplyUnreadable", live.Kind)
	}
	if strings.Contains(live.Reply, "\x1b") {
		t.Errorf("live.Reply still has a raw ESC: %q", live.Reply)
	}
}

// TestReadAgentLiveCapsAnUnboundedReply confirms that `wgft agent doctor` does not buffer a
// running agent's reply without bound when that agent never sends the trailing newline
// bufio.Reader.ReadString waits for (design.md 11 節: the agent is outside the trust boundary).
// Mutation check: wrapping readAgentLive's bufio.NewReader back around the bare net.Conn (removing
// the io.LimitReader) makes this test time out instead of observing an error quickly, since the
// read would then wait for the connection's own deadline instead of hitting EOF at
// agent.DoctorReplyMaxBytes.
func TestReadAgentLiveCapsAnUnboundedReply(t *testing.T) {
	dir := t.TempDir()
	in := testAgentDoctorInput(t, dir)
	writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
	holdTheLock(t, in.CredentialsPath)
	sock := agent.ControlPath(in.CredentialsPath)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("this host cannot open a unix socket at %s: %v", sock, err)
	}
	defer ln.Close()
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 512)
		c.Read(buf) //nolint:errcheck // the "doctor" request line; its content does not matter here
		c.Write(make([]byte, agent.DoctorReplyMaxBytes))
		<-block
	}()
	in.Dial = dialAgentControl // 既定の入口(net.DialTimeout)を使う

	done := make(chan agentLive, 1)
	go func() { done <- readAgentLive(in, agentRunState{State: flock.Locked}) }()
	select {
	case live := <-done:
		if live.Kind != liveReplyUnreadable {
			t.Fatalf("Kind = %v, want liveReplyUnreadable (the cap was hit)", live.Kind)
		}
		// The error should name the limit, not just say "EOF" (レビューの指摘, 2026-09-26; see
		// agent.ReadControlReply's own doc comment).
		if live.Err == nil || !strings.Contains(live.Err.Error(), "exceeded") || !strings.Contains(live.Err.Error(), "limit") {
			t.Errorf("live.Err = %v, want it to say the reply exceeded the limit, not a bare EOF", live.Err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("readAgentLive did not return within 3s; it is not capping the reply size")
	}
}

// TestAgentLsSanitizesAHostileTunnelAndRuleReport confirms that `agent ls`'s TUNNEL and RULES
// columns escape terminal control bytes in a heartbeat-derived admin.AgentInfo, and leaves normal
// (including Japanese) text unchanged. The hub already scrubs these fields before storing them
// (internal/vpsd/stream/sanitize.go), so this exercises the CLI's own, independent display-time
// layer (design.md 11 節) directly against a fake admin.AgentInfo, without needing the hub in the
// loop.
func TestAgentLsSanitizesAHostileTunnelAndRuleReport(t *testing.T) {
	agents := []admin.AgentInfo{
		{
			Name: "home", Address: "10.200.0.2", Connected: true, LastHeartbeat: time.Now().Format(time.RFC3339),
			Tunnel: admin.TunnelStatus{State: proto.StatusError, Reason: "hijacked\x1b[2J\x1b[Hreason"},
			Rules: []proto.RuleStatus{
				{ID: "r_evil\x1b]0;pwned\x07", State: proto.StatusError, Reason: "bind failed\rFAKE STATUS: healthy"},
				{ID: "r_ok", State: proto.StatusOK},
			},
		},
	}
	adminURL := newAgentCLITestServer(t, agents)

	stdout, _, err := runAgentCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("agent ls: %v", err)
	}

	home := agentLsFields(t, stdout, "home")
	if strings.ContainsAny(home.tunnel, "\x1b\x07\r\x00") {
		t.Errorf("home TUNNEL still has a raw control byte: %q", home.tunnel)
	}
	if !strings.Contains(home.tunnel, "hijacked") {
		t.Errorf("home TUNNEL = %q, want it to still carry the reported text", home.tunnel)
	}
	if strings.ContainsAny(home.rules, "\x1b\x07\r\x00") {
		t.Errorf("home RULES still has a raw control byte: %q", home.rules)
	}
	if !strings.Contains(home.rules, "r_evil") || !strings.Contains(home.rules, "bind failed") {
		t.Errorf("home RULES = %q, want it to still carry the reported rule ID and reason", home.rules)
	}
}

// TestAgentLsKeepsJapaneseTextUnchanged confirms SanitizeForTerminal does not mangle ordinary
// non-ASCII text. It checks the raw stdout for the two reasons verbatim rather than through
// agentLsFields: that helper locates tabwriter columns by the header's byte offsets, and
// tabwriter itself pads a column by rune count, so a cell with 3-byte Japanese runes ends up at a
// different byte offset than the same column in the (ASCII) header - a pre-existing limitation of
// that test helper, not of this column's output, so this test reads the whole line instead.
func TestAgentLsKeepsJapaneseTextUnchanged(t *testing.T) {
	agents := []admin.AgentInfo{
		{
			Name: "office", Address: "10.200.0.3", Connected: true, LastHeartbeat: time.Now().Format(time.RFC3339),
			Tunnel: admin.TunnelStatus{State: proto.StatusError, Reason: "接続を確認できませんでした"},
			Rules:  []proto.RuleStatus{{ID: "r_jp", State: proto.StatusError, Reason: "宛先に届きません"}},
		},
	}
	adminURL := newAgentCLITestServer(t, agents)
	stdout, _, err := runAgentCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("agent ls: %v", err)
	}
	if !strings.Contains(stdout, "error: 接続を確認できませんでした") {
		t.Errorf("agent ls output does not contain the Japanese tunnel reason unchanged:\n%s", stdout)
	}
	if !strings.Contains(stdout, "r_jp:宛先に届きません") {
		t.Errorf("agent ls output does not contain the Japanese rule reason unchanged:\n%s", stdout)
	}
}

// TestAgentLsRulesColumnManyRulesStaysCorrect exercises the strings.Builder rewrite of the RULES
// column (replacing an O(n^2) += loop a security review flagged, since a 1 MiB heartbeat with many
// non-ok rules could make it quadratic) with enough rules that a regression in the loop's
// character-for-character output (missing separator, dropped entry, wrong order) would show up.
func TestAgentLsRulesColumnManyRulesStaysCorrect(t *testing.T) {
	const n = 50
	var rules []proto.RuleStatus
	var want strings.Builder
	for i := 0; i < n; i++ {
		id := "r_" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		rules = append(rules, proto.RuleStatus{ID: id, State: proto.StatusError, Reason: "err"})
		want.WriteString(id)
		want.WriteString(":err ")
	}
	agents := []admin.AgentInfo{{
		Name: "many", Address: "10.200.0.4", Connected: true, LastHeartbeat: time.Now().Format(time.RFC3339),
		Tunnel: admin.TunnelStatus{State: proto.StatusOK},
		Rules:  rules,
	}}
	adminURL := newAgentCLITestServer(t, agents)
	stdout, _, err := runAgentCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("agent ls: %v", err)
	}
	got := agentLsFields(t, stdout, "many").rules
	if got != strings.TrimRight(want.String(), " ") {
		t.Errorf("RULES column with %d rules = %q, want %q", n, got, want.String())
	}
}

// TestAgentRuleNoteSanitizesAHostileReport confirms `rule ls`'s AGENT column (agentRuleNote,
// rule.go) escapes control bytes in the owning agent's reported state and reason, and leaves the
// "ok"/"error: " branch and the "last:" prefix logic driven by the raw, unsanitized values (so a
// hostile State this build does not recognize still falls into the same branch a legitimate
// unknown value would).
func TestAgentRuleNoteSanitizesAHostileReport(t *testing.T) {
	states := map[string]admin.AgentRuleStatus{
		"r1": {State: proto.StatusError, Reason: "bind failed\x1b[2Jinjected", Connected: true},
		"r2": {State: proto.StatusOK, Connected: false},
		// A hostile State never reaches the note as itself: any State other than exactly "ok"
		// takes the "error: "+Reason branch below, so State's own content is discarded either
		// way. This checks that invariant holds even when State itself carries the escape.
		"r3": {State: "\x1bevil", Reason: "clean reason", Connected: true},
	}
	if got := agentRuleNote(states, "r1"); strings.Contains(got, "\x1b") {
		t.Errorf("agentRuleNote(r1) = %q, still has a raw ESC", got)
	} else if !strings.HasPrefix(got, "error: bind failed") {
		t.Errorf("agentRuleNote(r1) = %q, want it to start with the reported reason", got)
	}
	if got := agentRuleNote(states, "r2"); got != "last:ok" {
		t.Errorf("agentRuleNote(r2) = %q, want \"last:ok\" unchanged", got)
	}
	if got := agentRuleNote(states, "r3"); strings.Contains(got, "\x1b") || strings.Contains(got, "evil") {
		t.Errorf("agentRuleNote(r3) = %q, want no trace of the hostile State", got)
	} else if got != "error: clean reason" {
		t.Errorf("agentRuleNote(r3) = %q, want \"error: clean reason\"", got)
	}
	if got := agentRuleNote(states, "missing"); got != "-" {
		t.Errorf("agentRuleNote(missing) = %q, want \"-\"", got)
	}
}

// TestWriteStatusLineSanitizesDetail confirms `status`'s single text-rendering chokepoint
// (writeStatusLine, status.go) escapes control bytes reaching it through an agent's heartbeat
// (design.md 11 節), and leaves clean text, including an empty detail, unchanged.
func TestWriteStatusLineSanitizesDetail(t *testing.T) {
	var buf bytes.Buffer
	writeStatusLine(&buf, "Agents", "1 degraded / 1", "home tunnel: hijacked\x1b[2Jinjected")
	if strings.Contains(buf.String(), "\x1b") {
		t.Errorf("writeStatusLine output still has a raw ESC:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "hijacked") {
		t.Errorf("writeStatusLine output dropped the reported text:\n%s", buf.String())
	}

	buf.Reset()
	writeStatusLine(&buf, "Server", "healthy", "")
	if got := buf.String(); !strings.Contains(got, "Server") || !strings.Contains(got, "healthy") || strings.Contains(got, "\x1b") {
		t.Errorf("writeStatusLine with an empty detail = %q, want the plain label/value line unchanged", got)
	}
}

// TestWriteLineSanitizesDetail confirms `server doctor`'s single text-rendering chokepoint
// (writeLine, doctor.go) escapes control bytes in a check's Detail. `group`・`label`・`detail`・
// `next` are explicitly not part of `server doctor --json`'s guarantee (design.md 10.2a 節), so
// this is not a compatibility requirement; sanitizing here rather than in checks.go is a choice to
// keep internal/vpsd/doctor free of internal/textsafe (レビューの指摘, 2026-09-26: an earlier
// version of this comment wrongly said Detail was a guaranteed value).
func TestWriteLineSanitizesDetail(t *testing.T) {
	var buf bytes.Buffer
	writeLine(&buf, "WireGuard", "FAILED", "the agent reports its tunnel in error: hijacked\x1b[2Jinjected; this VPS still saw a handshake 5s ago")
	if strings.Contains(buf.String(), "\x1b") {
		t.Errorf("writeLine output still has a raw ESC:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "hijacked") {
		t.Errorf("writeLine output dropped the reported text:\n%s", buf.String())
	}
}

// TestWriteInternalSanitizesLines confirms the verbose [internal] lines (writeInternal, doctor.go)
// are sanitized too: Check.Internal can carry agent-supplied text (checks.go's handshakeCheck
// puts "agent tunnel report is ..." there), and like Detail is human text with no --json guarantee.
func TestWriteInternalSanitizesLines(t *testing.T) {
	var buf bytes.Buffer
	writeInternal(&buf, []string{"agent tunnel report is error: hijacked\x1b[2Jinjected"}, true, 4)
	if strings.Contains(buf.String(), "\x1b") {
		t.Errorf("writeInternal output still has a raw ESC:\n%s", buf.String())
	}
	buf.Reset()
	writeInternal(&buf, []string{"should not print when not verbose\x1b"}, false, 4)
	if buf.Len() != 0 {
		t.Errorf("writeInternal wrote something when verbose=false: %q", buf.String())
	}
}

// TestWriteNextSanitizes confirms the "Check: ..." follow-up line (writeNext, doctor.go) is
// sanitized. This closes a gap an earlier version of this PR left open: a kernel-mode agent
// doctor check (agentdoctorkernel.go) puts ki.ServerAddress, read from agent.json, into some of
// its own Next text, and Next previously reached the terminal through a bare wrapAt call with no
// sanitize step at all (レビューの指摘, 2026-09-26).
func TestWriteNextSanitizes(t *testing.T) {
	var buf bytes.Buffer
	writeNext(&buf, "find what claims the address with ip rule and ip route get 10.200.0.1\x1b[2Jevil; a VPN is a common cause", 4)
	if strings.Contains(buf.String(), "\x1b") {
		t.Errorf("writeNext output still has a raw ESC:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "10.200.0.1") {
		t.Errorf("writeNext output dropped the reported text:\n%s", buf.String())
	}
}

// TestCheckDetailOfAndFirstNotOKDetailSanitize confirm the two helpers writeSurvey's Rules table
// uses to build its "why" column (doctor.go) sanitize the Detail text they return, closing a gap
// an earlier version of this PR left open: both already called textsafe.SanitizeForTerminal, but
// neither had a test that would fail if that call were removed (レビューの指摘, 2026-09-26).
func TestCheckDetailOfAndFirstNotOKDetailSanitize(t *testing.T) {
	rep := doctorReport{Checks: []checkReport{
		{ID: "tunnel.handshake", RuleID: "r1", Label: "WireGuard", Detail: "hijacked\x1b[2Jinjected", Status: statusFailed},
	}}
	if got := checkDetailOf(rep, "r1", "tunnel.handshake"); strings.Contains(got, "\x1b") {
		t.Errorf("checkDetailOf(...) = %q, still has a raw ESC", got)
	}
	rep2 := doctorReport{Checks: []checkReport{
		{ID: "tunnel.handshake", RuleID: "r1", Label: "WireGuard", Detail: "hijacked\x1b[2Jinjected", Status: statusUnknown},
	}}
	if got := firstNotOKDetail(rep2, "r1"); strings.Contains(got, "\x1b") {
		t.Errorf("firstNotOKDetail(...) = %q, still has a raw ESC", got)
	}
}

// TestWriteValueLineSanitizes confirms `agent doctor`'s "Observed values" line (writeValueLine,
// agentdoctor.go) sanitizes its detail, closing a gap an earlier version of this PR left open: the
// sanitize call was already there but had no test that would fail if it were removed
// (レビューの指摘, 2026-09-26).
func TestWriteValueLineSanitizes(t *testing.T) {
	var buf bytes.Buffer
	writeValueLine(&buf, "allow targets", "192.168.1.0/24\x1b[2Jinjected")
	if strings.Contains(buf.String(), "\x1b") {
		t.Errorf("writeValueLine output still has a raw ESC:\n%s", buf.String())
	}
}

// TestAgentDoctorJSONOfSanitizesDetailAndNext confirms `agent doctor --json`'s model
// (agentdoctorjson.go) sanitizes Detail and Next, closing the one remaining gap the display-side
// fixes above do not reach: a stopped agent's checks build Detail/Next straight from agent.json
// (the registered name, LastState's WG address and endpoint) without going through
// classifyDoctorReply's textsafe.SanitizeStrings, which only runs for a running agent's
// control-socket reply, and --json bypasses writeLine/writeNext entirely (レビューの指摘,
// 2026-09-26: "raw output happens only in ... agent doctor --json").
func TestAgentDoctorJSONOfSanitizesDetailAndNext(t *testing.T) {
	rep := agentDoctorReport{
		Checks: []agentDoctorCheck{
			{ID: "agent.last_state", Status: statusOK, Detail: "last: generation 1\x1b[2Jinjected"},
			{ID: "dataplane.interface", Status: statusFailed, Next: "find what claims the address\x07evil"},
		},
		History:   "no history\x1bhere",
		NotTested: []notTested{{ID: "x", Detail: "not tested\x1bhere"}},
	}
	got := agentDoctorJSONOf(rep)
	for _, c := range got.Checks {
		if strings.ContainsAny(c.Detail, "\x1b\x07") {
			t.Errorf("Checks[%s].Detail = %q, still has a raw control byte", c.ID, c.Detail)
		}
		if strings.ContainsAny(c.Next, "\x1b\x07") {
			t.Errorf("Checks[%s].Next = %q, still has a raw control byte", c.ID, c.Next)
		}
	}
	if strings.Contains(got.History.Detail, "\x1b") {
		t.Errorf("History.Detail = %q, still has a raw ESC", got.History.Detail)
	}
	if strings.Contains(got.NotTested[0].Detail, "\x1b") {
		t.Errorf("NotTested[0].Detail = %q, still has a raw ESC", got.NotTested[0].Detail)
	}
}

// TestAgentLsSanitizesAHostileTunnelState confirms `agent ls`'s TUNNEL column sanitizes
// a.Tunnel.State itself, not just a.Tunnel.Reason: unlike agentRuleNote (rule.go), where a
// non-"ok" State is always replaced by "error: "+Reason before display, agent.go always shows
// sanitize(a.Tunnel.State) as the start of the TUNNEL column, so a hostile State reaches the
// terminal directly if that call is removed - a real gap the original hostile-input test for this
// column left uncaught, since it only made Reason hostile (レビューの指摘, 2026-09-26).
func TestAgentLsSanitizesAHostileTunnelState(t *testing.T) {
	agents := []admin.AgentInfo{{
		Name: "home", Address: "10.200.0.2", Connected: true, LastHeartbeat: time.Now().Format(time.RFC3339),
		Tunnel: admin.TunnelStatus{State: "ok\x1b[2Jinjected"},
	}}
	adminURL := newAgentCLITestServer(t, agents)
	stdout, _, err := runAgentCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("agent ls: %v", err)
	}
	if strings.Contains(stdout, "\x1b") {
		t.Errorf("agent ls output still has a raw ESC:\n%s", stdout)
	}
}
