package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、名前の解決に失敗して直前の解決の結果で転送を続けているルール(設計文書 7b.2 節)を、
// `server doctor` が「転送が止まっている」と言わないことを確かめる(10.2a 節)。理由の文言は、
// カーネルモードのエージェントが実際に組み立てる形(internal/agent/dataplane_kernel.go の
// staleReason と ruleStatuses)をそのまま使う。その形は agent の側の
// TestKernelStaleReasonIsReadByServerDoctor が固定している。

const staleHead = `name resolution of target host "game.lan" failed: lookup game.lan on 127.0.0.53:53: no such host`

func staleReason(rest string) string {
	s := staleHead + "; still forwarding to 192.168.1.30 from the last successful resolution"
	if rest != "" {
		s += "; " + rest
	}
	return s
}

// staleInput は、ホスト名の宛先を持つルールと、そのルールについてのエージェントの今の報告である。
func staleInput(r *proto.Rule, reason string) doctorInput {
	r.Target = "game.lan:" + strings.Split(r.Target, ":")[1]
	in := healthyInput(*r)
	in.Rules.Rules = []proto.Rule{*r}
	in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{
		Agent: "home", State: proto.StatusError, Reason: reason, At: at(10 * time.Second), Connected: true,
	}
	return in
}

func TestStaleResolutionKeepsForwarding(t *testing.T) {
	r := tcpRule()
	in := staleInput(&r, staleReason(""))
	rep := buildReport([]proto.Rule{r}, in)

	res := checkOf(t, rep.Checks, checkTargetResolve)
	if res.Status != statusUnknown || res.Reason != reasonResolveFailed {
		t.Errorf("rule.target_resolve = %s/%s, want %s/%s", res.Status, res.Reason, statusUnknown, reasonResolveFailed)
	}
	for _, want := range []string{"still forwarding to 192.168.1.30", "game.lan", "no such host"} {
		if !strings.Contains(res.Detail, want) {
			t.Errorf("rule.target_resolve detail = %q, want it to hold %q", res.Detail, want)
		}
	}
	if !strings.Contains(res.Next, "fix name resolution on the agent host") {
		t.Errorf("rule.target_resolve next = %q, want it to point at name resolution", res.Next)
	}
	tgt := checkOf(t, rep.Checks, checkTarget)
	if tgt.Status != statusOK || tgt.Reason != "" {
		t.Errorf("rule.target = %s/%s (%s), want ok: the agent's probe of the old address did not fail", tgt.Status, tgt.Reason, tgt.Detail)
	}
	if !strings.Contains(tgt.Detail, "192.168.1.30") || !strings.Contains(tgt.Detail, "last successful resolution") {
		t.Errorf("rule.target detail = %q, want it to name the old address and where it came from", tgt.Detail)
	}

	rr := rep.Rules[0]
	if rr.Status != statusUnknown || rr.StoppedAt != "" {
		t.Errorf("rule = %s stopped at %q, want unknown with no stop", rr.Status, rr.StoppedAt)
	}
	if rep.Status != statusOK {
		t.Errorf("report status = %s, want ok", rep.Status)
	}
	if err := doctorExit(rep); err != nil {
		t.Errorf("a rule that still forwards must exit 0, got %v", err)
	}

	// 人向けの出力:解決の行は DEGRADED、結論は転送を続けていることと名前の解決を直すこと
	var out strings.Builder
	writeRuleReport(&out, rep, false)
	line := lineHolding(t, out.String(), "target resolve")
	if !strings.Contains(line, "DEGRADED") {
		t.Errorf("the target resolve line must read DEGRADED, got %q", line)
	}
	// 結論の行は折り返すので、次の空行までを 1 つの文として読む
	result, _, _ := strings.Cut(out.String()[strings.Index(out.String(), "Result:"):], "\n\n")
	result = strings.Join(strings.Fields(result), " ")
	for _, want := range []string{"still forwarding to 192.168.1.30", "fix name resolution"} {
		if !strings.Contains(result, want) {
			t.Errorf("result line = %q, want it to hold %q", result, want)
		}
	}
	if strings.Contains(out.String(), "traffic stops") {
		t.Errorf("the report must not say traffic stops:\n%s", out.String())
	}

	// 機械向けの出力に DEGRADED は出ない
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "DEGRADED") {
		t.Error("DEGRADED is a word for a person; it must not appear in the machine-readable output")
	}
}

// 直前のアドレスの宛先も接続を拒むなら、転送は宛先で止まっている。解決の行は DEGRADED のまま、
// 止まった位置は target である。
func TestStaleResolutionWithARefusingTargetStopsAtTarget(t *testing.T) {
	r := tcpRule()
	in := staleInput(&r, staleReason("target 192.168.1.30:25565: dial tcp 192.168.1.30:25565: connect: connection refused"))
	rep := buildReport([]proto.Rule{r}, in)

	if res := checkOf(t, rep.Checks, checkTargetResolve); res.Status != statusUnknown || res.Reason != reasonResolveFailed {
		t.Errorf("rule.target_resolve = %s/%s, want %s/%s", res.Status, res.Reason, statusUnknown, reasonResolveFailed)
	}
	tgt := checkOf(t, rep.Checks, checkTarget)
	if tgt.Status != statusFailed || tgt.Reason != reasonConnectionRefused {
		t.Errorf("rule.target = %s/%s, want %s/%s", tgt.Status, tgt.Reason, statusFailed, reasonConnectionRefused)
	}
	if !strings.Contains(tgt.Next, "a service is listening on game.lan:25565") {
		t.Errorf("rule.target next = %q, want the refusing target's next step", tgt.Next)
	}
	if rr := rep.Rules[0]; rr.Status != statusFailed || rr.StoppedAt != checkTarget {
		t.Errorf("rule = %s stopped at %q, want failed at %s", rr.Status, rr.StoppedAt, checkTarget)
	}
	if code := exitCode(doctorExit(rep)); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

func TestStaleResolutionOnAUDPRuleIsNotTested(t *testing.T) {
	r := udpRule()
	in := staleInput(&r, staleReason(""))
	rep := buildReport([]proto.Rule{r}, in)
	tgt := checkOf(t, rep.Checks, checkTarget)
	if tgt.Status != statusNotTested || tgt.Reason != doctor.ReasonUDPListenerOnly {
		t.Errorf("rule.target = %s/%s, want %s/%s", tgt.Status, tgt.Reason, statusNotTested, doctor.ReasonUDPListenerOnly)
	}
	if rr := rep.Rules[0]; rr.Status != statusUnknown || rr.StoppedAt != "" {
		t.Errorf("rule = %s stopped at %q, want unknown with no stop", rr.Status, rr.StoppedAt)
	}
}

// 直前の解決の結果を持たない解決の失敗は、今までどおり解決で止まる。カーネルモードで一度も解決
// できていない名前、直前のアドレスも使えない場合、ユーザー空間モードの接続ごとの解決の失敗である。
func TestResolveFailureWithoutAnOldAddressStillStops(t *testing.T) {
	for name, reason := range map[string]string{
		"kernel, never resolved": staleHead,
		"kernel, the old address is not usable either": staleHead +
			"; the address from the last successful resolution is not usable either: target 192.168.1.30:25565 is not in WGFT_AGENT_ALLOW_TARGETS",
		"userspace": "tcp/25565: dial tcp: lookup game.lan on 127.0.0.53:53: no such host",
	} {
		t.Run(name, func(t *testing.T) {
			r := tcpRule()
			in := staleInput(&r, reason)
			rep := buildReport([]proto.Rule{r}, in)
			res := checkOf(t, rep.Checks, checkTargetResolve)
			if res.Status != statusFailed || res.Reason != reasonResolveFailed {
				t.Errorf("rule.target_resolve = %s/%s, want %s/%s", res.Status, res.Reason, statusFailed, reasonResolveFailed)
			}
			if displayStatus(res) != "FAILED" {
				t.Errorf("displayStatus = %q, want FAILED", displayStatus(res))
			}
			if rr := rep.Rules[0]; rr.StoppedAt != checkTargetResolve {
				t.Errorf("rule stopped at %q, want %s", rr.StoppedAt, checkTargetResolve)
			}
		})
	}
}

// 一覧の要約は、直前の解決の結果で転送を続けているルールを「転送していない」に数えない。
func TestSurveyDoesNotCountAStaleRuleAsNotCarrying(t *testing.T) {
	stale := tcpRule()
	in := staleInput(&stale, staleReason(""))
	down := tcpRule()
	down.ID, down.ListenPort = "r_01M2R00BBBBBBBBBBBBBBBBBB", proto.PortRange{Lo: 25566, Hi: 25566}
	in.Rules.Rules = append(in.Rules.Rules, down)
	in.Rules.RuleStates[down.ID] = admin.RuleApply{ApplyState: admin.ApplyActive, ActiveGeneration: u64(12)}
	in.Rules.AgentRuleStates[down.ID] = admin.AgentRuleStatus{Agent: "home", State: proto.StatusError,
		Reason: "dial tcp 192.168.1.20:25565: connect: connection refused", At: at(10 * time.Second), Connected: true}
	rep := buildReport(in.Rules.Rules, in)

	var out strings.Builder
	writeSurvey(&out, rep, false)
	if got := lineHolding(t, out.String(), "Result:"); !strings.Contains(got, "1 of 2 rules not carrying traffic") {
		t.Errorf("result = %q, want 1 of 2", got)
	}
	row := lineHolding(t, out.String(), short(stale.ID))
	if strings.Contains(row, "stops at") || !strings.Contains(row, "still forwarding to 192.168.1.30") {
		t.Errorf("the stale rule's row = %q, want it to say it still forwards", row)
	}
}

func TestStaleResolutionParse(t *testing.T) {
	for _, tc := range []struct {
		reason, addr, rest string
		ok                 bool
	}{
		{staleReason(""), "192.168.1.30", "", true},
		{staleReason("target 192.168.1.30:80: i/o timeout"), "192.168.1.30", "target 192.168.1.30:80: i/o timeout", true},
		{staleHead, "", "", false},
		{"dial tcp 192.168.1.20:80: connect: connection refused; still forwarding to 192.168.1.30 from the last successful resolution", "", "", false},
		{staleHead + "; still forwarding to 192.168.1.30 from the last successful resolutions", "", "", false},
		{staleHead + "; the address from the last successful resolution is not usable either: x", "", "", false},
	} {
		addr, rest, ok := doctor.StaleResolution(tc.reason)
		if addr != tc.addr || rest != tc.rest || ok != tc.ok {
			t.Errorf("StaleResolution(%q) = %q, %q, %v; want %q, %q, %v", tc.reason, addr, rest, ok, tc.addr, tc.rest, tc.ok)
		}
	}
}
