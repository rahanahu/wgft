package main

import (
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、カーネルモードの server が稼働中に VPS の ip_forward を 0 にされた場合の診断
// (設計文書 6.1、10.2a、10.2b 節)を確かめる。server は起動時にだけ 1 にするので、その後の 0 は
// server が今読む値として管理用 API に載り、カーネルで転送するルールの止まった位置になる。

func withIPForward(in doctorInput, v string) doctorInput {
	in.Rules.IPForward = &admin.IPForwardStatus{Value: v}
	return in
}

func TestIPForwardOffStopsKernelRules(t *testing.T) {
	r := tcpRule()
	in := withIPForward(healthyInput(r), "0")
	pp := checkOf(t, diagnose(r, in), checkPublicPort)
	if pp.Status != statusFailed || pp.Reason != doctor.ReasonIPForwardOff {
		t.Fatalf("public port = %s/%s, want failed/%s", pp.Status, pp.Reason, doctor.ReasonIPForwardOff)
	}
	if !strings.Contains(pp.Next, "sysctl -w net.ipv4.ip_forward=1") {
		t.Errorf("public port next step does not name the sysctl: %q", pp.Next)
	}
	dp := dataplaneCheck(in)
	if dp.Status != statusFailed || dp.Reason != doctor.ReasonIPForwardOff {
		t.Fatalf("dataplane = %s/%s, want failed/%s", dp.Status, dp.Reason, doctor.ReasonIPForwardOff)
	}
	rep := buildReport([]proto.Rule{r}, in)
	if rep.Status != statusFailed || rep.Rules[0].StoppedAt != checkPublicPort {
		t.Errorf("report = %s stopped at %q, want failed at %s", rep.Status, rep.Rules[0].StoppedAt, checkPublicPort)
	}
	st := buildStatusReport(statusInput{Now: doctorNow, Rules: in.Rules, Agents: in.Agents})
	if st.Server.Status != serverDegraded || !strings.Contains(st.Server.Detail, "net.ipv4.ip_forward on this VPS is 0") {
		t.Errorf("status server = %+v, want degraded naming ip_forward", st.Server)
	}
}

// プロキシのルールは vpsd が受けて自分から wg0 へ接続し直すので、ip_forward に依らない。止まる
// ルールが無いなら FAILED にしない。FAILED は転送の停止を観測した場合にだけ使う。
func TestIPForwardOffLeavesProxyRules(t *testing.T) {
	r := tcpRule()
	r.VPSMode = proto.ModeProxy
	in := healthyInput(r)
	in.Rules.Rules = []proto.Rule{r}
	in = withIPForward(in, "0")
	if pp := checkOf(t, diagnose(r, in), checkPublicPort); pp.Status != statusNotTested {
		t.Errorf("a proxy rule's public port = %s/%s, want not tested", pp.Status, pp.Reason)
	}
	dp := dataplaneCheck(in)
	if dp.Status != statusOK || !strings.Contains(dp.Detail, "stops no rule now") {
		t.Errorf("dataplane = %s %q, want ok with a note", dp.Status, dp.Detail)
	}
	st := buildStatusReport(statusInput{Now: doctorNow, Rules: in.Rules, Agents: in.Agents})
	if st.Server.Status != serverHealthy {
		t.Errorf("status server = %+v, want healthy", st.Server)
	}
}

// 1 のとき、読めなかったとき、報告の無い server では何も変えない。
func TestIPForwardOnOrUnknownChangesNothing(t *testing.T) {
	r := tcpRule()
	for name, in := range map[string]doctorInput{
		"on":       withIPForward(healthyInput(r), "1"),
		"not read": healthyInput(r),
		"unreadable": func() doctorInput {
			in := healthyInput(r)
			in.Rules.IPForward = &admin.IPForwardStatus{Error: "permission denied"}
			return in
		}(),
	} {
		if pp := checkOf(t, diagnose(r, in), checkPublicPort); pp.Status != statusNotTested {
			t.Errorf("%s: public port = %s/%s, want not tested", name, pp.Status, pp.Reason)
		}
		if dp := dataplaneCheck(in); dp.Status != statusOK {
			t.Errorf("%s: dataplane = %s %q, want ok", name, dp.Status, dp.Detail)
		}
	}
}

// 止まるルールは、カーネルで転送する公開中のルールだけを数える。公開していない(not_active の)
// カーネルのルールしか無ければ、ip_forward が 0 でも止まる転送は無いので FAILED にしない。
func TestIPForwardOffIgnoresUnpublishedRules(t *testing.T) {
	r := tcpRule()
	in := withIPForward(healthyInput(r), "0")
	in.Rules.RuleStates[r.ID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: "agent \"home\" is not registered"}
	if dp := dataplaneCheck(in); dp.Status == statusFailed {
		t.Errorf("dataplane = %s %q with no published kernel rule, want not failed", dp.Status, dp.Detail)
	}
	st := buildStatusReport(statusInput{Now: doctorNow, Rules: in.Rules, Agents: in.Agents})
	if strings.Contains(st.Server.Detail, "ip_forward") {
		t.Errorf("status server names ip_forward with no published kernel rule: %+v", st.Server)
	}
}

// 世代の遅れと ip_forward の 0 が重なれば、世代の遅れの FAILED を先に示し、所見に ip_forward を併せて
// 示す(設計文書 10.2a 節)。status の Server 行も両方を述べる。
func TestIPForwardOffAlongsideAGenerationGap(t *testing.T) {
	r := tcpRule()
	in := withIPForward(healthyInput(r), "0")
	in.Rules.ActiveGeneration = u64(9)
	dp := dataplaneCheck(in)
	if dp.Status != statusFailed || dp.Reason != reasonNotPublished {
		t.Fatalf("dataplane = %s/%s, want failed/%s", dp.Status, dp.Reason, reasonNotPublished)
	}
	if !strings.Contains(dp.Detail, "generation 9") || !strings.Contains(dp.Detail, "net.ipv4.ip_forward on this VPS is 0") {
		t.Errorf("dataplane detail does not name both: %q", dp.Detail)
	}
	st := buildStatusReport(statusInput{Now: doctorNow, Rules: in.Rules, Agents: in.Agents})
	if !strings.Contains(st.Server.Detail, "generation 9") || !strings.Contains(st.Server.Detail, "net.ipv4.ip_forward on this VPS is 0") {
		t.Errorf("status server detail does not name both: %q", st.Server.Detail)
	}
}
