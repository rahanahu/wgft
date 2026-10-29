package main

import (
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、この VPS の他のテーブルの forward が wgft の転送を accept しない場合の診断
// (設計文書 6.1、10.2a 節)を確かめる。Docker が ip_forward を自分で 1 にしたホストでは iptables の
// FORWARD が policy drop になり、カーネルモードの転送は何も運ばないのに、server doctor は
// dataplane OK と失敗の無い報告を返していた。server check は同じ状態を警告していた。

var dockerDrop = admin.ForwardPolicyDrop{
	Where: "ip filter FORWARD",
	Suggest: []string{
		"iptables -I DOCKER-USER -o wgft0 -j ACCEPT",
		"iptables -I DOCKER-USER -i wgft0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
	},
}

func withForwardPolicy(in doctorInput, drops ...admin.ForwardPolicyDrop) doctorInput {
	in.Rules.ForwardPolicy = &admin.ForwardPolicyStatus{Drops: drops}
	return in
}

// 規則の形からの推定なので UNKNOWN にとどめ、終了コードを動かさない。所見はチェーンを名指し、
// 次の一手は server check と同じ行を示す。
func TestForwardPolicyDropIsReported(t *testing.T) {
	r := tcpRule()
	in := withForwardPolicy(healthyInput(r), dockerDrop)
	pp := checkOf(t, diagnose(r, in), checkPublicPort)
	dp := dataplaneCheck(in)
	for name, c := range map[string]checkReport{"public port": pp, "dataplane": dp} {
		if c.Status != statusUnknown || c.Reason != doctor.ReasonForwardPolicyDrop {
			t.Fatalf("%s = %s/%s, want unknown/%s", name, c.Status, c.Reason, doctor.ReasonForwardPolicyDrop)
		}
		if !strings.HasPrefix(c.Detail, "ip filter FORWARD drops forwarded packets by default") {
			t.Errorf("%s detail does not start with the chain: %q", name, c.Detail)
		}
		for _, want := range dockerDrop.Suggest {
			if !strings.Contains(c.Next, want) {
				t.Errorf("%s next step lacks %q: %s", name, want, c.Next)
			}
		}
	}
	if !strings.Contains(dp.Detail, "1 published kernel-mode rule") {
		t.Errorf("dataplane detail does not count the rules: %q", dp.Detail)
	}
	rep := buildReport([]proto.Rule{r}, in)
	if rep.Status == statusFailed || rep.Rules[0].Status != statusUnknown {
		t.Errorf("report = %s, rule %s; want not failed and the rule unknown", rep.Status, rep.Rules[0].Status)
	}
	st := buildStatusReport(statusInput{Now: doctorNow, Rules: in.Rules, Agents: in.Agents})
	if st.Server.Status != serverHealthy {
		t.Errorf("status server = %+v, want healthy: the finding is not an observation", st.Server)
	}
}

// プロキシのルールは vpsd が受けて自分から wg0 へ接続し直すので、forward を通らない。
func TestForwardPolicyDropLeavesProxyRules(t *testing.T) {
	r := tcpRule()
	r.VPSMode = proto.ModeProxy
	in := healthyInput(r)
	in.Rules.Rules = []proto.Rule{r}
	in = withForwardPolicy(in, dockerDrop)
	if pp := checkOf(t, diagnose(r, in), checkPublicPort); pp.Status != statusNotTested {
		t.Errorf("a proxy rule's public port = %s/%s, want not tested", pp.Status, pp.Reason)
	}
	dp := dataplaneCheck(in)
	if dp.Status != statusOK || !strings.Contains(dp.Detail, "affects no rule now") {
		t.Errorf("dataplane = %s %q, want ok with a note", dp.Status, dp.Detail)
	}
}

// 落とすチェーンが無いとき、検査できなかったとき、報告の無い server では何も変えない。
func TestForwardPolicyClearOrUnknownChangesNothing(t *testing.T) {
	r := tcpRule()
	for name, in := range map[string]doctorInput{
		"clear":    withForwardPolicy(healthyInput(r)),
		"not read": healthyInput(r),
		"unreadable": func() doctorInput {
			in := healthyInput(r)
			in.Rules.ForwardPolicy = &admin.ForwardPolicyStatus{Error: "netlink receive: operation not permitted"}
			return in
		}(),
	} {
		if pp := checkOf(t, diagnose(r, in), checkPublicPort); pp.Status != statusNotTested {
			t.Errorf("%s: public port = %s/%s, want not tested", name, pp.Status, pp.Reason)
		}
		if dp := dataplaneCheck(in); dp.Status != statusOK || strings.Contains(dp.Detail, "forwarded packets") {
			t.Errorf("%s: dataplane = %s %q, want ok without a note", name, dp.Status, dp.Detail)
		}
	}
}

// 観測した転送の停止を先に示す。ip_forward の 0 が重なれば FAILED ip_forward_off のまま、所見に
// チェーンを添える。
func TestForwardPolicyDropAlongsideIPForwardOff(t *testing.T) {
	r := tcpRule()
	in := withIPForward(withForwardPolicy(healthyInput(r), dockerDrop), "0")
	pp := checkOf(t, diagnose(r, in), checkPublicPort)
	if pp.Status != statusFailed || pp.Reason != doctor.ReasonIPForwardOff {
		t.Errorf("public port = %s/%s, want failed/%s", pp.Status, pp.Reason, doctor.ReasonIPForwardOff)
	}
	dp := dataplaneCheck(in)
	if dp.Status != statusFailed || dp.Reason != doctor.ReasonIPForwardOff {
		t.Fatalf("dataplane = %s/%s, want failed/%s", dp.Status, dp.Reason, doctor.ReasonIPForwardOff)
	}
	if !strings.Contains(dp.Detail, "ip filter FORWARD drops") {
		t.Errorf("dataplane detail does not add the chain: %q", dp.Detail)
	}
}

// 世代の遅れと重なれば、世代の遅れの FAILED を先に示し、所見にチェーンを添える。
func TestForwardPolicyDropAlongsideAGenerationGap(t *testing.T) {
	r := tcpRule()
	in := withForwardPolicy(healthyInput(r), dockerDrop)
	in.Rules.ActiveGeneration = u64(9)
	dp := dataplaneCheck(in)
	if dp.Status != statusFailed || dp.Reason != reasonNotPublished {
		t.Fatalf("dataplane = %s/%s, want failed/%s", dp.Status, dp.Reason, reasonNotPublished)
	}
	if !strings.Contains(dp.Detail, "generation 9") || !strings.Contains(dp.Detail, "ip filter FORWARD drops") {
		t.Errorf("dataplane detail does not name both: %q", dp.Detail)
	}
}

// 修復の失敗の UNKNOWN と重なり、止まりうるルールが無ければ、後から加えるルールへの注意を添える。
func TestForwardPolicyIdleNoteWithARepairFailure(t *testing.T) {
	r := tcpRule()
	r.VPSMode = proto.ModeProxy
	in := healthyInput(r)
	in.Rules.Rules = []proto.Rule{r}
	in = withForwardPolicy(in, dockerDrop)
	in.Rules.ApplyError = "conntrack: operation not permitted"
	dp := dataplaneCheck(in)
	if dp.Status != statusUnknown || dp.Reason != doctor.ReasonRepairFailed || !strings.Contains(dp.Detail, "affects no rule now") {
		t.Errorf("dataplane = %s/%s %q, want unknown/%s with the idle note", dp.Status, dp.Reason, dp.Detail, doctor.ReasonRepairFailed)
	}
}

// 1 本のルールの結論の行は、証拠が古いとは言わず、他のテーブルの forward を名指す。
func TestForwardPolicyDropRuleResult(t *testing.T) {
	r := tcpRule()
	in := withForwardPolicy(healthyInput(r), dockerDrop)
	rep := buildReport([]proto.Rule{r}, in)
	note := rep.RuleResultNote(r.ID)
	if !strings.Contains(note, "another table's forward chain may drop this rule's traffic") {
		t.Errorf("result note = %q, want the forward chain named", note)
	}
}
