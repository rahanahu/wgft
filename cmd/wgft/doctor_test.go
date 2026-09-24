package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは `wgft server doctor` の判定(設計文書 10.2a 節)を、合成した管理用 API の
// 応答に対して確かめる。表の各行は、実際に見つかった障害 1 つに対応する。

// 判定は internal/vpsd/doctor にある(設計文書 10.2d 節)。この一連の試験は切り出しの前に
// `wgft server doctor` の判定を固定したものであり、切り出しが挙動を変えていないことを示すため、
// 本文を変えずにそのまま残してある。下の別名は、切り出しの前と同じ名前でその package を指す
// ためだけのものである。
const (
	checkEnabled       = doctor.CheckEnabled
	checkPublicPort    = doctor.CheckPublicPort
	checkSourceFilter  = doctor.CheckSourceFilter
	checkHandshake     = doctor.CheckHandshake
	checkConnection    = doctor.CheckConnection
	checkRulesReceived = doctor.CheckRulesReceived
	checkCredentials   = doctor.CheckCredentials
	checkTargetResolve = doctor.CheckTargetResolve
	checkTarget        = doctor.CheckTarget
	checkFlowBudget    = doctor.CheckFlowBudget
	checkProbe         = doctor.CheckProbe

	reasonRuleDisabled        = doctor.ReasonRuleDisabled
	reasonBindFailed          = doctor.ReasonBindFailed
	reasonNotPublished        = doctor.ReasonNotPublished
	reasonGenerationBehind    = doctor.ReasonGenerationBehind
	reasonAgentNotRegistered  = doctor.ReasonAgentNotRegistered
	reasonAgentDisconnected   = doctor.ReasonAgentDisconnected
	reasonNoRecentHandshake   = doctor.ReasonNoRecentHandshake
	reasonTunnelError         = doctor.ReasonTunnelError
	reasonDeniedByDenyList    = doctor.ReasonDeniedByDenyList
	reasonNotInAllowList      = doctor.ReasonNotInAllowList
	reasonTargetNotAllowed    = doctor.ReasonTargetNotAllowed
	reasonResolveFailed       = doctor.ReasonResolveFailed
	reasonConnectionRefused   = doctor.ReasonConnectionRefused
	reasonTargetUnreachable   = doctor.ReasonTargetUnreachable
	reasonAgentUnreachable    = doctor.ReasonAgentUnreachable
	reasonNotReported         = doctor.ReasonNotReported
	reasonStaleReport         = doctor.ReasonStaleReport
	reasonNoFrom              = doctor.ReasonNoFrom
	reasonNotReportedByServer = doctor.ReasonNotReportedByServer
	reasonUnknownValue        = doctor.ReasonUnknownValue
	reasonExternalNotTested   = doctor.ReasonExternalNotTested
	reasonResolvedByAgent     = doctor.ReasonResolvedByAgent

	targetReportStale = doctor.TargetReportStale
)

// checkOrder は経路の順である。判定と同じ並びを使う。
var checkOrder = doctor.CheckOrder()

func diagnose(r proto.Rule, in doctorInput) []checkReport { return doctor.Diagnose(r, in) }

func dataplaneCheck(in doctorInput) checkReport { return doctor.DataplaneCheck(in) }

func freshAgentRuleStatus(st admin.AgentRuleStatus, now time.Time) (admin.AgentRuleStatus, bool) {
	return doctor.FreshAgentRuleStatus(st, now)
}

var doctorNow = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

func at(d time.Duration) string { return doctorNow.Add(-d).Format(time.RFC3339) }

func u64(v uint64) *uint64 { return &v }

// tcpRule は診断の対象にする健全な TCP のルールである。
func tcpRule() proto.Rule {
	return proto.Rule{
		ID: "r_01M2R009AAAAAAAAAAAAAAAAA", Agent: "home", Proto: proto.TCP,
		ListenPort: proto.PortRange{Lo: 25565, Hi: 25565}, Target: "192.168.1.20:25565",
		VPSMode: proto.ModeKernel, Enabled: true,
		SourceAllow: []netip.Prefix{}, SourceDeny: []netip.Prefix{},
	}
}

func udpRule() proto.Rule {
	r := tcpRule()
	r.Proto, r.ListenPort, r.Target = proto.UDP, proto.PortRange{Lo: 2456, Hi: 2457}, "192.168.1.20:2456"
	return r
}

// healthyInput は、壊れた検査が 1 つも無い証拠一式である。各試験はこれを 1 点だけ崩す。
func healthyInput(r proto.Rule) doctorInput {
	return doctorInput{
		Now: doctorNow,
		Rules: &admin.BatchResponse{
			Generation:        12,
			Rules:             []proto.Rule{r},
			DesiredGeneration: u64(12),
			ActiveGeneration:  u64(12),
			RuleStates: map[string]admin.RuleApply{
				r.ID: {ApplyState: admin.ApplyActive, ActiveGeneration: u64(12)},
			},
			Drift:            &admin.Drift{},
			ResourceRefusals: map[string]map[string]uint64{},
			FlowBudget:       map[proto.Proto]admin.FlowBudget{proto.TCP: {InUse: 1, Limit: 2048}},
			AgentRuleStates: map[string]admin.AgentRuleStatus{
				r.ID: {Agent: "home", State: proto.StatusOK, At: at(10 * time.Second), Connected: true},
			},
		},
		Agents: []admin.AgentInfo{{
			Name: "home", Address: "10.200.0.2", Connected: true, StreamFrom: "203.0.113.9:51234",
			LastHeartbeat: at(10 * time.Second), Generation: 12,
			Tunnel:        admin.TunnelStatus{State: proto.StatusOK, LastHandshake: at(30 * time.Second)},
			LastHandshake: at(30 * time.Second),
		}},
		Probes: map[string]probeResult{},
	}
}

func checkOf(t *testing.T, checks []checkReport, id string) checkReport {
	t.Helper()
	for _, c := range checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %q in %s", id, dumpChecks(checks))
	return checkReport{}
}

func dumpChecks(checks []checkReport) string {
	var b strings.Builder
	for _, c := range checks {
		b.WriteString("\n  " + c.Status + " " + c.ID + " (" + c.Reason + "): " + c.Detail)
	}
	return b.String()
}

func firstFailed(checks []checkReport) string {
	for _, id := range checkOrder {
		for _, c := range checks {
			if c.ID == id && c.Status == statusFailed {
				return id
			}
		}
	}
	return ""
}

// TestDiagnose は、実際に見つかった障害ごとに、どの検査が最初に failed になるかを確かめる。
func TestDiagnose(t *testing.T) {
	tests := []struct {
		name string
		// mutate は健全な証拠を 1 点だけ崩す。
		mutate func(r *proto.Rule, in *doctorInput)
		// wantFailed は最初に failed になる検査の ID。空なら failed が無いこと。
		wantFailed string
		// wantReason はその検査の機械向けの理由の符号。
		wantReason string
		// wantDetail は、どれかの検査の detail に必ず含まれる文字列である。
		wantDetail string
		// wantNext は、その検査の next に必ず含まれる文字列である。
		wantNext string
	}{
		{
			name:   "healthy",
			mutate: func(*proto.Rule, *doctorInput) {},
		},
		{
			// 公開ポートを bind できなかったルール(ユーザー空間モードでエフェメラルポートと衝突)
			name: "listener could not bind the public port",
			mutate: func(r *proto.Rule, in *doctorInput) {
				in.Rules.RuleStates[r.ID] = admin.RuleApply{
					ApplyState: admin.ApplyNotActive,
					Reason:     "bind failed: listen tcp4 :39000: bind: address already in use",
				}
			},
			wantFailed: checkPublicPort, wantReason: reasonBindFailed,
			wantDetail: "bind failed",
			wantNext:   "ip_local_port_range",
		},
		{
			// 別のエージェントへ移され、移った先がまだ受け取っていないルール
			name: "rule moved to an agent whose rule set is behind",
			mutate: func(r *proto.Rule, in *doctorInput) {
				in.Agents[0].Generation = 11
				in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{Agent: "home", Connected: true}
			},
			wantFailed: checkRulesReceived, wantReason: reasonGenerationBehind,
			wantDetail: "still holds rule set 11 while this server serves 12",
			wantNext:   "moved to another agent",
		},
		{
			name: "tunnel without a recent handshake",
			mutate: func(r *proto.Rule, in *doctorInput) {
				in.Agents[0].LastHandshake = at(9 * time.Minute)
			},
			wantFailed: checkHandshake, wantReason: reasonNoRecentHandshake,
			wantDetail: "handshake 9m0s ago",
			wantNext:   "agent host",
		},
		{
			name: "target the agent cannot reach",
			mutate: func(r *proto.Rule, in *doctorInput) {
				in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{
					Agent: "home", State: proto.StatusError, Reason: "dial tcp 192.168.1.20:25565: connect: connection refused",
					At: at(10 * time.Second), Connected: true,
				}
			},
			wantFailed: checkTarget, wantReason: reasonConnectionRefused,
			wantDetail: "connection refused",
			wantNext:   "a service is listening on 192.168.1.20:25565",
		},
		{
			name: "target refused by the agent's allow list",
			mutate: func(r *proto.Rule, in *doctorInput) {
				in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{
					Agent: "home", State: proto.StatusError,
					Reason: "target 192.168.1.20:25565 is not in " + allowtargets.Env,
					At:     at(10 * time.Second), Connected: true,
				}
			},
			wantFailed: checkTarget, wantReason: reasonTargetNotAllowed,
			wantDetail: allowtargets.Env,
			wantNext:   "refuses this target itself",
		},
		{
			name: "client dropped by the deny list",
			mutate: func(r *proto.Rule, in *doctorInput) {
				r.SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
				in.From, in.HasFrom = netip.MustParseAddr("203.0.113.7"), true
			},
			wantFailed: checkSourceFilter, wantReason: reasonDeniedByDenyList,
			wantDetail: "the deny list drops 203.0.113.7",
			wantNext:   "rule deny rm",
		},
		{
			name: "client not covered by a non-empty allow list",
			mutate: func(r *proto.Rule, in *doctorInput) {
				r.SourceAllow = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
				in.From, in.HasFrom = netip.MustParseAddr("203.0.113.7"), true
			},
			wantFailed: checkSourceFilter, wantReason: reasonNotInAllowList,
			wantDetail: "none covers 203.0.113.7",
			wantNext:   "rule allow add",
		},
		{
			name: "publication that keeps failing while the active generation is behind",
			mutate: func(r *proto.Rule, in *doctorInput) {
				in.Rules.ActiveGeneration = u64(9)
				in.Rules.ApplyError = "nftables: no space left on device"
				in.Rules.RuleStates[r.ID] = admin.RuleApply{ApplyState: admin.ApplyPending, ActiveGeneration: u64(9)}
			},
			wantFailed: checkPublicPort, wantReason: reasonNotPublished,
			wantDetail: "has not yet published this port",
			wantNext:   "retries every 30s",
		},
		{
			name: "agent not registered at all",
			mutate: func(r *proto.Rule, in *doctorInput) {
				in.Agents = nil
			},
			wantFailed: checkConnection, wantReason: reasonAgentNotRegistered,
			wantDetail: "is registered, so this rule has nowhere to forward to",
			wantNext:   "join-string",
		},
		{
			name: "target resolution failure reaches the server only in the reason",
			mutate: func(r *proto.Rule, in *doctorInput) {
				r.Target = "nas.home.lan:25565"
				in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{
					Agent: "home", State: proto.StatusError,
					Reason: "lookup nas.home.lan: no such host", At: at(10 * time.Second), Connected: true,
				}
			},
			wantFailed: checkTargetResolve, wantReason: reasonResolveFailed,
			wantDetail: "could not resolve nas.home.lan",
			wantNext:   "name resolution on the agent host",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tcpRule()
			in := healthyInput(r)
			tt.mutate(&r, &in)
			in.Rules.Rules = []proto.Rule{r}
			checks := diagnose(r, in)

			if got := firstFailed(checks); got != tt.wantFailed {
				t.Errorf("first failed check = %q, want %q: %s", got, tt.wantFailed, dumpChecks(checks))
			}
			if tt.wantFailed == "" {
				return
			}
			c := checkOf(t, checks, tt.wantFailed)
			if c.Reason != tt.wantReason {
				t.Errorf("%s reason = %q, want %q", c.ID, c.Reason, tt.wantReason)
			}
			if !strings.Contains(c.Detail, tt.wantDetail) {
				t.Errorf("%s detail = %q, want it to hold %q", c.ID, c.Detail, tt.wantDetail)
			}
			if !strings.Contains(c.Next, tt.wantNext) {
				t.Errorf("%s next = %q, want it to hold %q", c.ID, c.Next, tt.wantNext)
			}
		})
	}
}

// TestGenerationBehindDetailDoesNotClaimThisRule は、`agent.rules_received` が FAILED の
// ときの detail が、エージェントとルール集合の世代の事実だけを述べ、この 1 本のルールが
// 届いていないとは述べないことを確かめる(v1.1、所有者の決定)。ルール集合の世代が変わる
// たびに、そのエージェントの有効なすべてのルールがこの検査を経由する。変わっていないルール
// も含まれるので、「このルールは届いていない」という言い方は届いているルールについて誤りに
// なる。
func TestGenerationBehindDetailDoesNotClaimThisRule(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	in.Agents[0].Generation = 11
	in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{Agent: "home", Connected: true}
	c := checkOf(t, diagnose(r, in), checkRulesReceived)

	if c.Status != statusFailed || c.Reason != reasonGenerationBehind {
		t.Fatalf("status/reason = %s/%s, want %s/%s", c.Status, c.Reason, statusFailed, reasonGenerationBehind)
	}
	if strings.Contains(c.Detail, "this rule has not reached it") || strings.Contains(c.Detail, "this rule") {
		t.Errorf("detail must not claim this particular rule has not arrived, got %q", c.Detail)
	}
	if !strings.Contains(c.Detail, "this agent still holds rule set 11") || !strings.Contains(c.Detail, "this server serves 12") {
		t.Errorf("detail must state the agent/rule-set level fact, got %q", c.Detail)
	}
}

// TestEveryFindingSaysWhatToDoNext は、この機能の成功条件を直に確かめる。次に見るものを
// 言わない所見は、この機能の失敗である(設計文書 10.2a 節)。
func TestEveryFindingSaysWhatToDoNext(t *testing.T) {
	cases := []func(r *proto.Rule, in *doctorInput){
		func(*proto.Rule, *doctorInput) {},
		func(r *proto.Rule, in *doctorInput) { r.Enabled = false },
		func(r *proto.Rule, in *doctorInput) { in.Agents = nil },
		func(r *proto.Rule, in *doctorInput) { in.Agents[0].Connected = false },
		func(r *proto.Rule, in *doctorInput) { in.Agents[0].LastHandshake = at(9 * time.Minute) },
		func(r *proto.Rule, in *doctorInput) { in.Agents[0].Generation = 3 },
		func(r *proto.Rule, in *doctorInput) {
			in.Rules.RuleStates[r.ID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: "bind failed: x"}
		},
		func(r *proto.Rule, in *doctorInput) {
			in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{Agent: "home", State: proto.StatusError, Reason: "x", At: at(time.Second), Connected: true}
		},
		func(r *proto.Rule, in *doctorInput) { in.Rules.RuleStates, in.Rules.AgentRuleStates = nil, nil },
		func(r *proto.Rule, in *doctorInput) {
			in.Agents[0].Warnings = []admin.Warning{{Agent: "home", Kind: "ip-flapping", At: at(time.Minute)}}
		},
		func(r *proto.Rule, in *doctorInput) {
			in.Rules.ResourceRefusals = map[string]map[string]uint64{r.ID: {"rule": 7}}
		},
	}
	for i, mutate := range cases {
		r := tcpRule()
		in := healthyInput(r)
		mutate(&r, &in)
		in.Rules.Rules = []proto.Rule{r}
		for _, c := range append(diagnose(r, in), dataplaneCheck(in)) {
			if c.Status == statusOK {
				continue
			}
			if strings.TrimSpace(c.Next) == "" {
				t.Errorf("case %d: check %q is %s with no next action; every finding must say what to look at next", i, c.ID, c.Status)
			}
		}
	}
}

// TestOKIsNeverPermanent は、ok の所見が必ず観測の古さを伴うことを確かめる(設計文書 10.2a 節)。
func TestOKIsNeverPermanent(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	checks := diagnose(r, in)
	for _, id := range []string{checkConnection, checkHandshake, checkTarget} {
		c := checkOf(t, checks, id)
		if c.Status != statusOK {
			t.Fatalf("%s: expected ok in the healthy case, got %s (%s)", id, c.Status, c.Detail)
		}
		if !strings.Contains(c.Detail, "ago") {
			t.Errorf("%s: an ok finding must carry how old the observation is, got %q", id, c.Detail)
		}
		if c.ObservedAt == "" {
			t.Errorf("%s: an ok finding must carry observed_at", id)
		}
	}
}

// TestEvidenceFallsToUnknownWhenStale は、項目ごとに選んだ古さの閾値を越えた証拠が ok から
// unknown へ落ちることを確かめる(設計文書 10.2a 節)。
func TestEvidenceFallsToUnknownWhenStale(t *testing.T) {
	t.Run("heartbeat past 90s", func(t *testing.T) {
		r := tcpRule()
		in := healthyInput(r)
		in.Agents[0].LastHeartbeat = at(2 * time.Minute)
		c := checkOf(t, diagnose(r, in), checkConnection)
		if c.Status != statusUnknown || c.Reason != reasonStaleReport {
			t.Errorf("status/reason = %s/%s, want %s/%s: %s", c.Status, c.Reason, statusUnknown, reasonStaleReport, c.Detail)
		}
	})
	t.Run("agent rule report past 90s", func(t *testing.T) {
		r := tcpRule()
		in := healthyInput(r)
		in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{
			Agent: "home", State: proto.StatusOK, At: at(2*time.Minute + 14*time.Second), Connected: true,
		}
		c := checkOf(t, diagnose(r, in), checkTarget)
		if c.Status != statusUnknown {
			t.Errorf("status = %s, want %s: %s", c.Status, statusUnknown, c.Detail)
		}
		if !strings.Contains(c.Detail, "2m14s ago") {
			t.Errorf("detail must carry the age of the last check, got %q", c.Detail)
		}
	})
	t.Run("a stale error report is not a current cause", func(t *testing.T) {
		r := tcpRule()
		in := healthyInput(r)
		in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{
			Agent: "home", State: proto.StatusError, Reason: "connection refused", At: at(10 * time.Minute), Connected: true,
		}
		c := checkOf(t, diagnose(r, in), checkTarget)
		if c.Status != statusUnknown {
			t.Errorf("status = %s, want %s: a report older than 90s must not be given as the current cause (%s)", c.Status, statusUnknown, c.Detail)
		}
	})
}

// TestFreshAgentRuleStatusBoundary は、targetReportStale(90 秒)ちょうどの境界を固定する
// (design.md 10.2b 節、レビューの指摘)。既存の試験は 5 秒(新しい)と 2 分すぎ(古い)しか
// 使っておらず、90 秒ちょうどを踏む例が無かったため、`age > targetReportStale` を
// `age >= targetReportStale` に変える変異が検出されずに残っていた。90 秒ちょうどはまだ
// fresh で、90 秒 + 1 秒からは古いという境界そのものを、2 つの値で確かめる。
func TestFreshAgentRuleStatusBoundary(t *testing.T) {
	st := admin.AgentRuleStatus{State: proto.StatusOK, Connected: true, At: at(targetReportStale)}
	if _, fresh := freshAgentRuleStatus(st, doctorNow); !fresh {
		t.Error("a report exactly targetReportStale old must still be fresh")
	}
	stOld := admin.AgentRuleStatus{State: proto.StatusOK, Connected: true, At: at(targetReportStale + time.Second)}
	if _, fresh := freshAgentRuleStatus(stOld, doctorNow); fresh {
		t.Error("a report one second past targetReportStale must be stale")
	}
}

// TestPublicPortIsNeverOK は、外からの到達性を試していない以上、公開ポートを ok にしないことを
// 確かめる(設計文書 10.2a 節の状態の定義)。
func TestPublicPortIsNeverOK(t *testing.T) {
	r := tcpRule()
	c := checkOf(t, diagnose(r, healthyInput(r)), checkPublicPort)
	if c.Status != statusNotTested || c.Reason != reasonExternalNotTested {
		t.Errorf("status/reason = %s/%s, want %s/%s", c.Status, c.Reason, statusNotTested, reasonExternalNotTested)
	}
	if !strings.Contains(c.Detail, "reachability from outside was not tested") {
		t.Errorf("detail must say the external side was not tested, got %q", c.Detail)
	}
	if !strings.Contains(c.Next, "nc -vz") {
		t.Errorf("next must tell the operator how to test it from outside, got %q", c.Next)
	}
}

// TestDiagnoseNeverContradictsItself は、検査どうしの優先順位(設計文書 10.2a 節)を確かめる。
// エージェントの stream が切れている間、そのエージェントが報告した値は履歴であり、今の原因として
// 示してはならない(5.2 節)。とくに、古い target の誤りを今の原因として出してはならない。
func TestDiagnoseNeverContradictsItself(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	in.Agents[0].Connected = false
	in.Agents[0].LastHeartbeat = at(20 * time.Minute)
	in.Agents[0].LastHandshake = at(20 * time.Minute)
	in.Agents[0].Tunnel = admin.TunnelStatus{State: proto.StatusError, Reason: "handshake not established"}
	in.Agents[0].Generation = 3
	in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{
		Agent: "home", State: proto.StatusError, Reason: "dial tcp 192.168.1.20:25565: connect: connection refused",
		At: at(20 * time.Minute), Connected: false,
	}
	checks := diagnose(r, in)

	for _, id := range []string{checkRulesReceived, checkTarget} {
		c := checkOf(t, checks, id)
		if c.Status != statusUnknown {
			t.Errorf("%s: status = %q, want %q while the agent is disconnected", id, c.Status, statusUnknown)
		}
		if c.Reason != reasonStaleReport {
			t.Errorf("%s: reason = %q, want %q", id, c.Reason, reasonStaleReport)
		}
		if !strings.HasPrefix(c.Detail, "last:") {
			t.Errorf("%s: detail must be marked as history with a \"last:\" prefix, got %q", id, c.Detail)
		}
	}
	// 止まった位置は、いちばん手前で観測した失敗でなければならない。
	if got := firstFailed(checks); got != checkHandshake {
		t.Errorf("first failed check = %q, want %q: the tunnel is the earliest observed failure", got, checkHandshake)
	}
}

// TestStaleTunnelReportIsNotCurrent は、stream が切れていてもハンドシェイクが新しい場合に、
// トンネルの判定を server 自身が読んだハンドシェイクから行い、エージェントの報告を履歴として
// 添えることを確かめる。
func TestStaleTunnelReportIsNotCurrent(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	in.Agents[0].Connected = false
	in.Agents[0].LastHeartbeat = at(5 * time.Minute)
	in.Agents[0].LastHandshake = at(20 * time.Second)
	in.Agents[0].Tunnel = admin.TunnelStatus{State: proto.StatusOK}
	checks := diagnose(r, in)

	tun := checkOf(t, checks, checkHandshake)
	if tun.Status != statusOK {
		t.Errorf("WireGuard status = %q, want %q: the handshake this VPS reads itself is current", tun.Status, statusOK)
	}
	if !strings.Contains(tun.Detail, "last:") {
		t.Errorf("the agent's own tunnel report must be marked as history, got %q", tun.Detail)
	}
	conn := checkOf(t, checks, checkConnection)
	if len(conn.Causes) == 0 {
		t.Error("a finding this evidence cannot attribute must name the causes it cannot separate")
	}
}

// TestUnattributableFindingsNameTheirCauses は、VPS の側から 1 つに絞れない所見が、原因を
// 並べて示すことを確かめる(設計文書 10.2a 節)。
func TestUnattributableFindingsNameTheirCauses(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	in.Agents[0].LastHandshake = at(9 * time.Minute)
	c := checkOf(t, diagnose(r, in), checkHandshake)
	if len(c.Causes) < 4 {
		t.Errorf("no recent handshake has at least four causes this side cannot separate, got %v", c.Causes)
	}
	for _, want := range []string{"WireGuard UDP port", "home firewall", "agent is not running", "between"} {
		found := false
		for _, cause := range c.Causes {
			if strings.Contains(cause, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("the causes must name %q, got %v", want, c.Causes)
		}
	}
}

// TestHandshakeTunnelErrorWhileConnected は、tunnel.handshake の判定(tunnelHealth、
// design.md 10.2a 節)を固定する。制御ストリームが繋がっていて最終ハンドシェイクも新しいが、
// エージェント自身がトンネルを error と報告している場合は failed かつ reasonTunnelError に
// なる。この分岐は、`wgft status` の Agents 行(status.go の agentHealthOf、design.md
// 10.2b 節、2026-09-22 の所有者の決定)が tunnelHealth を共有する前提になるので、doctor 側の
// 挙動として固定しておく。
func TestHandshakeTunnelErrorWhileConnected(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	in.Agents[0].Tunnel = admin.TunnelStatus{State: proto.StatusError, Reason: "handshake not established"}
	c := checkOf(t, diagnose(r, in), checkHandshake)
	if c.Status != statusFailed || c.Reason != reasonTunnelError {
		t.Errorf("status/reason = %s/%s, want %s/%s: %s", c.Status, c.Reason, statusFailed, reasonTunnelError, c.Detail)
	}
	if !strings.Contains(c.Detail, "handshake not established") {
		t.Errorf("detail must carry the agent's own reason, got %q", c.Detail)
	}
}

// TestHandshakeUnknownTunnelStateWhileConnected は、tunnelHealth の unknown 側の分岐を固定
// する。制御ストリームが繋がっていて最終ハンドシェイクも新しいが、エージェントがこの版の知らない
// トンネルの状態を報告している場合は unknown かつ reasonUnknownValue になり、故障とは決めつけ
// ない(7a.11 節の開いた集合の約束)。
func TestHandshakeUnknownTunnelStateWhileConnected(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	in.Agents[0].Tunnel = admin.TunnelStatus{State: "handshaking"}
	c := checkOf(t, diagnose(r, in), checkHandshake)
	if c.Status != statusUnknown || c.Reason != reasonUnknownValue {
		t.Errorf("status/reason = %s/%s, want %s/%s: %s", c.Status, c.Reason, statusUnknown, reasonUnknownValue, c.Detail)
	}
}

// TestDisabledRuleIsSkippedNotFailed は、無効なルールが宣言どおりの状態であり、監視を鳴らさない
// ことを確かめる(設計文書 10.2a 節)。
func TestDisabledRuleIsSkippedNotFailed(t *testing.T) {
	r := tcpRule()
	r.Enabled = false
	in := healthyInput(r)
	in.Rules.Rules = []proto.Rule{r}
	checks := diagnose(r, in)
	for _, c := range checks {
		if c.Status != statusSkipped {
			t.Errorf("check %q is %s; a disabled rule makes every check skipped", c.ID, c.Status)
		}
		if c.Reason != reasonRuleDisabled {
			t.Errorf("check %q reason = %q, want %q", c.ID, c.Reason, reasonRuleDisabled)
		}
	}
	rep := buildReport([]proto.Rule{r}, in)
	if rep.Status == statusFailed {
		t.Error("a disabled rule must not make the whole report failed")
	}
	if err := doctorExit(rep); err != nil {
		t.Errorf("a disabled rule must not make the command exit non-zero, got %v", err)
	}
}

// TestUDPCannotBeTestedEndToEnd は、UDP のルールで能動的な確認ができないことを、doctor が
// 黙らずに示すことを確かめる(設計文書 10.1、10.2a 節)。
func TestUDPCannotBeTestedEndToEnd(t *testing.T) {
	r := udpRule()
	in := healthyInput(r)
	in.Probed = true
	in.Probes[r.ID] = probeResult{Err: errString("connectivity check is for TCP rules only; a UDP send cannot tell success")}
	checks := diagnose(r, in)

	p := checkOf(t, checks, checkProbe)
	if p.Status != statusNotTested {
		t.Errorf("probe status = %q, want %q for a UDP rule", p.Status, statusNotTested)
	}
	if !strings.Contains(p.Detail, "cannot be dialled end to end") {
		t.Errorf("probe detail must say a UDP rule cannot be dialled, got %q", p.Detail)
	}
	if got := firstFailed(checks); got != "" {
		t.Errorf("a UDP rule must not be called broken just because it cannot be probed, got %q", got)
	}
	tg := checkOf(t, checks, checkTarget)
	if !strings.Contains(tg.Detail, "a UDP send cannot tell whether the target received it or answered") {
		t.Errorf("a UDP rule's target line must say what it does not cover, got %q", tg.Detail)
	}
}

// TestUDPTargetIsNotTested は、`rule.target` の判定を、ルールの proto とエージェントの報告の
// 組ごとに固定する(設計文書 10.2a 節、2026-09-24 の改訂の記録)。UDP のルールの新しい ok の報告は
// リスナーを開けたことしか示さないので、OK ではなく NOT TESTED(理由 udp_listener_only)にする。
// TCP のルールの新しい ok は宛先への接続を観測しているので OK のままである。古い報告の UNKNOWN と、
// error の報告の FAILED は、UDP でも TCP と同じである。
func TestUDPTargetIsNotTested(t *testing.T) {
	cases := []struct {
		name       string
		rule       proto.Rule
		edit       func(r proto.Rule, in *doctorInput)
		wantStatus string
		wantReason string
		wantRule   string
	}{
		{"healthy UDP rule", udpRule(), nil, statusNotTested, doctor.ReasonUDPListenerOnly, statusOK},
		{"healthy TCP rule", tcpRule(), nil, statusOK, "", statusOK},
		{"UDP rule with a stale ok report", udpRule(), func(r proto.Rule, in *doctorInput) {
			st := in.Rules.AgentRuleStates[r.ID]
			st.At = at(targetReportStale + time.Second)
			in.Rules.AgentRuleStates[r.ID] = st
		}, statusUnknown, reasonStaleReport, statusUnknown},
		{"UDP rule whose agent is disconnected", udpRule(), func(r proto.Rule, in *doctorInput) {
			st := in.Rules.AgentRuleStates[r.ID]
			st.Connected = false
			in.Rules.AgentRuleStates[r.ID] = st
		}, statusUnknown, reasonStaleReport, statusUnknown},
		{"UDP rule whose agent reports an error", udpRule(), func(r proto.Rule, in *doctorInput) {
			in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{Agent: "home", State: proto.StatusError,
				Reason: "bind failed: address already in use", At: at(10 * time.Second), Connected: true}
		}, statusFailed, doctor.ReasonListenerBindFailed, statusFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := healthyInput(tc.rule)
			if tc.edit != nil {
				tc.edit(tc.rule, &in)
			}
			rep := buildReport([]proto.Rule{tc.rule}, in)
			c := checkOf(t, rep.Checks, checkTarget)
			if c.Status != tc.wantStatus || c.Reason != tc.wantReason {
				t.Errorf("rule.target = %q/%q, want %q/%q: %s", c.Status, c.Reason, tc.wantStatus, tc.wantReason, c.Detail)
			}
			if c.ObservedAt != in.Rules.AgentRuleStates[tc.rule.ID].At {
				t.Errorf("observed_at = %q, want the agent's report time %q", c.ObservedAt, in.Rules.AgentRuleStates[tc.rule.ID].At)
			}
			if got := rep.Rules[0].Status; got != tc.wantRule {
				t.Errorf("the rule's status = %q, want %q", got, tc.wantRule)
			}
			// 終了コードを動かすのは FAILED だけである。NOT TESTED と UNKNOWN は 0 のままにする。
			err := doctorExit(rep)
			if wantFail := tc.wantStatus == statusFailed; (err != nil) != wantFail {
				t.Errorf("doctorExit = %v, want a failure: %v", err, wantFail)
			}
			if c.Status == statusNotTested && !strings.HasPrefix(c.Detail, "not tested: ") {
				t.Errorf("a NOT TESTED target line must say so first, got %q", c.Detail)
			}
		})
	}
}

// TestUDPEndToEndItemDoesNotContradictTheTargetLine は、試していない範囲の「udp end to end」の
// 項目が、`rule.target` が NOT TESTED 以外になる実行と食い違わないことを確かめる。エージェントが
// bind の失敗を報告している UDP のルールでは target の行は FAILED になり、報告が古ければ
// UNKNOWN になる。同じ出力の末尾の項目が、条件を付けずに「target の行は NOT TESTED になる」と
// 述べると、1 つの出力の中で矛盾する(設計文書 10.2a 節、2026-09-24 の改訂の記録)。
func TestUDPEndToEndItemDoesNotContradictTheTargetLine(t *testing.T) {
	cases := []struct {
		name     string
		edit     func(r proto.Rule, in *doctorInput)
		wantLine string
	}{
		{"agent reports a bind failure", func(r proto.Rule, in *doctorInput) {
			in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{Agent: "home", State: proto.StatusError,
				Reason: "bind failed: address already in use", At: at(10 * time.Second), Connected: true}
		}, "FAILED"},
		{"agent's report is stale", func(r proto.Rule, in *doctorInput) {
			st := in.Rules.AgentRuleStates[r.ID]
			st.At = at(targetReportStale + time.Second)
			in.Rules.AgentRuleStates[r.ID] = st
		}, "UNKNOWN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := udpRule()
			in := healthyInput(r)
			tc.edit(r, &in)
			var b strings.Builder
			writeRuleReport(&b, buildReport([]proto.Rule{r}, in), false)
			out := b.String()
			if !regexp.MustCompile(`(?m)^  target +` + tc.wantLine).MatchString(out) {
				t.Fatalf("precondition: the target line must read %s:\n%s", tc.wantLine, out)
			}
			i := strings.Index(out, "  udp end to end")
			if i < 0 {
				t.Fatalf("the report lists no udp end to end item:\n%s", out)
			}
			item := strings.Join(strings.Fields(out[i:]), " ")
			if j := strings.Index(item, " mtu "); j >= 0 {
				item = item[:j]
			}
			if strings.Contains(item, "so its target line reads NOT TESTED") {
				t.Errorf("the udp end to end item must not say unconditionally that the target reads NOT TESTED while the target line reads %s: %q", tc.wantLine, item)
			}
			if !strings.Contains(item, "while the agent reports its listener open, the target line reads NOT TESTED, never OK") {
				t.Errorf("the udp end to end item must put its NOT TESTED under the condition of an open listener, got %q", item)
			}
		})
	}
}

// TestUDPTargetJSON は、健全な UDP のルールの `rule.target` が `--json` で `"status":"not_tested"`
// と `"reason":"udp_listener_only"` になることを、報告を JSON に直した値で固定する。
// `checks[].status` と `checks[].reason` は機械向けの保証なので(設計文書 7a.11 節)、値そのものを
// 文字列で確かめる。
func TestUDPTargetJSON(t *testing.T) {
	r := udpRule()
	rep := buildReport([]proto.Rule{r}, healthyInput(r))
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Status string `json:"status"`
		Checks []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "ok" {
		t.Errorf("status = %q, want ok", got.Status)
	}
	for _, c := range got.Checks {
		if c.ID == "rule.target" && (c.Status != "not_tested" || c.Reason != "udp_listener_only") {
			t.Errorf("rule.target = %q/%q, want not_tested/udp_listener_only", c.Status, c.Reason)
		}
	}
}

// TestProbeCheckNextForAnUnprobedRule は、`rule.probe` の次の一手を、疎通確認をまだ試していない
// 実行について固定する。TCP のルールは `--probe` を勧め、UDP のルールは勧めない。管理用 API は
// UDP のルールの確認そのものを拒むので、`--probe` を付けても意味が無い。UDP のルールの次の一手
// は、確認をした後で管理用 API が拒んだときと同じ文にする(設計文書 10.2a 節の改訂の記録、
// 2026-09-23)。
func TestProbeCheckNextForAnUnprobedRule(t *testing.T) {
	tr := tcpRule()
	tc := checkOf(t, diagnose(tr, healthyInput(tr)), checkProbe)
	if !strings.Contains(tc.Next, "--probe") {
		t.Errorf("an unprobed TCP rule must still suggest --probe, got %q", tc.Next)
	}

	ur := udpRule()
	uc := checkOf(t, diagnose(ur, healthyInput(ur)), checkProbe)
	if strings.Contains(uc.Next, "--probe") {
		t.Errorf("an unprobed UDP rule must not suggest --probe, got %q", uc.Next)
	}
	want := "judge a UDP rule from the target line above, and confirm the service from a real client"
	if uc.Next != want {
		t.Errorf("an unprobed UDP rule's next step = %q, want %q", uc.Next, want)
	}

	// 疎通確認を試して管理用 API に拒まれた実行と、同じ文になる。
	rin := healthyInput(ur)
	rin.Probed = true
	rin.Probes[ur.ID] = probeResult{Err: errString("connectivity check is for TCP rules only; a UDP send cannot tell success")}
	rc := checkOf(t, diagnose(ur, rin), checkProbe)
	if rc.Next != uc.Next {
		t.Errorf("a UDP rule's next step must read the same whether or not --probe was tried: unprobed %q, refused %q", uc.Next, rc.Next)
	}
}

// TestProbeResults は、疎通確認の 3 つの到達段階がそれぞれ正しい判定になることを確かめる。
func TestProbeResults(t *testing.T) {
	cases := []struct {
		reach      string
		wantStatus string
		wantReason string
		wantDetail string
	}{
		{"target", statusOK, "", "does not prove the service itself is healthy"},
		{"agent", statusFailed, reasonTargetUnreachable, "could not reach 192.168.1.20:25565"},
		{"none", statusFailed, reasonAgentUnreachable, "did not reach the agent's listener"},
		{"martian", statusUnknown, reasonUnknownValue, "this build does not know"},
	}
	for _, tc := range cases {
		t.Run(tc.reach, func(t *testing.T) {
			r := tcpRule()
			in := healthyInput(r)
			in.Probed = true
			in.Probes[r.ID] = probeResult{Check: &admin.ConnCheck{OK: tc.reach == "target", Reach: tc.reach, Detail: "detail"}}
			c := checkOf(t, diagnose(r, in), checkProbe)
			if c.Status != tc.wantStatus || c.Reason != tc.wantReason {
				t.Errorf("status/reason = %s/%s, want %s/%s", c.Status, c.Reason, tc.wantStatus, tc.wantReason)
			}
			if !strings.Contains(c.Detail, tc.wantDetail) {
				t.Errorf("detail = %q, want it to hold %q", c.Detail, tc.wantDetail)
			}
		})
	}
}

// TestBackendWithoutOptionalReports は、加算的な報告(rule_states、agent_rule_states、
// flow_budget)を持たない Backend に対して、doctor が健全と言わず unknown と言うことを
// 確かめる(設計文書 10.5 節。読み取れないものを正常な値に変えて見せてはならない)。
func TestBackendWithoutOptionalReports(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	in.Rules.RuleStates = nil
	in.Rules.AgentRuleStates = nil
	in.Rules.ResourceRefusals = nil
	in.Rules.FlowBudget = nil
	in.Rules.Drift = nil
	in.Rules.DesiredGeneration, in.Rules.ActiveGeneration = nil, nil
	checks := append(diagnose(r, in), dataplaneCheck(in))

	if got := firstFailed(checks); got != "" {
		t.Errorf("a backend without the optional reports must not be called broken, got %q: %s", got, dumpChecks(checks))
	}
	for _, id := range []string{checkPublicPort, checkTarget, checkFlowBudget, checkDataplane} {
		c := checkOf(t, checks, id)
		if c.Status != statusUnknown || c.Reason != reasonNotReportedByServer {
			t.Errorf("%s: status/reason = %s/%s, want %s/%s", id, c.Status, c.Reason, statusUnknown, reasonNotReportedByServer)
		}
	}
}

// TestReportAlwaysSaysWhatItDidNotTest は、何も壊れていない実行でも、試していない範囲と履歴の
// 不在が必ず出ることを確かめる(設計文書 10.2a 節)。沈黙は健全と読まれるためである。
func TestReportAlwaysSaysWhatItDidNotTest(t *testing.T) {
	r := tcpRule()
	rep := buildReport([]proto.Rule{r}, healthyInput(r))
	if rep.Status != statusOK {
		t.Fatalf("expected no failing check, got %s", dumpChecks(rep.Checks))
	}
	want := []string{"from outside", "udp end to end", "mtu", "under load", "the service", "one-way tunnel", "the agent host", "inner path"}
	got := map[string]string{}
	for _, n := range rep.NotTested {
		got[n.ID] = n.Detail
	}
	for _, id := range want {
		if got[id] == "" {
			t.Errorf("the report must always name %q as not tested; got %v", id, got)
		}
	}
	if !strings.Contains(got["from outside"], "DNAT applies to input from outside") {
		t.Errorf("the outside entry must say why the server cannot test its own public port: %q", got["from outside"])
	}
	if !strings.Contains(got["from outside"], "tcp 25565") {
		t.Errorf("the outside entry must name the port to test from outside: %q", got["from outside"])
	}
	if rep.History.Available {
		t.Error("this version stores no history, so history.available must be false")
	}
	// 人向けの出力にも必ず出る。
	for _, render := range []func(*strings.Builder){
		func(b *strings.Builder) { writeRuleReport(b, rep, false) },
		func(b *strings.Builder) { writeSurvey(b, rep, false) },
	} {
		var b strings.Builder
		render(&b)
		for _, want := range []string{"Not tested by this command", "NOT AVAILABLE"} {
			if !strings.Contains(b.String(), want) {
				t.Errorf("the human output must always print %q:\n%s", want, b.String())
			}
		}
	}
	// --probe を付けた実行では inner path の項目が消える。
	in := healthyInput(r)
	in.Probed = true
	in.Probes[r.ID] = probeResult{Check: &admin.ConnCheck{OK: true, Reach: "target", Detail: "ok"}}
	for _, n := range buildReport([]proto.Rule{r}, in).NotTested {
		if n.ID == "inner path" {
			t.Error("with --probe the inner path is dialled, so it must not be listed as not tested")
		}
	}
}

// udpRule2 は udpRule とは別の ID を持つ、もう 1 本の UDP のルールである。複数ルールの診断で
// 使う。
func udpRule2() proto.Rule {
	r := udpRule()
	r.ID, r.ListenPort, r.Target = "r_01M2R009BBBBBBBBBBBBBBBBB", proto.PortRange{Lo: 2458, Hi: 2459}, "192.168.1.21:2458"
	return r
}

// tcpRuleWithID は tcpRule の変種で、複数ルールの診断で ID が重ならないようにする。
func tcpRuleWithID(id string) proto.Rule {
	r := tcpRule()
	r.ID = id
	return r
}

// hasInnerPath は、報告の試していない範囲に inner path の項目があるかどうかを返す。
func hasInnerPath(rep doctorReport) bool {
	for _, n := range rep.NotTested {
		if n.ID == "inner path" {
			return true
		}
	}
	return false
}

// TestInnerPathDropsOnlyWhenEveryDiagnosedRuleIsUDP は、inner path の項目が消える条件を固定
// する。`--probe` は 1 本のルールにしか付けられないので、`wgft server doctor`(引数無し)や
// `/ui/doctor` は複数のルールを一度に診断できる。診断の対象がすべて UDP のルールであるとき
// だけ、この項目を要らなくする。管理用 API は UDP のルールの確認そのものを拒むため、混じって
// いる TCP のルールには `--probe` が今も意味を持つ(設計文書 10.2a 節の改訂の記録、
// 2026-09-23)。
func TestInnerPathDropsOnlyWhenEveryDiagnosedRuleIsUDP(t *testing.T) {
	t.Run("a single UDP rule drops it", func(t *testing.T) {
		ur := udpRule()
		if hasInnerPath(buildReport([]proto.Rule{ur}, healthyInput(ur))) {
			t.Error("diagnosing a single UDP rule must not list inner path as not tested; --probe cannot help there")
		}
	})
	t.Run("all UDP rules together drop it", func(t *testing.T) {
		ur1, ur2 := udpRule(), udpRule2()
		in := healthyInput(ur1)
		in.Rules.Rules = []proto.Rule{ur1, ur2}
		if hasInnerPath(buildReport([]proto.Rule{ur1, ur2}, in)) {
			t.Error("diagnosing only UDP rules must not list inner path as not tested; --probe cannot help any of them")
		}
	})
	t.Run("a TCP rule mixed in keeps it", func(t *testing.T) {
		tr, ur := tcpRule(), udpRule2()
		in := healthyInput(tr)
		in.Rules.Rules = []proto.Rule{tr, ur}
		if !hasInnerPath(buildReport([]proto.Rule{tr, ur}, in)) {
			t.Error("a TCP rule in the mix can still be probed, so inner path must stay listed")
		}
	})
	t.Run("a TCP rule mixed in, UDP first, still keeps it", func(t *testing.T) {
		ur, tr := udpRule(), tcpRuleWithID("r_01M2R009CCCCCCCCCCCCCCCCC")
		in := healthyInput(ur)
		in.Rules.Rules = []proto.Rule{ur, tr}
		if !hasInnerPath(buildReport([]proto.Rule{ur, tr}, in)) {
			t.Error("inner path must not key off rules[0] alone: a UDP rule first must not hide the entry when a TCP rule follows")
		}
	})
}

// TestReportJSONShape は、機械向けの模型(設計文書 10.2a 節。--json だけが保証の対象)の骨格を固定する。
func TestReportJSONShape(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	in.Agents[0].LastHandshake = at(9 * time.Minute)
	b, err := json.Marshal(buildReport([]proto.Rule{r}, in))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"status", "checked_at", "probed", "checks", "rules", "history", "not_tested"} {
		if _, ok := got[k]; !ok {
			t.Errorf("the report must hold %q; got %v", k, got)
		}
	}
	if got["status"] != statusFailed {
		t.Errorf("status = %v, want %q", got["status"], statusFailed)
	}
	checks, _ := got["checks"].([]any)
	if len(checks) != len(checkOrder) {
		t.Errorf("one check per id (%d), got %d", len(checkOrder), len(checks))
	}
	seen := map[string]bool{}
	for _, raw := range checks {
		c, _ := raw.(map[string]any)
		for _, k := range []string{"id", "status", "group", "label", "detail"} {
			if _, ok := c[k]; !ok {
				t.Errorf("check %v must hold %q", c["id"], k)
			}
		}
		id, _ := c["id"].(string)
		seen[id] = true
		if c["status"] == statusOK {
			if _, ok := c["reason"]; ok {
				t.Errorf("an ok check must omit reason: %v", c)
			}
		}
	}
	for _, id := range checkOrder {
		if !seen[id] {
			t.Errorf("v1 defines check %q, which is missing from the report", id)
		}
	}
	rules, _ := got["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("rules = %v, want one entry", got["rules"])
	}
	rule, _ := rules[0].(map[string]any)
	for _, k := range []string{"rule_id", "agent", "proto", "listen_port", "target", "enabled", "status", "stopped_at"} {
		if _, ok := rule[k]; !ok {
			t.Errorf("a rule must hold %q; got %v", k, rule)
		}
	}
	if rule["stopped_at"] != checkHandshake {
		t.Errorf("stopped_at = %v, want %q", rule["stopped_at"], checkHandshake)
	}
}

// TestDoctorExit は、終了コードの決め方(設計文書 10.2a 節)を確かめる。unknown と not_tested
// だけの実行は 0 で終わり、failed のある実行だけが誤りを返す。
func TestDoctorExit(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	in.Rules.ResourceRefusals = map[string]map[string]uint64{r.ID: {"rule": 7}}
	if err := doctorExit(buildReport([]proto.Rule{r}, in)); err != nil {
		t.Errorf("unknown and not_tested alone must exit 0, got %v", err)
	}
	in = healthyInput(r)
	in.Agents[0].LastHandshake = at(9 * time.Minute)
	err := doctorExit(buildReport([]proto.Rule{r}, in))
	if err == nil {
		t.Fatal("a failed check must make the command exit non-zero")
	}
	if !strings.Contains(err.Error(), checkHandshake) {
		t.Errorf("the error must name where traffic stops, got %q", err)
	}
	if code := exitCode(err); code != 1 {
		t.Errorf("a failed check exits 1, got %d", code)
	}
	if code := exitCode(unavailable(errString("admin api did not answer"))); code != exitUnavailable {
		t.Errorf("a report that could not be produced exits %d, got %d", exitUnavailable, code)
	}
}

// TestSourceFilterWithoutFrom は、--from を渡さない実行が、接続元の判定を「試していない」と
// 言い、通ると言わないことを確かめる。
func TestSourceFilterWithoutFrom(t *testing.T) {
	r := tcpRule()
	r.SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	in := healthyInput(r)
	c := checkOf(t, diagnose(r, in), checkSourceFilter)
	if c.Status != statusNotTested || c.Reason != reasonNoFrom {
		t.Errorf("status/reason = %s/%s, want %s/%s", c.Status, c.Reason, statusNotTested, reasonNoFrom)
	}
	if !strings.Contains(c.Next, "--from") {
		t.Errorf("next must say how to evaluate it, got %q", c.Next)
	}
}

// errString は、管理用 API が確認そのものを拒んだ場合の誤りを作る。
type errString string

func (e errString) Error() string { return string(e) }

// TestHostnameTargetDoesNotMakeAHealthyRuleUnknown は、ホスト名の `target` を持つ健全な TCP の
// ルールが ok のままであることを確かめる(設計文書 10.2a 節)。TCP のルールの ok は、エージェントが
// その `target` への接続を開けたことを意味し(5.2 節)、名前への接続は解決を経るので、解決の成功
// そのものを観測している。かつては解決を常に unknown にしており、何も壊れていないルールが
// unknown に落ちていた。
func TestHostnameTargetDoesNotMakeAHealthyRuleUnknown(t *testing.T) {
	r := tcpRule()
	r.Target = "nas.home.lan:25565"
	in := healthyInput(r)
	in.Rules.Rules = []proto.Rule{r}
	rep := buildReport([]proto.Rule{r}, in)

	if rep.Rules[0].Status != statusOK {
		t.Errorf("rule status = %q, want %q: nothing about this rule is wrong%s", rep.Rules[0].Status, statusOK, dumpChecks(rep.Checks))
	}
	c := checkOf(t, rep.Checks, checkTargetResolve)
	if c.Status != statusOK {
		t.Errorf("target resolve = %q, want %q", c.Status, statusOK)
	}
	if c.ObservedAt == "" {
		t.Error("an ok resolve must carry the time of the agent report it is drawn from")
	}
	if !strings.Contains(c.Detail, "resolved nas.home.lan") || !strings.Contains(c.Detail, "ago") {
		t.Errorf("detail must say the name resolved and how old that is, got %q", c.Detail)
	}
}

// TestResolveWithoutEvidenceIsNotTested は、解決について証拠がまったく無い場合を not_tested に
// することを確かめる(設計文書 10.2a 節)。server はエージェントの解決を観測しないので、判定に
// 足りない古い証拠ではなく、そもそも試さない条件として扱う。unknown にするとルールの総合判定まで
// 下がってしまう。
func TestResolveWithoutEvidenceIsNotTested(t *testing.T) {
	cases := []struct {
		name  string
		build func() (proto.Rule, doctorInput)
	}{
		{"udp rule with a hostname target", func() (proto.Rule, doctorInput) {
			r := udpRule()
			r.Target = "nas.home.lan:2456"
			in := healthyInput(r)
			in.Rules.Rules = []proto.Rule{r}
			return r, in
		}},
		{"tcp rule whose report is stale", func() (proto.Rule, doctorInput) {
			r := tcpRule()
			r.Target = "nas.home.lan:25565"
			in := healthyInput(r)
			in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{
				Agent: "home", State: proto.StatusOK, At: at(10 * time.Minute), Connected: true,
			}
			in.Rules.Rules = []proto.Rule{r}
			return r, in
		}},
		{"tcp rule whose agent has not reported it", func() (proto.Rule, doctorInput) {
			r := tcpRule()
			r.Target = "nas.home.lan:25565"
			in := healthyInput(r)
			in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{Agent: "home", Connected: true}
			in.Rules.Rules = []proto.Rule{r}
			return r, in
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, in := tc.build()
			c := checkOf(t, diagnose(r, in), checkTargetResolve)
			if c.Status != statusNotTested || c.Reason != reasonResolvedByAgent {
				t.Errorf("status/reason = %s/%s, want %s/%s: %s", c.Status, c.Reason, statusNotTested, reasonResolvedByAgent, c.Detail)
			}
			if !strings.Contains(c.Next, "on the agent host") {
				t.Errorf("next must send the operator to the agent host, got %q", c.Next)
			}
		})
	}
}

// TestOffPathChecksDoNotMoveTheRuleStatus は、経路の外の検査(累積の拒否と窃取の警告)が
// ルールの総合判定を動かさないことを確かめる(設計文書 10.2a 節)。どちらも server の起動からの
// 事実であり、今転送しているかどうかを述べない。判定に混ぜると、一度の異常のあと server を
// 再起動するまで要約が下がり続ける。
func TestOffPathChecksDoNotMoveTheRuleStatus(t *testing.T) {
	cases := []struct {
		name   string
		id     string
		mutate func(r proto.Rule, in *doctorInput)
	}{
		{"resource refusals from an earlier flood", checkFlowBudget, func(r proto.Rule, in *doctorInput) {
			in.Rules.ResourceRefusals = map[string]map[string]uint64{r.ID: {"rule": 7}}
		}},
		{"an open credential warning", checkCredentials, func(r proto.Rule, in *doctorInput) {
			in.Agents[0].Warnings = []admin.Warning{{Agent: "home", Kind: "ip-flapping", At: at(time.Hour)}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tcpRule()
			in := healthyInput(r)
			tc.mutate(r, &in)
			in.Rules.Rules = []proto.Rule{r}
			rep := buildReport([]proto.Rule{r}, in)

			if rep.Rules[0].Status != statusOK {
				t.Errorf("rule status = %q, want %q: an off-path observation must not drag the summary down%s",
					rep.Rules[0].Status, statusOK, dumpChecks(rep.Checks))
			}
			if rep.Status != statusOK {
				t.Errorf("report status = %q, want %q", rep.Status, statusOK)
			}
			if err := doctorExit(rep); err != nil {
				t.Errorf("an off-path observation must not change the exit code, got %v", err)
			}
			// それでも所見そのものは出し続ける。
			c := checkOf(t, rep.Checks, tc.id)
			if c.Status != statusUnknown {
				t.Errorf("%s: status = %q, want %q: the observation itself is still reported", tc.id, c.Status, statusUnknown)
			}
			if c.Next == "" {
				t.Errorf("%s: an off-path finding still has to say what to do next", tc.id)
			}
		})
	}
}

// TestOffPathChecksAreExactlyTheDocumentedTwo は、経路の外と定めた検査が設計文書 10.2a 節の
// 一覧と一致することを確かめる。経路の上の検査を誤って外すと、転送が止まっていても要約が ok の
// ままになる。
func TestOffPathChecksAreExactlyTheDocumentedTwo(t *testing.T) {
	want := map[string]bool{checkCredentials: true, checkFlowBudget: true}
	r := tcpRule()
	for _, c := range diagnose(r, healthyInput(r)) {
		if c.OffPath() != want[c.ID] {
			t.Errorf("check %q: offPath = %v, want %v", c.ID, c.OffPath(), want[c.ID])
		}
		// 経路の外の検査は転送の停止を主張しないので、failed になってはならない。
		if c.OffPath() && c.Status == statusFailed {
			t.Errorf("check %q is off the path, so it must never report failed", c.ID)
		}
	}
}

// TestHandshakeOlderThanThresholdIsFailedNotStale は、最終ハンドシェイクの扱いを固定する
// (設計文書 10.2a 節)。`agent.connection` と `rule.target` はエージェントが過去に送った報告
// なので、古ければ「今どうなっているか分からない」を意味し unknown になる。`tunnel.handshake`
// は報告ではなく、server が WireGuard から今読む値である。「最終ハンドシェイクは 181 秒前」と
// いう値は、今この瞬間に読んだ現在の観測であり、トンネルが健全の条件を満たしていないことを
// 示す。古い証拠ではないので unknown ではなく failed にする。7 節の時定数がこれを裏づける。
// keepalive が 25 秒、`RekeyAfterTime` が 120 秒なので健全なトンネルの最終ハンドシェイクは
// 145 秒より古くならず、`RejectAfterTime` の 180 秒を過ぎた鍵は送信にも使えない。
func TestHandshakeOlderThanThresholdIsFailedNotStale(t *testing.T) {
	tests := []struct {
		name       string
		handshake  string
		wantStatus string
		wantReason string
	}{
		{"just inside the threshold", at(179 * time.Second), statusOK, ""},
		{"just past the threshold", at(181 * time.Second), statusFailed, reasonNoRecentHandshake},
		{"never handshook", "", statusFailed, reasonNoRecentHandshake},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tcpRule()
			in := healthyInput(r)
			in.Agents[0].LastHandshake = tt.handshake
			in.Rules.Rules = []proto.Rule{r}
			c := checkOf(t, diagnose(r, in), checkHandshake)
			if c.Status != tt.wantStatus || c.Reason != tt.wantReason {
				t.Errorf("status/reason = %s/%s, want %s/%s: %s", c.Status, c.Reason, tt.wantStatus, tt.wantReason, c.Detail)
			}
			if tt.wantStatus == statusFailed && c.Status == statusUnknown {
				t.Error("a handshake read now is a current observation, not stale evidence; it must not fall to unknown")
			}
		})
	}
}

// TestHandshakePastThresholdExitsNonZero は、上の判定が終了コードまで届くことを確かめる。
// unknown にすると warn と同じく 0 で終わってしまい、転送が止まっているトンネルを監視が
// 見逃す。
func TestHandshakePastThresholdExitsNonZero(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	in.Agents[0].LastHandshake = at(181 * time.Second)
	in.Rules.Rules = []proto.Rule{r}
	rep := buildReport([]proto.Rule{r}, in)

	if rep.Rules[0].StoppedAt != checkHandshake {
		t.Errorf("stopped_at = %q, want %q", rep.Rules[0].StoppedAt, checkHandshake)
	}
	err := doctorExit(rep)
	if err == nil {
		t.Fatal("a handshake past the threshold must make the command exit non-zero")
	}
	if code := exitCode(err); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// TestWrongArgumentCountExitsUnavailable は、引数の数の誤りが終了コード 2 になることを確かめる
// (設計文書 10.2a 節)。cobra の Args をそのまま渡すと、その誤りだけが包まれずに exitCode へ
// 届き、「壊れた検査があった」の 1 と見分けが付かなくなる。
func TestWrongArgumentCountExitsUnavailable(t *testing.T) {
	err := newServerDoctorCmd().Args(nil, []string{"one", "two"})
	if err == nil {
		t.Fatal("two arguments must be rejected")
	}
	var un *unavailableError
	if !errors.As(err, &un) {
		t.Errorf("the argument error must be an *unavailableError so it exits %d, got %T: %v", exitUnavailable, err, err)
	}
	if code := exitCode(err); code != exitUnavailable {
		t.Errorf("exit code = %d, want %d", code, exitUnavailable)
	}
	if err := newServerDoctorCmd().Args(nil, []string{"one"}); err != nil {
		t.Errorf("one argument is valid, got %v", err)
	}
	if err := newServerDoctorCmd().Args(nil, nil); err != nil {
		t.Errorf("no argument is valid, got %v", err)
	}
}

// TestUnknownFlagExitsUnavailable は、フラグの誤りも終了コード 2 になることを確かめる(設計文書
// 10.2a 節)。フラグの解析は Args の検査より前に行われるので、Args を包むだけでは届かない。
// 引数の数と同じ種類の誤りが、入口の違いだけで 1 と 2 に分かれることを防ぐ。
func TestUnknownFlagExitsUnavailable(t *testing.T) {
	cmd := newServerDoctorCmd()
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

// disconnectedButTunnelledInput は、制御の経路だけが切れていてトンネルは生きている状態である。
// 転送を続けているエージェントを server が切断と表示する、2026-09-21 に実測した区間に当たる。
func disconnectedButTunnelledInput(r proto.Rule) doctorInput {
	in := healthyInput(r)
	in.Agents[0].Connected = false
	in.Agents[0].LastHeartbeat = at(4 * time.Minute)
	in.Agents[0].LastHandshake = at(20 * time.Second)
	in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{
		Agent: "home", State: proto.StatusOK, At: at(4 * time.Minute), Connected: false,
	}
	in.Rules.Rules = []proto.Rule{r}
	return in
}

// TestDisconnectedAgentWithFreshHandshakeIsUnknownNotFailed は、`agent.connection` が測るものを
// 固定する(設計文書 10.2a 節)。この検査は制御の経路の健全さと、新しい設定を配れるかどうかを
// 測るのであって、転送が止まった位置を測るのではない。stream が切れていてトンネルが生きている
// 状態では、このルールが今も転送しているかどうかはこの証拠から決まらないので unknown にする。
// かつては failed にしており、ルールの止まった位置をここだと報告していた。
//
// 表(TestDiagnose)にあった「disconnected agent with a fresh handshake」の行は、failed を
// 前提にした形なので、意味を変えたこの試験へ移した。
func TestDisconnectedAgentWithFreshHandshakeIsUnknownNotFailed(t *testing.T) {
	r := tcpRule()
	in := disconnectedButTunnelledInput(r)
	checks := diagnose(r, in)

	c := checkOf(t, checks, checkConnection)
	if c.Status != statusUnknown {
		t.Errorf("status = %q, want %q: the stream being down does not locate where forwarding stopped", c.Status, statusUnknown)
	}
	if c.Reason != reasonAgentDisconnected {
		t.Errorf("reason = %q, want %q: the fact is certain, only its consequence for this rule is not", c.Reason, reasonAgentDisconnected)
	}
	// 所見は 2 つの半分を両方はっきり述べる。
	for _, want := range []string{"the control connection is down", "existing traffic can still flow", "rule changes will not arrive", "may still be forwarding"} {
		if !strings.Contains(c.Detail, want) {
			t.Errorf("detail must hold %q, got %q", want, c.Detail)
		}
	}
	if len(c.Causes) != 3 {
		t.Errorf("the causes this evidence cannot separate must be kept, got %v", c.Causes)
	}
	// 10.2a 節が「agent doctor ができた時点で案内し直す」と定めた箇所である。自宅側を見る
	// 必要がある所見は、ログの読み取りではなくそのコマンドを案内する(10.2c 節の「置き場所」)。
	if !strings.Contains(c.Next, "wgft agent doctor") {
		t.Errorf("the next step must send the operator to the agent host's own diagnosis, got %q", c.Next)
	}
	if got := firstFailed(checks); got != "" {
		t.Errorf("no check may be failed in this state, got %q: %s", got, dumpChecks(checks))
	}

	// ルールは ok にはならず unknown になる。本当に落ちているエージェントも要約から消えない。
	rep := buildReport([]proto.Rule{r}, in)
	if rep.Rules[0].Status != statusUnknown {
		t.Errorf("rule status = %q, want %q", rep.Rules[0].Status, statusUnknown)
	}
	if rep.Rules[0].StoppedAt != "" {
		t.Errorf("stopped_at = %q, want empty: nothing was observed to stop", rep.Rules[0].StoppedAt)
	}
	if err := doctorExit(rep); err != nil {
		t.Errorf("no failed check means exit 0, got %v", err)
	}
}

// TestProbeSucceedsWhileControlStreamIsDown は、二度と戻してはならない退行を固定する。疎通確認が
// トンネルとエージェントを通って target まで実際に届いたのに、`agent.connection` がそれを覆して
// 「転送はここで止まった」と報告していた。
func TestProbeSucceedsWhileControlStreamIsDown(t *testing.T) {
	r := tcpRule()
	in := disconnectedButTunnelledInput(r)
	in.Probed = true
	in.Probes[r.ID] = probeResult{Check: &admin.ConnCheck{OK: true, Reach: "target", Detail: "home service responded"}}
	rep := buildReport([]proto.Rule{r}, in)

	if rep.Rules[0].Status == statusFailed {
		t.Errorf("a rule whose probe reached the target must not be reported as stopped: %s", dumpChecks(rep.Checks))
	}
	if rep.Rules[0].StoppedAt != "" {
		t.Errorf("stopped_at = %q, want empty: a real connection reached the target", rep.Rules[0].StoppedAt)
	}
	if err := doctorExit(rep); err != nil {
		t.Errorf("doctorExit must return nil, got %v", err)
	}
	if p := checkOf(t, rep.Checks, checkProbe); p.Status != statusOK {
		t.Errorf("probe status = %q, want %q", p.Status, statusOK)
	}
}

// TestDisconnectedAgentStaysFailedWhenNothingElseExplainsIt は、unknown にしたのが 1 つの場合
// だけであることを確かめる。トンネルも死んでいれば `tunnel.handshake` が failed になり、経路の
// 順でそちらが先なのでルールはトンネルで止まる。エージェントがそもそも登録されていなければ、
// `tunnel.handshake` は skipped なので `agent.connection` が最初の失敗として正しい。
func TestDisconnectedAgentStaysFailedWhenNothingElseExplainsIt(t *testing.T) {
	t.Run("disconnected with a stale handshake stops at the tunnel", func(t *testing.T) {
		r := tcpRule()
		in := disconnectedButTunnelledInput(r)
		in.Agents[0].LastHandshake = at(20 * time.Minute)
		checks := diagnose(r, in)
		if c := checkOf(t, checks, checkConnection); c.Status != statusFailed || c.Reason != reasonAgentDisconnected {
			t.Errorf("agent.connection = %s/%s, want %s/%s", c.Status, c.Reason, statusFailed, reasonAgentDisconnected)
		}
		if got := firstFailed(checks); got != checkHandshake {
			t.Errorf("first failed check = %q, want %q", got, checkHandshake)
		}
	})
	t.Run("an unregistered agent stops at the connection", func(t *testing.T) {
		r := tcpRule()
		in := healthyInput(r)
		in.Agents = nil
		in.Rules.Rules = []proto.Rule{r}
		checks := diagnose(r, in)
		if c := checkOf(t, checks, checkHandshake); c.Status != statusSkipped {
			t.Errorf("tunnel.handshake = %q, want %q with no agent registered", c.Status, statusSkipped)
		}
		if got := firstFailed(checks); got != checkConnection {
			t.Errorf("first failed check = %q, want %q", got, checkConnection)
		}
		if c := checkOf(t, checks, checkConnection); c.Reason != reasonAgentNotRegistered {
			t.Errorf("reason = %q, want %q", c.Reason, reasonAgentNotRegistered)
		}
	})
}

// TestDisconnectedNextDoesNotSuggestAProbeAlreadyRun は、既に疎通確認を行った実行が
// 「--probe を付けよ」と言わないことを確かめる。今やったことを勧める行は雑音である。
func TestDisconnectedNextDoesNotSuggestAProbeAlreadyRun(t *testing.T) {
	r := tcpRule()
	in := disconnectedButTunnelledInput(r)
	if c := checkOf(t, diagnose(r, in), checkConnection); !strings.Contains(c.Next, "--probe") {
		t.Errorf("without a probe, the next step should offer one, got %q", c.Next)
	}
	in.Probed = true
	in.Probes[r.ID] = probeResult{Check: &admin.ConnCheck{OK: true, Reach: "target", Detail: "ok"}}
	if c := checkOf(t, diagnose(r, in), checkConnection); strings.Contains(c.Next, "--probe") {
		t.Errorf("after a probe has run, the next step must not suggest adding one, got %q", c.Next)
	}
}

// TestDisconnectedNextDoesNotSuggestAProbeForUDP は、同じ agent.connection の次の一手が、UDP の
// ルールには --probe を勧めないことを確かめる。管理用 API は UDP のルールの確認そのものを拒む
// ので、疎通確認を試したかどうかに関わらずこの案内は意味を持たない(設計文書 10.2a 節の改訂の
// 記録、2026-09-23)。代わりに、`rule.probe` の判定と同じ「target の行から判断し、実際の
// クライアントで確かめる」案内を繰り返すことも確かめる。2 つの文言を作らないためである。
func TestDisconnectedNextDoesNotSuggestAProbeForUDP(t *testing.T) {
	r := udpRule()
	in := disconnectedButTunnelledInput(r)
	c := checkOf(t, diagnose(r, in), checkConnection)
	if strings.Contains(c.Next, "--probe") {
		t.Errorf("a UDP rule's next step must not suggest --probe, got %q", c.Next)
	}
	want := "Judge a UDP rule from the target line above, and confirm the service from a real client."
	if !strings.Contains(c.Next, want) {
		t.Errorf("a UDP rule's next step must repeat rule.probe's own guidance, got %q, want it to hold %q", c.Next, want)
	}
}

// TestDegradedIsADisplayWordOnly は、画面の語と JSON の値が意図して食い違う 1 か所を固定する
// (設計文書 10.2a 節)。制御の経路が切れていてトンネルが生きている状態は、人には DEGRADED と
// 見せる。終了コードが 0 でも出力が黙らないためである。機械が読む値は unknown と
// `agent_disconnected` のままで、状態は 5 つから増やさない。
func TestDegradedIsADisplayWordOnly(t *testing.T) {
	r := tcpRule()
	in := disconnectedButTunnelledInput(r)
	rep := buildReport([]proto.Rule{r}, in)

	// 機械が読む側は変わらない。
	c := checkOf(t, rep.Checks, checkConnection)
	if c.Status != statusUnknown || c.Reason != reasonAgentDisconnected {
		t.Errorf("JSON status/reason = %s/%s, want %s/%s", c.Status, c.Reason, statusUnknown, reasonAgentDisconnected)
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "DEGRADED") {
		t.Error("DEGRADED is a word for a person; it must not appear in the machine-readable output")
	}

	// 人が読む側にだけ DEGRADED が出る。
	if got := displayStatus(c); got != "DEGRADED" {
		t.Errorf("displayStatus = %q, want %q", got, "DEGRADED")
	}
	var out strings.Builder
	writeRuleReport(&out, rep, false)
	line := lineHolding(t, out.String(), "control connection")
	if !strings.Contains(line, "DEGRADED") {
		t.Errorf("the rendered line must read DEGRADED, got %q", line)
	}
	if strings.Contains(line, "UNKNOWN") {
		t.Errorf("the rendered line must not also read UNKNOWN, got %q", line)
	}

	// 他の unknown は UNKNOWN のままである。この 1 つの条件だけに絞る。
	for _, id := range []string{checkRulesReceived, checkTarget} {
		if got := displayStatus(checkOf(t, rep.Checks, id)); got != "UNKNOWN" {
			t.Errorf("%s: displayStatus = %q, want %q: only agent.connection reads DEGRADED", id, got, "UNKNOWN")
		}
	}
	// 同じ検査でも、理由が違う unknown は UNKNOWN のままである。
	other := checkReport{ID: checkConnection, Status: statusUnknown, Reason: reasonNotReported}
	if got := displayStatus(other); got != "UNKNOWN" {
		t.Errorf("agent.connection unknown for another reason must stay %q, got %q", "UNKNOWN", got)
	}
}

// lineHolding は、出力の中で want を含む最初の行を返す。
func lineHolding(t *testing.T, out, want string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, want) {
			return l
		}
	}
	t.Fatalf("no line holding %q in:\n%s", want, out)
	return ""
}

// TestAgentLineIgnoresADisabledRuleListedFirst は、エージェントの行が無効なルールの検査から
// 作られないことを確かめる。無効なルールの agent.connection は rule_disabled の skipped で、
// エージェントの状態を述べない。そのルールが一覧の先にあっても、行は有効なルールの検査から
// 作る。Web UI の診断の画面も同じ関数を読むので、CLI と画面の行が食い違わない(設計文書
// 10.2a 節の改訂の記録、2026-09-23)。
func TestAgentLineIgnoresADisabledRuleListedFirst(t *testing.T) {
	off := tcpRule()
	off.ID, off.Enabled = "r_01M2R009DISABLEDAAAAAAAAA", false
	on := tcpRule()
	in := healthyInput(on)
	in.Rules.Rules = []proto.Rule{off, on}
	rep := buildReport([]proto.Rule{off, on}, in)

	lines := agentLines(rep)
	if len(lines) != 1 {
		t.Fatalf("agent lines = %d, want 1 for the one agent home", len(lines))
	}
	if lines[0].Status != statusOK || lines[0].Reason == "rule_disabled" {
		t.Errorf("home's line = %s/%s, want ok from the enabled rule", lines[0].Status, lines[0].Reason)
	}
	var b strings.Builder
	writeSurvey(&b, rep, false)
	agents := b.String()
	agents = agents[strings.Index(agents, "Agents"):strings.Index(agents, "\nRules")]
	if strings.Contains(agents, "SKIPPED") || strings.Contains(agents, "disabled") {
		t.Errorf("the Agents section speaks of the disabled rule instead of the agent:\n%s", agents)
	}
}
