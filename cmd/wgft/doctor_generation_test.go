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

// TestRulesReceivedGenerationLag は、`agent.rules_received` がルール集合の世代の遅れを、
// 遅れの始まり(管理用 API の generation_behind_since)からの長さで 2 つに分けることを確かめる
// (設計文書 10.2a 節、v1.1.1 の所有者の決定)。60 秒未満は届きかけとして UNKNOWN
// generation_pending、60 秒以上は止まった遅れとして FAILED generation_behind である。
// 始まりが無い応答は v1.1 のまま FAILED、切れているエージェントは stale_report のままである。
func TestRulesReceivedGenerationLag(t *testing.T) {
	// v1.1 の原因の候補と次の手順。始まりを返さない旧い server の場合はこのまま出す
	const v11Advice = "the new rules are in flight and will be applied in a moment\n" +
		"the agent is connected but is not applying them; see its log\n" +
		"re-run in a few seconds; if it stays behind, read the agent's log. A rule moved to another agent carries no traffic until that agent takes the new rule set."
	cases := []struct {
		name       string
		connected  bool
		noHB       bool   // この接続でまだハートビートが無い(LastHeartbeat を返さず、Generation は 0)
		since      string // generation_behind_since。空なら返さない
		wantStatus string
		wantReason string
		wantDetail string
		wantRule   string // ルールの総合判定
		wantExit   bool   // 終了コードが 0 以外になるか
	}{
		{
			name: "lag just started", connected: true, since: at(0),
			wantStatus: statusUnknown, wantReason: doctor.ReasonGenerationPending,
			wantDetail: "it has been behind for 0s", wantRule: statusUnknown,
		},
		{
			name: "lag of 59s", connected: true, since: at(59 * time.Second),
			wantStatus: statusUnknown, wantReason: doctor.ReasonGenerationPending,
			wantDetail: "it has been behind for 59s", wantRule: statusUnknown,
		},
		{
			name: "lag of exactly 60s", connected: true, since: at(60 * time.Second),
			wantStatus: statusFailed, wantReason: reasonGenerationBehind,
			wantDetail: "it has been behind for 1m0s without taking", wantRule: statusFailed, wantExit: true,
		},
		{
			name: "lag of 10m", connected: true, since: at(10 * time.Minute),
			wantStatus: statusFailed, wantReason: reasonGenerationBehind,
			wantDetail: "it has been behind for 10m0s", wantRule: statusFailed, wantExit: true,
		},
		{
			name: "server that does not report the lag start", connected: true, since: "",
			wantStatus: statusFailed, wantReason: reasonGenerationBehind,
			wantDetail: "it has not taken the latest rule set yet", wantRule: statusFailed, wantExit: true,
		},
		{
			name: "reconnected agent before its first heartbeat, no lag start", connected: true, noHB: true,
			wantStatus: statusUnknown, wantReason: doctor.ReasonNotReported,
			wantDetail: "has not sent a heartbeat yet", wantRule: statusUnknown,
		},
		{
			name: "reconnected agent before its first heartbeat, lag start from before the reconnect", connected: true, noHB: true,
			since:      at(10 * time.Minute),
			wantStatus: statusUnknown, wantReason: doctor.ReasonNotReported,
			wantDetail: "has not sent a heartbeat yet", wantRule: statusUnknown,
		},
		{
			name: "reconnected agent before its first heartbeat, recent lag start", connected: true, noHB: true,
			since:      at(3 * time.Second),
			wantStatus: statusUnknown, wantReason: doctor.ReasonNotReported,
			wantDetail: "has not sent a heartbeat yet", wantRule: statusUnknown,
		},
		{
			name: "disconnected agent keeps stale_report", connected: false, since: at(10 * time.Minute),
			wantStatus: statusUnknown, wantReason: reasonStaleReport,
			wantDetail: "last: it held rule set 11", wantRule: statusUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tcpRule()
			in := healthyInput(r)
			in.Agents[0].Generation = 11
			in.Agents[0].GenerationBehindSince = tc.since
			in.Agents[0].Connected = tc.connected
			in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{Agent: "home", Connected: tc.connected}
			if tc.noHB {
				// 再接続した直後の管理用 API の応答の形:hub が接続ごとに状態を作り直すので、
				// ハートビートの時刻を省き、世代は 0 である
				in.Agents[0].LastHeartbeat = ""
				in.Agents[0].Generation = 0
			}
			rep := buildReport([]proto.Rule{r}, in)
			c := checkOf(t, rep.Checks, checkRulesReceived)
			if tc.noHB {
				// 接続の検査と同じ判定になり、2 つの検査が食い違わない
				conn := checkOf(t, rep.Checks, checkConnection)
				if conn.Status != c.Status || conn.Reason != c.Reason {
					t.Errorf("%s = %s/%s but %s = %s/%s; they must agree before the first heartbeat",
						checkConnection, conn.Status, conn.Reason, checkRulesReceived, c.Status, c.Reason)
				}
			}
			if c.Status != tc.wantStatus || c.Reason != tc.wantReason {
				t.Fatalf("status/reason = %s/%s, want %s/%s: %s", c.Status, c.Reason, tc.wantStatus, tc.wantReason, c.Detail)
			}
			if !strings.Contains(c.Detail, tc.wantDetail) {
				t.Errorf("detail = %q, want it to contain %q", c.Detail, tc.wantDetail)
			}
			if strings.Contains(c.Detail, "this rule") {
				t.Errorf("detail must not claim this particular rule has not arrived, got %q", c.Detail)
			}
			if c.Next == "" {
				t.Errorf("every finding says what to do next; got none for %s/%s", c.Status, c.Reason)
			}
			// 60 秒以上の遅れは 10.2a 節の定めで届く途中ではないので、「すぐ届く」「数秒後に再実行」を
			// 言ってはならない。始まりを返さない旧い server の場合だけ v1.1 の文言を残す
			advice := strings.Join(append(append([]string{}, c.Causes...), c.Next), "\n")
			inFlight := strings.Contains(advice, "in flight") || strings.Contains(advice, "in a moment") ||
				strings.Contains(advice, "in a few seconds")
			switch {
			case tc.wantReason == reasonGenerationBehind && tc.since != "" && inFlight:
				t.Errorf("a lag of 60s or more must not be called in flight, got causes/next %q", advice)
			case tc.wantReason == reasonGenerationBehind && tc.since == "" && advice != v11Advice:
				t.Errorf("without the lag start the v1.1 wording stays:\ngot  %q\nwant %q", advice, v11Advice)
			}
			if got := rep.Rules[0].Status; got != tc.wantRule {
				t.Errorf("rule status = %s, want %s", got, tc.wantRule)
			}
			if err := doctorExit(rep); (err != nil) != tc.wantExit {
				t.Errorf("doctorExit = %v, want non-nil %v", err, tc.wantExit)
			}
		})
	}
}

// TestRulesReceivedPendingInJSON は、届きかけの遅れが --json に新しい理由の符号
// generation_pending と状態 unknown で現れることを確かめる。符号は 7a.11 節の開いた集合への
// 加算であり、既存の generation_behind の意味は変えない。
func TestRulesReceivedPendingInJSON(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	in.Agents[0].Generation = 11
	in.Agents[0].GenerationBehindSince = at(3 * time.Second)
	in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{Agent: "home", Connected: true}
	b, err := json.Marshal(buildReport([]proto.Rule{r}, in))
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
	if got.Status != statusOK {
		t.Errorf("report status = %q, want %q: a pending generation is not a failure", got.Status, statusOK)
	}
	for _, c := range got.Checks {
		if c.ID != checkRulesReceived {
			continue
		}
		if c.Status != "unknown" || c.Reason != "generation_pending" {
			t.Errorf("%s = %s/%s, want unknown/generation_pending", c.ID, c.Status, c.Reason)
		}
		return
	}
	t.Fatalf("no %s check in %s", checkRulesReceived, b)
}
