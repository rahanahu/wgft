package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、server 自身が見た UDP の宛先の応答(管理用 API の udp_replies)を `rule.target` に
// 添える扱いを固定する(設計文書 10.2a 節「UDP の応答の観測」)。添えた観測は、どの組み合わせでも
// 検査の状態、理由、観測の時刻、ルールの総合判定、報告の状態、終了コードを動かさない。

// replyCases は観測の 4 通りである。nil は、観測を報告しない server(旧い版)である。
func replyCases(id string) map[string]map[string]admin.UDPReply {
	return map[string]map[string]admin.UDPReply{
		"no report":    nil,
		"recent reply": {id: {Since: at(3 * time.Hour), LastReplyAt: at(5 * time.Second)}},
		"old reply":    {id: {Since: at(3 * time.Hour), LastReplyAt: at(2 * time.Hour)}},
		"none seen":    {id: {Since: at(3 * time.Hour)}},
		"not observed": {id: {NotObserved: "reading the reply counters: permission denied"}},
	}
}

func TestUDPReplyNeverChangesTheVerdict(t *testing.T) {
	edits := map[string]func(r proto.Rule, in *doctorInput){
		"healthy": nil,
		"stale report": func(r proto.Rule, in *doctorInput) {
			st := in.Rules.AgentRuleStates[r.ID]
			st.At = at(targetReportStale + time.Second)
			in.Rules.AgentRuleStates[r.ID] = st
		},
		"agent disconnected": func(r proto.Rule, in *doctorInput) {
			st := in.Rules.AgentRuleStates[r.ID]
			st.Connected = false
			in.Rules.AgentRuleStates[r.ID] = st
		},
		"bind failure": func(r proto.Rule, in *doctorInput) {
			in.Rules.AgentRuleStates[r.ID] = admin.AgentRuleStatus{Agent: "home", State: proto.StatusError,
				Reason: "bind failed: address already in use", At: at(10 * time.Second), Connected: true}
		},
	}
	type verdict struct {
		Target, Reason, ObservedAt, Rule, Report string
		Exit                                     bool
	}
	r := udpRule()
	for name, edit := range edits {
		base := healthyInput(r)
		if edit != nil {
			edit(r, &base)
		}
		verdictOf := func(in doctorInput) verdict {
			rep := buildReport([]proto.Rule{r}, in)
			c := checkOf(t, rep.Checks, checkTarget)
			return verdict{c.Status, c.Reason, c.ObservedAt, rep.Rules[0].Status, rep.Status, doctorExit(rep) != nil}
		}
		want := verdictOf(base)
		for obsName, obs := range replyCases(r.ID) {
			in := healthyInput(r)
			if edit != nil {
				edit(r, &in)
			}
			in.Rules.UDPReplies = obs
			if got := verdictOf(in); got != want {
				t.Errorf("%s, %s: verdict %+v, want %+v as without the observation", name, obsName, got, want)
			}
		}
	}
}

// 観測は `--json` の `rule.target` の任意の項目になり、人向けの出力では detail の下の 1 行になる。
// 観測できないことは、未観測と別の文と項目で示す。
func TestUDPReplyFieldsAndLine(t *testing.T) {
	r := udpRule()
	cases := []struct {
		obs                             string
		lastReplyAt, since, notObserved string
		line                            string
	}{
		{"no report", "", "", "", ""},
		{"recent reply", at(5 * time.Second), at(3 * time.Hour), "", "last UDP reply seen by this server 5s ago"},
		{"none seen", "", at(3 * time.Hour), "", "no UDP reply seen since this server started watching the rule 3h0m0s ago"},
		{"not observed", "", "", "reading the reply counters: permission denied", "UDP replies are not observed: reading the reply counters: permission denied"},
	}
	for _, tc := range cases {
		t.Run(tc.obs, func(t *testing.T) {
			in := healthyInput(r)
			in.Rules.UDPReplies = replyCases(r.ID)[tc.obs]
			rep := buildReport([]proto.Rule{r}, in)

			b, err := json.Marshal(rep)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				Checks []map[string]any `json:"checks"`
			}
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatal(err)
			}
			for _, c := range got.Checks {
				fields := map[string]any{}
				for _, k := range []string{"last_reply_at", "reply_since", "reply_not_observed"} {
					if v, ok := c[k]; ok {
						fields[k] = v
					}
				}
				if c["id"] != "rule.target" {
					if len(fields) != 0 {
						t.Errorf("%s carries reply fields %v", c["id"], fields)
					}
					continue
				}
				want := map[string]any{}
				for k, v := range map[string]string{"last_reply_at": tc.lastReplyAt, "reply_since": tc.since, "reply_not_observed": tc.notObserved} {
					if v != "" {
						want[k] = v
					}
				}
				if !reflect.DeepEqual(fields, want) {
					t.Errorf("rule.target reply fields = %v, want %v", fields, want)
				}
				if _, ok := c["ReplyLine"]; ok {
					t.Error("the human line leaked into --json")
				}
			}

			var out strings.Builder
			writeRuleReport(&out, rep, false)
			text := strings.Join(strings.Fields(out.String()), " ")
			for _, line := range []string{"last UDP reply", "no UDP reply", "UDP replies are not observed"} {
				if (tc.line != "" && strings.HasPrefix(tc.line, line)) != strings.Contains(text, line) {
					t.Errorf("output mentions %q: %v, want only the line %q\n%s", line, strings.Contains(text, line), tc.line, out.String())
				}
			}
			if tc.line != "" && !strings.Contains(text, tc.line) {
				t.Errorf("output lacks %q:\n%s", tc.line, out.String())
			}
		})
	}
}

// TCP のルールは、仮に udp_replies に同じ ID があっても観測を添えない。
func TestUDPReplyNotOnTCPRules(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	in.Rules.UDPReplies = map[string]admin.UDPReply{r.ID: {Since: at(time.Hour), LastReplyAt: at(time.Second)}}
	c := checkOf(t, buildReport([]proto.Rule{r}, in).Checks, checkTarget)
	if c.LastReplyAt != "" || c.ReplySince != "" || c.ReplyLine != "" {
		t.Errorf("a TCP rule's target carries a reply observation: %+v", c)
	}
}
