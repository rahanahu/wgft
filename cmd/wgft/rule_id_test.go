package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// このファイルは、ルールの ID の表示と受け取りの境界(設計文書 10.2 節)を確かめる。表の ID の列は
// 短い形でよいが、そのまま打つコマンドとして示す場所には完全な ID を使う。受け取る側は、表の短い形を
// 貼っても通るよう、末尾の省略記号を落として前方一致で受ける。

// 診断がそのまま打つコマンドとして示す次の一手は、完全な ID を持つ。短い形の "r_01M2R009AA…" を
// 打つと、以前は not found で拒まれた。
func TestDoctorNextStepsCarryTheFullRuleID(t *testing.T) {
	r := tcpRule()
	r.Enabled = false
	for _, c := range diagnose(r, healthyInput(r)) {
		if strings.Contains(c.Next, "wgft rule enable") && !strings.Contains(c.Next, "wgft rule enable "+r.ID) {
			t.Errorf("%s: next step names a short ID: %q", c.ID, c.Next)
		}
	}

	r = tcpRule()
	r.SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	in := healthyInput(r)
	in.From, in.HasFrom = netip.MustParseAddr("203.0.113.7"), true
	if c := checkOf(t, diagnose(r, in), checkSourceFilter); !strings.Contains(c.Next, "wgft rule deny rm "+r.ID+" ") {
		t.Errorf("deny rm names a short ID: %q", c.Next)
	}

	r = tcpRule()
	r.SourceAllow = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	in = healthyInput(r)
	in.From, in.HasFrom = netip.MustParseAddr("203.0.113.7"), true
	if c := checkOf(t, diagnose(r, in), checkSourceFilter); !strings.Contains(c.Next, "wgft rule allow add "+r.ID+" ") {
		t.Errorf("allow add names a short ID: %q", c.Next)
	}
}

// server doctor の終了の 1 行は、次に `server doctor <rule>` へ貼る ID を名指すので、完全な ID を
// 使う。
func TestDoctorExitNamesTheFullRuleID(t *testing.T) {
	r := tcpRule()
	in := healthyInput(r)
	in.Agents = nil
	err := doctorExit(buildReport([]proto.Rule{r}, in))
	if err == nil {
		t.Fatal("a rule with no registered agent did not fail")
	}
	if !strings.Contains(err.Error(), "traffic stops on rule "+r.ID+" at ") {
		t.Errorf("the closing line does not name the full ID: %v", err)
	}
	if strings.Contains(err.Error(), "…") {
		t.Errorf("the closing line carries an elided ID: %v", err)
	}
}

// 表の短い形をそのまま貼っても、前方一致が 1 つなら通る。前方一致が 2 つ以上なら、候補の完全な
// ID を挙げて拒む。
func TestMatchRuleAcceptsTheShortForm(t *testing.T) {
	a := proto.Rule{ID: "r_01M3AWMEPZAAAAAAAAAAAAAAAA"}
	b := proto.Rule{ID: "r_01M3AWMEPZBBBBBBBBBBBBBBBB"}
	c := proto.Rule{ID: "r_01M4CCCCCCCCCCCCCCCCCCCCCC"}
	rules := []proto.Rule{a, b, c}
	for _, tc := range []struct {
		arg, want string
	}{
		{a.ID, a.ID},
		{short(c.ID), c.ID},
		{"r_01M4CCCCCC...", c.ID},
		{"r_01M3AWMEPZA", a.ID},
		{short(a.ID)[:len(short(a.ID))-len("…")] + "A…", a.ID},
	} {
		got, err := matchRule(rules, tc.arg)
		if err != nil {
			t.Errorf("matchRule(%q): %v", tc.arg, err)
			continue
		}
		if got.ID != tc.want {
			t.Errorf("matchRule(%q) = %s, want %s", tc.arg, got.ID, tc.want)
		}
	}

	_, err := matchRule(rules, short(a.ID))
	if err == nil {
		t.Fatalf("%q matched although two rules share it", short(a.ID))
	}
	for _, id := range []string{a.ID, b.ID} {
		if !strings.Contains(err.Error(), id) {
			t.Errorf("the refusal does not list the candidate %s: %v", id, err)
		}
	}
	if strings.Contains(err.Error(), c.ID) {
		t.Errorf("the refusal lists a rule that does not match: %v", err)
	}

	for _, arg := range []string{"", "…", "...", "r_09"} {
		if got, err := matchRule(rules, arg); err == nil {
			t.Errorf("matchRule(%q) = %s, want not found", arg, got.ID)
		}
		// 省略記号だけ、または空の引数は、ルールが 1 本しか無くてもそれを指さない。
		if got, err := matchRule([]proto.Rule{a}, arg); err == nil {
			t.Errorf("matchRule(%q) over one rule = %s, want not found", arg, got.ID)
		}
	}
}

// 候補は上限までしか挙げず、残りの数を添える。
func TestMatchRuleCapsTheCandidates(t *testing.T) {
	var rules []proto.Rule
	for _, s := range []string{"A", "B", "C", "D", "E", "F", "G"} {
		rules = append(rules, proto.Rule{ID: "r_01M5" + strings.Repeat(s, 22)})
	}
	_, err := matchRule(rules, "r_01M5")
	if err == nil {
		t.Fatal("a prefix shared by seven rules matched")
	}
	if !strings.Contains(err.Error(), "matches 7 rules") || !strings.Contains(err.Error(), "and 2 more") {
		t.Errorf("the refusal does not count the candidates: %v", err)
	}
	if strings.Contains(err.Error(), rules[6].ID) {
		t.Errorf("the refusal lists more candidates than the cap: %v", err)
	}
}
