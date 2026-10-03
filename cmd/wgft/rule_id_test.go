package main

import (
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"

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

// rule import と管理用 API は空でない任意の ID を受けるので、省略記号で終わる ID もありうる。生の入力の
// 完全一致を先に試し、省略記号を落とした照合で別のルールを指さない。
func TestMatchRuleKeepsIDsThatEndInAnEllipsis(t *testing.T) {
	web := proto.Rule{ID: "web"}
	webDots := proto.Rule{ID: "web..."}
	webEll := proto.Rule{ID: "web…"}
	webserver := proto.Rule{ID: "webserver"}
	for _, rules := range [][]proto.Rule{{web, webDots, webEll, webserver}, {webserver, webEll, webDots, web}} {
		for _, arg := range []string{"web...", "web…", "web"} {
			got, err := matchRule(rules, arg)
			if err != nil || got.ID != arg {
				t.Errorf("matchRule(%q) over %v = %v %v, want %s", arg, rules, got, err, arg)
			}
		}
	}
}

// 完全一致は前方一致より先に立つ。省略記号を落とした残りと完全に一致する ID があれば、前方一致が
// 他にあってもそれを指す。省略記号が無い入力と同じ扱いである。
func TestMatchRulePrefersAnExactMatchOfTheRest(t *testing.T) {
	web := proto.Rule{ID: "web"}
	webserver := proto.Rule{ID: "webserver"}
	for _, rules := range [][]proto.Rule{{web, webserver}, {webserver, web}} {
		for _, arg := range []string{"web", "web…", "web..."} {
			if got, err := matchRule(rules, arg); err != nil || got.ID != web.ID {
				t.Errorf("matchRule(%q) over %v = %v %v, want web", arg, rules, got, err)
			}
		}
		for _, arg := range []string{"webs", "webs…", "webs..."} {
			if got, err := matchRule(rules, arg); err != nil || got.ID != webserver.ID {
				t.Errorf("matchRule(%q) over %v = %v %v, want webserver", arg, rules, got, err)
			}
		}
	}
}

// 前方一致に求める長さは、省略記号の有無で変えない。12 文字は表示で省略する長さであって、受け取る
// 先頭の最小の長さではない。省略記号の無い短い先頭が通るなら、同じ先頭に省略記号を付けても通り、
// 複数に当たるなら同じく候補を挙げて拒む。
func TestMatchRuleTakesAShortPrefixWithAnEllipsis(t *testing.T) {
	a := proto.Rule{ID: "r_01M3AWMEPZAAAAAAAAAAAAAAAA"}
	b := proto.Rule{ID: "r_01M3AWMEPZBBBBBBBBBBBBBBBB"}
	c := proto.Rule{ID: "r_01M4CCCCCCCCCCCCCCCCCCCCCC"}
	rules := []proto.Rule{a, b, c}
	for _, base := range []string{"r_01M4", "r_01M4C", "r_01M4CCCCC"} {
		for _, arg := range []string{base, base + "…", base + "..."} {
			if got, err := matchRule(rules, arg); err != nil || got.ID != c.ID {
				t.Errorf("matchRule(%q) = %v %v, want %s", arg, got, err, c.ID)
			}
		}
	}
	for _, arg := range []string{"r_01M3", "r_01M3…", "r_01M3...", "r_01M3AWMEP…"} {
		_, err := matchRule(rules, arg)
		if err == nil {
			t.Errorf("matchRule(%q) matched although two rules share it", arg)
			continue
		}
		if !strings.Contains(err.Error(), "matches 2 rules") || !strings.Contains(err.Error(), a.ID) || !strings.Contains(err.Error(), b.ID) {
			t.Errorf("matchRule(%q) was not refused with both candidates: %v", arg, err)
		}
		if strings.Contains(err.Error(), c.ID) {
			t.Errorf("matchRule(%q) lists a rule that does not match: %v", arg, err)
		}
	}
	for _, arg := range []string{"r_09…", "r_09...", "x…"} {
		if got, err := matchRule(rules, arg); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("matchRule(%q) = %v %v, want not found", arg, got, err)
		}
	}

	// ルールが 1 本の配置では、`r_...` のようなプレースホルダもそのルールを指す。省略記号の無い `r_`
	// が同じルールを指すのと同じである。残りが空の入力だけは指さない。
	one := []proto.Rule{a}
	for _, arg := range []string{"r_", "r_...", "r_…", "r_01M3AWMEP…", "r_01M3AWMEP...", "r_01M3"} {
		if got, err := matchRule(one, arg); err != nil || got.ID != a.ID {
			t.Errorf("matchRule(%q) over one rule = %v %v, want %s", arg, got, err, a.ID)
		}
	}
	for _, arg := range []string{"", "…", "..."} {
		if got, err := matchRule(one, arg); err == nil {
			t.Errorf("matchRule(%q) over one rule = %s, want refused", arg, got.ID)
		}
	}
}

// 多バイト文字の ID でも、表の短い形は文字の途中で切れず、そのまま貼れば通る。省略記号を付けた先頭は、
// 12 文字に満たなくても、前方一致が 1 つなら通る。v1.4.0 の表がバイトで切って出した短い形
// (4 文字で 12 バイトの "週末のサ…")も、前方一致が 1 つならそのまま通る。
func TestMatchRuleWithMultibyteIDs(t *testing.T) {
	a := proto.Rule{ID: "週末のサーバー用ルールでA"}
	b := proto.Rule{ID: "週末のサーバー用ルールでB"}
	weekday := proto.Rule{ID: "平日のサーバー"}
	rules := []proto.Rule{a, b, weekday}
	if got := short(a.ID); got != "週末のサーバー用ルールで…" || !utf8.ValidString(got) {
		t.Fatalf("short(%q) = %q", a.ID, got)
	}
	if got := short(weekday.ID); got != weekday.ID {
		t.Fatalf("short(%q) = %q, want it in full", weekday.ID, got)
	}
	if _, err := matchRule(rules, short(a.ID)); err == nil || !strings.Contains(err.Error(), a.ID) || !strings.Contains(err.Error(), b.ID) {
		t.Errorf("the two-rule prefix was not refused with candidates: %v", err)
	}
	for _, arg := range []string{"週末のサ…", "週末…", "週末..."} {
		if _, err := matchRule(rules, arg); err == nil || !strings.Contains(err.Error(), "matches 2 rules") {
			t.Errorf("matchRule(%q) was not refused as matching two rules: %v", arg, err)
		}
	}
	for arg, want := range map[string]string{
		"週末のサーバー用ルールでA…": a.ID,
		"平日…":      weekday.ID,
		"平…":       weekday.ID,
		"平日のサーバー…": weekday.ID,
		"平日":       weekday.ID,
	} {
		if got, err := matchRule(rules, arg); err != nil || got.ID != want {
			t.Errorf("matchRule(%q) = %v %v, want %s", arg, got, err, want)
		}
	}
	if got, err := matchRule([]proto.Rule{a}, "週末のサ…"); err != nil || got.ID != a.ID {
		t.Errorf("a 4-rune prefix with an ellipsis over one rule = %v %v", got, err)
	}
}
