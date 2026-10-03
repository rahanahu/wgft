package proto

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestTargetLimits は、target の長さと文字の検査(仕様 5.3 節)を確かめる。長さは UTF-8 のバイトで
// 数え、259 バイト(253 バイトのホスト、":"、5 桁のポート)まで受ける。ポートの先頭の 0 で長くした
// 値も長さで拒む。文字は unicode.IsGraphic が真のものだけを受ける。
// 変異の確認:上限を 260 にすると 260 バイトの行が通って落ちる。長さの比較を文字数に変えると「3 バイトの
// 文字で 260 バイト」が通って落ちる。IsGraphic の検査を外すと制御文字の行が通って落ちる。
func TestTargetLimits(t *testing.T) {
	host := func(n int) string { return strings.Repeat("a", n) }
	tests := []struct {
		name    string
		target  string
		wantErr string // 空なら成功を期待
	}{
		{"253 バイトのホストと 5 桁のポートで 259 バイト", host(253) + ":65535", ""},
		{"260 バイト", host(254) + ":65535", "target is 260 bytes long; the limit is 259 bytes"},
		{"先頭の 0 で 260 バイトにしたポート", host(250) + ":000000080", "target is 260 bytes long"},
		{"先頭の 0 で長くした 259 バイトは形の検査に進む", host(250) + ":00000080", ""},
		{"3 バイトの文字で 259 バイトちょうど", host(251) + "あ" + ":8080", ""},
		{"3 バイトの文字で 260 バイト", host(252) + "あ" + ":8080", "target is 260 bytes long"},
		{"文字数では 89 文字で 261 バイト", strings.Repeat("あ", 86) + ":80", "target is 261 bytes long"},
		{"日本語のホスト", "ホスト.example:80", ""},
		{"記号", "a&b<c>:80", ""},
		{"ASCII の空白", "a b:80", ""},
		{"改行", "a\nb:80", "target contains U+000A at byte 1"},
		{"ESC", "\x1b[31m:80", "target contains U+001B at byte 0"},
		{"行区切り", "a\u2028:80", "U+2028"},
		{"ゼロ幅接合子", "a\u200d:80", "U+200D"},
		{"不正な UTF-8", "a\xff:80", "target is not valid UTF-8"},
		{"長さの検査は形の検査の前", host(300), "target is 300 bytes long"},
		{"形の誤りは従来どおり", "192.168.1.20", "target: "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validRule()
			r.ListenPort = PortRange{Lo: 2456, Hi: 2456}
			r.Target = tt.target
			err := r.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() with target of %d bytes = %v, want nil", len(tt.target), err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() with target %q = %v, want error containing %q", tt.target, err, tt.wantErr)
			}
			if strings.ContainsFunc(err.Error(), func(r rune) bool { return r < 0x20 || r == 0x7f }) || !utf8.ValidString(err.Error()) {
				t.Errorf("error %q carries a control character or invalid UTF-8", err)
			}
		})
	}
	if MaxTargetLen != 259 {
		t.Errorf("MaxTargetLen = %d, want 259", MaxTargetLen)
	}
}

// TestValidateUpsertKeepsStoredLongTargets は、target の検査の前に保存された、長すぎるか表示できない
// 文字を含む target の行の扱いを確かめる(仕様 5.4 節)。触らない限り無関係なバッチを妨げず、書き出しを
// そのまま戻すバッチも通る。その target のまま変えるバッチは拒み、削除と、target を正しい値に変える
// 書き換えは通る。
func TestValidateUpsertKeepsStoredLongTargets(t *testing.T) {
	for _, bad := range []string{strings.Repeat("a", 254) + ":65535", "a:" + strings.Repeat("0", 300) + "80", "a\nb:80"} {
		legacy := validRule()
		legacy.ID = "r_legacy"
		legacy.ListenPort = PortRange{Lo: 3000, Hi: 3000}
		legacy.Target = bad
		before := []Rule{legacy}
		other := validRule()

		if err := ValidateUpsert([]Rule{legacy, other}, before, nil); err != nil {
			t.Errorf("target %q: an unrelated add must not fail: %v", bad, err)
		}
		if err := ValidateUpsert([]Rule{legacy}, before, nil); err != nil {
			t.Errorf("target %q: keeping the set unchanged must not fail: %v", bad, err)
		}
		changed := legacy
		changed.Enabled = false
		if err := ValidateUpsert([]Rule{changed}, before, nil); err == nil || !strings.Contains(err.Error(), "rule r_legacy: target") {
			t.Errorf("target %q: changing the stored row = %v, want it refused", bad, err)
		}
		if err := ValidateUpsert(nil, before, nil); err != nil {
			t.Errorf("target %q: deleting the stored row must work: %v", bad, err)
		}
		fixed := legacy
		fixed.Target = "a:80"
		if err := ValidateUpsert([]Rule{fixed}, before, nil); err != nil {
			t.Errorf("target %q: fixing the target must work: %v", bad, err)
		}
		// 新しく書く行には検査が掛かる
		if err := ValidateUpsert([]Rule{legacy}, nil, nil); err == nil {
			t.Errorf("target %q: adding it as a new row must be refused", bad)
		}
	}
}

// countRules は、agent を持ち主とする n 本のルールを、ポート base から 1 つずつずらして作る。ID は
// prefix と番号である。
func countRules(agent, prefix string, base, n int) []Rule {
	out := make([]Rule, 0, n)
	for i := 0; i < n; i++ {
		p := uint16(base + i)
		out = append(out, Rule{ID: fmt.Sprintf("%s%d", prefix, i), Agent: agent, Proto: UDP, ListenPort: PortRange{Lo: p, Hi: p},
			Target: "192.168.1.20:2456", VPSMode: ModeKernel, Enabled: true})
	}
	return out
}

func concat(sets ...[]Rule) []Rule {
	var out []Rule
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

// moveTo は rules の先頭から n 本の持ち主を agent に変えた写しを返す。
func moveTo(rules []Rule, agent string, n int) []Rule {
	out := append([]Rule(nil), rules...)
	for i := 0; i < n; i++ {
		out[i].Agent = agent
	}
	return out
}

// TestAgentRuleCountLimit は、エージェントあたりのルールの数の上限の判定(仕様 5.4 節)を確かめる。
// あるエージェントについて、バッチの後の本数が上限を超え、かつバッチの前より多いときだけ拒む。
// 変異の確認:判定を「後の本数 > 上限」だけにすると、上限を超えた既存のデータの置き換え、削除、移し替え
// で落ちる。「後の本数 > 前の本数」を外すと同じ行で落ちる。上限との比較を >= にすると 511 から 512 で
// 落ちる。無効なルールを数えないと、無効を含む 513 本の行が通って落ちる。
func TestAgentRuleCountLimit(t *testing.T) {
	if MaxRulesPerAgent != 512 {
		t.Fatalf("MaxRulesPerAgent = %d, want 512", MaxRulesPerAgent)
	}
	a700 := countRules("home", "a", 10000, 700)
	a512 := a700[:512]
	a511 := a700[:511]
	b10 := countRules("other", "b", 20000, 10)
	b512 := countRules("other", "b", 20000, 512)
	disabled513 := append([]Rule(nil), a700[:513]...)
	disabled513[512].Enabled = false

	tests := []struct {
		name          string
		before, after []Rule
		wantAgent     string // 空なら成功を期待
		wantAfter     int
	}{
		{"700 本を同じ本数の別の ID で置き換える", a700, countRules("home", "x", 30000, 700), "", 0},
		{"700 本を同じ集合のまま戻す", a700, a700, "", 0},
		{"700 本の 1 本を書き換える", a700, func() []Rule { r := append([]Rule(nil), a700...); r[0].Enabled = false; return r }(), "", 0},
		{"700 本から 699 本へ減らす", a700, a700[:699], "", 0},
		{"700 本から 701 本へ増やす", a700, concat(a700, countRules("home", "y", 40000, 1)), "home", 701},
		{"511 本から 512 本へ", a511, a512, "", 0},
		{"512 本から 513 本へ", a512, a700[:513], "home", 513},
		{"0 本から 513 本を 1 回で", nil, a700[:513], "home", 513},
		{"無効なルールも数える", a512, disabled513, "home", 513},
		{"上限の 512 本のエージェントの隣に別のエージェントの行を足す", a512, concat(a512, b10), "", 0},
		{"700 本のエージェントから別のエージェントへ 1 本移す", concat(a700, b10), concat(moveTo(a700, "other", 1), b10), "", 0},
		{"別のエージェントから 700 本のエージェントへ 1 本移す", concat(a700, b10), concat(a700, moveTo(b10, "home", 1)), "home", 701},
		{"511 本のエージェントへ 1 本移して 512 本", concat(a511, b512), concat(a511, moveTo(b512, "home", 1)), "", 0},
		{"移した先が 513 本になる", concat(a512, b10), concat(a512, moveTo(b10, "home", 1)), "home", 513},
		{"2 つのエージェントが超えると名前の順で最初を示す", concat(a512, b512), concat(a700[:513], b512, countRules("other", "z", 50000, 1)), "home", 513},
		{"超えたエージェントで別のエージェントのルールを足す", concat(a700, b10), concat(a700, b10, countRules("other", "z", 50000, 1)), "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUpsert(tt.after, tt.before, nil)
			if tt.wantAgent == "" {
				if err != nil {
					t.Fatalf("ValidateUpsert = %v, want nil", err)
				}
				return
			}
			var le *AgentRuleLimitError
			if !errors.As(err, &le) || le.Agent != tt.wantAgent || le.After != tt.wantAfter {
				t.Fatalf("ValidateUpsert = %v, want the limit error for agent %s with %d rules", err, tt.wantAgent, tt.wantAfter)
			}
			want := fmt.Sprintf("agent %q would have %d rules, over the limit of 512 rules per agent; delete rules or move them to another agent first", tt.wantAgent, tt.wantAfter)
			if err.Error() != want {
				t.Errorf("error = %q, want %q", err, want)
			}
		})
	}
	// before を持たない ValidateRules は数を見ない
	if err := ValidateRules(a700, nil); err != nil {
		t.Errorf("ValidateRules on 700 rules = %v, want nil", err)
	}
}

// TestAgentsOverRuleLimit は、起動のときの警告に使う一覧が、上限を超えるエージェントだけを名前の順に
// 返すことを確かめる。
func TestAgentsOverRuleLimit(t *testing.T) {
	rules := concat(countRules("zeta", "z", 1000, 513), countRules("alpha", "a", 2000, 600), countRules("mid", "m", 3000, 512))
	got := AgentsOverRuleLimit(rules)
	if len(got) != 2 || got[0] != "alpha" || got[1] != "zeta" {
		t.Errorf("AgentsOverRuleLimit = %v, want [alpha zeta]", got)
	}
	if c := RuleCountsByAgent(rules); c["alpha"] != 600 || c["zeta"] != 513 || c["mid"] != 512 {
		t.Errorf("RuleCountsByAgent = %v", c)
	}
	if got := AgentsOverRuleLimit(countRules("home", "h", 1000, 512)); len(got) != 0 {
		t.Errorf("AgentsOverRuleLimit at the limit = %v, want none", got)
	}
}
