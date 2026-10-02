package store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// TestApplyBatchRuleIDLimitsAndStoredRows は、長すぎるか表示できない文字を含む ID のルールを新しく
// 書き込めないこと(仕様 5.3 節)と、この検査の前から保存されている同じ形の ID の行の扱い(仕様
// 5.4 節)を、保存の経路で確かめる。その行はそのまま読み込まれ、無関係なバッチも、同じ集合を戻す
// バッチも通る。同じ ID のまま変えるバッチは拒まれ、削除と、正しい ID への 1 回のバッチでの置き換えは
// 通る。
// 変異の確認:Rule.Validate から ID の検査を外すと、新しく書き込むバッチが通って落ちる。
func TestApplyBatchRuleIDLimitsAndStoredRows(t *testing.T) {
	for _, id := range []string{strings.Repeat("x", 129), "r_a\nr_b", "r_\u2029"} {
		s := openTemp(t)
		if _, err := s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
			return append(r, rule(id, proto.UDP, 3001, 3001, "h:3001")), nil
		}); err == nil || !strings.Contains(err.Error(), "id ") {
			t.Errorf("batch adding id %q = %v, want it refused", id, err)
		}
		if rules, _ := s.Rules(); len(rules) != 0 {
			t.Fatalf("a refused batch stored rules: %+v", rules)
		}

		// この検査の前に保存された行を、SQL で直接作る
		legacy := rule(id, proto.UDP, 3002, 3002, "h:3002")
		js, err := json.Marshal(legacy)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec("INSERT INTO rules (id, position, json) VALUES (?, 0, ?)", legacy.ID, string(js)); err != nil {
			t.Fatal(err)
		}
		if rules, err := s.Rules(); err != nil || len(rules) != 1 || rules[0].ID != id {
			t.Fatalf("loading the stored row = %+v, %v; want it with its id unchanged", rules, err)
		}
		if _, err := s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
			return append(r, rule("a", proto.UDP, 2456, 2457, "h:2456")), nil
		}); err != nil {
			t.Fatalf("id %q: an unrelated batch must not fail: %v", id, err)
		}
		if _, err := s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) { return r, nil }); err != nil {
			t.Errorf("id %q: a batch that keeps the set unchanged must not fail: %v", id, err)
		}
		if _, err := s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
			for i := range r {
				if r[i].ID == id {
					r[i].Enabled = false
				}
			}
			return r, nil
		}); err == nil || !strings.Contains(err.Error(), "id ") {
			t.Errorf("id %q: changing the stored row = %v, want it refused", id, err)
		}
		// 同じポートのまま正しい ID へ置き換える。listen_port の重なりはバッチの後の集合で見るので通る
		if _, err := s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
			var out []proto.Rule
			for _, x := range r {
				if x.ID == id {
					x.ID = "r_fixed"
				}
				out = append(out, x)
			}
			return out, nil
		}); err != nil {
			t.Errorf("id %q: replacing the stored row with a valid id must work: %v", id, err)
		}
		rules, _ := s.Rules()
		if len(rules) != 2 || rules[0].ID != "r_fixed" && rules[1].ID != "r_fixed" {
			t.Errorf("rules after the replacement = %+v, want a and r_fixed", rules)
		}
	}
}

// TestApplyBatchDeletesStoredBadRuleID は、検査の前に保存された、長すぎるか表示できない文字を
// 含む ID の行を削除できることを確かめる。
func TestApplyBatchDeletesStoredBadRuleID(t *testing.T) {
	s := openTemp(t)
	legacy := rule("r_a\nr_b", proto.UDP, 3002, 3002, "h:3002")
	js, _ := json.Marshal(legacy)
	if _, err := s.db.Exec("INSERT INTO rules (id, position, json) VALUES (?, 0, ?)", legacy.ID, string(js)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) { return nil, nil }); err != nil {
		t.Fatalf("deleting the stored row must work: %v", err)
	}
	if rules, _ := s.Rules(); len(rules) != 0 {
		t.Errorf("rules after deleting = %+v, want none", rules)
	}
}
