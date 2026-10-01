package admin

import (
	"errors"
	"math/rand"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

func batchRule(id, agent string, port uint16) proto.Rule {
	return proto.Rule{ID: id, Agent: agent, Proto: proto.TCP, ListenPort: proto.PortRange{Lo: port, Hi: port},
		Target: "192.168.1.10:80", VPSMode: proto.ModeKernel, Enabled: true}
}

func mergedIDs(rs []proto.Rule) []string {
	out := []string{}
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

// 置き換えは元の位置、追加は upsert の順で末尾、削除は最後。同じ ID が Upsert と Delete の両方に
// あれば外れる。成功ログ用の ID の列は、変わった行だけを Updated に数える。
func TestMergeBatch(t *testing.T) {
	a, b, c := batchRule("a", "home", 100), batchRule("b", "home", 200), batchRule("c", "home", 300)
	b2 := b
	b2.Note = "changed"
	current := []proto.Rule{a, b, c}
	m := MergeBatch(current, BatchRequest{
		// b2 を先頭に置く。後の追加で配列が取り直される前に置き換えるので、入力を変えれば見える
		Upsert: []proto.Rule{b2, batchRule("n1", "home", 400), a, batchRule("n2", "home", 500), batchRule("gone", "home", 600)},
		Delete: []string{"c", "gone"},
	})
	if got, want := mergedIDs(m.Rules), []string{"a", "b", "n1", "n2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("rules = %v, want %v", got, want)
	}
	if m.Rules[1].Note != "changed" {
		t.Errorf("rule b was not replaced in place: %+v", m.Rules[1])
	}
	if !reflect.DeepEqual(m.Added, []string{"n1", "n2", "gone"}) || !reflect.DeepEqual(m.Updated, []string{"b"}) || !reflect.DeepEqual(m.Deleted, []string{"c", "gone"}) {
		t.Errorf("added %v updated %v deleted %v, want [n1 n2 gone] [b] [c gone]", m.Added, m.Updated, m.Deleted)
	}
	if got := mergedIDs(current); !reflect.DeepEqual(got, []string{"a", "b", "c"}) || current[1].Note != "" {
		t.Errorf("MergeBatch changed its input: %+v", current)
	}

	// 同じ ID が upsert に 2 度あれば後の行が残る
	x1, x2 := batchRule("x", "home", 700), batchRule("x", "home", 701)
	m = MergeBatch(nil, BatchRequest{Upsert: []proto.Rule{x1, x2}})
	if len(m.Rules) != 1 || m.Rules[0].ListenPort.Lo != 701 || !reflect.DeepEqual(m.Added, []string{"x"}) || !reflect.DeepEqual(m.Updated, []string{"x"}) {
		t.Errorf("duplicate upsert: rules %+v added %v updated %v", m.Rules, m.Added, m.Updated)
	}
}

// fake と demo の Backend が使う ApplyBatchToRules は、無い ID の削除を黙って無視し、空の集合を
// nil ではなく空のスライスで返す。
func TestApplyBatchToRulesIgnoresAMissingDeleteAndNeverReturnsNil(t *testing.T) {
	got, err := ApplyBatchToRules(nil, BatchRequest{Delete: []string{"nope"}})
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("ApplyBatchToRules(nil, delete a missing ID) = %#v, %v; want an empty non-nil slice", got, err)
	}
	if _, err := ApplyBatchToRules([]proto.Rule{batchRule("a", "home", 100)}, BatchRequest{ExpectedDigest: "stale"}); !errors.Is(err, ErrBatchConflict) {
		t.Fatalf("stale digest: err = %v, want ErrBatchConflict", err)
	}
}

// AdmitBatch は ExpectedDigest、無い ID の削除、エージェントの登録の順に確かめ、最初の誤りを返す。
// すべて通れば MergeBatch と同じ結果を返す。
func TestAdmitBatch(t *testing.T) {
	rules := []proto.Rule{batchRule("a", "home", 100), batchRule("b", "home", 200)}
	registered := func(name string) bool { return name == "home" }
	ghost := batchRule("r1", "ghost", 300)
	ghost2 := batchRule("r2", "ghost2", 400)
	stale := proto.RulesDigest(rules[:1])
	cases := []struct {
		name string
		req  BatchRequest
		want string // 誤りの文言。空なら受理
	}{
		{"accepted", BatchRequest{Upsert: []proto.Rule{batchRule("n", "home", 300)}, Delete: []string{"b", "a"}, ExpectedDigest: proto.RulesDigest(rules)}, ""},
		{"stale digest comes first", BatchRequest{Upsert: []proto.Rule{ghost}, Delete: []string{"zz"}, ExpectedDigest: stale}, ErrBatchConflict.Error()},
		{"missing delete before the agent", BatchRequest{Upsert: []proto.Rule{ghost}, Delete: []string{"a", "zz", "yy"}}, `rule "zz" not found`},
		{"first unregistered agent", BatchRequest{Upsert: []proto.Rule{rules[0], ghost, ghost2}}, `rule r1: agent "ghost" is not registered`},
	}
	for _, tc := range cases {
		m, err := AdmitBatch(rules, tc.req, registered)
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			} else if want := MergeBatch(rules, tc.req); !reflect.DeepEqual(m, want) {
				t.Errorf("%s: %+v, want MergeBatch's %+v", tc.name, m, want)
			}
			continue
		}
		if err == nil || err.Error() != tc.want {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	_, err := AdmitBatch(rules, BatchRequest{ExpectedDigest: stale}, registered)
	if !errors.Is(err, ErrBatchConflict) {
		t.Errorf("stale digest: err = %v, want ErrBatchConflict", err)
	}
	_, err = AdmitBatch(rules, BatchRequest{Upsert: []proto.Rule{ghost}}, registered)
	var unregistered *AgentNotRegisteredError
	if !errors.As(err, &unregistered) || unregistered.Rule.ID != "r1" {
		t.Errorf("unregistered agent: err = %#v, want *AgentNotRegisteredError for r1", err)
	}
}

// 行ごとの誤りは行の順に全部集める。形の落ちた行のエージェントは見ない。変わっていない行の形は
// 見ない。全体の検査は行ごとの誤りが無いときだけ、呼び手の渡した set に掛ける。
func TestPreflightBatch(t *testing.T) {
	agents := map[string]bool{"home": true}
	legacy := batchRule("legacy", "home", 100)
	legacy.Target = "not a target" // 保存済みで、今の Validate には落ちる行
	current := []proto.Rule{legacy}

	bad := batchRule("bad", "ghost", 200)
	bad.Target = "nope"
	rows := []proto.Rule{legacy, batchRule("g1", "ghost", 300), bad, batchRule("g2", "ghost2", 400)}
	var got []string
	for _, err := range PreflightBatch(rows, current, rows, agents, nil) {
		got = append(got, err.Error())
	}
	if len(got) != 3 || !strings.HasPrefix(got[0], `rule g1: agent "ghost"`) || !strings.HasPrefix(got[1], "rule bad: target") || !strings.HasPrefix(got[2], `rule g2: agent "ghost2"`) {
		t.Errorf("row issues = %q", got)
	}
	var invalid *RuleInvalidError
	if errs := PreflightBatch([]proto.Rule{bad}, nil, nil, agents, nil); len(errs) != 1 || !errors.As(errs[0], &invalid) || invalid.Rule.ID != "bad" || invalid.Err == nil {
		t.Errorf("invalid row = %v, want one *RuleInvalidError", errs)
	}

	// 行が通れば set に ValidateUpsert を掛ける。重なりと予約ポートは set で見る
	ok1, ok2 := batchRule("o1", "home", 500), batchRule("o2", "home", 500)
	if errs := PreflightBatch([]proto.Rule{ok1}, nil, []proto.Rule{ok1, ok2}, agents, nil); len(errs) != 1 || !strings.Contains(errs[0].Error(), "overlaps") {
		t.Errorf("overlap in set = %v", errs)
	}
	if errs := PreflightBatch([]proto.Rule{ok1}, nil, []proto.Rule{ok1}, agents, proto.Reserved{500: "WireGuard"}); len(errs) != 1 || !strings.Contains(errs[0].Error(), "WireGuard port 500") {
		t.Errorf("reserved port = %v", errs)
	}
	if errs := PreflightBatch([]proto.Rule{ok1}, nil, []proto.Rule{ok1}, agents, nil); len(errs) != 0 {
		t.Errorf("clean batch = %v", errs)
	}
}

// CLI の --dry-run の組み立て(MergeBatch した集合への PreflightBatch)が受理する変更と、Daemon.Batch
// と同じ手順の mutate を通した store.ApplyBatch が受理する変更が一致することを、乱数の入力で
// 確かめる。checkRule(他テーブルの DNAT と bind 中のポート)はカーネルが要るので除く。行は
// `rule add` と `rule set` が --dry-run の前に掛ける proto.Rule.Validate を通ったものに限る。
func TestPreflightAgreesWithTheSavePath(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	r := rand.New(rand.NewSource(1))
	gen := func() proto.Rule {
		ru := batchRule([]string{"a", "b", "c", "d"}[r.Intn(4)], []string{"home", "work", "ghost"}[r.Intn(3)], uint16(100+r.Intn(6)))
		ru.ListenPort.Hi += uint16(r.Intn(2))
		if r.Intn(2) == 0 {
			ru.Proto = proto.UDP
		}
		return ru
	}
	agents := map[string]bool{"home": true, "work": true}
	registered := func(name string) bool { return agents[name] }
	accepted, refused := 0, 0
	for i := 0; i < 400; i++ {
		// 今の集合を store に置く
		var current []proto.Rule
		for j := r.Intn(4); j > 0; j-- {
			current = append(current, gen())
		}
		if _, err := st.ApplyBatch(nil, func([]proto.Rule) ([]proto.Rule, error) { return current, nil }); err != nil {
			continue // 保存できない集合は今の集合になれない
		}
		var rows []proto.Rule
		for j := 1 + r.Intn(2); j > 0; j-- {
			rows = append(rows, gen())
		}
		var reserved proto.Reserved
		if r.Intn(2) == 0 {
			reserved = proto.Reserved{103: "WireGuard"}
		}
		req := BatchRequest{Upsert: rows}
		preview := PreflightBatch(rows, current, MergeBatch(current, req).Rules, agents, reserved)
		_, saveErr := st.ApplyBatch(reserved, func(rules []proto.Rule) ([]proto.Rule, error) {
			m, err := AdmitBatch(rules, req, registered)
			return m.Rules, err
		})
		if (len(preview) == 0) != (saveErr == nil) {
			t.Fatalf("current %+v rows %+v reserved %v: preview %v, save %v", current, rows, reserved, preview, saveErr)
		}
		if saveErr == nil {
			accepted++
		} else {
			refused++
		}
	}
	if accepted == 0 || refused == 0 {
		t.Fatalf("the inputs never exercised both outcomes: %d accepted, %d refused", accepted, refused)
	}
}
