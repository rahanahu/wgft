package store

import (
	"encoding/json"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "wgft.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func rule(id string, p proto.Proto, lo, hi uint16, target string) proto.Rule {
	return proto.Rule{ID: id, Agent: "home", Proto: p, ListenPort: proto.PortRange{Lo: lo, Hi: hi}, Target: target, VPSMode: proto.ModeKernel, Enabled: true}
}

func TestApplyBatchGeneration(t *testing.T) {
	s := openTemp(t)
	reserved := proto.Reserved{51820: "WireGuard"}

	res, err := s.ApplyBatch(reserved, func(r []proto.Rule) ([]proto.Rule, error) {
		return append(r, rule("a", proto.UDP, 2456, 2457, "h:2456")), nil
	})
	if err != nil || res.Generation != 1 || !res.Changed || len(res.Rules) != 1 {
		t.Fatalf("add: %+v %v", res, err)
	}
	// 接続元制限だけの変更:世代は上がらない
	res, err = s.ApplyBatch(reserved, func(r []proto.Rule) ([]proto.Rule, error) {
		r[0].SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
		rate, _ := proto.ParseRate("10/second")
		r[0].PerSourceRate = &rate
		return r, nil
	})
	if err != nil || res.Generation != 1 || res.Changed {
		t.Fatalf("restriction change must not bump: %+v %v", res, err)
	}
	// enabled の切り替え:上がる
	res, err = s.ApplyBatch(reserved, func(r []proto.Rule) ([]proto.Rule, error) { r[0].Enabled = false; return r, nil })
	if err != nil || res.Generation != 2 || !res.Changed {
		t.Fatalf("enabled change must bump: %+v %v", res, err)
	}
	// 検証に失敗するバッチは何も変えない(世代もルールも)
	_, err = s.ApplyBatch(reserved, func(r []proto.Rule) ([]proto.Rule, error) {
		return append(r, rule("b", proto.UDP, 2457, 2460, "h:1")), nil // a と重なる
	})
	if err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("overlap must fail: %v", err)
	}
	if g, _ := s.Generation(); g != 2 {
		t.Errorf("generation after failed batch = %d, want 2", g)
	}
	if rules, _ := s.Rules(); len(rules) != 1 || rules[0].SourceDeny == nil || rules[0].Enabled {
		t.Errorf("rules after failed batch = %+v", rules)
	}
	// 予約ポート
	if _, err := s.ApplyBatch(reserved, func(r []proto.Rule) ([]proto.Rule, error) {
		return append(r, rule("c", proto.UDP, 51820, 51820, "h:1")), nil
	}); err == nil {
		t.Error("reserved port must fail")
	}
	// 分割(縮める + 足す)を 1 バッチで:中間状態の重複検査に引っかからず、世代は 1 つだけ上がる
	res, err = s.ApplyBatch(reserved, func(r []proto.Rule) ([]proto.Rule, error) {
		r[0].Enabled = true
		r[0].ListenPort = proto.PortRange{Lo: 2456, Hi: 2456}
		return append(r, rule("d", proto.UDP, 2457, 2457, "h:2457")), nil
	})
	if err != nil || res.Generation != 3 || len(res.Rules) != 2 {
		t.Fatalf("split: %+v %v", res, err)
	}
	// 開き直しても残る
	s2, err := Open(s.path())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if rules, _ := s2.Rules(); len(rules) != 2 || rules[1].ID != "d" {
		t.Errorf("after reopen: %+v", rules)
	}
	if g, _ := s2.Generation(); g != 3 {
		t.Errorf("generation after reopen = %d", g)
	}
}

func TestMutateCannotLeakIntoStore(t *testing.T) {
	s := openTemp(t)
	if _, err := s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
		return append(r, rule("a", proto.TCP, 80, 80, "h:80")), nil
	}); err != nil {
		t.Fatal(err)
	}
	// mutate に渡された slice を書き換えても、失敗したバッチなら保存されない
	_, _ = s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
		r[0].Target = "changed:1"
		return nil, errShort
	})
	rules, _ := s.Rules()
	if rules[0].Target != "h:80" {
		t.Errorf("leaked: %+v", rules)
	}
}

// TestApplyBatchPreservesEmptyVsNilSourceLists は、mutate に渡す前の防御的コピー
// (cloneRules)が、空だが nil でない SourceAllow/SourceDeny(rule add や Web UI が明示的に
// 設定する []netip.Prefix{})を nil に取り違えないことを確かめる。append([]netip.Prefix(nil),
// p...) は p が空でも非 nil であれば結果を nil にしてしまうため、無関係なフィールド(ここでは
// target)だけを変えるバッチを経由するだけで、保存される JSON が "source_allow":[] から
// "source_allow":null に静かに変わってしまっていた。proto.RulesDigest はこの JSON をハッシュ
// するため、この取り違えは BatchRequest.ExpectedDigest の照合(admin_backend.go)を、
// 何も変わっていないのに拒む食い違いにもつながる。
func TestApplyBatchPreservesEmptyVsNilSourceLists(t *testing.T) {
	s := openTemp(t)
	r := rule("a", proto.UDP, 2456, 2456, "h:2456")
	r.SourceAllow, r.SourceDeny = []netip.Prefix{}, []netip.Prefix{}
	if _, err := s.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, r), nil
	}); err != nil {
		t.Fatal(err)
	}
	before, err := s.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if before[0].SourceAllow == nil || before[0].SourceDeny == nil {
		t.Fatalf("initial rule lost its non-nil empty source lists: %+v", before[0])
	}

	// target だけを変える、無関係なバッチ(SourceAllow/SourceDeny に触れない)。
	if _, err := s.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		rules[0].Target = "h:9999"
		return rules, nil
	}); err != nil {
		t.Fatal(err)
	}
	after, err := s.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if after[0].SourceAllow == nil || after[0].SourceDeny == nil {
		t.Errorf("an unrelated batch turned the empty source lists into nil: %+v", after[0])
	}
}

// TestApplyBatchGrandfathersUntouchedLegacyRow は、proto.Rule.Validate() に検査を後から
// 追加しても(ここでは proxy の範囲を拒否する検査)、それ以前に保存された、検査に落ちる行を
// 触っていないバッチまで失敗させないことを確かめる(仕様 5.4 節、proto.ValidateUpsert)。
// 直接 SQL を書いて legacy な行を作るのは、この検査を追加した後の ApplyBatch では同じ行を
// 通常の経路で作れないため(意図どおり拒否される)。
func TestApplyBatchGrandfathersUntouchedLegacyRow(t *testing.T) {
	s := openTemp(t)
	legacy := proto.Rule{
		ID: "legacy", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 443, Hi: 444},
		Target: "192.168.1.20:443", VPSMode: proto.ModeProxy, Enabled: true,
	}
	if err := legacy.Validate(); err == nil {
		t.Fatal("fixture must be invalid under the current Rule.Validate(); update the test")
	}
	js, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO rules (id, position, json) VALUES (?, 0, ?)", legacy.ID, string(js)); err != nil {
		t.Fatal(err)
	}

	// 無関係なルールを足すだけのバッチは、legacy に触れないので通る
	if _, err := s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
		return append(r, rule("a", proto.UDP, 2456, 2457, "h:2456")), nil
	}); err != nil {
		t.Fatalf("an unrelated batch must not fail because of an untouched legacy row: %v", err)
	}
	if rules, _ := s.Rules(); len(rules) != 2 {
		t.Fatalf("legacy row must survive untouched: %+v", rules)
	}

	// legacy 自身を変えるバッチは、変えた後の内容が Validate() に落ちるので拒む
	if _, err := s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
		for i := range r {
			if r[i].ID == "legacy" {
				r[i].Note = "touched"
			}
		}
		return r, nil
	}); err == nil {
		t.Error("touching the legacy row must re-run Validate() and fail")
	}
}

var errShort = &shortErr{}

type shortErr struct{}

func (*shortErr) Error() string { return "abort" }

// group/note だけの変更では世代が上がらない(エージェントに配らないメタ、仕様 5.3 節)。
func TestGroupNoteNoGeneration(t *testing.T) {
	s := openTemp(t)
	res, err := s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
		return append(r, rule("a", proto.UDP, 2456, 2457, "h:2456")), nil
	})
	if err != nil || res.Generation != 1 {
		t.Fatalf("add: %+v %v", res, err)
	}
	res, err = s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
		r[0].Group = "valheim"
		r[0].Note = "週末サーバ"
		return r, nil
	})
	if err != nil || res.Generation != 1 || res.Changed {
		t.Fatalf("group/note change must not bump: %+v %v", res, err)
	}
	if rules, _ := s.Rules(); len(rules) != 1 || rules[0].Group != "valheim" || rules[0].Note != "週末サーバ" {
		t.Errorf("group/note not persisted: %+v", rules)
	}
}

// distributedTo は vpsd.Daemon.AgentState と同じ選び方で、そのエージェントに配るルールを返す。
func distributedTo(rules []proto.Rule, agent string) []proto.AgentRule {
	out := []proto.AgentRule{}
	for i := range rules {
		if rules[i].Agent == agent {
			out = append(out, rules[i].ForAgent())
		}
	}
	return out
}

// TestRuleMoveBetweenAgentsBumpsGeneration は、ルールの持ち主を別のエージェントへ移す変更で
// 世代が上がることを確かめる(仕様 5.2、5.3 節)。proto.Rule.Agent は proto.AgentRule に
// 入らないので、行ごとの射影だけを並べて比べていた頃は移動が差として現れず、世代が上がらず、
// 旧い持ち主も新しい持ち主も新しい全体状態を受け取らなかった。
func TestRuleMoveBetweenAgentsBumpsGeneration(t *testing.T) {
	s := openTemp(t)
	res, err := s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
		return append(r, rule("a", proto.TCP, 25565, 25565, "h:25565")), nil
	})
	if err != nil || res.Generation != 1 || !res.Changed {
		t.Fatalf("add: %+v %v", res, err)
	}
	before := res.Rules
	if len(distributedTo(before, "home")) != 1 || len(distributedTo(before, "office")) != 0 {
		t.Fatalf("before the move: home=%+v office=%+v", distributedTo(before, "home"), distributedTo(before, "office"))
	}

	res, err = s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
		r[0].Agent = "office"
		return r, nil
	})
	if err != nil {
		t.Fatalf("move: %v", err)
	}
	if !res.Changed || res.Generation != 2 {
		t.Fatalf("moving a rule to another agent must bump the generation: changed=%v generation=%d, want true 2",
			res.Changed, res.Generation)
	}
	after := res.Rules
	if got := distributedTo(after, "home"); len(got) != 0 {
		t.Errorf("after the move the old agent still gets the rule: %+v", got)
	}
	if got := distributedTo(after, "office"); len(got) != 1 || got[0].ID != "a" {
		t.Errorf("after the move the new agent does not get the rule: %+v", got)
	}
	if rules, _ := s.Rules(); len(rules) != 1 || rules[0].Agent != "office" {
		t.Errorf("owner not persisted: %+v", rules)
	}

	// 移し戻しても同じように上がる。
	res, err = s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
		r[0].Agent = "home"
		return r, nil
	})
	if err != nil || !res.Changed || res.Generation != 3 {
		t.Fatalf("moving back: %+v %v", res, err)
	}
}

// TestBatchMovingAndEditingTogether は、1 つのバッチが片方のルールの持ち主を移し、もう片方の
// 配らないフィールドだけを変える場合に、世代が 1 つだけ上がり、両方の変更が保存されることを
// 確かめる(仕様 5.4 節。バッチの結果で上がる世代は 1 つ)。
func TestBatchMovingAndEditingTogether(t *testing.T) {
	s := openTemp(t)
	res, err := s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
		return append(r, rule("a", proto.TCP, 25565, 25565, "h:25565"), rule("b", proto.UDP, 2456, 2456, "h:2456")), nil
	})
	if err != nil || res.Generation != 1 {
		t.Fatalf("add: %+v %v", res, err)
	}
	res, err = s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
		r[0].Agent = "office" // 配る先が変わる
		r[1].Note = "a note"  // 配らないので、単独なら世代は上がらない
		return r, nil
	})
	if err != nil || !res.Changed || res.Generation != 2 {
		t.Fatalf("move plus an invisible edit must bump the generation exactly once: %+v %v", res, err)
	}
	rules, err := s.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Agent != "office" || rules[1].Agent != "home" || rules[1].Note != "a note" {
		t.Fatalf("both changes must be persisted: %+v", rules)
	}
	if got := distributedTo(rules, "office"); len(got) != 1 || got[0].ID != "a" {
		t.Errorf("office must get rule a: %+v", got)
	}
	if got := distributedTo(rules, "home"); len(got) != 1 || got[0].ID != "b" {
		t.Errorf("home must keep rule b only: %+v", got)
	}
}

// invisibleChange は proto.Rule のフィールドのうち、proto.AgentRule に無く、変更しても世代が
// 上がってはならないものと、その変え方。持ち主(Agent)だけは例外で、移すと配る先が変わるため
// 世代が上がる(TestRuleMoveBetweenAgentsBumpsGeneration)。順に 1 つずつ適用するので、
// VPSMode を proxy にしてから ProxyProtocol を立てる並びにしてある(kernel のまま
// proxy_protocol を立てると Rule.Validate が拒む)。
type invisibleChange struct {
	field  string
	mutate func(*proto.Rule)
}

func invisibleChanges() []invisibleChange {
	rate, _ := proto.ParseRate("10/second")
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	return []invisibleChange{
		{"Group", func(r *proto.Rule) { r.Group = "valheim" }},
		{"Note", func(r *proto.Rule) { r.Note = "a note" }},
		{"SourceAllow", func(r *proto.Rule) { r.SourceAllow = []netip.Prefix{prefix} }},
		{"SourceDeny", func(r *proto.Rule) { r.SourceDeny = []netip.Prefix{prefix} }},
		{"NewFlowRate", func(r *proto.Rule) { v := rate; r.NewFlowRate = &v }},
		{"PacketRate", func(r *proto.Rule) { v := rate; r.PacketRate = &v }},
		{"PerSourceRate", func(r *proto.Rule) { v := rate; r.PerSourceRate = &v }},
		{"VPSMode", func(r *proto.Rule) { r.VPSMode = proto.ModeProxy }},
		{"ProxyProtocol", func(r *proto.Rule) { r.ProxyProtocol = true }},
	}
}

// TestInvisibleFieldsDoNotBumpGeneration は、エージェントに配らないフィールドの変更で世代が
// 上がらないことを、フィールドごとに確かめる(仕様 5.3 節)。持ち主の比較を加えたことで、
// 配らない変更まで世代を上げるようになっていないことを見る。最初の照合は、proto.Rule に
// フィールドが増えたときに、その新しいフィールドがどちら側(配る、配らない)かを決めないまま
// 通り過ぎないようにするためのものである。
func TestInvisibleFieldsDoNotBumpGeneration(t *testing.T) {
	agentFields := map[string]bool{}
	at := reflect.TypeOf(proto.AgentRule{})
	for i := 0; i < at.NumField(); i++ {
		agentFields[at.Field(i).Name] = true
	}
	covered := map[string]bool{"Agent": true} // 持ち主は上がる側。上の 2 つのテストが見る
	changes := invisibleChanges()
	for _, c := range changes {
		covered[c.field] = true
	}
	rt := reflect.TypeOf(proto.Rule{})
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		if agentFields[name] || covered[name] {
			continue
		}
		t.Errorf("proto.Rule.%s is not in proto.AgentRule and no test says whether it bumps the generation", name)
	}

	s := openTemp(t)
	res, err := s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
		return append(r, rule("a", proto.TCP, 25565, 25565, "h:25565")), nil
	})
	if err != nil || res.Generation != 1 {
		t.Fatalf("add: %+v %v", res, err)
	}
	for _, c := range changes {
		before, err := s.Rules()
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.ApplyBatch(nil, func(r []proto.Rule) ([]proto.Rule, error) {
			c.mutate(&r[0])
			return r, nil
		})
		if err != nil {
			t.Fatalf("%s: %v", c.field, err)
		}
		if res.Changed || res.Generation != 1 {
			t.Errorf("changing %s must not bump the generation: changed=%v generation=%d",
				c.field, res.Changed, res.Generation)
		}
		after, err := s.Rules()
		if err != nil {
			t.Fatal(err)
		}
		// 変更が本当に保存されていることを見る。何も変えていない変更を「上がらない」と
		// 判定しても意味が無いため。
		if reflect.DeepEqual(before, after) {
			t.Errorf("changing %s changed nothing; the case proves nothing", c.field)
		}
	}
}
