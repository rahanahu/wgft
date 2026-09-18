package store

import (
	"net/netip"
	"path/filepath"
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
