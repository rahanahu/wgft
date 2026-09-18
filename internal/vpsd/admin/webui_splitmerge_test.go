package admin

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、webui_splitmerge.go にある分割・統合区画のテストを持つ。

// newSplitMergeTestServer は r_a(UDP 2456-2457)に、r_a と統合できる隣接ルール
// r_b(2458-2459)を添える。r_c(2460-2461)は r_b にだけ隣接し、拒否リストが違うので
// r_b とは統合できず、r_a とは隣接すらしない(仕様 10.1、10.2 節)。
func newSplitMergeTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rule := func(id string, lo, hi uint16, targetPort int) proto.Rule {
		return proto.Rule{
			ID: id, Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: lo, Hi: hi},
			Target: fmt.Sprintf("192.168.1.20:%d", targetPort), VPSMode: proto.ModeKernel, Enabled: true,
			SourceAllow: []netip.Prefix{}, SourceDeny: []netip.Prefix{},
		}
	}
	rC := rule("r_c", 2460, 2461, 2460)
	rC.SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, rule("r_a", 2456, 2457, 2456), rule("r_b", 2458, 2459, 2458), rC), nil
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(st, &fakeBackend{st: st}))
	t.Cleanup(srv.Close)
	return srv, st
}

// TestRuleDetailShowsSplitAndMergeSections は詳細ページに分割・統合の両区画が出て、
// 統合区画には合う隣接ルール(r_b)だけが候補として出ることを確かめる(仕様 10.1 節)。
func TestRuleDetailShowsSplitAndMergeSections(t *testing.T) {
	srv, _ := newSplitMergeTestServer(t)

	resp, err := http.Get(srv.URL + "/ui/rules/r_a?lang=en")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)

	if !strings.Contains(s, `id="split-at"`) || !strings.Contains(s, `<option value="2457">2457</option>`) {
		t.Errorf("split section missing the split-point select with port 2457: %s", s)
	}
	if !strings.Contains(s, `action="/ui/rules/r_a/merge"`) || !strings.Contains(s, `value="r_b"`) {
		t.Errorf("merge section missing a candidate button for r_b: %s", s)
	}
	if strings.Contains(s, `value="r_c"`) {
		t.Errorf("merge section must not offer r_c (not adjacent to r_a): %s", s)
	}
}

// TestRuleDetailSplitPortsAtUint16Boundary は、listen_port が uint16 の最大値を含む
// 範囲(65534-65535)のルールの詳細ページを開いても固まらないことを確かめる。分割位置の
// 選択肢を Lo+1 から Hi まで uint16 のまま回すと、p が 65535 に達した直後の p++ が 0 に
// 折り返り、p <= Hi(65535)が恒に真になって無限ループになるため、client の Timeout で
// その場合は必ず失敗させる。
func TestRuleDetailSplitPortsAtUint16Boundary(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, proto.Rule{
			ID: "r_edge", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 65534, Hi: 65535},
			Target: "192.168.1.20:65534", VPSMode: proto.ModeKernel, Enabled: true,
			SourceAllow: []netip.Prefix{}, SourceDeny: []netip.Prefix{},
		}), nil
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(st, &fakeBackend{st: st}))
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(srv.URL + "/ui/rules/r_edge?lang=en")
	if err != nil {
		t.Fatalf("opening the detail page for listen_port=65534-65535 did not return in time (uint16 wraparound infinite loop?): %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, `<option value="65535">65535</option>`) {
		t.Errorf("split section missing the boundary port 65535: %s", s)
	}
}

// TestRuleDetailSplit はルール詳細ページからの分割を確かめる。head は元の ID のまま
// 縮まり、tail は実効宛先を保った新しい ID で作られ、どちらも 1 バッチで反映される
// (仕様 5.4、10.1 節)。
func TestRuleDetailSplit(t *testing.T) {
	srv, st := newSplitMergeTestServer(t)

	resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/split", url.Values{"at": {"2457"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if req := resp.Request; req == nil || !strings.HasSuffix(req.URL.Path, "/ui/rules/r_a") {
		t.Errorf("split must redirect to the head's (unchanged) detail page, got %v", req)
	}

	rules, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	head := findRuleT(t, st, "r_a")
	if head.ListenPort != (proto.PortRange{Lo: 2456, Hi: 2456}) {
		t.Errorf("head listen_port = %v, want 2456", head.ListenPort)
	}
	var tail *proto.Rule
	for i := range rules {
		if rules[i].ListenPort == (proto.PortRange{Lo: 2457, Hi: 2457}) {
			tail = &rules[i]
		}
	}
	if tail == nil {
		t.Fatal("no rule covers the split-off port 2457")
	}
	if tail.Target != "192.168.1.20:2457" {
		t.Errorf("tail target = %q, want 192.168.1.20:2457 (unchanged effective target)", tail.Target)
	}
}

// TestRuleDetailSplitInvalid は範囲外の分割位置が誤りとして再表示され、何も変えないことを
// 確かめる。
func TestRuleDetailSplitInvalid(t *testing.T) {
	srv, st := newSplitMergeTestServer(t)
	before, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/split", url.Values{"at": {"9999"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invalid split status = %d, want 200 (re-rendered with the error)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "must be inside range") {
		t.Errorf("expected an out-of-range error: %s", body)
	}
	after, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("an invalid split must not change the rule count: before=%d after=%d", len(before), len(after))
	}
}

// TestRuleDetailMerge は統合が self(パスの r_a)の ID を残し、other(r_b)を削除して
// listen_port を広げることを確かめる(仕様 10.1、10.2 節)。
func TestRuleDetailMerge(t *testing.T) {
	srv, st := newSplitMergeTestServer(t)

	resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/merge", url.Values{"other": {"r_b"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if req := resp.Request; req == nil || !strings.HasSuffix(req.URL.Path, "/ui/rules/r_a") {
		t.Errorf("merge must redirect to self's (surviving) detail page, got %v", req)
	}

	merged := findRuleT(t, st, "r_a")
	if merged.ListenPort != (proto.PortRange{Lo: 2456, Hi: 2459}) {
		t.Errorf("merged listen_port = %v, want 2456-2459", merged.ListenPort)
	}
	rules, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.ID == "r_b" {
			t.Error("r_b must be deleted after merging into r_a")
		}
	}
}

// TestRuleDetailMergeRejectsBlocked は、条件の揃わない隣接ルールとの統合が誤りとして
// 再表示され、理由(拒否リストの違い)を含むことを確かめる(仕様 10.1 節)。
func TestRuleDetailMergeRejectsBlocked(t *testing.T) {
	srv, st := newSplitMergeTestServer(t)

	resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/merge", url.Values{"other": {"r_c"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("blocked merge status = %d, want 200 (re-rendered with the error)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "not adjacent") {
		t.Errorf("expected the not-adjacent reason (r_a and r_c are not adjacent): %s", body)
	}
	if r := findRuleT(t, st, "r_a"); r.ListenPort != (proto.PortRange{Lo: 2456, Hi: 2457}) {
		t.Errorf("a rejected merge must not change r_a: %v", r.ListenPort)
	}
}

// TestMergeSection は統合区画のビュー組み立て(仕様 10.1 節)を確かめる。r_a に、
// 統合できる隣接ルール(r_b)と統合できない隣接ルール(r_c、拒否リストが違う)の両方が
// あるとき、候補には合う方だけが出て、理由は出ない(候補が 1 つでもあれば理由は出さない)。
// r_e には隣接ルールが無く候補も理由も出ない。r_g には統合できない隣接ルール(r_f)しか
// 無いので、候補は空で理由が出る。
func TestMergeSection(t *testing.T) {
	base := func(id string, lo, hi uint16, targetPort int) proto.Rule {
		return proto.Rule{
			ID: id, Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: lo, Hi: hi},
			Target: fmt.Sprintf("192.168.1.20:%d", targetPort), VPSMode: proto.ModeKernel, Enabled: true,
		}
	}
	rA := base("r_a", 2456, 2457, 2456)
	rB := base("r_b", 2458, 2459, 2458) // r_a と揃っていて隣接:候補
	rC := base("r_c", 2460, 2461, 2460)
	rC.SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")} // r_b の上に隣接、拒否リストが違う
	rE := base("r_e", 3000, 3000, 3000)                                     // 隣接ルールなし
	rF := base("r_f", 3100, 3101, 3100)
	rG := base("r_g", 3102, 3102, 3102)
	rG.Enabled = false // r_f の上に隣接、enabled が違う(候補は無く理由だけ出る)
	all := []proto.Rule{rA, rB, rC, rE, rF, rG}

	cands, blocked := mergeSection(rA, all, "en")
	if len(cands) != 1 || cands[0].ID != "r_b" {
		t.Fatalf("r_a candidates = %+v, want just r_b", cands)
	}
	if blocked != nil {
		t.Errorf("r_a: blocked = %+v, want nil (a candidate exists)", blocked)
	}

	cands, blocked = mergeSection(rE, all, "en")
	if len(cands) != 0 || blocked != nil {
		t.Errorf("r_e (no neighbors): candidates = %+v, blocked = %+v, want both empty", cands, blocked)
	}

	cands, blocked = mergeSection(rG, all, "en")
	if len(cands) != 0 {
		t.Errorf("r_g candidates = %+v, want none", cands)
	}
	if blocked == nil || blocked.ID != "r_f" || blocked.Reason != "enabled state differs" {
		t.Fatalf("r_g blocked = %+v, want r_f with reason %q", blocked, "enabled state differs")
	}
	if got := mergeBlockerLabel(proto.BlockDenyList, "ja"); got != "拒否リストが違う" {
		t.Errorf("mergeBlockerLabel(BlockDenyList, ja) = %q, want %q", got, "拒否リストが違う")
	}
}
