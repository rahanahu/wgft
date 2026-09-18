package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、webui_rule.go にあるルール追加フォームと、ルール詳細ページの
// メタ情報・拒否/許可リスト・レート制限のテストを持つ。分割・統合は
// webui_splitmerge_test.go に分ける。

// TestAddRuleFormFollowsMode は、ルール追加フォームがサーバーの転送方式(kernel/userspace)に
// 応じて出し分けることを確かめる(仕様 6.3 節)。userspace ではルールごとの kernel/proxy の
// 選択に意味が無いので、ラジオ群を出さず PROXY protocol のチェックボックス 1 つにする。
func TestAddRuleFormFollowsMode(t *testing.T) {
	get := func(t *testing.T, mode string) string {
		t.Helper()
		st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		srv := httptest.NewServer(New(st, &fakeBackend{st: st, mode: mode}))
		defer srv.Close()
		resp, err := http.Get(srv.URL + "/ui/add-rule")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /ui/add-rule status = %d, want 200", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	t.Run("kernel", func(t *testing.T) {
		body := get(t, "kernel")
		if !strings.Contains(body, `name="vps_mode" value="kernel"`) || !strings.Contains(body, `name="vps_mode" value="proxy"`) {
			t.Error("kernel mode: expected the vps_mode radio group to be present")
		}
		if strings.Contains(body, `id="f-proxy-userspace"`) {
			t.Error("kernel mode: unexpected userspace PROXY protocol checkbox")
		}
	})

	t.Run("userspace", func(t *testing.T) {
		body := get(t, "userspace")
		if strings.Contains(body, `name="vps_mode" value="kernel" checked`) || strings.Contains(body, `name="vps_mode" value="proxy"`) {
			t.Error("userspace mode: the vps_mode radio group must be absent")
		}
		if !strings.Contains(body, `id="f-proxy-userspace"`) || !strings.Contains(body, `type="checkbox"`) {
			t.Error("userspace mode: expected the PROXY protocol checkbox")
		}
		if !strings.Contains(body, `id="f-vps-mode-userspace"`) {
			t.Error("userspace mode: expected the hidden vps_mode field the checkbox drives")
		}
	})
}

// newDetailTestServer は 1 件のルール(r_a, UDP 2456-2457)を持つ管理 API サーバーを立てる。
// ルール詳細ページのテストで使う。
func newDetailTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, proto.Rule{
			ID: "r_a", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2457},
			Target: "192.168.1.20:2456", VPSMode: proto.ModeKernel, Enabled: true,
			SourceAllow: []netip.Prefix{}, SourceDeny: []netip.Prefix{},
		}), nil
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(st, &fakeBackend{st: st}))
	t.Cleanup(srv.Close)
	return srv, st
}

// TestRuleDetailDenyList は拒否リストの追加・削除と、不正な行の扱いを確かめる(仕様 10.1 節)。
func TestRuleDetailDenyList(t *testing.T) {
	srv, st := newDetailTestServer(t)

	// 不正な行が 1 つでもあれば何も保存せず、その行番号と内容を含むエラーを返す
	resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/deny/add", url.Values{"cidrs": {"203.0.113.7\nnot-a-cidr"}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invalid deny add status = %d, want 200 (re-rendered with the error)", resp.StatusCode)
	}
	if !strings.Contains(string(body), "line 2") || !strings.Contains(string(body), "not-a-cidr") {
		t.Errorf("error must name the bad line: %s", body)
	}
	if !strings.Contains(string(body), "203.0.113.7\nnot-a-cidr") {
		t.Error("the textarea must keep the entered input on error")
	}
	if len(findRuleT(t, st, "r_a").SourceDeny) != 0 {
		t.Fatal("invalid deny add must not save anything")
	}

	// 単独アドレスは /32 で補い、重複は加えない
	resp, err = http.PostForm(srv.URL+"/ui/rules/r_a/deny/add", url.Values{"cidrs": {"203.0.113.7\n203.0.113.7"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := findRuleT(t, st, "r_a").SourceDeny; len(got) != 1 || got[0].String() != "203.0.113.7/32" {
		t.Fatalf("deny add = %v, want a single 203.0.113.7/32", got)
	}

	resp, err = http.Get(srv.URL + "/ui/rules/r_a")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "203.0.113.7/32") {
		t.Errorf("detail page must list the deny entry: %s", body)
	}

	resp, err = http.PostForm(srv.URL+"/ui/rules/r_a/deny/rm", url.Values{"cidr": {"203.0.113.7"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := findRuleT(t, st, "r_a").SourceDeny; len(got) != 0 {
		t.Fatalf("deny rm = %v, want empty", got)
	}
}

// TestRuleDetailAllowListConfirm は、許可リストを空から作る操作と、最後の 1 件を外す操作に
// data-confirm が付くことを確かめる(全開放/全遮断に変わる操作。仕様 10.1 節)。
func TestRuleDetailAllowListConfirm(t *testing.T) {
	srv, st := newDetailTestServer(t)

	get := func() string {
		resp, err := http.Get(srv.URL + "/ui/rules/r_a")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	// リストが空の間、追加フォームは確認を求める
	body := get()
	if !strings.Contains(body, `action="/ui/rules/r_a/allow/add"`) || !strings.Contains(body, T("ja", "confirmAllowFirst")) {
		t.Errorf("the allow add form must carry a confirm message while the list is empty: %s", body)
	}

	resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/allow/add", url.Values{"cidrs": {"198.51.100.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := findRuleT(t, st, "r_a").SourceAllow; len(got) != 1 {
		t.Fatalf("allow add = %v, want 1 entry", got)
	}

	// 1 件だけになった後は、追加フォームに確認は要らず、その 1 件の削除フォームに確認が付く
	body = get()
	if strings.Contains(body, `action="/ui/rules/r_a/allow/add" class="inline-form" data-confirm=`) {
		t.Errorf("the allow add form must not require confirmation once the list is non-empty: %s", body)
	}
	if !strings.Contains(body, `action="/ui/rules/r_a/allow/rm" data-confirm="`+T("ja", "confirmAllowLast")+`"`) {
		t.Errorf("removing the sole allow entry must carry a confirm message: %s", body)
	}

	resp, err = http.PostForm(srv.URL+"/ui/rules/r_a/allow/rm", url.Values{"cidr": {"198.51.100.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := findRuleT(t, st, "r_a").SourceAllow; len(got) != 0 {
		t.Fatalf("allow rm = %v, want empty", got)
	}
}

// TestRuleDetailRates はレート制限の保存と「制限しない」による解除を確かめる(仕様 10.1 節)。
func TestRuleDetailRates(t *testing.T) {
	srv, st := newDetailTestServer(t)

	post := func(vals url.Values) *http.Response {
		resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/rates", vals)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// 値の入っていない欄は、no limit のチェックが無ければ誤りとして何も保存しない
	resp := post(url.Values{
		"per_source_count": {""}, "per_source_unit": {"second"},
		"new_flow_nolimit": {"1"}, "new_flow_unit": {"second"},
		"packet_nolimit": {"1"}, "packet_unit": {"second"},
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("missing value without no-limit: status = %d, want 200 (re-rendered with the error)", resp.StatusCode)
	}
	if !strings.Contains(string(body), T("ja", "rateRequired")) {
		t.Errorf("expected the rateRequired message: %s", body)
	}
	if r := findRuleT(t, st, "r_a"); r.PerSourceRate != nil || r.NewFlowRate != nil || r.PacketRate != nil {
		t.Fatalf("an invalid rate submission must not save anything: %+v", r)
	}

	// 有効な値は保存され、Rate.String() の形で読める
	resp = post(url.Values{
		"per_source_count": {"10"}, "per_source_unit": {"minute"},
		"new_flow_nolimit": {"1"}, "new_flow_unit": {"second"},
		"packet_nolimit": {"1"}, "packet_unit": {"second"},
	})
	resp.Body.Close()
	r := findRuleT(t, st, "r_a")
	if r.PerSourceRate == nil || r.PerSourceRate.String() != "10/minute" {
		t.Fatalf("per_source_rate = %v, want 10/minute", r.PerSourceRate)
	}
	if r.NewFlowRate != nil || r.PacketRate != nil {
		t.Fatalf("new_flow_rate/packet_rate must stay unset: %+v", r)
	}

	// no limit に切り替えると外れる
	resp = post(url.Values{
		"per_source_nolimit": {"1"}, "per_source_unit": {"minute"},
		"new_flow_nolimit": {"1"}, "new_flow_unit": {"second"},
		"packet_nolimit": {"1"}, "packet_unit": {"second"},
	})
	resp.Body.Close()
	if r := findRuleT(t, st, "r_a"); r.PerSourceRate != nil {
		t.Fatalf("per_source_rate after no-limit = %v, want nil", r.PerSourceRate)
	}
}

// TestRuleDetailRateWording は、レート制限の見出しと補足文言(10.1 節。パケット制限を
// 接続数の制限と誤読されないための言い直し)を確かめる。見出しの言い直し、このルールの
// 累積 drop 数(一覧と同じ値)、パケット欄が既定では折りたたまれていて値が入っていると
// 開くこと、値を入れた欄に読み上げの一文が付くことを、ja/en 両方で見る。
func TestRuleDetailRateWording(t *testing.T) {
	srv, _ := newDetailTestServer(t)

	get := func(lang string) string { return getBody(t, srv.URL+"/ui/rules/r_a?lang="+lang) }

	ja, en := get("ja"), get("en")
	for _, tc := range []struct{ ja, en string }{
		{"1 つの接続元からの新しい接続", "New connections per source"},
		{"ルール全体の新しい接続", "New connections for the whole rule"},
		{"パケット (通信中のデータも含む)", "Packets (including ongoing traffic)"},
		{"拒否 42 件", "42 dropped"}, // fakeBackend.RuleDrops: r_a=42
	} {
		if !strings.Contains(ja, tc.ja) {
			t.Errorf("ja: missing %q", tc.ja)
		}
		if !strings.Contains(en, tc.en) {
			t.Errorf("en: missing %q", tc.en)
		}
	}
	// no rate set yet: the packet section stays collapsed and no summary sentence appears
	if strings.Contains(ja, `class="advanced" open`) {
		t.Error("packet details must be collapsed when no packet limit is set")
	}
	if strings.Contains(ja, "本まで") || strings.Contains(en, "Up to") {
		t.Error("no summary sentence should appear before a rate is set")
	}

	// setting per_source only: its summary sentence reads back the value
	resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/rates", url.Values{
		"per_source_count": {"10"}, "per_source_unit": {"minute"},
		"new_flow_nolimit": {"1"}, "new_flow_unit": {"second"},
		"packet_nolimit": {"1"}, "packet_unit": {"second"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	ja, en = get("ja"), get("en")
	if !strings.Contains(ja, "1 つの接続元から 1 分に 10 本まで") {
		t.Errorf("ja: missing the per-source summary sentence: %s", ja)
	}
	if !strings.Contains(en, "Up to 10 new connections per minute from one source") {
		t.Errorf("en: missing the per-source summary sentence: %s", en)
	}
	if strings.Contains(ja, `class="advanced" open`) {
		t.Error("packet details must stay collapsed while packet_rate has no limit")
	}

	// setting packet_rate opens the (otherwise collapsed) packet section by default
	resp, err = http.PostForm(srv.URL+"/ui/rules/r_a/rates", url.Values{
		"per_source_nolimit": {"1"}, "per_source_unit": {"second"},
		"new_flow_nolimit": {"1"}, "new_flow_unit": {"second"},
		"packet_count": {"500"}, "packet_unit": {"second"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	ja, en = get("ja"), get("en")
	if !strings.Contains(ja, `class="advanced" open`) {
		t.Error("packet details must open by default once packet_rate has a value")
	}
	if !strings.Contains(ja, "1 秒に 500 個まで") {
		t.Errorf("ja: missing the packet summary sentence: %s", ja)
	}
	if !strings.Contains(en, "Up to 500 packets per second") {
		t.Errorf("en: missing the packet summary sentence: %s", en)
	}
}

// TestRuleDetailMeta は、詳細ページに取り込まれたグループ/説明の編集がルール詳細ページへ戻ることを確かめる。
func TestRuleDetailMeta(t *testing.T) {
	srv, st := newDetailTestServer(t)
	resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/meta", url.Values{"group": {"valheim"}, "note": {"weekend"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if req := resp.Request; req == nil || !strings.HasSuffix(req.URL.Path, "/ui/rules/r_a") {
		t.Errorf("saving meta must redirect back to the detail page, got %v", req)
	}
	r := findRuleT(t, st, "r_a")
	if r.Group != "valheim" || r.Note != "weekend" {
		t.Errorf("meta not saved: group=%q note=%q", r.Group, r.Note)
	}
}

// TestAddRuleDisabled は、追加フォームの「無効のまま追加する」チェックボックスが
// enabled=false でルールを作ることを確かめる(仕様 10.1 節、rule add --disabled 相当)。
func TestAddRuleDisabled(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer(New(st, &fakeBackend{st: st}))
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/ui/add-rule", url.Values{
		"agent": {"home"}, "proto": {"tcp"}, "listen_port": {"25565"}, "target": {"192.168.1.20:25565"},
		"vps_mode": {"kernel"}, "disabled": {"1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	rules, err := st.Rules()
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules = %v, %v", rules, err)
	}
	if rules[0].Enabled {
		t.Error("the disabled checkbox must add the rule with enabled=false")
	}
}
