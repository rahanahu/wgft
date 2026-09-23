package admin

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
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
		srv := httptest.NewServer(New(&fakeBackend{st: st, mode: mode}))
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
	srv := httptest.NewServer(New(&fakeBackend{st: st}))
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
		resp, _ := postSettings(t, srv.URL, "r_a", vals)
		return resp
	}

	// 値の入っていない欄は、no limit のチェックが無ければ誤りとして何も保存しない
	resp, body := postSettings(t, srv.URL, "r_a", url.Values{
		"per_source_count": {""}, "per_source_unit": {"second"},
		"new_flow_nolimit": {"1"}, "new_flow_unit": {"second"},
		"packet_nolimit": {"1"}, "packet_unit": {"second"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("missing value without no-limit: status = %d, want 200 (re-rendered with the error)", resp.StatusCode)
	}
	if !strings.Contains(body, T("ja", "rateRequired")) {
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
		{"パケット (通信中のデータも含む)", "Packets, including ongoing traffic"},
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
	resp, _ := postSettings(t, srv.URL, "r_a", url.Values{
		"per_source_count": {"10"}, "per_source_unit": {"minute"},
		"new_flow_nolimit": {"1"}, "new_flow_unit": {"second"},
		"packet_nolimit": {"1"}, "packet_unit": {"second"},
	})
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
	resp, _ = postSettings(t, srv.URL, "r_a", url.Values{
		"per_source_nolimit": {"1"}, "per_source_unit": {"second"},
		"new_flow_nolimit": {"1"}, "new_flow_unit": {"second"},
		"packet_count": {"500"}, "packet_unit": {"second"},
	})
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

// TestRuleDetailPacketRateTCPNotice は、TCP のルールに packet_rate があるとき、詳細ページと
// レート区画に「TCP には効かない」旨(design.md 7a.9 節。CLI の旨と文言を揃える)が出ること、
// UDP のルールやレートの無い TCP のルールには出ないこと、他の欄を保存しても保存済みの
// packet_rate が消えないことを確かめる。フォームは入力欄自体を無効にしない(disabled にすると
// ブラウザがその欄を送らず、他の欄の保存ごと拒まれるか、値を静かに消しかねないため)。
func TestRuleDetailPacketRateTCPNotice(t *testing.T) {
	srv, st := newDetailTestServer(t)

	rate := proto.Rate{Count: 500, Unit: proto.PerSecond}
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules,
			proto.Rule{
				ID: "r_tcp", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 25565, Hi: 25565},
				Target: "192.168.1.20:25565", VPSMode: proto.ModeKernel, Enabled: true,
				SourceAllow: []netip.Prefix{}, SourceDeny: []netip.Prefix{},
				PacketRate: &rate,
			},
			proto.Rule{
				ID: "r_tcp_norate", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 25566, Hi: 25566},
				Target: "192.168.1.20:25566", VPSMode: proto.ModeKernel, Enabled: true,
				SourceAllow: []netip.Prefix{}, SourceDeny: []netip.Prefix{},
			},
		), nil
	}); err != nil {
		t.Fatal(err)
	}

	// TCP + packet_rate: the notice renders in both locales, and the kernel-mode default
	// server (newDetailTestServer's fakeBackend leaves mode == "") also shows it, not just
	// userspace mode.
	ja, en := getBody(t, srv.URL+"/ui/rules/r_tcp?lang=ja"), getBody(t, srv.URL+"/ui/rules/r_tcp?lang=en")
	if !strings.Contains(ja, T("ja", "packetTCPNoEffectNote")) {
		t.Errorf("ja: TCP rule detail page must show the packet_rate notice: %s", ja)
	}
	if !strings.Contains(en, "packet_rate is stored but has no effect on TCP rules") {
		t.Errorf("en: TCP rule detail page must show the packet_rate notice: %s", en)
	}

	// r_a is UDP (no packet_rate at all in this fixture): no notice.
	udpBody := getBody(t, srv.URL+"/ui/rules/r_a?lang=en")
	if strings.Contains(udpBody, T("en", "packetTCPNoEffectNote")) {
		t.Errorf("a UDP rule must not show the TCP packet_rate notice: %s", udpBody)
	}

	// r_tcp_norate is TCP but has no stored packet_rate: no notice either. The notice
	// must depend on a stored packet_rate, not merely on the protocol being TCP.
	tcpNoRateBody := getBody(t, srv.URL+"/ui/rules/r_tcp_norate?lang=en")
	if strings.Contains(tcpNoRateBody, T("en", "packetTCPNoEffectNote")) {
		t.Errorf("a TCP rule without a stored packet_rate must not show the notice: %s", tcpNoRateBody)
	}

	// saving the rate form (per_source changes, packet field resubmits its current value
	// since it is not disabled) must keep the stored packet_rate.
	resp, _ := postSettings(t, srv.URL, "r_tcp", url.Values{
		"per_source_count": {"5"}, "per_source_unit": {"minute"},
		"new_flow_nolimit": {"1"}, "new_flow_unit": {"second"},
		"packet_count": {"500"}, "packet_unit": {"second"},
	})
	resp.Body.Close()
	r := findRuleT(t, st, "r_tcp")
	if r.PacketRate == nil || r.PacketRate.String() != "500/second" {
		t.Fatalf("packet_rate must survive saving the other rate fields: %+v", r.PacketRate)
	}
	if r.PerSourceRate == nil || r.PerSourceRate.String() != "5/minute" {
		t.Fatalf("per_source_rate = %v, want 5/minute", r.PerSourceRate)
	}
}

// ---- 設定の区画(group、note、レート制限を 1 つのフォームで保存する。仕様 10.1 節) ----

var (
	settingsFormRe = regexp.MustCompile(`(?s)<form method="post" action="([^"]*)"[^>]*id="settings-form"[^>]*>(.*?)</form>`)
	inputTagRe     = regexp.MustCompile(`<input\b[^>]*>`)
	selectRe       = regexp.MustCompile(`(?s)<select name="([^"]*)">(.*?)</select>`)
	optionRe       = regexp.MustCompile(`<option value="([^"]*)"\s*(selected)?\s*>`)
	attrNameRe     = regexp.MustCompile(`\bname="([^"]*)"`)
	attrValueRe    = regexp.MustCompile(`\bvalue="([^"]*)"`)
	attrTypeRe     = regexp.MustCompile(`\btype="([^"]*)"`)
)

// settingsFormHTML は詳細ページの HTML から設定フォームの中身を取り出す。
func settingsFormHTML(t *testing.T, page string) string {
	t.Helper()
	m := settingsFormRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("the page has no settings form: %s", page)
	}
	return m[2]
}

// settingsFormValues は、ブラウザが設定フォームをそのまま送るときの値を、描かれた HTML から
// 組み立てる(チェックの無いチェックボックスは送らず、select は選ばれた option の値を送る)。
func settingsFormValues(t *testing.T, page string) url.Values {
	t.Helper()
	form := settingsFormHTML(t, page)
	vals := url.Values{}
	for _, tag := range inputTagRe.FindAllString(form, -1) {
		name := attrNameRe.FindStringSubmatch(tag)
		if name == nil {
			continue
		}
		value := ""
		if m := attrValueRe.FindStringSubmatch(tag); m != nil {
			value = html.UnescapeString(m[1])
		}
		if typ := attrTypeRe.FindStringSubmatch(tag); typ != nil && typ[1] == "checkbox" && !strings.Contains(tag, " checked") {
			continue
		}
		vals.Add(name[1], value)
	}
	for _, sel := range selectRe.FindAllStringSubmatch(form, -1) {
		opts := optionRe.FindAllStringSubmatch(sel[2], -1)
		if len(opts) == 0 {
			continue
		}
		chosen := opts[0][1]
		for _, o := range opts {
			if o[2] != "" {
				chosen = o[1]
			}
		}
		vals.Set(sel[1], chosen)
	}
	return vals
}

// postSettings は詳細ページを開いて設定フォームを読み、set の欄だけを書き換えて送る。
// set にレート欄(<prefix>_count など)が 1 つでもあれば、その欄の 3 つの値を set で置き換える
// (「制限しない」を外すには set に <prefix>_nolimit を含めない)。応答の本文も返す。
func postSettings(t *testing.T, base, id string, set url.Values) (*http.Response, string) {
	t.Helper()
	return postSettingsForm(t, base, id, getBody(t, base+"/ui/rules/"+id), set)
}

// postSettingsForm は postSettings と同じだが、既に描かれたページ(page)のフォームから送る。
// ページを開いた後に別の場所で変更が入る場合を模すのに使う。
func postSettingsForm(t *testing.T, base, id, page string, set url.Values) (*http.Response, string) {
	t.Helper()
	form := settingsFormValues(t, page)
	for _, prefix := range []string{"per_source", "new_flow", "packet"} {
		touched := false
		for k := range set {
			if strings.HasPrefix(k, prefix+"_") {
				touched = true
			}
		}
		if touched {
			for _, suffix := range []string{"_count", "_unit", "_nolimit"} {
				form.Del(prefix + suffix)
			}
		}
	}
	for k, v := range set {
		form[k] = v
	}
	action := settingsFormRe.FindStringSubmatch(page)[1]
	if action != "/ui/rules/"+id+"/settings" {
		t.Fatalf("settings form action = %q", action)
	}
	resp, err := http.PostForm(base+action, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// setRuleInStore は、ページを開いた後の別の場所(CLI など)からの変更を模して、ストアの
// ルールを直接書き換える。
func setRuleInStore(t *testing.T, st *store.Store, id string, edit func(*proto.Rule)) {
	t.Helper()
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		for i := range rules {
			if rules[i].ID == id {
				edit(&rules[i])
			}
		}
		return rules, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func mustRate(t *testing.T, s string) *proto.Rate {
	t.Helper()
	r, err := proto.ParseRate(s)
	if err != nil {
		t.Fatal(err)
	}
	return &r
}

// newSettingsTestServer は、group、note、per_source_rate、packet_rate が入った r_a を持つ
// 詳細ページのテスト用サーバー。
func newSettingsTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	srv, st := newDetailTestServer(t)
	setRuleInStore(t, st, "r_a", func(r *proto.Rule) {
		r.Group, r.Note = "valheim", "weekend"
		r.PerSourceRate, r.PacketRate = mustRate(t, "10/minute"), mustRate(t, "500/second")
	})
	return srv, st
}

// ruleSettings はルールの設定の区画にあたる欄を、比べやすい 5 つの文字列にする。
func ruleSettings(r proto.Rule) [5]string {
	return [5]string{r.Group, r.Note, rateString(r.PerSourceRate), rateString(r.NewFlowRate), rateString(r.PacketRate)}
}

// TestRuleSettingsSavesOnlyChangedFields は、設定フォームの 1 つの保存ボタンで、利用者が
// 変えた欄だけが保存され、他の欄が保存値のまま残ることを確かめる(仕様 10.1 節)。レート欄は
// 保存値で埋めて描くので、説明だけを変えた保存がレート欄のせいで拒まれることは無い。
func TestRuleSettingsSavesOnlyChangedFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  url.Values
		want [5]string
	}{
		{"note only", url.Values{"note": {"friday night"}}, [5]string{"valheim", "friday night", "10/minute", "", "500/second"}},
		{"group only", url.Values{"group": {"survival"}}, [5]string{"survival", "weekend", "10/minute", "", "500/second"}},
		{"per-source rate only", url.Values{"per_source_count": {"20"}, "per_source_unit": {"hour"}}, [5]string{"valheim", "weekend", "20/hour", "", "500/second"}},
		{"new-flow rate only", url.Values{"new_flow_count": {"100"}, "new_flow_unit": {"second"}}, [5]string{"valheim", "weekend", "10/minute", "100/second", "500/second"}},
		{"packet rate to no limit", url.Values{"packet_nolimit": {"1"}, "packet_unit": {"second"}}, [5]string{"valheim", "weekend", "10/minute", "", ""}},
		{"nothing changed", url.Values{}, [5]string{"valheim", "weekend", "10/minute", "", "500/second"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, st := newSettingsTestServer(t)
			resp, body := postSettings(t, srv.URL, "r_a", tc.set)
			if req := resp.Request; req == nil || req.Method != http.MethodGet || !strings.HasSuffix(req.URL.Path, "/ui/rules/r_a") {
				t.Fatalf("saving must redirect back to the detail page; got %v: %s", req, body)
			}
			if got := ruleSettings(findRuleT(t, st, "r_a")); got != tc.want {
				t.Errorf("saved settings = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRuleSettingsInvalidKeepsInput は、レート欄の誤りがあると何も保存せず、その欄に誤りを
// 示し、利用者が入力した説明やグループを残して描き直すことを確かめる。
func TestRuleSettingsInvalidKeepsInput(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
		set          url.Values
		wantErr      string
	}{
		{"per-source empty", "per_source", url.Values{"per_source_count": {""}, "per_source_unit": {"minute"}}, T("ja", "rateRequired")},
		{"new-flow zero", "new_flow", url.Values{"new_flow_count": {"0"}, "new_flow_unit": {"second"}}, "count is not a positive integer"},
		{"packet empty", "packet", url.Values{"packet_count": {""}, "packet_unit": {"second"}}, T("ja", "rateRequired")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, st := newSettingsTestServer(t)
			before := ruleSettings(findRuleT(t, st, "r_a"))
			set := url.Values{"note": {"typed note"}, "group": {"typed-group"}}
			for k, v := range tc.set {
				set[k] = v
			}
			resp, body := postSettings(t, srv.URL, "r_a", set)
			if resp.StatusCode != http.StatusOK || resp.Request.Method != http.MethodPost {
				t.Fatalf("an invalid submission must re-render the page, got status %d via %s", resp.StatusCode, resp.Request.Method)
			}
			if got := ruleSettings(findRuleT(t, st, "r_a")); got != before {
				t.Errorf("an invalid submission must save nothing: %q, want %q", got, before)
			}
			form := settingsFormHTML(t, body)
			if !strings.Contains(form, `name="note" value="typed note"`) || !strings.Contains(form, `name="group" value="typed-group"`) {
				t.Errorf("the typed group and note must stay in the form: %s", form)
			}
			// 誤りはその欄のブロック(その欄の入力から次のレート欄の手前まで)に出る
			start := strings.Index(form, `name="`+tc.prefix+`_count"`)
			if start < 0 {
				t.Fatalf("no %s_count input: %s", tc.prefix, form)
			}
			block := form[start:]
			if end := strings.Index(block, `class="rate-field"`); end >= 0 {
				block = block[:end]
			}
			if !strings.Contains(block, `<p class="danger-text">`) || !strings.Contains(block, html.EscapeString(tc.wantErr)) {
				t.Errorf("the error %q must be shown at the %s field: %s", tc.wantErr, tc.prefix, block)
			}
			if !strings.Contains(body, T("ja", "settingsInvalid")) {
				t.Errorf("missing the not-saved message: %s", body)
			}
			// 描き直したフォームは、描いた時点の保存値(hidden)を送られたまま持つ
			vals := settingsFormValues(t, body)
			if vals.Get("orig_note") != "weekend" || vals.Get("orig_per_source") != "10/minute" || vals.Get("orig_packet") != "500/second" {
				t.Errorf("the re-rendered form must keep the original values: %v", vals)
			}
			// 要約の説明は保存値のまま(入力中の説明を保存済みのように見せない)
			if !strings.Contains(body, `<p class="muted">weekend</p>`) || strings.Contains(body, `<p class="muted">typed note</p>`) {
				t.Error("the header must show the stored note, not the typed one")
			}
			if tc.prefix == "packet" && !strings.Contains(form, `class="advanced" open`) {
				t.Error("the packet details must be open when the packet field has an error")
			}
		})
	}
}

// TestRuleSettingsConcurrentChange は、ページを開いた後に別の場所(CLI など)で変わった欄を
// 上書きしないことを確かめる(仕様 10.1 節)。利用者が変えていない欄の変更は残り、利用者も
// 変えた欄の変更は、何も保存せず今の値を示し、利用者の入力を残して描き直す。描き直した
// フォームを確かめてから送り直すと、利用者の値が入る。
func TestRuleSettingsConcurrentChange(t *testing.T) {
	for _, tc := range []struct {
		name      string
		elsewhere func(*proto.Rule)
		set       url.Values
		// conflict が空なら保存され want になる。空でなければ何も保存せず(ストアは別の場所の
		// 変更のまま)、その欄に今の値の表示 conflict が出て、送り直すと wantAfterRetry になる。
		want           [5]string
		conflict       string
		wantAfterRetry [5]string
		// wantPacketOpen は、描き直したページでパケットの制限の詳細が開いていること
		wantPacketOpen bool
	}{
		{
			name:      "rate changed elsewhere, note changed here",
			elsewhere: func(r *proto.Rule) { r.PerSourceRate = mustRate(t, "99/second") },
			set:       url.Values{"note": {"friday night"}},
			want:      [5]string{"valheim", "friday night", "99/second", "", "500/second"},
		},
		{
			name:      "note changed elsewhere, rate changed here",
			elsewhere: func(r *proto.Rule) { r.Note = "from the cli" },
			set:       url.Values{"packet_count": {"800"}, "packet_unit": {"second"}},
			want:      [5]string{"valheim", "from the cli", "10/minute", "", "800/second"},
		},
		{
			name:      "same field to the same value",
			elsewhere: func(r *proto.Rule) { r.Group = "survival" },
			set:       url.Values{"group": {"survival"}, "note": {"friday night"}},
			want:      [5]string{"survival", "friday night", "10/minute", "", "500/second"},
		},
		{
			name:           "rate changed in both places",
			elsewhere:      func(r *proto.Rule) { r.PerSourceRate = mustRate(t, "99/second") },
			set:            url.Values{"per_source_count": {"20"}, "per_source_unit": {"minute"}, "note": {"friday night"}},
			conflict:       fmt.Sprintf(T("ja", "settingsCurrentFmt"), "99 / 秒"),
			wantAfterRetry: [5]string{"valheim", "friday night", "20/minute", "", "500/second"},
		},
		{
			name:           "rate removed elsewhere, changed here",
			elsewhere:      func(r *proto.Rule) { r.PacketRate = nil },
			set:            url.Values{"packet_count": {"800"}, "packet_unit": {"second"}},
			conflict:       fmt.Sprintf(T("ja", "settingsCurrentFmt"), T("ja", "noLimit")),
			wantAfterRetry: [5]string{"valheim", "weekend", "10/minute", "", "800/second"},
		},
		{
			name:           "note changed in both places",
			elsewhere:      func(r *proto.Rule) { r.Note = "from the cli" },
			set:            url.Values{"note": {"friday night"}},
			conflict:       fmt.Sprintf(T("ja", "settingsCurrentFmt"), "from the cli"),
			wantAfterRetry: [5]string{"valheim", "friday night", "10/minute", "", "500/second"},
		},
		{
			name:           "group changed in both places",
			elsewhere:      func(r *proto.Rule) { r.Group = "from-cli" },
			set:            url.Values{"group": {"survival"}},
			conflict:       fmt.Sprintf(T("ja", "settingsCurrentFmt"), "from-cli"),
			wantAfterRetry: [5]string{"survival", "weekend", "10/minute", "", "500/second"},
		},
		{
			// 食い違った欄の他に、利用者が触れていない欄(note と packet_rate)も別の場所で
			// 変わっている。描き直しはそれらを今の値で埋めるので、送り直しても消えない。
			name: "conflict plus untouched fields changed elsewhere",
			elsewhere: func(r *proto.Rule) {
				r.PerSourceRate, r.PacketRate, r.Note = mustRate(t, "99/second"), mustRate(t, "700/second"), "from the cli"
			},
			set:            url.Values{"per_source_count": {"20"}, "per_source_unit": {"minute"}},
			conflict:       fmt.Sprintf(T("ja", "settingsCurrentFmt"), "99 / 秒"),
			wantAfterRetry: [5]string{"valheim", "from the cli", "20/minute", "", "700/second"},
		},
		{
			// 利用者が触れていない group が別の場所で変わり、別の欄が食い違う。描き直しは
			// group を今の値で埋めるので、送り直しても別の場所の group は消えない。
			name: "conflict plus untouched group changed elsewhere",
			elsewhere: func(r *proto.Rule) {
				r.PerSourceRate, r.Group = mustRate(t, "99/second"), "from-cli"
			},
			set:            url.Values{"per_source_count": {"20"}, "per_source_unit": {"minute"}},
			conflict:       fmt.Sprintf(T("ja", "settingsCurrentFmt"), "99 / 秒"),
			wantAfterRetry: [5]string{"from-cli", "weekend", "20/minute", "", "500/second"},
		},
		{
			// 利用者は「制限しない」を選んだので、入力欄の値だけでは詳細は開かない。
			// 食い違いの表示のために開く。
			name:           "packet changed elsewhere, cleared here",
			elsewhere:      func(r *proto.Rule) { r.PacketRate = mustRate(t, "700/second") },
			set:            url.Values{"packet_nolimit": {"1"}, "packet_unit": {"second"}},
			conflict:       fmt.Sprintf(T("ja", "settingsCurrentFmt"), "700 / 秒"),
			wantAfterRetry: [5]string{"valheim", "weekend", "10/minute", "", ""},
			wantPacketOpen: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, st := newSettingsTestServer(t)
			page := getBody(t, srv.URL+"/ui/rules/r_a")
			setRuleInStore(t, st, "r_a", tc.elsewhere)
			stored := ruleSettings(findRuleT(t, st, "r_a"))

			resp, body := postSettingsForm(t, srv.URL, "r_a", page, tc.set)
			if tc.conflict == "" {
				if resp.Request.Method != http.MethodGet {
					t.Fatalf("expected a save and a redirect, got a re-render: %s", body)
				}
				if got := ruleSettings(findRuleT(t, st, "r_a")); got != tc.want {
					t.Errorf("saved settings = %q, want %q", got, tc.want)
				}
				return
			}

			if resp.StatusCode != http.StatusOK || resp.Request.Method != http.MethodPost {
				t.Fatalf("a conflicting save must re-render the page, got status %d via %s", resp.StatusCode, resp.Request.Method)
			}
			if got := ruleSettings(findRuleT(t, st, "r_a")); got != stored {
				t.Errorf("a conflicting save must not change the rule: %q, want %q", got, stored)
			}
			if !strings.Contains(body, T("ja", "settingsConflict")) {
				t.Errorf("missing the conflict message: %s", body)
			}
			form := settingsFormHTML(t, body)
			if tc.wantPacketOpen && !strings.Contains(form, `class="advanced" open`) {
				t.Error("the packet details must be open when the packet field has a conflict")
			}
			if !strings.Contains(form, html.EscapeString(tc.conflict)) {
				t.Errorf("missing the current value %q at the field: %s", tc.conflict, form)
			}
			vals := settingsFormValues(t, body)
			for k := range tc.set {
				if vals.Get(k) != tc.set.Get(k) {
					t.Errorf("the user's input %s=%q must be kept, got %q", k, tc.set.Get(k), vals.Get(k))
				}
			}

			// 描き直したフォームをそのまま送り直すと、利用者の値が入る
			resp, body = postSettingsForm(t, srv.URL, "r_a", body, url.Values{})
			if resp.Request.Method != http.MethodGet {
				t.Fatalf("resubmitting the reviewed form must save: %s", body)
			}
			if got := ruleSettings(findRuleT(t, st, "r_a")); got != tc.wantAfterRetry {
				t.Errorf("after resubmitting: %q, want %q", got, tc.wantAfterRetry)
			}
		})
	}
}

// TestRuleSettingsBatchConflict は、今の値を読んでから保存を確定するまでの間に別の場所の
// 書き込みが割り込んだ場合(Batch が ExpectedDigest の不一致で拒む)も、何も保存せず入力を
// 残して描き直すことを確かめる。
func TestRuleSettingsBatchConflict(t *testing.T) {
	_, st := newSettingsTestServer(t)
	srv := httptest.NewServer(New(&conflictOnceBackend{fakeBackend: &fakeBackend{st: st}}))
	defer srv.Close()
	before := ruleSettings(findRuleT(t, st, "r_a"))
	resp, body := postSettings(t, srv.URL, "r_a", url.Values{"note": {"friday night"}})
	if resp.Request.Method != http.MethodPost || !strings.Contains(body, T("ja", "settingsRaced")) {
		t.Fatalf("a batch conflict must re-render with the raced message: %s", body)
	}
	if got := ruleSettings(findRuleT(t, st, "r_a")); got != before {
		t.Errorf("a batch conflict must save nothing: %q, want %q", got, before)
	}
	if !strings.Contains(settingsFormHTML(t, body), `name="note" value="friday night"`) {
		t.Error("the typed note must stay in the form after a batch conflict")
	}
}

// TestRuleSettingsRequiresOriginalValues は、描いた時点の保存値(hidden)のどれか 1 つでも
// 無い送信を 400 で拒むことを確かめる。無いまま受けると、どの欄を利用者が変えたかを判定できない。
func TestRuleSettingsRequiresOriginalValues(t *testing.T) {
	for _, missing := range []string{"orig_group", "orig_note", "orig_per_source", "orig_new_flow", "orig_packet"} {
		t.Run(missing, func(t *testing.T) {
			srv, st := newSettingsTestServer(t)
			before := ruleSettings(findRuleT(t, st, "r_a"))
			form := settingsFormValues(t, getBody(t, srv.URL+"/ui/rules/r_a"))
			form.Set("note", "changed")
			form.Del(missing)
			resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/settings", form)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
			if got := ruleSettings(findRuleT(t, st, "r_a")); got != before {
				t.Errorf("nothing must be saved: %q", got)
			}
		})
	}
}

// TestRuleSettingsInvalidThenFixedKeepsConcurrentNote は、入力の誤りで描き直したフォームが、
// 送られてきた描いた時点の保存値を持ち続けることを確かめる。ページを開いた後に CLI が説明を
// 変え、利用者はレート欄を誤って送り、直して送り直す。利用者は説明に触れていないので、
// CLI の説明が残る。
func TestRuleSettingsInvalidThenFixedKeepsConcurrentNote(t *testing.T) {
	srv, st := newSettingsTestServer(t)
	page := getBody(t, srv.URL+"/ui/rules/r_a")
	setRuleInStore(t, st, "r_a", func(r *proto.Rule) { r.Note = "from the cli" })
	resp, body := postSettingsForm(t, srv.URL, "r_a", page, url.Values{"per_source_count": {""}, "per_source_unit": {"minute"}})
	if resp.Request.Method != http.MethodPost || !strings.Contains(body, T("ja", "settingsInvalid")) {
		t.Fatalf("expected a validation re-render: %s", body)
	}
	resp, body = postSettingsForm(t, srv.URL, "r_a", body, url.Values{"per_source_count": {"20"}, "per_source_unit": {"minute"}})
	if resp.Request.Method != http.MethodGet {
		t.Fatalf("the fixed resubmission must save: %s", body)
	}
	if got, want := ruleSettings(findRuleT(t, st, "r_a")), [5]string{"valheim", "from the cli", "20/minute", "", "500/second"}; got != want {
		t.Errorf("after the fixed resubmission: %q, want %q", got, want)
	}
}

// TestRuleSettingsOddStoredNote は、改行や前後の空白を含む保存済みの説明(CLI の
// rule set --note や読み込みで入りうる)が、レートだけを変えた保存で書き換わらず、食い違い
// にもならないこと、説明を変えた保存も食い違いにならないことを確かめる。ブラウザは <input type="text"> の値から改行を取り除き、
// hidden の値の改行を送信時に CRLF に揃えるので、その形で送る。
func TestRuleSettingsOddStoredNote(t *testing.T) {
	for _, tc := range []struct {
		name, stored string
		set          url.Values
		want         string // 保存後の note
	}{
		{"newline", "a\nb", url.Values{"orig_note": {"a\r\nb"}, "note": {"ab"}}, "a\nb"},
		{"edge spaces", " x ", url.Values{}, " x "},
		// 利用者が説明を変えた場合も、保存値の改行を別の場所の変更と取り違えない
		{"newline, note changed", "a\nb", url.Values{"orig_note": {"a\r\nb"}, "note": {"new"}}, "new"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, st := newSettingsTestServer(t)
			setRuleInStore(t, st, "r_a", func(r *proto.Rule) { r.Note = tc.stored })
			set := url.Values{"per_source_count": {"20"}, "per_source_unit": {"minute"}}
			for k, v := range tc.set {
				set[k] = v
			}
			resp, body := postSettings(t, srv.URL, "r_a", set)
			if resp.Request.Method != http.MethodGet {
				t.Fatalf("a rate-only save must not conflict: %s", body)
			}
			r := findRuleT(t, st, "r_a")
			if r.Note != tc.want {
				t.Errorf("note = %q, want %q", r.Note, tc.want)
			}
			if rateString(r.PerSourceRate) != "20/minute" {
				t.Errorf("per_source_rate = %v, want 20/minute", r.PerSourceRate)
			}
		})
	}
}

// TestRuleDetailSections は、詳細ページが設定、アクセス制御、ルール操作の 3 つの区画に
// この順で分かれ、設定の区画だけが 1 つの保存ボタンを持ち、拒否/許可リストと分割・統合が
// 設定のフォームの外にあることを、ja/en の両方で確かめる。
func TestRuleDetailSections(t *testing.T) {
	srv, _ := newSettingsTestServer(t)
	for _, lang := range []string{"ja", "en"} {
		t.Run(lang, func(t *testing.T) {
			page := getBody(t, srv.URL+"/ui/rules/r_a?lang="+lang)
			last := -1
			for _, key := range []string{"settingsHead", "accessHead", "ruleOpsHead"} {
				i := strings.Index(page, "<h2>"+T(lang, key)+"</h2>")
				if i < 0 {
					t.Fatalf("missing the %s heading %q", key, T(lang, key))
				}
				if i < last {
					t.Errorf("the %s heading is out of order", key)
				}
				last = i
			}
			if n := strings.Count(page, ">"+T(lang, "save")+"</button>"); n != 1 {
				t.Errorf("the page must have exactly one Save button, found %d", n)
			}
			form := settingsFormHTML(t, page)
			if n := strings.Count(form, `type="submit"`); n != 1 {
				t.Errorf("the settings form must have exactly one submit button, found %d", n)
			}
			for _, name := range []string{"group", "note", "per_source_count", "new_flow_count", "packet_count"} {
				if !strings.Contains(form, `name="`+name+`"`) {
					t.Errorf("the settings form must contain %s", name)
				}
			}
			for _, outside := range []string{"<form", "<textarea", `name="cidrs"`, `name="cidr"`, "/deny/", "/allow/", "/split", "/merge"} {
				if strings.Contains(form, outside) {
					t.Errorf("the settings form must not contain %q", outside)
				}
			}
			// 設定の区画はアクセス制御の見出しより前で閉じる
			if strings.Index(page, `id="settings-form"`) > strings.Index(page, "<h2>"+T(lang, "accessHead")+"</h2>") {
				t.Error("the settings form must come before the access control section")
			}
		})
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
	srv := httptest.NewServer(New(&fakeBackend{st: st}))
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
