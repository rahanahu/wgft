package admin

import (
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、テンプレートに直接書いてあった語を i18n に通した変更が戻らないことを確かめる。
// 日本語のラベルは i18n.go の中だけにあり、テンプレートは T を通して引く(CLAUDE.md の「コードと
// 出力の約束」)。語を片方の言語のまま直接書くと、もう一方のロケールでその語だけが切り替わらない。

// templateAction は Go のテンプレートの動作 {{ ... }} である。動作の中には T のキーや
// コメントが入るので、直接書いた語を探す前に取り除く。
var templateAction = regexp.MustCompile(`(?s)\{\{.*?\}\}`)

// TestTemplatesDoNotWriteProxyOrGenDirectly は、方式の列の PROXY protocol の印と、エージェントの
// 一覧の世代の見出しが、テンプレートの本文に直接書かれた形へ戻らないことを確かめる。この 2 語は
// かつて直接書いてあった。
//
// 守る範囲はこの 2 語だけである。テンプレートのすべての語が T を通ることは確かめていない。
// 照合は語の境界で、大文字と小文字を区別して行う。Generated のような語の一部や、Proxy のような
// 別の綴りには当たらない。動作の中の文字列、たとえば {{ "PROXY" }} も見ない。
//
// テンプレートには、意図して英語のままにしている語もある。この検査の対象ではないが、ここに
// 挙げておく。診断の画面(設計文書 10.2d 節)の Server、Agents、Rules、Check:、Result:、
// NOT AVAILABLE と、エージェントの行が無いときの no agent is named by any rule である。最後の文は、
// 隣のルール表の空の表示が T を通しているのと違い、CLI の `server doctor` が出す文と同じ所見の
// 自由文なので、10.2d 節の「所見の自由文は英語のまま」に当たる。ほかに、どちらの言語でも同じ
// 字面の WG:、VPS、TCP、UDP と、言語を切り替える JA、EN と、製品名の wgft がある。
func TestTemplatesDoNotWriteProxyOrGenDirectly(t *testing.T) {
	// 語と、その語を引くための i18n のキー。
	words := map[string]string{
		"PROXY": "modeProxyProto",
		"Gen":   "gen",
	}

	entries, err := tmplFS.ReadDir("webui/templates")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no template was embedded, so this check would pass without looking at anything")
	}
	for _, e := range entries {
		b, err := tmplFS.ReadFile("webui/templates/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		text := templateAction.ReplaceAllString(string(b), " ")
		for word, key := range words {
			if regexp.MustCompile(`\b` + word + `\b`).MatchString(text) {
				t.Errorf("%s writes %q outside a template action; render it as {{ T $loc %q }} so the other locale switches too", e.Name(), word, key)
			}
		}
	}
}

// TestProxyProtocolMarkReadsTheSameInBothLocales は、方式の列の PROXY protocol の印を日本語でも
// PROXY のままにすることを確かめる。PROXY protocol は仕様の固有の名前であり、i18n.go で PROXY
// protocol を指す他の項目も、日本語の側でその語をそのまま保っている。
func TestProxyProtocolMarkReadsTheSameInBothLocales(t *testing.T) {
	ja, en := T("ja", "modeProxyProto"), T("en", "modeProxyProto")
	if ja != "PROXY" || en != "PROXY" {
		t.Errorf("the mark is %q in ja and %q in en; both must stay PROXY, the name the specification uses", ja, en)
	}
}

// newProxyRuleTestServer は PROXY protocol を付けたルール 1 件を持つ管理 API サーバーを立てる。
func newProxyRuleTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, proto.Rule{
			ID: "r_pp", Agent: "home", Proto: proto.TCP,
			ListenPort: proto.PortRange{Lo: 25565, Hi: 25565}, Target: "h:25565",
			VPSMode: proto.ModeProxy, ProxyProtocol: true, Enabled: true,
		}), nil
	}); err != nil {
		t.Fatal(err)
	}
	agents := []AgentInfo{{Name: "home", Connected: true, Generation: 1}}
	srv := httptest.NewServer(New(&fakeBackend{st: st, agents: agents}))
	t.Cleanup(srv.Close)
	return srv
}

// TestRulesTableShowsTheProxyProtocolMark は、PROXY protocol を付けたルールの方式の列にその印が
// 出ることを、両方のロケールで確かめる。
func TestRulesTableShowsTheProxyProtocolMark(t *testing.T) {
	srv := newProxyRuleTestServer(t)

	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/?lang="+lang)
		want := "<small>" + T(lang, "modeProxyProto") + "</small>"
		if !strings.Contains(body, want) {
			t.Errorf("%s: the mode column does not carry %q:\n%s", lang, want, body)
		}
	}
}

// TestAgentListShowsTheGenerationLabelInTheChosenLocale は、エージェントの一覧の世代の欄が
// ロケールに従うことを確かめる。ルールの一覧の見出しが同じキーを引いているので、片方だけが
// 英語のままだと同じ画面の中で語が食い違う。
func TestAgentListShowsTheGenerationLabelInTheChosenLocale(t *testing.T) {
	srv := newStateTestServer(t)

	for _, lang := range []string{"ja", "en"} {
		body := getBody(t, srv.URL+"/ui/agents?lang="+lang)
		want := T(lang, "gen") + " 1"
		if !strings.Contains(body, want) {
			t.Errorf("%s: the agent list does not label the generation as %q:\n%s", lang, want, body)
		}
	}
	if T("ja", "gen") == T("en", "gen") {
		t.Error("the generation label must differ between the locales, or this test proves nothing")
	}
}
