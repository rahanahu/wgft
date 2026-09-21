package admin

import (
	"errors"
	"mime/multipart"
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

// このファイルは、Web UI のページ/区画が依拠する読み取りが失敗したとき、design.md 10.5 節の
// とおり「0 件」や「0」のような正常な結果に化けず、そのページ・区画がエラーの状態を返すことを
// 確かめる。getrules_error_test.go(管理用 API 側)と同じ、fakeBackend を 1 メソッドだけ
// 上書きするフェイクで、実際の store 障害(admin_backend_test.go 側)ではなく Backend の
// 契約そのものを確かめる。

type errWarningsBackend struct{ *fakeBackend }

func (b *errWarningsBackend) Warnings() ([]Warning, error) {
	return nil, errors.New("simulated store failure: warnings")
}

type errAgentsBackend struct{ *fakeBackend }

func (b *errAgentsBackend) Agents() ([]AgentInfo, error) {
	return nil, errors.New("simulated store failure: agents")
}

type errRulesBackend struct{ *fakeBackend }

func (b *errRulesBackend) Rules() ([]proto.Rule, error) {
	return nil, errors.New("simulated store failure: rules")
}

// TestDashboardReadFailureIsNotSilentZero confirms that GET / (and its partials) answers 500 when
// any of the reads buildDash depends on fails, instead of drawing an empty/zero dashboard.
// Agents/Rules were already guarded; Generation/RuleDrops/Warnings were not (`gen, _ :=` etc.).
func TestDashboardReadFailureIsNotSilentZero(t *testing.T) {
	cases := []struct {
		name    string
		backend func(base *fakeBackend) Backend
	}{
		{"generation", func(base *fakeBackend) Backend { return &errGenerationBackend{fakeBackend: base} }},
		{"rule drops", func(base *fakeBackend) Backend { return &errRuleDropsBackend{fakeBackend: base} }},
		{"warnings", func(base *fakeBackend) Backend { return &errWarningsBackend{fakeBackend: base} }},
		{"agents", func(base *fakeBackend) Backend { return &errAgentsBackend{fakeBackend: base} }},
		{"rules", func(base *fakeBackend) Backend { return &errRulesBackend{fakeBackend: base} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			srv := httptest.NewServer(New(c.backend(&fakeBackend{st: st})))
			defer srv.Close()

			for _, path := range []string{"/", "/ui/agents", "/ui/warnings", "/ui/rules", "/ui/health"} {
				resp, err := http.Get(srv.URL + path)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusInternalServerError {
					t.Errorf("%s failure, GET %s: status = %d, want %d", c.name, path, resp.StatusCode, http.StatusInternalServerError)
				}
			}
		})
	}
}

// TestRuleNotFoundVsStoreFailure confirms that a store failure while looking a rule up (findRule)
// is reported as 500, not folded into the ordinary 404 for an ID that genuinely does not exist.
// Before the fix, findRule discarded Rules()'s error and always returned "not found", so an
// operator hitting a database hiccup on a real rule's detail page saw "rule not found" -- as if
// they had mistyped the URL -- with no sign that anything was actually broken.
func TestRuleNotFoundVsStoreFailure(t *testing.T) {
	srv, _ := newDetailTestServer(t)

	t.Run("genuinely missing", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/ui/rules/r_does_not_exist")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
		}
	})

	// 別サーバー: Rules() を丸ごと失敗させる (findRule はこれを使う)。
	st2, err := store.Open(filepath.Join(t.TempDir(), "s2.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	srv2 := httptest.NewServer(New(&errRulesBackend{fakeBackend: &fakeBackend{st: st2}}))
	defer srv2.Close()

	t.Run("store failure", func(t *testing.T) {
		resp, err := http.Get(srv2.URL + "/ui/rules/r_a")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d (a store failure must not look like an ordinary 404)", resp.StatusCode, http.StatusInternalServerError)
		}
	})
}

// TestRuleDetailReadFailureIsNotSilentZero confirms that the rule detail page (which repeats the
// generation/drops/agents reads independently of the JSON API) also answers 500, rather than
// drawing a plausible-looking but fabricated apply state, dropped-count, or merge section.
func TestRuleDetailReadFailureIsNotSilentZero(t *testing.T) {
	cases := []struct {
		name    string
		backend func(st *store.Store) Backend
	}{
		{"generation", func(st *store.Store) Backend { return &errGenerationBackend{fakeBackend: &fakeBackend{st: st}} }},
		{"rule drops", func(st *store.Store) Backend { return &errRuleDropsBackend{fakeBackend: &fakeBackend{st: st}} }},
		{"agents", func(st *store.Store) Backend { return &errAgentsBackend{fakeBackend: &fakeBackend{st: st}} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
				return append(rules, proto.Rule{
					ID: "r_a", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2457},
					Target: "192.168.1.20:2456", VPSMode: proto.ModeKernel, Enabled: true,
					SourceAllow: []netip.Prefix{}, SourceDeny: []netip.Prefix{},
				}), nil
			}); err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(New(c.backend(st)))
			defer srv.Close()

			resp, err := http.Get(srv.URL + "/ui/rules/r_a")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusInternalServerError {
				t.Errorf("%s failure: status = %d, want %d", c.name, resp.StatusCode, http.StatusInternalServerError)
			}
		})
	}
}

// TestAddRuleFormReadFailureIsNotSilentZero confirms that the add-rule form answers 500 when the
// agent list cannot be read, instead of silently rendering the "no agents registered" state
// (which is a real, legitimate state the form already draws when the list is genuinely empty).
func TestAddRuleFormReadFailureIsNotSilentZero(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer(New(&errAgentsBackend{fakeBackend: &fakeBackend{st: st}}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/ui/add-rule")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}

// TestImportConfirmReadFailureIsNotSilentZero confirms that the read-only confirmation page
// answers 500 when Generation() or Agents() fails, instead of embedding a fabricated generation
// (which the apply step later trusts for its optimistic-concurrency check) or wrongly flagging
// every rule as pointing at an unregistered agent.
func TestImportConfirmReadFailureIsNotSilentZero(t *testing.T) {
	cases := []struct {
		name    string
		backend func(st *store.Store) Backend
	}{
		{"generation", func(st *store.Store) Backend { return &errGenerationBackend{fakeBackend: &fakeBackend{st: st}} }},
		{"agents", func(st *store.Store) Backend { return &errAgentsBackend{fakeBackend: &fakeBackend{st: st}} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			srv := httptest.NewServer(New(c.backend(st)))
			defer srv.Close()

			var body strings.Builder
			w := multipart.NewWriter(&body)
			fw, err := w.CreateFormFile("file", "rules.json")
			if err != nil {
				t.Fatal(err)
			}
			fw.Write([]byte(`[]`))
			w.Close()

			resp, err := http.Post(srv.URL+"/ui/rules/import", w.FormDataContentType(), strings.NewReader(body.String()))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusInternalServerError {
				t.Errorf("%s failure: status = %d, want %d", c.name, resp.StatusCode, http.StatusInternalServerError)
			}
		})
	}
}

// TestImportApplyReadFailureIsNotSilentZero confirms that the apply step (which re-reads the
// generation to detect a stale confirmation page, design.md 10.1 節) answers 500 when that read
// fails, rather than comparing the submitted generation against a fabricated "0" that could
// coincidentally match a confirmation page built under the same failure.
func TestImportApplyReadFailureIsNotSilentZero(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer(New(&errGenerationBackend{fakeBackend: &fakeBackend{st: st}}))
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/ui/rules/import/apply", url.Values{
		"content":    {"[]"},
		"generation": {"0"},
		"digest":     {proto.RulesDigest(nil)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}
