package admin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// errGenerationBackend is a fakeBackend whose Generation() always fails, simulating a store
// failure (e.g. "database is locked") that leaves Rules() itself unaffected.
type errGenerationBackend struct {
	*fakeBackend
}

func (b *errGenerationBackend) Generation() (uint64, error) {
	return 0, errors.New("simulated store failure: generation")
}

// errRuleDropsBackend is a fakeBackend whose RuleDrops() always fails.
type errRuleDropsBackend struct {
	*fakeBackend
}

func (b *errRuleDropsBackend) RuleDrops() (map[string]uint64, error) {
	return nil, errors.New("simulated store failure: rule drops")
}

// TestGetRulesReadFailureIsNotSilentZero confirms that GET /api/v1/rules answers with an
// error when Generation() or RuleDrops() fails, instead of silently reporting generation 0
// and no drops with a 200. Before the fix, `gen, _ := s.backend.Generation()` and
// `drops, _ := s.backend.RuleDrops()` discarded the error, and `cmd/wgft/rule.go`'s `rule ls`
// would print a plausible-looking but fabricated "generation 0" and an all-zero DROPPED
// column instead of failing loudly.
func TestGetRulesReadFailureIsNotSilentZero(t *testing.T) {
	cases := []struct {
		name    string
		backend func(base *fakeBackend) Backend
	}{
		{"generation", func(base *fakeBackend) Backend { return &errGenerationBackend{fakeBackend: base} }},
		{"rule drops", func(base *fakeBackend) Backend { return &errRuleDropsBackend{fakeBackend: base} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			base := &fakeBackend{st: st}
			srv := httptest.NewServer(New(st, c.backend(base)))
			defer srv.Close()

			resp, err := http.Get(srv.URL + "/api/v1/rules")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusInternalServerError {
				t.Errorf("%s failure: status = %d, want %d (the caller must see the failure, not a fabricated zero value)", c.name, resp.StatusCode, http.StatusInternalServerError)
			}
		})
	}
}
