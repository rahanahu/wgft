package main

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestHasParen(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s    string
		want bool
	}{
		{"no parens here", false},
		{"the deployment is degraded: bad", false},
		{"traffic stops on rule r1", false},
		{"Forwarding(%d)", true},
		{"got %v (want %v)", true},
		{"only a close paren)", true},
		{"only an open paren(", true},
	}
	for _, tc := range cases {
		if got := hasParen(tc.s); got != tc.want {
			t.Errorf("hasParen(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestSQLKeyword(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s    string
		want bool
	}{
		{"CREATE TABLE agents (name TEXT PRIMARY KEY)", true},
		{"ALTER TABLE agents DROP COLUMN stream_blocked", true},
		{"DROP TABLE IF EXISTS agent_known_ips", true},
		{"INSERT INTO warnings (agent, kind) VALUES (?, ?)", true},
		{"SELECT count(*) FROM agents WHERE name = ?", true},
		{"UPDATE join_tokens SET used_at = ? WHERE token_hash = ?", true},
		{"ON CONFLICT(agent, kind, detail) DO UPDATE SET created_at = excluded.created_at", true},
		{"mode=ro&_pragma=busy_timeout(5000)", false}, // lowercase pragma, not matched
		{"select an agent to see its rules", false},   // lowercase, ordinary English
		{"the report could not be produced (exit 2)", false},
	}
	for _, tc := range cases {
		if got := sqlKeyword.MatchString(tc.s); got != tc.want {
			t.Errorf("sqlKeyword.MatchString(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestContainsJapanese(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s    string
		want bool
	}{
		{"Bad (English) text", false},
		{"got %v (want %v)", false},
		{"%d日 %d時間", true},      // hours-ago format from webui.go
		{"%d分前", true},          // minutes-ago format from webui.go
		{"ルール %s(%s 経由)", true}, // i18n.go's Japanese side of a tr pair
	}
	for _, tc := range cases {
		if got := containsJapanese(tc.s); got != tc.want {
			t.Errorf("containsJapanese(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestLoadAllowlist(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/allowlist.txt"
	content := "# a comment\n\ncmd/wgft/main.go:\"(devel)\"\n  \ninternal/nettun/nettun.go:\"AddProtocolAddress(%v): %v\"\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	allow, err := loadAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(allow) != 2 {
		t.Fatalf("loadAllowlist: got %d entries, want 2: %v", len(allow), allow)
	}
	if !allow[`cmd/wgft/main.go:"(devel)"`] {
		t.Error("expected the devel-sentinel entry to be loaded")
	}
	if !allow[`internal/nettun/nettun.go:"AddProtocolAddress(%v): %v"`] {
		t.Error("expected the AddProtocolAddress entry to be loaded")
	}
}

func TestLoadAllowlistMissingFile(t *testing.T) {
	t.Parallel()
	allow, err := loadAllowlist("/nonexistent/does-not-exist.txt")
	if err != nil {
		t.Fatalf("loadAllowlist on a missing file should not error, got %v", err)
	}
	if len(allow) != 0 {
		t.Fatalf("loadAllowlist on a missing file should be empty, got %v", allow)
	}
}

// findParensSrc is a shared test fixture: a synthetic Go file with one hit
// that must be reported, one excluded by SQL content, and one excluded by
// the allowlist, exercising findParens end to end.
const findParensSrc = `package sample

import "fmt"

const sqlText = "INSERT INTO warnings (agent, kind) VALUES (?, ?)"

func f() {
	fmt.Sprintf("Forwarding(%d)", 1)
	fmt.Errorf("got %v (want %v)", 1, 2)
}
`

func TestFindParensReportsAndExcludes(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sample.go", findParensSrc, 0)
	if err != nil {
		t.Fatal(err)
	}
	allow := map[string]bool{`sample.go:"Forwarding(%d)"`: true}
	hits := findParens("sample.go", fset, f, allow)
	if len(hits) != 1 {
		t.Fatalf("findParens: got %d hits, want 1: %v", len(hits), hits)
	}
	if !strings.Contains(hits[0].String(), `got %v (want %v)`) {
		t.Errorf("findParens: hit %q does not report the expected literal", hits[0])
	}
}

// TestFindParensHitIncludesAllowlistLine covers requirement D: a reported
// hit must carry the exact "path:literal" line a developer can paste into
// scripts/check-parens-allowlist.txt, since that differs from the
// "path:line: literal" form used to locate the hit in the source.
func TestFindParensHitIncludesAllowlistLine(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sample.go", findParensSrc, 0)
	if err != nil {
		t.Fatal(err)
	}
	hits := findParens("sample.go", fset, f, nil)
	if len(hits) != 2 {
		t.Fatalf("findParens: got %d hits, want 2: %v", len(hits), hits)
	}
	for _, h := range hits {
		want := normalize(h.relPath, h.literal)
		if !strings.Contains(h.String(), want) {
			t.Errorf("finding.String() = %q, want it to contain the allowlist-ready line %q", h.String(), want)
		}
	}
}

// i18nSrc mirrors internal/vpsd/admin/i18n.go's tr map shape: a Japanese
// element with a round parenthesis, which must be skipped by content, next
// to an English element that must still be checked.
const i18nSrc = `package admin

var tr = map[string][2]string{
	"checkRuleVia": {"ルール %s(%s 経由)", "Rule %s via %s"},
	"badEnglish":   {"日本語", "Bad (English) text"},
}
`

func TestFindParensSkipsJapaneseContentAnywhere(t *testing.T) {
	t.Parallel()
	// Unlike the i18n.go-specific AST walk this replaced, the Japanese-content
	// exclusion is not gated on the file name: it applies the same way in
	// i18n.go, in webui.go, or in any other file, since it is a property of
	// the literal's own text, not its position in a known map shape.
	for _, name := range []string{"i18n.go", "webui.go", "other.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, i18nSrc, 0)
		if err != nil {
			t.Fatal(err)
		}
		hits := findParens(name, fset, f, nil)
		if len(hits) != 1 {
			t.Fatalf("findParens on %s: got %d hits, want 1 (only the English-side violation): %v", name, len(hits), hits)
		}
		if !strings.Contains(hits[0].String(), "Bad (English) text") {
			t.Errorf("findParens on %s: hit %q, want the English-side violation", name, hits[0])
		}
	}
}

// webuiSrc mirrors webui.go's locale-branching relative-time helpers: a
// Japanese-language format string with a round parenthesis (not present in
// the real file today, but exercising the same shape a future one could
// take) next to the English format the locale branch uses instead.
const webuiSrc = `package admin

func relTime(locale string, days, hours int) string {
	if locale == "en" {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	return fmt.Sprintf("%d日(%d時間)", days, hours)
}
`

func TestFindParensSkipsJapaneseFormatStringInWebui(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "webui.go", webuiSrc, 0)
	if err != nil {
		t.Fatal(err)
	}
	hits := findParens("webui.go", fset, f, nil)
	if len(hits) != 0 {
		t.Fatalf("findParens on webui.go: got %d hits, want 0 (the only paren-bearing literal is Japanese): %v", len(hits), hits)
	}
}

func TestNormalizeUsesRootRelativePath(t *testing.T) {
	t.Parallel()
	// findParens is always called with a path already relative to the
	// repository root (main computes it via filepath.Rel before parsing), so
	// the allowlist key never depends on whether the check was invoked with
	// a relative or an absolute root argument.
	got := normalize("cmd/wgft/main.go", `"(devel)"`)
	want := `cmd/wgft/main.go:"(devel)"`
	if got != want {
		t.Errorf("normalize = %q, want %q", got, want)
	}
}
