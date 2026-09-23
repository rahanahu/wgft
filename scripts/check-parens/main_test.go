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
	if !strings.Contains(hits[0], `got %v (want %v)`) {
		t.Errorf("findParens: hit %q does not report the expected literal", hits[0])
	}
}

// i18nSrc mirrors internal/vpsd/admin/i18n.go's shape closely enough to
// exercise japaneseSideLiterals: a Japanese element with a round
// parenthesis, which must be skipped, next to an English element that must
// still be checked.
const i18nSrc = `package admin

var tr = map[string][2]string{
	"checkRuleVia": {"ルール %s(%s 経由)", "Rule %s via %s"},
	"badEnglish":   {"日本語", "Bad (English) text"},
}
`

func TestFindParensSkipsI18nJapaneseSideOnly(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "i18n.go", i18nSrc, 0)
	if err != nil {
		t.Fatal(err)
	}
	hits := findParens("i18n.go", fset, f, nil)
	if len(hits) != 1 {
		t.Fatalf("findParens on i18n.go: got %d hits, want 1: %v", len(hits), hits)
	}
	if !strings.Contains(hits[0], "Bad (English) text") {
		t.Errorf("findParens on i18n.go: hit %q, want the English-side violation", hits[0])
	}
}

// TestFindParensTrExemptionIsFilenameGated confirms the {ja, en} exemption is
// specific to i18n.go: the same tr-map shape in another file gets no special
// treatment, so its first element is checked like any other literal.
func TestFindParensTrExemptionIsFilenameGated(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "other.go", i18nSrc, 0)
	if err != nil {
		t.Fatal(err)
	}
	hits := findParens("other.go", fset, f, nil)
	if len(hits) != 2 {
		t.Fatalf("findParens on other.go: got %d hits, want 2 (both the ja and en violations): %v", len(hits), hits)
	}
}
