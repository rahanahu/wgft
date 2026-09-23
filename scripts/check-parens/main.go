// check-parens is a machine check for the "no round parentheses in English tool
// output" rule: logs, errors, CLI help and results, and the Web UI's English text
// express an aside with a colon, a semicolon, or a separate sentence, not
// "(...)". It walks Go string literals with go/parser the same way
// scripts/check-japanese does, and flags any literal whose unquoted value
// contains a round parenthesis.
//
// Three kinds of literal are not operator-facing English output and are
// excluded structurally, without naming a file one by one:
//
//   - _test.go files, entirely. Test assertions such as t.Fatalf and t.Errorf
//     are not seen by an operator, and "got %v (want %v)"-style messages are
//     common and harmless; excluding the whole file matches
//     scripts/check-japanese's precedent for the same reason.
//   - SQL text, by content. internal/vpsd/store keeps SQL statements and
//     English error strings in the same files, so this can't be an
//     exclude-by-file rule; sqlKeyword below recognizes the uppercase
//     keywords this codebase's SQL always uses, such as CREATE TABLE and
//     SELECT.
//   - Any literal that contains a Japanese character, by content. This rule
//     is about English output, so a Japanese literal that happens to contain
//     a stray "(" is not the kind of violation it targets; see
//     containsJapanese. internal/vpsd/admin/i18n.go's Japanese half of its
//     {ja, en} pairs and internal/vpsd/admin/webui.go's Japanese-locale
//     format strings (for example "%d日 %d時間") are both covered this way,
//     without listing either file by name: scripts/check-japanese already
//     guarantees every other Go file has no Japanese in a string literal at
//     all, so this content check only ever fires in files that are already
//     allowed to mix the two languages.
//
// Everything else that isn't operator-facing prose but still contains a round
// parenthesis, such as a regexp literal, a Windows SDDL string, or a test
// helper's t.Errorf format outside a _test.go file, is a short, fixed list of
// one-off cases in ../check-parens-allowlist.txt, normalized the same way as
// scripts/check-log-tokens-allowlist.txt: "path:trimmed literal", with path
// relative to the repository root regardless of how this check is invoked.
package main

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// sqlKeyword matches the uppercase SQL keywords this codebase's SQL text
// always uses; see internal/vpsd/store. It is deliberately case-sensitive:
// ordinary English prose in this codebase does not spell these words in all
// caps, so this does not risk exempting a real English aside that merely
// mentions "select" or "update" in passing.
var sqlKeyword = regexp.MustCompile(`\b(CREATE TABLE|ALTER TABLE|DROP TABLE|INSERT INTO|DELETE FROM|ON CONFLICT|PRAGMA|SELECT|UPDATE)\b`)

// allowlistPath is relative to the repository root, matching how
// scripts/check-log-tokens.sh keeps its allowlist next to itself.
const allowlistPath = "scripts/check-parens-allowlist.txt"

// skipDirs lists directory base names this check never descends into, the
// same set scripts/check-japanese uses plus ".claude": this repository keeps
// working copies of other in-progress changes under .claude/worktrees/, and
// without this, running the check from the repository root would also lint
// those copies. Their file paths do not match the root-relative form the
// allowlist below is keyed on, so every one of that allowlist's entries
// would additionally misfire as a false positive once per copy.
var skipDirs = map[string]bool{
	"experiments": true,
	"notes":       true,
	".git":        true,
	".claude":     true,
	"vendor":      true,
	"scripts":     true,
}

func isJapanese(r rune) bool {
	return unicode.In(r, unicode.Hiragana, unicode.Katakana, unicode.Han)
}

func containsJapanese(s string) bool {
	for _, r := range s {
		if isJapanese(r) {
			return true
		}
	}
	return false
}

func loadAllowlist(path string) (map[string]bool, error) {
	allow := make(map[string]bool)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return allow, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		allow[line] = true
	}
	return allow, scanner.Err()
}

// normalize builds the allowlist key, and the text to paste into the
// allowlist file, for a literal at relPath: "path:trimmed literal", relPath
// already relative to the repository root and slash-separated.
func normalize(relPath, literal string) string {
	return relPath + ":" + strings.TrimSpace(literal)
}

func hasParen(s string) bool {
	return strings.ContainsAny(s, "()")
}

// finding is one string literal that contains a round parenthesis and is not
// covered by any exclusion.
type finding struct {
	relPath string
	line    int
	literal string // source text of the literal, including its quotes or backticks
}

func (h finding) String() string {
	entry := normalize(h.relPath, h.literal)
	return fmt.Sprintf("%s:%d: %s\n    if this is a legitimate exception, add this line to %s:\n    %s",
		h.relPath, h.line, strings.TrimSpace(h.literal), allowlistPath, entry)
}

// findParens walks the parsed file, whose content came from the file at
// relPath relative to the repository root, and returns one finding for every
// string literal that contains a round parenthesis and isn't covered by the
// SQL, Japanese-content, or allowlist exclusions.
func findParens(relPath string, fset *token.FileSet, f *ast.File, allow map[string]bool) []finding {
	var hits []finding
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, uerr := strconv.Unquote(lit.Value)
		if uerr != nil {
			// Not a literal strconv.Unquote handles as given, such as a
			// malformed escape; fall back to the raw source text so a
			// genuine hit is still caught rather than silently ignored.
			value = lit.Value
		}
		if !hasParen(value) {
			return true
		}
		if sqlKeyword.MatchString(value) {
			return true
		}
		if containsJapanese(value) {
			return true
		}
		if allow[normalize(relPath, lit.Value)] {
			return true
		}
		pos := fset.Position(lit.Pos())
		hits = append(hits, finding{relPath: relPath, line: pos.Line, literal: lit.Value})
		return true
	})
	return hits
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	allow, err := loadAllowlist(filepath.Join(root, allowlistPath))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var hits []finding
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relPath, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		relPath = filepath.ToSlash(relPath)
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		hits = append(hits, findParens(relPath, fset, f, allow)...)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(hits) > 0 {
		plural := "s"
		if len(hits) == 1 {
			plural = ""
		}
		fmt.Fprintf(os.Stderr, "round parenthesis found in %d string literal%s; tests, SQL text, and Japanese-language literals are excluded:\n", len(hits), plural)
		for _, h := range hits {
			fmt.Fprintln(os.Stderr, h.String())
		}
		fmt.Fprintln(os.Stderr, "use a colon, a semicolon, or a separate sentence instead")
		os.Exit(1)
	}
	fmt.Println("OK: no round parentheses in English string literals")
}
