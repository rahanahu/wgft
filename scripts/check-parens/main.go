// check-parens is a machine check for the "no round parentheses in English tool
// output" rule: logs, errors, CLI help and results, and the Web UI's English text
// express an aside with a colon, a semicolon, or a separate sentence, not
// "(...)". It walks Go string literals with go/parser the same way
// scripts/check-japanese does, and flags any literal whose unquoted value
// contains a round parenthesis.
//
// Three kinds of literal are not operator-facing output and are excluded
// structurally, without naming them one by one:
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
//   - The Japanese side of internal/vpsd/admin/i18n.go's tr map. Unlike
//     scripts/check-japanese, this check does not exempt the whole file: its
//     English side is exactly the text this check exists for. Only the
//     literal at index 0 of each {ja, en} pair is skipped; see
//     japaneseSideLiterals.
//
// Everything else that isn't operator-facing prose but still contains a round
// parenthesis, such as a regexp literal, a Windows SDDL string, or a test
// helper's t.Errorf format outside a _test.go file, is a short, fixed list of
// one-off cases in ../check-parens-allowlist.txt, normalized the same way as
// scripts/check-log-tokens-allowlist.txt: "path:trimmed literal", so an edit
// elsewhere in the file doesn't cause drift.
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
)

// sqlKeyword matches the uppercase SQL keywords this codebase's SQL text
// always uses; see internal/vpsd/store. It is deliberately case-sensitive:
// ordinary English prose in this codebase does not spell these words in all
// caps, so this does not risk exempting a real English aside that merely
// mentions "select" or "update" in passing.
var sqlKeyword = regexp.MustCompile(`\b(CREATE TABLE|ALTER TABLE|DROP TABLE|INSERT INTO|DELETE FROM|ON CONFLICT|PRAGMA|SELECT|UPDATE)\b`)

// allowlistPath is relative to the check's root argument, matching how
// scripts/check-log-tokens.sh keeps its allowlist next to itself.
const allowlistPath = "scripts/check-parens-allowlist.txt"

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

func normalize(path, literal string) string {
	return filepath.ToSlash(path) + ":" + strings.TrimSpace(literal)
}

func hasParen(s string) bool {
	return strings.ContainsAny(s, "()")
}

// japaneseSideLiterals returns the set of *ast.BasicLit nodes that are the
// Japanese element of internal/vpsd/admin/i18n.go's tr map, {ja, en}. It is a
// no-op for any other file: the "tr" var name and the {ja, en} pair shape are
// specific to that one file's known layout, but gating on the filename too
// means a same-shaped "tr" var introduced elsewhere would not silently gain
// this exemption. Only the two-element composite literals directly inside the
// "tr" var declaration count; every other literal in the file, including the
// English element of the same pair, is checked normally.
func japaneseSideLiterals(path string, f *ast.File) map[*ast.BasicLit]bool {
	skip := make(map[*ast.BasicLit]bool)
	if filepath.Base(filepath.ToSlash(path)) != "i18n.go" {
		return skip
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "tr" {
				continue
			}
			for _, val := range vs.Values {
				mapLit, ok := val.(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, elt := range mapLit.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					pair, ok := kv.Value.(*ast.CompositeLit)
					if !ok || len(pair.Elts) != 2 {
						continue
					}
					if lit, ok := pair.Elts[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						skip[lit] = true
					}
				}
			}
		}
	}
	return skip
}

// findParens walks the parsed file and returns "path:line: literal" for every
// string literal that contains a round parenthesis and isn't covered by the
// SQL, i18n.go-Japanese-side, or allowlist exclusions.
func findParens(path string, fset *token.FileSet, f *ast.File, allow map[string]bool) []string {
	var hits []string
	skip := japaneseSideLiterals(path, f)
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if skip[lit] {
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
		pos := fset.Position(lit.Pos())
		if allow[normalize(pos.Filename, lit.Value)] {
			return true
		}
		hits = append(hits, fmt.Sprintf("%s:%d: %s", pos.Filename, pos.Line, strings.TrimSpace(lit.Value)))
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
	var hits []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			base := info.Name()
			if base == "experiments" || base == "notes" || base == ".git" || base == "vendor" || base == "scripts" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		hits = append(hits, findParens(path, fset, f, allow)...)
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
		fmt.Fprintf(os.Stderr, "round parenthesis found in %d string literal%s; tests, SQL text, and the Japanese side of i18n.go are excluded:\n", len(hits), plural)
		for _, h := range hits {
			fmt.Fprintln(os.Stderr, h)
		}
		fmt.Fprintf(os.Stderr, "use a colon, a semicolon, or a separate sentence instead; if this is a legitimate exception, add it to %s\n", allowlistPath)
		os.Exit(1)
	}
	fmt.Println("OK: no round parentheses in English string literals")
}
