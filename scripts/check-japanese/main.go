// check-japanese は、ツールの出力(ログ・エラー・標準出力・CLI ヘルプ)から日本語を
// 締め出すための検査。Go の文字列リテラルだけを走査し、ひらがな・
// カタカナ・漢字が残っていれば場所を出して非 0 で終わる。コメントは対象外(日本語コメントは
// 残す方針)。テストと Web UI の i18n(JA/EN 切替を持つ)は除外する。
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

func isJapanese(r rune) bool {
	return unicode.In(r, unicode.Hiragana, unicode.Katakana, unicode.Han)
}

// exemptFromJapaneseCheck skips the Web UI i18n files. filepath.Walk yields
// backslashes on Windows, so the old HasSuffix(path, "/i18n.go") check missed
// them and reported Japanese literals that are supposed to be excluded.
func exemptFromJapaneseCheck(path string) bool {
	p := filepath.ToSlash(path)
	p = strings.ReplaceAll(p, `\`, "/")
	base := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		base = p[i+1:]
	}
	return base == "i18n.go" || base == "webui.go"
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	var hits []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
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
		if exemptFromJapaneseCheck(path) {
			return nil // Web UI の表示テキスト層(JA/EN)は対象外
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			for _, r := range lit.Value {
				if isJapanese(r) {
					pos := fset.Position(lit.Pos())
					hits = append(hits, fmt.Sprintf("%s:%d: %s", pos.Filename, pos.Line, strings.TrimSpace(lit.Value)))
					break
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(hits) > 0 {
		fmt.Fprintf(os.Stderr, "Japanese found in %d string literal(s) (comments, tests, and i18n.go are excluded):\n", len(hits))
		for _, h := range hits {
			fmt.Fprintln(os.Stderr, h)
		}
		os.Exit(1)
	}
	fmt.Println("OK: no Japanese in string literals")
}
