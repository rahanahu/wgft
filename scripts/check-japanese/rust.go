package main

import (
	"fmt"
	"strings"
)

// rustJapaneseLiterals は Rust のソースから、日本語を含む文字列リテラルの
// 位置を返す。コメントは対象外。`#[cfg(test)]` を付けた項目 (mod、fn、use など) は、
// 次の `;` か対応する `}` までを走査しない。字句の解析は文字列 (b と c の接頭辞、
// 生文字列を含む)、文字リテラル、入れ子のブロックコメントを区別するだけの簡易なもの。
func rustJapaneseLiterals(file, src string) []string {
	rs := []rune(src)
	n := len(rs)
	line := 1
	var hits []string
	i := 0
	for i < n {
		kind, end, lit := rustToken(rs, i)
		switch kind {
		case tokString, tokChar:
			if hasJapanese(lit) {
				hits = append(hits, fmt.Sprintf("%s:%d: %q", file, line, string(lit)))
			}
		case tokOther:
			if rs[i] == '#' {
				if attrEnd, text, inner := rustAttribute(rs, i); attrEnd > 0 && text == "cfg(test)" {
					if inner {
						return hits // #![cfg(test)] はファイル全体がテスト
					}
					end = rustSkipItem(rs, attrEnd)
				}
			}
		}
		line += strings.Count(string(rs[i:end]), "\n")
		i = end
	}
	return hits
}

const (
	tokOther = iota
	tokComment
	tokString
	tokChar
)

// rustToken は rs[i] から始まる 1 つの字句を読み、種類と終わりの位置 (排他) を返す。
// 文字列と文字リテラルでは、引用符の中身を lit で返す。
func rustToken(rs []rune, i int) (kind, end int, lit []rune) {
	n := len(rs)
	c := rs[i]
	switch {
	case c == '/' && i+1 < n && rs[i+1] == '/':
		j := i
		for j < n && rs[j] != '\n' {
			j++
		}
		return tokComment, j, nil
	case c == '/' && i+1 < n && rs[i+1] == '*':
		depth := 1
		j := i + 2
		for j < n && depth > 0 {
			switch {
			case rs[j] == '/' && j+1 < n && rs[j+1] == '*':
				depth++
				j++
			case rs[j] == '*' && j+1 < n && rs[j+1] == '/':
				depth--
				j++
			}
			j++
		}
		return tokComment, min(j, n), nil
	case c == '\'':
		// 文字リテラルか、ライフタイムか。
		if i+1 < n && rs[i+1] == '\\' {
			j := i + 2
			for j < n && rs[j] != '\'' {
				j++
			}
			return tokChar, min(j+1, n), rs[i+1 : min(j, n)]
		}
		if i+2 < n && rs[i+2] == '\'' {
			return tokChar, i + 3, rs[i+1 : i+2]
		}
		return tokOther, i + 1, nil
	}
	if i > 0 && isIdent(rs[i-1]) {
		return tokOther, i + 1, nil
	}
	// 文字列: "..."、b"..."、c"..."、r#"..."#、br"..."、cr#"..."# のどれか。
	j := i
	if rs[j] == 'b' || rs[j] == 'c' {
		j++
	}
	raw := false
	hashes := 0
	if j < n && rs[j] == 'r' {
		raw = true
		j++
		for j < n && rs[j] == '#' {
			hashes++
			j++
		}
	}
	if j >= n || rs[j] != '"' {
		return tokOther, i + 1, nil
	}
	j++
	start := j
	for j < n {
		if raw {
			if rs[j] == '"' && hasHashes(rs, j+1, hashes) {
				return tokString, j + 1 + hashes, rs[start:j]
			}
		} else {
			if rs[j] == '\\' && j+1 < n {
				j += 2
				continue
			}
			if rs[j] == '"' {
				return tokString, j + 1, rs[start:j]
			}
		}
		j++
	}
	return tokString, n, rs[start:n]
}

// rustAttribute は rs[i] の `#` が属性なら、閉じの `]` の次の位置と、空白を除いた
// 属性の本文を返す。属性でなければ end は 0。コメントは本文に含めない。
func rustAttribute(rs []rune, i int) (end int, text string, inner bool) {
	n := len(rs)
	j := i + 1
	if j < n && rs[j] == '!' {
		inner = true
		j++
	}
	for j < n && (rs[j] == ' ' || rs[j] == '\t' || rs[j] == '\n') {
		j++
	}
	if j >= n || rs[j] != '[' {
		return 0, "", false
	}
	depth := 0
	var b strings.Builder
	for j < n {
		kind, e, _ := rustToken(rs, j)
		if kind == tokOther {
			switch rs[j] {
			case '[':
				depth++
			case ']':
				depth--
				if depth == 0 {
					return e, b.String()[1:], inner
				}
			}
			if rs[j] != ' ' && rs[j] != '\t' && rs[j] != '\n' && rs[j] != '\r' {
				b.WriteRune(rs[j])
			}
		} else if kind != tokComment {
			b.WriteString(`"`)
		}
		j = e
	}
	return 0, "", false
}

// rustSkipItem は i から始まる項目を読み飛ばし、その次の位置を返す。
// 括弧の外で最初に現れる `;` か、`{` に対応する `}` までが項目の終わり。
func rustSkipItem(rs []rune, i int) int {
	n := len(rs)
	paren := 0
	for i < n {
		kind, end, _ := rustToken(rs, i)
		if kind == tokOther {
			switch rs[i] {
			case '(', '[':
				paren++
			case ')', ']':
				paren--
			case ';':
				if paren <= 0 {
					return end
				}
			case '{':
				if paren <= 0 {
					return rustSkipBraces(rs, i)
				}
			}
		}
		i = end
	}
	return n
}

// rustSkipBraces は rs[i] の `{` に対応する `}` の次の位置を返す。
func rustSkipBraces(rs []rune, i int) int {
	depth := 0
	for i < len(rs) {
		kind, end, _ := rustToken(rs, i)
		if kind == tokOther {
			switch rs[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return end
				}
			}
		}
		i = end
	}
	return len(rs)
}

// rustExempt は、Go の _test.go に当たる Rust のテスト用ファイル
// (crates/<name>/tests と crates/<name>/benches 以下) かを返す。
func rustExempt(path string) bool {
	p := strings.ReplaceAll(path, `\`, "/")
	parts := strings.Split(p, "/")
	for k := 0; k+2 < len(parts); k++ {
		if parts[k] == "crates" && (parts[k+2] == "tests" || parts[k+2] == "benches") {
			return true
		}
	}
	return false
}

func isIdent(r rune) bool {
	return r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}

func hasHashes(rs []rune, i, n int) bool {
	for k := 0; k < n; k++ {
		if i+k >= len(rs) || rs[i+k] != '#' {
			return false
		}
	}
	return true
}

func hasJapanese(rs []rune) bool {
	for _, r := range rs {
		if isJapanese(r) {
			return true
		}
	}
	return false
}
