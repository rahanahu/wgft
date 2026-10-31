package main

import (
	"fmt"
	"strings"
)

// rustJapaneseLiterals は Rust のソースから、日本語を含む文字列リテラルの
// 位置を返す。コメントは対象外。`#[cfg(test)]` 以降は、単体テストのモジュールが
// ファイルの末尾にある慣習に従って走査しない。字句の解析は文字列、生文字列、
// 文字リテラル、入れ子のブロックコメントを区別するだけの簡易なもの。
func rustJapaneseLiterals(file, src string) []string {
	if i := strings.Index(src, "#[cfg(test)]"); i >= 0 {
		src = src[:i]
	}
	rs := []rune(src)
	var hits []string
	line := 1
	n := len(rs)
	for i := 0; i < n; i++ {
		c := rs[i]
		switch {
		case c == '\n':
			line++
		case c == '/' && i+1 < n && rs[i+1] == '/':
			for i < n && rs[i] != '\n' {
				i++
			}
			i-- // 改行は外側のループで数える
		case c == '/' && i+1 < n && rs[i+1] == '*':
			depth := 1
			i += 2
			for i < n && depth > 0 {
				switch {
				case rs[i] == '\n':
					line++
				case rs[i] == '/' && i+1 < n && rs[i+1] == '*':
					depth++
					i++
				case rs[i] == '*' && i+1 < n && rs[i+1] == '/':
					depth--
					i++
				}
				i++
			}
			i--
		case c == '"' || isRawStart(rs, i):
			start := line
			hashes := 0
			raw := c != '"'
			j := i
			if raw {
				for rs[j] != 'r' {
					j++
				}
				j++
				for rs[j] == '#' {
					hashes++
					j++
				}
			}
			j++ // 開きの二重引用符
			var lit []rune
			for j < n {
				if raw {
					if rs[j] == '"' && hasHashes(rs, j+1, hashes) {
						j += hashes
						break
					}
				} else {
					if rs[j] == '\\' && j+1 < n {
						lit = append(lit, rs[j], rs[j+1])
						if rs[j+1] == '\n' {
							line++
						}
						j += 2
						continue
					}
					if rs[j] == '"' {
						break
					}
				}
				if rs[j] == '\n' {
					line++
				}
				lit = append(lit, rs[j])
				j++
			}
			if hasJapanese(lit) {
				hits = append(hits, fmt.Sprintf("%s:%d: %q", file, start, string(lit)))
			}
			i = j
		case c == '\'':
			// 文字リテラルか、ライフタイムか。
			if i+1 < n && rs[i+1] == '\\' {
				j := i + 2
				for j < n && rs[j] != '\'' {
					j++
				}
				i = j
			} else if i+2 < n && rs[i+2] == '\'' {
				if isJapanese(rs[i+1]) {
					hits = append(hits, fmt.Sprintf("%s:%d: %q", file, line, string(rs[i:i+3])))
				}
				i += 2
			}
		}
	}
	return hits
}

// isRawStart は rs[i] が r"、r#"、br"、b"、br#" のような接頭辞の先頭かを返す。
// b" は通常の文字列と同じ扱いで足りるので、ここでは raw の接頭辞だけを見る。
func isRawStart(rs []rune, i int) bool {
	if i > 0 && (isIdent(rs[i-1])) {
		return false
	}
	j := i
	if rs[j] == 'b' && j+1 < len(rs) && rs[j+1] == 'r' {
		j++
	}
	if rs[j] != 'r' {
		return false
	}
	j++
	for j < len(rs) && rs[j] == '#' {
		j++
	}
	return j < len(rs) && rs[j] == '"'
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
