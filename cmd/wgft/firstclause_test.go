package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// firstClause は 1 行の長さを文字(rune)の数で切る。多バイト文字を含む値(ルール ID、エージェント名、
// 宛先のホスト名)が境にかかっても、不正な UTF-8 を出さない。ASCII だけの文は、バイトで切っていた
// 以前と同じ出力になる。
func TestFirstClause(t *testing.T) {
	ascii := strings.Repeat("a", 80)
	exact58 := strings.Repeat("b", 58)
	jp := strings.Repeat("あ", 80)
	// 56 バイトの ASCII のあとに多バイト文字が並び、57 バイト目が文字の途中にかかる。
	straddle := strings.Repeat("c", 56) + strings.Repeat("日", 10)

	cases := []struct{ name, in, want string }{
		{"short", "agent offline", "agent offline"},
		{"ascii is cut at 57 bytes", ascii, strings.Repeat("a", 57) + "…"},
		{"ascii at the limit is kept", exact58, exact58},
		{"clause separator", "the agent home is down. Start it", "the agent home is down"},
		{"multibyte cut on a character", jp, strings.Repeat("あ", 57) + "…"},
		{"multibyte straddling byte 57", straddle, strings.Repeat("c", 56) + "日…"},
		{"multibyte within the limit", strings.Repeat("あ", 58), strings.Repeat("あ", 58)},
	}
	for _, c := range cases {
		got := firstClause(c.in)
		if got != c.want {
			t.Errorf("%s: firstClause = %q, want %q", c.name, got, c.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("%s: invalid UTF-8 %q", c.name, got)
		}
	}
}

func TestUpperFirstKeepsMultibyteIntact(t *testing.T) {
	for in, want := range map[string]string{"": "", "abc": "Abc", "éa": "Éa", "日本": "日本"} {
		if got := upperFirst(in); got != want || !utf8.ValidString(got) {
			t.Errorf("upperFirst(%q) = %q, want %q", in, got, want)
		}
	}
}
