package doctor

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// ShortID は先頭 12 文字(rune)で切る。バイトで切ると、日本語や絵文字の ID が文字の途中で切れて
// 不正な UTF-8 が表に出た。ASCII の ID の出力は、バイトで切っていた頃と同じに保つ。
func TestShortIDCutsOnRuneBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, id, want string
	}{
		{"ascii long", "r_01M335HMABBS0HAXB58DE7QSTR", "r_01M335HMAB…"},
		{"ascii 12", "r_01M335HMAB", "r_01M335HMAB"},
		{"ascii 13", "r_01M335HMABB", "r_01M335HMAB…"},
		{"ascii short", "web", "web"},
		{"empty", "", ""},
		{"japanese 12", "週末のサーバー用ルールで", "週末のサーバー用ルールで"},
		{"japanese 13", "週末のサーバー用ルールです", "週末のサーバー用ルールで…"},
		{"japanese short", "週末", "週末"},
		{"mixed", "ok-週末-ルール-valheim", "ok-週末-ルール-va…"},
		{"emoji 12", "🎮🎮🎮🎮🎮🎮🎮🎮🎮🎮🎮🎮", "🎮🎮🎮🎮🎮🎮🎮🎮🎮🎮🎮🎮"},
		{"emoji 13", "🎮🎮🎮🎮🎮🎮🎮🎮🎮🎮🎮🎮🎮", "🎮🎮🎮🎮🎮🎮🎮🎮🎮🎮🎮🎮…"},
	} {
		got := ShortID(tc.id)
		if got != tc.want {
			t.Errorf("%s: ShortID(%q) = %q, want %q", tc.name, tc.id, got, tc.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("%s: ShortID(%q) = %q is not valid UTF-8", tc.name, tc.id, got)
		}
		if n := utf8.RuneCountInString(strings.TrimSuffix(got, "…")); n > ShortIDLen {
			t.Errorf("%s: %d runes kept, want at most %d", tc.name, n, ShortIDLen)
		}
	}
}
