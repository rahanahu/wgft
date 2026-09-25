package textsafe

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeForTerminalLeavesCleanTextAlone(t *testing.T) {
	cases := []string{
		"",
		"ok",
		"bind failed: address already in use",
		"接続を確認できませんでした", // Japanese must read exactly as sent (design.md 11 節)
		"emoji ok \U0001F600",
		"tab-free, punctuation: fine; semicolons too",
	}
	for _, s := range cases {
		if got := SanitizeForTerminal(s); got != s {
			t.Errorf("SanitizeForTerminal(%q) = %q, want unchanged", s, got)
		}
	}
}

func TestSanitizeForTerminalEscapesControlBytes(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"ESC", "before\x1b[31mafter"},
		{"BEL", "before\abell"},
		{"CR overwrite", "real status\rFAKE STATUS"},
		{"NUL", "a\x00b"},
		{"DEL", "a\x7fb"},
		// U+009B (CSI) written as \u009b so Go encodes it as the 2-byte UTF-8 sequence C2 9B: a
		// *valid* rune in the C1 range, read by utf8.DecodeRuneInString and only then judged unsafe
		// by isUnsafeRune. The raw byte 0x9B alone (as a single-byte "\x9b" literal) is not valid
		// UTF-8 on its own and would instead take SanitizeForTerminal's separate invalid-byte path
		// (escapeByte), which does not exercise isUnsafeRune at all - so a case written that way
		// would keep passing even if isUnsafeRune stopped covering the C1 range (レビューの指摘)。
		{"C1 control (CSI, valid UTF-8)", "a\u009bb"},
		{"newline", "a\nb"},
		{"tab", "a\tb"},
		// The following are not C0/C1 controls at all: unicode.IsPrint reports them as not
		// printable for other reasons (bidirectional override, zero width, line/paragraph
		// separator, language tag), so they are only caught because isUnsafeRune is defined as
		// "not unicode.IsPrint", matching strconv.Quote's own rule (design.md 11 節, 所有者の決定
		// 2026-09-25). A narrower, C0/C1-only isUnsafeRune would leave every one of these
		// unchanged, which is exactly the mutation this table is meant to catch.
		{"RTL override (U+202E)", "safe\u202edetcefni"},
		{"zero-width space (U+200B)", "a\u200bb"},
		{"BOM/ZWNBSP (U+FEFF)", "a\ufeffb"},
		{"line separator (U+2028)", "a\u2028b"},
		{"paragraph separator (U+2029)", "a\u2029b"},
		{"language tag (U+E0001)", "a\U000E0001b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := SanitizeForTerminal(c.in)
			if got == c.in {
				t.Fatalf("SanitizeForTerminal(%q) left the unsafe rune unchanged", c.in)
			}
			if strings.ContainsFunc(got, isUnsafeRune) {
				t.Fatalf("SanitizeForTerminal(%q) = %q, still contains an unsafe rune", c.in, got)
			}
			// The escaped form must stand for the input in a way a person can read back: it
			// is exactly what strconv.Quote would put between the quotes for the same bytes,
			// since the surrounding text (all ASCII printable) needs no escaping of its own.
			want := mustUnquoteInner(t, c.in)
			if got != want {
				t.Errorf("SanitizeForTerminal(%q) = %q, want %q", c.in, got, want)
			}
		})
	}
}

// TestSanitizeForTerminalLeavesOrdinarySpacingAlone confirms the wider, unicode.IsPrint-based rule
// (design.md 11 節) does not sweep up an ordinary space, unlike the invisible and directional
// characters above.
func TestSanitizeForTerminalLeavesOrdinarySpacingAlone(t *testing.T) {
	s := "two words, one space"
	if got := SanitizeForTerminal(s); got != s {
		t.Errorf("SanitizeForTerminal(%q) = %q, want the ordinary space unchanged", s, got)
	}
}

// mustUnquoteInner returns what strconv.Quote(s) would put between its quotes, used as the
// reference escaping in TestSanitizeForTerminalEscapesControlBytes.
func mustUnquoteInner(t *testing.T, s string) string {
	t.Helper()
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}

func TestSanitizeForTerminalHandlesInvalidUTF8(t *testing.T) {
	in := "before\xffafter"
	got := SanitizeForTerminal(in)
	if strings.Contains(got, "\xff") {
		t.Fatalf("SanitizeForTerminal(%q) = %q, still contains the raw invalid byte", in, got)
	}
	if !strings.HasPrefix(got, "before") || !strings.HasSuffix(got, "after") {
		t.Errorf("SanitizeForTerminal(%q) = %q, want the surrounding valid text kept", in, got)
	}
}

func TestSanitizeForTerminalIsIdempotent(t *testing.T) {
	in := "\x1b[31mred\x1b[0m"
	once := SanitizeForTerminal(in)
	twice := SanitizeForTerminal(once)
	if once != twice {
		t.Errorf("SanitizeForTerminal is not idempotent: once=%q twice=%q", once, twice)
	}
}

func TestClipTextLeavesShortTextAlone(t *testing.T) {
	if got := ClipText("short", 100); got != "short" {
		t.Errorf("ClipText did not leave a short string alone: %q", got)
	}
}

func TestClipTextTruncatesOnRuneBoundary(t *testing.T) {
	// "接" is 3 bytes in UTF-8; clipping to 4 bytes lands mid-character (byte 4 of 6 across the
	// first two runes), so a correct cut backs off to 3 bytes (the first whole "接"), not 4.
	s := strings.Repeat("接", 10) // 30 bytes
	got := ClipText(s, 4)
	if !strings.HasSuffix(got, "... truncated") {
		t.Fatalf("ClipText(%q, 4) = %q, want a truncation marker", s, got)
	}
	kept := strings.TrimSuffix(got, "... truncated")
	if !strings.HasPrefix(s, kept) {
		t.Fatalf("ClipText kept %q, which is not a prefix of the input", kept)
	}
	if len([]byte(kept)) > 4 {
		t.Fatalf("ClipText kept %d bytes, want at most 4", len([]byte(kept)))
	}
	// The prefix-of-input and at-most-4-bytes checks above both still pass for a naive s[:4]
	// (byte slicing is always a "prefix" and always respects the byte count asked for), so
	// neither would catch the rune-boundary loop being removed (レビューの指摘). Validity is the
	// property a mid-rune cut actually breaks: s[:4] here is 3 full bytes of "接" plus 1 byte of a
	// second "接" that never gets its other 2 bytes, which utf8.ValidString reports as invalid.
	if !utf8.ValidString(kept) {
		t.Fatalf("ClipText kept %q, which is not valid UTF-8: it cut mid-rune", kept)
	}
	if len([]byte(kept)) != 3 {
		t.Fatalf("ClipText kept %d bytes, want exactly 3 (one whole \"接\", backed off from the requested 4)", len([]byte(kept)))
	}
}

func TestSanitizeStringsWalksNestedFields(t *testing.T) {
	type inner struct {
		Reason string
		IDs    []string
	}
	type outer struct {
		Name  string
		Inner *inner
		Items []inner
	}

	v := &outer{
		Name:  "a\x1bb",
		Inner: &inner{Reason: "c\x07d", IDs: []string{"e\x00f", "clean"}},
		Items: []inner{{Reason: "g\x7fh"}},
	}
	SanitizeStrings(v)

	if strings.ContainsFunc(v.Name, isUnsafeRune) {
		t.Errorf("Name still unsafe: %q", v.Name)
	}
	if strings.ContainsFunc(v.Inner.Reason, isUnsafeRune) {
		t.Errorf("Inner.Reason still unsafe: %q", v.Inner.Reason)
	}
	if strings.ContainsFunc(v.Inner.IDs[0], isUnsafeRune) {
		t.Errorf("Inner.IDs[0] still unsafe: %q", v.Inner.IDs[0])
	}
	if v.Inner.IDs[1] != "clean" {
		t.Errorf("Inner.IDs[1] changed from a clean value: %q", v.Inner.IDs[1])
	}
	if strings.ContainsFunc(v.Items[0].Reason, isUnsafeRune) {
		t.Errorf("Items[0].Reason still unsafe: %q", v.Items[0].Reason)
	}
}

func TestSanitizeStringsHandlesNilPointersWithoutPanic(t *testing.T) {
	type inner struct{ Reason string }
	type outer struct {
		Inner *inner
		Items []inner
	}
	v := &outer{}
	SanitizeStrings(v) // must not panic on a nil *inner and an empty slice
}
