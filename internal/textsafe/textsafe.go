// Package textsafe holds the one function each command uses to keep a string this process did not
// choose (design.md 11 節: a heartbeat's tunnel or rule reason, a rule ID, an agent's control-socket
// reply) from driving the operator's terminal. Like internal/resource, internal/lograte and
// internal/startup (design.md 7a.7 節), it is a leaf: it imports nothing from the module, so every
// layer from cmd/wgft down to internal/vpsd/stream can import it without pulling anything else in.
package textsafe

import (
	"reflect"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SanitizeForTerminal replaces every rune unicode.IsPrint reports as not printable, and every
// invalid UTF-8 byte, in s with a visible, inert escape in the style of strconv.Quote, and leaves
// every other rune unchanged, including non-ASCII scripts. This is the same rule strconv.Quote
// itself uses to decide what to escape (design.md 11 節, 所有者の決定 2026-09-25), so it reaches
// past the C0/C1 control bytes (ESC-led escape sequences, BEL, CR used to overwrite a line, the
// rest of C0/C1) to also cover bidirectional-override controls (U+202A-202E, U+2066-2069), zero-
// width characters (U+200B-200F, U+FEFF), the line and paragraph separators (U+2028, U+2029) and
// language tag characters, all of which can misrepresent a line on a terminal without using a C0 or
// C1 byte at all. A string with nothing unsafe in it comes back byte-for-byte identical, so text an
// operator wrote themselves (Japanese, emoji, ordinary punctuation and spacing) reads exactly as
// typed. This is display-time hardening for text this process reads from something outside its
// trust boundary; it never lengthens a clean string and is safe to call more than once on the same
// value (its own output contains nothing it would escape again).
func SanitizeForTerminal(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, isUnsafeRune) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			// 不正な 1 バイト。UTF-8 として読めないのでバイトのまま逃がす
			b.WriteString(escapeByte(s[i]))
			i++
		case isUnsafeRune(r):
			b.WriteString(escapeRune(r))
			i += size
		default:
			b.WriteRune(r)
			i += size
		}
	}
	return b.String()
}

// isUnsafeRune reports whether r is a rune strconv.Quote would itself escape: anything
// unicode.IsPrint reports as not printable. This includes the C0 and C1 control ranges, DEL, and
// the wider set of invisible and directional-override code points strconv.Quote already treats the
// same way, so this function's notion of "unsafe" never drifts from escapeRune's own.
func isUnsafeRune(r rune) bool {
	return !unicode.IsPrint(r)
}

// escapeRune renders r the way strconv.Quote would inside a quoted string, without the quotes:
// "\x1b" for ESC, "\a" for BEL, "\u0080" for a C1 control, and so on.
func escapeRune(r rune) string {
	q := strconv.QuoteRune(r)
	return q[1 : len(q)-1]
}

// escapeByte renders a single byte that utf8.DecodeRuneInString could not read as UTF-8.
func escapeByte(b byte) string {
	return `\x` + strconv.FormatUint(uint64(b), 16)
}

// ClipText truncates s to at most max bytes, cutting on a rune boundary so the result stays valid
// UTF-8, and marks that it did. Callers that read text they do not control cap the amount of data
// one value can hold with this before the value reaches storage or display.
func ClipText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	n := max
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "... truncated"
}

// SanitizeStrings walks v, which must be a pointer to a struct (or to a slice or array of such),
// and replaces every exported string field it finds, however deeply nested through structs,
// pointers, slices and arrays, with SanitizeForTerminal's escaped form. It is the one call a reader
// of a response built by something outside the trust boundary (design.md 11 節: the agent's
// control-socket reply to `agent doctor`) makes to cover every text field that response type holds,
// including ones added to it later, without listing each field by hand. Only strings v itself lets
// it set are touched; an unexported field (a time.Time's internal fields, e.g.) is left alone
// because reflect already refuses to set it, not because this function singles it out.
//
// It does not walk into a map's values (none of agent.DoctorResponse's fields are maps today). A
// type this covers that later grows a map[string]string or similar field would need that field
// added here, or the field's own reader would need to call SanitizeForTerminal on its values
// directly; "covers fields added later" holds for struct, pointer, slice and array fields only.
func SanitizeStrings(v any) {
	sanitizeValue(reflect.ValueOf(v))
}

func sanitizeValue(v reflect.Value) {
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if !v.IsNil() {
			sanitizeValue(v.Elem())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if f := v.Field(i); f.CanSet() {
				sanitizeValue(f)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			sanitizeValue(v.Index(i))
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(SanitizeForTerminal(v.String()))
		}
	}
}
