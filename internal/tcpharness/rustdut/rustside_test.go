package rustdut

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/tcpharness"
)

// The Go side of the Rust tool crate's checks (test-tooling.md section 2): values the Rust copy of
// Go code must reproduce.

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

// rustVectors is what crates/wgft-tcpharness checks its copies against: HELLO's seed for several
// scenario seeds, strconv.Quote of the byte strings a script's quote() may see, and
// strconv.FormatFloat 'f' of the seconds seconds_text() formats, with the ties and the
// representation errors where a rounding copy would go wrong.
type rustVectors struct {
	Seeds []seedVector  `json:"seeds"`
	Quote []quoteVector `json:"quote"`
	Float []floatVector `json:"float"`
}

type seedVector struct {
	Seed  uint64 `json:"seed"`
	Hello string `json:"hello"`
}

type quoteVector struct {
	In  string `json:"in"` // hex
	Out string `json:"out"`
}

type floatVector struct {
	Nanos int64  `json:"nanos"`
	Prec  int    `json:"prec"`
	Out   string `json:"out"`
}

func makeRustVectors() rustVectors {
	var v rustVectors
	for _, s := range []uint64{0, 1, 5, 1 << 63, 0x0123456789abcdef, ^uint64(0), tcpharness.ScenarioSeed(1, "handshake-options")} {
		h := Seed(s)
		v.Seeds = append(v.Seeds, seedVector{Seed: s, Hello: hexString(h[:])})
	}
	for _, in := range []string{"", "more", "pong", "a\"b\\c", "\x00\x01\a\b\f\n\r\t\v\x1f\x7f", "\xff\xfe", "\xe2\x80", "\u00e9", "\u3042",
		"\u00a0", "\u00ad", "\u2028", "\ufeff", "\U0001f600", "\xed\xa0\x80", string([]byte{0x41, 0xc3, 0xa9, 0x80})} {
		v.Quote = append(v.Quote, quoteVector{In: hexString([]byte(in)), Out: strconv.Quote(in)})
	}
	for _, f := range []struct {
		d    time.Duration
		prec int
	}{
		{0, 0}, {500 * time.Millisecond, 0}, {1500 * time.Millisecond, 0}, {2500 * time.Millisecond, 0},
		{30 * time.Second, 0}, {30*time.Second + 499*time.Millisecond, 0}, {30*time.Second + 500*time.Millisecond, 0},
		{29999999999, 0}, {1234567890, 3}, {1250 * time.Millisecond, 1}, {1350 * time.Millisecond, 1}, {15 * time.Millisecond, 2},
		{-1500 * time.Millisecond, 0}, {35 * time.Second, 2},
	} {
		v.Float = append(v.Float, floatVector{Nanos: int64(f.d), Prec: f.prec, Out: strconv.FormatFloat(f.d.Seconds(), 'f', f.prec, 64)})
	}
	return v
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	var s strings.Builder
	for _, x := range b {
		s.WriteByte(digits[x>>4])
		s.WriteByte(digits[x&0xf])
	}
	return s.String()
}

// TestRustVectors keeps testdata/vectors.json equal to what the Go code computes; -update rewrites it.
func TestRustVectors(t *testing.T) {
	got, err := json.MarshalIndent(makeRustVectors(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "vectors.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v; run with -update", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), got) {
		t.Errorf("%s differs from the Go code; run with -update", path)
	}
}
