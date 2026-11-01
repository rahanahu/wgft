package rustdut

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/rahanahu/wgft/internal/tcpharness"
)

// The Go side of the Rust tool crate's checks (test-tooling.md section 2): values the Rust copy of
// Go code must reproduce, and the transcripts and check traces of the Go runner that the Rust
// runner must reproduce byte for byte.

var update = flag.Bool("update", false, "rewrite testdata/vectors.json and the Rust table of printable runes")

// TranscriptDirEnv names the directory TestWriteTranscripts writes to. The harness-rust-go CI job
// and the host gate set it, then run the Rust test that reads the same directory.
const TranscriptDirEnv = "WGFT_TEST_TCPHARNESS_TRANSCRIPTS"

// transcriptRuns are the run seeds of the transcript comparison.
var transcriptRuns = []uint64{1, 2, 3, 4, 5}

// rustVectors is what crates/wgft-tcpharness checks its copies against: HELLO's seed for several
// scenario seeds, strconv.Quote of the byte strings a script's quote() may see, strconv.FormatFloat
// 'f' of the seconds seconds_text() formats, with the ties and the representation errors where a
// rounding copy would go wrong and the shortest form a negative precision asks for, and the
// digest of the table of printable runes that the Rust quote() reads.
type rustVectors struct {
	Seeds []seedVector  `json:"seeds"`
	Quote []quoteVector `json:"quote"`
	Float []floatVector `json:"float"`
	Print printVector   `json:"print"`
}

// printVector names the Rust table of printable runes: the Unicode version of the Go that made
// it, its number of ranges, and the FNV-1a 64 of its ranges as little-endian uint32 pairs, so the
// Rust side can tell that its checked-in table is the one this Go makes without Go at hand.
type printVector struct {
	Unicode string `json:"unicode"`
	Ranges  int    `json:"ranges"`
	FNV64a  string `json:"fnv64a"`
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
		"\u00a0", "\u00ad", "\u2028", "\ufeff", "\U0001f600", "\xed\xa0\x80", string([]byte{0x41, 0xc3, 0xa9, 0x80}),
		// runes a hand-written test of printability gets wrong, and the ends of the table
		"\u202e", "\u0378", "\ufffe", "\U000e0001", "\u0600", "\u2066", "\u180e", "\ufffd", "\U000e01ef", "\U000e01f0",
		"\U0010fffd", "\u0377", "\u0379", "\u00a1", "\u0300", "\u3000"} {
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
		// a negative precision asks for the shortest form that reads back as the same float64
		{0, -1}, {1, -1}, {1500 * time.Millisecond, -1}, {1234567890, -1}, {-1500 * time.Millisecond, -1},
		{15 * time.Millisecond, -3}, {30 * time.Second, -1}, {100 * time.Millisecond, -1},
	} {
		v.Float = append(v.Float, floatVector{Nanos: int64(f.d), Prec: f.prec, Out: strconv.FormatFloat(f.d.Seconds(), 'f', f.prec, 64)})
	}
	ranges := printRanges()
	v.Print = printVector{Unicode: unicode.Version, Ranges: len(ranges), FNV64a: printDigest(ranges)}
	return v
}

// printRanges are the runs of runes strconv.IsPrint reports, which strconv.Quote writes as they
// are; strconv.IsPrint has unicode.IsPrint's definition.
func printRanges() [][2]rune {
	var out [][2]rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !strconv.IsPrint(r) {
			continue
		}
		if n := len(out); n > 0 && out[n-1][1] == r-1 {
			out[n-1][1] = r
		} else {
			out = append(out, [2]rune{r, r})
		}
	}
	return out
}

func printDigest(ranges [][2]rune) string {
	h := fnv.New64a()
	for _, r := range ranges {
		h.Write(binary.LittleEndian.AppendUint32(binary.LittleEndian.AppendUint32(nil, uint32(r[0])), uint32(r[1])))
	}
	return fmt.Sprintf("%016x", h.Sum64())
}

// printTablePath is the generated Rust table, from this package's directory.
var printTablePath = filepath.Join("..", "..", "..", "crates", "wgft-tcpharness", "src", "runner", "goprint.rs")

// printTable is the Rust source of the table of printable runes.
func printTable(ranges [][2]rune) []byte {
	var b bytes.Buffer
	b.WriteString("// Code generated by TestRustVectors in internal/tcpharness/rustdut with -update. DO NOT EDIT.\n\n")
	b.WriteString("//! Go の `strconv.IsPrint` が真の文字の範囲です。`quote` は、この範囲の文字を Go の `strconv.Quote` と\n")
	b.WriteString("//! 同じくそのまま書きます。Go の試験 `TestRustVectors` が `-update` で書き、今の Go の表と同じことを確かめます。\n")
	b.WriteString("//! Rust の単体の試験 (`runner::gofmt`) は、表の digest を `vectors.json` の値と照らします。\n\n")
	b.WriteString("/// 表を作った Go の Unicode の版 (`unicode.Version`) です。\n")
	fmt.Fprintf(&b, "pub const UNICODE_VERSION: &str = %q;\n\n", unicode.Version)
	b.WriteString("/// `strconv.IsPrint` が真の文字の範囲です。両端を含み、昇順で重なりません。\n")
	b.WriteString("#[rustfmt::skip]\n")
	b.WriteString("pub(crate) const PRINT: &[(u32, u32)] = &[\n")
	for chunk := range slices.Chunk(ranges, 4) {
		b.WriteString("   ")
		for _, r := range chunk {
			fmt.Fprintf(&b, " (%s, %s),", rustHex(r[0]), rustHex(r[1]))
		}
		b.WriteString("\n")
	}
	b.WriteString("];\n")
	return b.Bytes()
}

// rustHex writes r as a Rust hexadecimal literal with its digits in groups of four from the
// right, which clippy's unreadable_literal accepts.
func rustHex(r rune) string {
	d := fmt.Sprintf("%x", r)
	var parts []string
	for len(d) > 4 {
		parts = append([]string{d[len(d)-4:]}, parts...)
		d = d[:len(d)-4]
	}
	return "0x" + strings.Join(append([]string{d}, parts...), "_")
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

	table := printTable(printRanges())
	if *update {
		if err := os.WriteFile(printTablePath, table, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err = os.ReadFile(printTablePath)
	if err != nil {
		t.Fatalf("%v; run with -update", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), table) {
		t.Errorf("%s differs from this Go's strconv.IsPrint; run with -update", printTablePath)
	}
}

// scriptNames is every scenario script, from the scripts directory.
func scriptNames(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "scripts", "*.scn"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no scripts: %v", err)
	}
	var names []string
	for _, f := range files {
		names = append(names, strings.TrimSuffix(filepath.Base(f), ".scn"))
	}
	return names
}

// transcriptKnownEngine names the engine of the second transcript pass, which runs with
// transcriptKnown as its expected-difference list.
const transcriptKnownEngine = "go-wgstack-known"

// transcriptKnown is a small expected-difference list that takes the frozen Go wgstack's checks
// down every path of the list: a failing check the list matches (KNOWN DIFFERENCE), a failing
// check it does not match (CHANGED DIFFERENCE), a passing check (UNEXPECTED PASS), an entry marked
// sometimes on a passing check, which a DUT on the harness's clock reports as an unexpected pass,
// and a key no check reaches. No require fails on the frozen Go wgstack, so the skip of a matched
// require is left to the Rust unit tests.
var transcriptKnown = map[string]tcpharness.Known{
	"icmp-echo/oversized": {Observed: "no reply", Reason: "the list matches the failing check"},
	"handshake-mss-floor/mss535.synack": {
		Observed: "a SYN-ACK acknowledging ISS+1", Reason: "the list does not match the failing check"},
	"handshake-mss-floor/mss536.synack": {
		Observed: "no SYN-ACK", Reason: "a passing check marked as shown on some runs", Sometimes: true},
	"icmp-echo/no-such-check": {Observed: "nothing", Reason: "no check reaches this key"},
}

// knownEntry is one entry of an expected-difference list file such as known-wgstack-rs.json.
type knownEntry struct {
	Observed  string `json:"observed"`
	Reason    string `json:"reason"`
	Sometimes bool   `json:"sometimes,omitempty"`
}

// unreachedKeys are the keys of known under scenario that no check of trace reached, sorted: the
// per-scenario part of tcpharness.Run's check of the list.
func unreachedKeys(known map[string]tcpharness.Known, scenario string, trace tcpharness.CheckTrace) []string {
	reached := map[string]bool{}
	for _, c := range trace.Checks {
		if c.Outcome != "measure" {
			reached[c.Key] = true
		}
	}
	var out []string
	for k := range known {
		if strings.HasPrefix(k, scenario+"/") && !reached[k] {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// TestWriteTranscripts writes, for every scenario script and each run seed of transcriptRuns, the
// transcript of the Go runner through rustdut against dutserve and the run's check trace, to the
// directory TranscriptDirEnv names: <script>/<run>.bin and <script>/<run>.trace.json. The Rust
// runner runs the same scripts through its ProcessDut against the same dutserve and must write the
// same bytes (crates/wgft-tcpharness/tests/scripts.rs). Both sides name the engine go-wgstack and
// use no expected-difference list, so a known difference is a failure on both and compares too.
// The trace's lines leave out the DUT process's standard error, which only rustdut relays.
//
// A second pass runs the scripts transcriptKnown names under transcriptKnownEngine with that list,
// which it also writes as known.json for the Rust side to read, and writes <script>/<run>.known.bin,
// .known.trace.json and .known.unreached, the list's keys under the script that no check reached.
func TestWriteTranscripts(t *testing.T) {
	dir := os.Getenv(TranscriptDirEnv)
	if dir == "" {
		t.Skipf("set %s to a directory to write the transcripts for the Rust runner", TranscriptDirEnv)
	}
	bin := requireDutserve(t)
	entries := map[string]knownEntry{}
	for k, v := range transcriptKnown {
		entries[k] = knownEntry{Observed: v.Observed, Reason: v.Reason, Sometimes: v.Sometimes}
	}
	list, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "known.json"), list, 0o644); err != nil {
		t.Fatal(err)
	}
	byName := map[string]tcpharness.Scenario{}
	for _, s := range tcpharness.Scenarios {
		byName[s.Name] = s
	}
	for _, name := range scriptNames(t) {
		s, ok := byName[name]
		if !ok {
			t.Errorf("script %s is not in tcpharness.Scenarios", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
				t.Fatal(err)
			}
			// the second pass runs the scripts the list has keys under: with no check run, every such key is unreached
			listed := len(unreachedKeys(transcriptKnown, name, tcpharness.CheckTrace{})) > 0
			for _, run := range transcriptRuns {
				var tr bytes.Buffer
				e := transcriptEngine(bin, &tr)
				e.Name = "go-wgstack"
				start := time.Now()
				trace := tcpharness.RecordChecks(t, e, s, tcpharness.ScenarioSeed(run, name))
				elapsed := time.Since(start)
				base := filepath.Join(dir, name, strconv.FormatUint(run, 10))
				writeTranscript(t, base, tr.Bytes(), trace)
				t.Logf("run seed %d: transcript of %d bytes in %v", run, tr.Len(), elapsed.Round(time.Millisecond))
				if !listed {
					continue
				}
				tr.Reset()
				e = transcriptEngine(bin, &tr)
				e.Name, e.Known = transcriptKnownEngine, transcriptKnown
				trace = tcpharness.RecordChecks(t, e, s, tcpharness.ScenarioSeed(run, name))
				writeTranscript(t, base+".known", tr.Bytes(), trace)
				var unreached strings.Builder
				for _, k := range unreachedKeys(transcriptKnown, name, trace) {
					unreached.WriteString(k + "\n")
				}
				if err := os.WriteFile(base+".known.unreached", []byte(unreached.String()), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// writeTranscript writes base.bin and base.trace.json, the trace without the DUT's standard error.
func writeTranscript(t *testing.T, base string, transcript []byte, trace tcpharness.CheckTrace) {
	t.Helper()
	trace.Lines = engineLines(trace.Lines)
	js, err := json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".bin", transcript, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".trace.json", js, 0o644); err != nil {
		t.Fatal(err)
	}
}
