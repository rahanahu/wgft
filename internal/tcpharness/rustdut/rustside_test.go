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
// Go code must reproduce, and the transcripts and check traces of the Go runner that the Rust
// runner must reproduce byte for byte.

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

// TranscriptDirEnv names the directory TestWriteTranscripts writes to. The harness-rust-go CI job
// and the host gate set it, then run the Rust test that reads the same directory.
const TranscriptDirEnv = "WGFT_TEST_TCPHARNESS_TRANSCRIPTS"

// transcriptRuns are the run seeds of the transcript comparison.
var transcriptRuns = []uint64{1, 2, 3, 4, 5}

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

// TestWriteTranscripts writes, for every scenario script and each run seed of transcriptRuns, the
// transcript of the Go runner through rustdut against dutserve and the run's check trace, to the
// directory TranscriptDirEnv names: <script>/<run>.bin and <script>/<run>.trace.json. The Rust
// runner runs the same scripts through its ProcessDut against the same dutserve and must write the
// same bytes (crates/wgft-tcpharness/tests/scripts.rs). Both sides name the engine go-wgstack and
// use no expected-difference list, so a known difference is a failure on both and compares too.
// The trace's lines leave out the DUT process's standard error, which only rustdut relays.
func TestWriteTranscripts(t *testing.T) {
	dir := os.Getenv(TranscriptDirEnv)
	if dir == "" {
		t.Skipf("set %s to a directory to write the transcripts for the Rust runner", TranscriptDirEnv)
	}
	bin := requireDutserve(t)
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
			for _, run := range transcriptRuns {
				var tr bytes.Buffer
				e := transcriptEngine(bin, &tr)
				e.Name = "go-wgstack"
				start := time.Now()
				trace := tcpharness.RecordChecks(t, e, s, tcpharness.ScenarioSeed(run, name))
				elapsed := time.Since(start)
				trace.Lines = engineLines(trace.Lines)
				js, err := json.Marshal(trace)
				if err != nil {
					t.Fatal(err)
				}
				base := filepath.Join(dir, name, strconv.FormatUint(run, 10))
				if err := os.WriteFile(base+".bin", tr.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(base+".trace.json", js, 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("run seed %d: transcript of %d bytes in %v", run, tr.Len(), elapsed.Round(time.Millisecond))
			}
		})
	}
}
