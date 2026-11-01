package tcpharness

import (
	"bytes"
	"encoding/json"
	"flag"
	"io/fs"
	"math"
	"math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the script fixtures under scripts/testdata from the Go parser")

// golden compares data with the file at path, or writes it with -update.
func golden(t *testing.T, path string, data []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v; run go test ./internal/tcpharness -run %s -update", err, t.Name())
	}
	// a Windows checkout may write CRLF line ends; .gitattributes asks for LF, but a checkout made
	// before it or with other settings may still have them
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(want, data) {
		t.Errorf("%s is out of date; run go test ./internal/tcpharness -run %s -update and review the diff", path, t.Name())
	}
}

// astJSON is v as minified JSON with sorted keys and a final newline, which keeps the fixtures
// small in diffs; a JSON tool shows them indented.
func astJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// TestScriptParseFixtures pins the Go parser's canonical AST, or its error, for the parser
// fixtures. The Rust parser reads the same fixtures and must produce the same JSON values.
func TestScriptParseFixtures(t *testing.T) {
	files, err := filepath.Glob("scripts/testdata/parse/*.scn")
	if err != nil || len(files) == 0 {
		t.Fatalf("no parser fixtures: %v", err)
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(f)
		s, perr := ParseScript(name, string(src))
		var v any
		switch {
		case strings.HasPrefix(name, "err-") && perr == nil:
			t.Errorf("%s parsed; an err- fixture must fail", f)
			continue
		case !strings.HasPrefix(name, "err-") && perr != nil:
			t.Errorf("%s: %v", f, perr)
			continue
		case perr != nil:
			se, ok := perr.(*ScriptError)
			if !ok {
				t.Fatalf("%s: error of type %T", f, perr)
			}
			if se.Kind == "" {
				t.Errorf("%s: error without a kind: %v", f, se)
			}
			v = map[string]any{"error": map[string]any{"line": se.Line, "kind": se.Kind}}
		default:
			v = ScriptAST(s)
		}
		golden(t, strings.TrimSuffix(f, ".scn")+".ast.json", astJSON(t, v))
	}
}

// TestScriptASTs pins the canonical AST of every scenario script, for the Rust parser to match.
func TestScriptASTs(t *testing.T) {
	// the embedded files, whose names use / on every OS, as loadScript takes them
	files, err := fs.Glob(scriptFiles, "scripts/*.scn")
	if err != nil || len(files) == 0 {
		t.Fatalf("no scripts: %v", err)
	}
	for _, f := range files {
		s, err := loadScript(f)
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		if want := strings.TrimSuffix(path.Base(f), ".scn"); s.Name != want {
			t.Errorf("%s names scenario %s", f, s.Name)
		}
		golden(t, filepath.Join("scripts/testdata/ast", s.Name+".ast.json"), astJSON(t, ScriptAST(s)))
	}
}

// TestScriptsInTable checks that every script is in Scenarios and loaded without error.
func TestScriptsInTable(t *testing.T) {
	files, _ := filepath.Glob("scripts/*.scn")
	table := map[string]Scenario{}
	for _, s := range Scenarios {
		table[s.Name] = s
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".scn")
		s, ok := table[name]
		switch {
		case !ok:
			t.Errorf("%s is not in Scenarios", f)
		case s.Refs == "script error":
			t.Errorf("%s did not load", f)
		}
	}
}

// TestScriptRNGVectors writes the values the harness draws for a scenario's seed, through newH
// and NewPeer as a scenario draws them: the scenario seed from the run seed and the name, the
// first peer's port and each peer's ISS and timestamp base. The Rust runner ports Go's PCG and
// checks itself against them. 64-bit values are decimal strings, so a reader that parses JSON
// numbers as floats keeps them.
func TestScriptRNGVectors(t *testing.T) {
	type peer struct {
		Port   uint16 `json:"port"`
		ISS    uint32 `json:"iss"`
		TSBase uint32 `json:"ts_base"`
	}
	type vector struct {
		RunSeed      string `json:"run_seed"`
		Scenario     string `json:"scenario"`
		ScenarioSeed string `json:"scenario_seed"`
		Peers        []peer `json:"peers"`
	}
	var out []vector
	for _, run := range []uint64{0, 1, 5, 0x9e3779b97f4a7c15, 1<<64 - 1} {
		for _, name := range []string{"fin-passive-close", "handshake-options", ""} {
			seed := ScenarioSeed(run, name)
			h := newH(t, Engine{Name: "stub"}, name, &stubClocked{}, seed)
			v := vector{RunSeed: strconv.FormatUint(run, 10), Scenario: name, ScenarioSeed: strconv.FormatUint(seed, 10)}
			for range 4 {
				p := h.NewPeer(8000)
				v.Peers = append(v.Peers, peer{Port: p.Local.Port(), ISS: p.ISS, TSBase: p.tsBase})
			}
			out = append(out, v)
		}
	}
	golden(t, "scripts/testdata/rng.json", astJSON(t, out))
}

// TestScriptRNGIntN writes IntN draws that hit its rejection branch, which the scenario vectors
// above do not: a PCG state whose first IntN(20000) draw is rejected, and bounds near 2^63 where a
// draw is rejected often. Each row ends with the Uint32 that follows, so a port that draws a
// different number of values per IntN falls out of step. The Rust runner checks its port against
// the file.
func TestScriptRNGIntN(t *testing.T) {
	type row struct {
		Seed1  string   `json:"seed1"`
		Seed2  string   `json:"seed2"`
		N      string   `json:"n"`
		Draws  []string `json:"draws"`
		Uint32 uint32   `json:"uint32_after"`
	}
	var out []row
	for _, c := range []struct {
		s1, s2 uint64
		n      int
	}{
		{6951352846511211335, 15097960536887720410, 20000},
		{1, 2, 3 << 61},
		{5, 7, 1<<62 + 1},
		{0, 0, math.MaxInt64},
	} {
		r := rand.New(rand.NewPCG(c.s1, c.s2))
		v := row{Seed1: strconv.FormatUint(c.s1, 10), Seed2: strconv.FormatUint(c.s2, 10), N: strconv.Itoa(c.n)}
		for range 8 {
			v.Draws = append(v.Draws, strconv.Itoa(r.IntN(c.n)))
		}
		v.Uint32 = r.Uint32()
		out = append(out, v)
	}
	golden(t, "scripts/testdata/rng-intn.json", astJSON(t, out))
}

// TestScriptRuntimeError checks that a type error in a running script fails the scenario with
// the script's file and line, the way a panic in a Go scenario would fail it.
func TestScriptRuntimeError(t *testing.T) {
	src := "scenario bad\nrefs: test\n\nlet x = 1\nlet y = x + \"a\"\n"
	s, err := ParseScript("bad.scn", src)
	if err != nil {
		t.Fatal(err)
	}
	e := Engine{Name: "stub", New: func(testing.TB, uint64) DUT { return &stubClocked{} }}
	sc := Scenario{Name: "bad", Run: func(h *H) { runScript(h, "bad.scn", s) }}
	_, msgs := RecordFailures(t, e, sc, 1)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "bad.scn:5: int + bytes is not defined") {
		t.Fatalf("failures %q; want one naming bad.scn:5", msgs)
	}
}

// FuzzParseScript checks that the parser and the static checks never panic, and that a script
// that parses has a canonical AST that encodes to JSON. The seeds are every scenario script and
// parser fixture.
func FuzzParseScript(f *testing.F) {
	for _, pat := range []string{"scripts/*.scn", "scripts/testdata/parse/*.scn"} {
		files, _ := filepath.Glob(pat)
		for _, file := range files {
			src, err := os.ReadFile(file)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(string(src))
		}
	}
	f.Fuzz(func(t *testing.T, src string) {
		s, err := ParseScript("fuzz.scn", src)
		if err != nil {
			se, ok := err.(*ScriptError)
			if !ok || se.Kind == "" {
				t.Fatalf("error without a kind: %v", err)
			}
			return
		}
		if _, err := json.Marshal(ScriptAST(s)); err != nil {
			t.Fatalf("the AST does not encode: %v", err)
		}
	})
}

// TestScriptPanicBecomesFailure checks that a Go panic under a script, here the stub DUT's nil
// listener in Accept, fails the scenario with the script's file and line instead of crashing.
func TestScriptPanicBecomesFailure(t *testing.T) {
	src := "scenario bad\nrefs: test\n\nlisten l 8000\naccept c l\n"
	s, err := ParseScript("bad.scn", src)
	if err != nil {
		t.Fatal(err)
	}
	e := Engine{Name: "stub", New: func(testing.TB, uint64) DUT { return &stubClocked{} }}
	sc := Scenario{Name: "bad", Run: func(h *H) { runScript(h, "bad.scn", s) }}
	_, msgs := RecordFailures(t, e, sc, 1)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "bad.scn:5: panic:") {
		t.Fatalf("failures %q; want one naming bad.scn:5 and the panic", msgs)
	}
}
