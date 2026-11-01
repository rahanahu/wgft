package tcpharness

import (
	"bytes"
	"encoding/json"
	"flag"
	"math/rand/v2"
	"os"
	"path/filepath"
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
	if !bytes.Equal(want, data) {
		t.Errorf("%s is out of date; run go test ./internal/tcpharness -run %s -update and review the diff", path, t.Name())
	}
}

func astJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
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
			v = map[string]any{"error": map[string]any{"line": se.Line, "msg": se.Msg}}
		default:
			v = ScriptAST(s)
		}
		golden(t, strings.TrimSuffix(f, ".scn")+".ast.json", astJSON(t, v))
	}
}

// TestScriptASTs pins the canonical AST of every scenario script, for the Rust parser to match.
func TestScriptASTs(t *testing.T) {
	files, err := filepath.Glob("scripts/*.scn")
	if err != nil || len(files) == 0 {
		t.Fatalf("no scripts: %v", err)
	}
	for _, f := range files {
		s, err := loadScript(f)
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		if want := strings.TrimSuffix(filepath.Base(f), ".scn"); s.Name != want {
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

// TestScriptRNGVectors writes the values the harness draws for a scenario's seed: the scenario
// seed from the run seed and the name, the first port and each peer's ISS and timestamp base, in
// the order NewPeer draws them. The Rust runner ports Go's PCG and checks itself against them.
func TestScriptRNGVectors(t *testing.T) {
	type vector struct {
		RunSeed      uint64   `json:"run_seed"`
		Scenario     string   `json:"scenario"`
		ScenarioSeed uint64   `json:"scenario_seed"`
		FirstPort    uint16   `json:"first_port"`
		Draws        []uint32 `json:"draws"`
	}
	var out []vector
	for _, run := range []uint64{0, 1, 5, 0x9e3779b97f4a7c15, 1<<64 - 1} {
		for _, name := range []string{"fin-passive-close", "handshake-options", ""} {
			seed := ScenarioSeed(run, name)
			rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
			v := vector{RunSeed: run, Scenario: name, ScenarioSeed: seed, FirstPort: uint16(40000 + rng.IntN(20000))}
			for range 8 {
				v.Draws = append(v.Draws, rng.Uint32())
			}
			out = append(out, v)
		}
	}
	golden(t, "scripts/testdata/rng.json", astJSON(t, out))
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
