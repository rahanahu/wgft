package tcpharness

import (
	"embed"
	"fmt"
	"strings"
)

// The scenario scripts of docs/design/v2/test-tooling.md. A converted scenario keeps its place in
// Scenarios; its entry runs the script of the same name.
//
//go:embed scripts/*.scn
var scriptFiles embed.FS

// script returns the Scenario of scripts/<name>.scn. A script that does not parse or whose
// header names another scenario becomes a scenario that fails with the error, so the rest of the
// table and the package's importers keep working.
func script(name string) Scenario {
	file := "scripts/" + name + ".scn"
	s, err := loadScript(file)
	if err == nil && s.Name != name {
		err = fmt.Errorf("%s: the header names scenario %s", file, s.Name)
	}
	if err != nil {
		return Scenario{Name: name, Refs: "script error", Run: func(h *H) { h.T.Fatalf("%v", err) }}
	}
	return Scenario{Name: name, Refs: s.Refs, Linux: s.Linux, Run: func(h *H) { runScript(h, file, s) }}
}

func loadScript(file string) (*Script, error) {
	src, err := scriptFiles.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return ParseScript(file, string(src))
}

// CheckLines keeps the lines of a trace that a real-time DUT gives the same way on every run:
// each check's outcome, key, expectation and observation, and the names of the measured values
// without the values. Segment lines carry the engine's own random numbers and are left out.
func CheckLines(lines []string) []string {
	var out []string
	for _, l := range lines {
		for _, p := range []string{"PASS  ", "FAIL  ", "KNOWN DIFFERENCE  ", "CHANGED DIFFERENCE  ", "UNEXPECTED PASS  "} {
			if strings.HasPrefix(l, p) {
				out = append(out, l)
			}
		}
		// MEASURE engine=NAME scenario/name=value: keep everything before the value
		if engine, rest, ok := strings.Cut(l, " "); ok && engine == "MEASURE" {
			eng, rest, _ := strings.Cut(rest, " ")
			name, _, _ := strings.Cut(rest, "=")
			out = append(out, "MEASURE "+eng+" "+name)
		}
	}
	return out
}

// DiffLines returns the first line where want and got differ, or "" when they are equal.
func DiffLines(want, got []string) string {
	for i := range max(len(want), len(got)) {
		var w, g string
		if i < len(want) {
			w = want[i]
		}
		if i < len(got) {
			g = got[i]
		}
		if w != g {
			return fmt.Sprintf("line %d differs\n    Go: %s\nscript: %s", i, w, g)
		}
	}
	return ""
}
