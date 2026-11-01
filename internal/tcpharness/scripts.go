package tcpharness

import (
	"embed"
	"fmt"
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
