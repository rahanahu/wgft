package dataplane_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/rahanahu/wgft"

// moduleRoot finds the directory holding go.mod, walking up from the test's directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// directImports returns every package (in the module or not) the non-test Go files of pkg import
// directly. Files for every GOOS are read, so the result is a superset of any one build's imports.
// The files are opened by this process, so `go test` re-runs the test when any of them changes.
func directImports(t *testing.T, root, pkg string) []string {
	t.Helper()
	dir := filepath.Join(root, strings.TrimPrefix(pkg, module))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			seen[path] = true
		}
	}
	var out []string
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// moduleImports returns the in-module packages among directImports(t, root, pkg).
func moduleImports(t *testing.T, root, pkg string) []string {
	t.Helper()
	var out []string
	for _, path := range directImports(t, root, pkg) {
		if path == module || strings.HasPrefix(path, module+"/") {
			out = append(out, path)
		}
	}
	return out
}

// deps returns every in-module package pkg depends on, directly or not.
func deps(t *testing.T, root, pkg string) []string {
	t.Helper()
	seen := map[string]bool{}
	var walk func(p string)
	walk = func(p string) {
		for _, d := range moduleImports(t, root, p) {
			if !seen[d] {
				seen[d] = true
				walk(d)
			}
		}
	}
	walk(pkg)
	var out []string
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// packagesUnder lists the packages (directories with non-test Go files) at and below dir.
func packagesUnder(t *testing.T, root, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			rel, _ := filepath.Rel(root, filepath.Dir(path))
			p := module + "/" + filepath.ToSlash(rel)
			if len(out) == 0 || out[len(out)-1] != p {
				out = append(out, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestDependencyDirection checks the one-way dependency rules of design.md 7a.7 節 on the real
// import graph, so a stray import fails the tests rather than waiting for a review:
//
//   - nothing under internal/dataplane or internal/reconcile imports a control plane
//     (internal/vpsd, internal/agent or their subpackages): this is what keeps
//     internal/dataplane/linuxkernel free of internal/vpsd (design.md 7a.8 節 Phase 3's completion
//     criterion), the same way it already kept internal/dataplane/userspace free of it since Phase 2;
//   - internal/dataplane (the interface package) and internal/reconcile import no dataplane
//     implementation;
//   - a dataplane implementation (userspace, linuxkernel, and their subpackages: nft, wg, conntrack,
//     relay, utun, ...) imports no other dataplane implementation.
//
// The walk is generic over the implementation directories under internal/dataplane, so a future
// implementation (e.g. the agent's kernel backend reusing linuxkernel, design.md 7a.8 節 Phase 7)
// is checked without editing this test; the explicit count below only guards against the walk
// silently covering zero packages if internal/dataplane's layout changes.
func TestDependencyDirection(t *testing.T) {
	root := moduleRoot(t)
	pkgs := append(packagesUnder(t, root, "internal/dataplane"), packagesUnder(t, root, "internal/reconcile")...)
	if len(pkgs) < 2 {
		t.Fatalf("found packages %v; expected at least internal/dataplane and internal/reconcile", pkgs)
	}
	impl := func(p string) string {
		// ".../internal/dataplane/userspace/relay" -> ".../internal/dataplane/userspace"
		rest, ok := strings.CutPrefix(p, module+"/internal/dataplane/")
		if !ok {
			return ""
		}
		name, _, _ := strings.Cut(rest, "/")
		return module + "/internal/dataplane/" + name
	}
	seenImpl := map[string]bool{}
	for _, pkg := range pkgs {
		own := impl(pkg)
		seenImpl[own] = true
		for _, dep := range deps(t, root, pkg) {
			for _, cp := range []string{"/internal/vpsd", "/internal/agent"} {
				if dep == module+cp || strings.HasPrefix(dep, module+cp+"/") {
					t.Errorf("%s imports %s (a control plane; design.md 7a.7 節)", pkg, dep)
				}
			}
			if d := impl(dep); d != "" && d != own {
				t.Errorf("%s imports the dataplane implementation %s (design.md 7a.7 節)", pkg, dep)
			}
		}
	}
	for _, want := range []string{module + "/internal/dataplane/userspace", module + "/internal/dataplane/linuxkernel"} {
		if !seenImpl[want] {
			t.Errorf("expected to find and check packages under %s, found none; did it move?", want)
		}
	}
}

// TestPureLayersStayPure checks design.md 7a.7 節's rule that internal/model, internal/policy (and
// its sub-packages, the nftables-row and Go-evaluator Admission Policy compilers, design.md 7a.7
// 節's package layout) and internal/planner "know nothing about the OS, nftables, or gVisor": inside
// the module, they import only proto and each other, never dataplane/*, frontend/*, platform/*,
// vpsd or agent. internal/resource, internal/lograte, internal/startup and internal/textsafe are
// even stricter and import nothing at all from the module (design.md 7a.7 節).
func TestPureLayersStayPure(t *testing.T) {
	root := moduleRoot(t)
	var pure []string
	pure = append(pure, packagesUnder(t, root, "internal/model")...)
	pure = append(pure, packagesUnder(t, root, "internal/policy")...)
	pure = append(pure, packagesUnder(t, root, "internal/planner")...)
	if len(pure) < 3 {
		t.Fatalf("found packages %v; expected at least internal/model, internal/policy and internal/planner", pure)
	}
	allowed := map[string]bool{module + "/proto": true}
	for _, p := range pure {
		allowed[p] = true
	}
	for _, pkg := range pure {
		for _, dep := range moduleImports(t, root, pkg) {
			if !allowed[dep] {
				t.Errorf("%s imports %s, neither proto nor another pure layer (design.md 7a.7 節)", pkg, dep)
			}
		}
	}

	// internal/startup is held to the same rule (design.md 7a.7 節): the refusal type is imported
	// by cmd/wgft, internal/vpsd, internal/agent and internal/dataplane/linuxkernel/wg alike, so it
	// stays a leaf. If it grew an import of, say, internal/vpsd/store, every one of those layers
	// would pull the control plane in through it and the direction of 7a.7 節 would break.
	for _, name := range []string{"internal/resource", "internal/lograte", "internal/startup", "internal/textsafe"} {
		pkgs := packagesUnder(t, root, name)
		if len(pkgs) == 0 {
			t.Fatalf("found no packages under %s; did it move?", name)
		}
		for _, pkg := range pkgs {
			if deps := moduleImports(t, root, pkg); len(deps) > 0 {
				t.Errorf("%s imports %v from the module; design.md 7a.7 節 says it imports nothing from the module", pkg, deps)
			}
		}
	}
}

// TestPolicyNftablesDoesNotImportGoogleNftables checks design.md 7a.9 節's rule that
// internal/policy/nftables ("IR から nftables の行の列へのコンパイラ(google/nftables を import
// しない。7a.9 節)") produces a row program and stays out of netlink: only the kernel backend,
// internal/dataplane/linuxkernel/nft, imports google/nftables.
func TestPolicyNftablesDoesNotImportGoogleNftables(t *testing.T) {
	root := moduleRoot(t)
	const pkg = module + "/internal/policy/nftables"
	for _, dep := range directImports(t, root, pkg) {
		if dep == "github.com/google/nftables" || strings.HasPrefix(dep, "github.com/google/nftables/") {
			t.Errorf("%s imports %s (design.md 7a.9 節: it produces a row program; only the kernel backend talks to netlink)", pkg, dep)
		}
	}
}

// TestVpsdSubpackagesDoNotImportVpsd checks design.md 7a.7 節's rule that internal/vpsd's own
// sub-packages never import internal/vpsd itself: the daemon (internal/vpsd) implements the
// sub-packages' interfaces (Backend and friends), so an upward import would defeat that and, for
// internal/dataplane/linuxkernel reused by an agent kernel backend (design.md 7a.8 節 Phase 7),
// would pull the server's control plane in with it.
func TestVpsdSubpackagesDoNotImportVpsd(t *testing.T) {
	root := moduleRoot(t)
	const vpsd = module + "/internal/vpsd"
	pkgs := packagesUnder(t, root, "internal/vpsd")
	var sub []string
	for _, pkg := range pkgs {
		if pkg != vpsd {
			sub = append(sub, pkg)
		}
	}
	if len(sub) == 0 {
		t.Fatalf("found no sub-packages under internal/vpsd (only %v); did they move?", pkgs)
	}
	for _, pkg := range sub {
		for _, dep := range deps(t, root, pkg) {
			if dep == vpsd {
				t.Errorf("%s imports %s (design.md 7a.7 節: a vpsd sub-package must not import vpsd itself)", pkg, dep)
			}
		}
	}
}
