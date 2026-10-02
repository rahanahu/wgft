package dataplane_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
// The walk is generic over the implementation directories under internal/dataplane, so a new
// implementation directory is checked without editing this test; the explicit count below only guards against the walk
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
// vpsd or agent. internal/resource, internal/lograte, internal/startup, internal/textsafe and
// internal/reasontext are even stricter and import nothing at all from the module (design.md 7a.7 節).
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
	for _, name := range []string{"internal/resource", "internal/lograte", "internal/startup", "internal/textsafe", "internal/reasontext"} {
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

// TestVpsdTeardownImportsOnlyTheStore checks design.md 7a.7 節's rule for internal/vpsd/teardown:
// `wgft server teardown` runs only after the server has stopped and reads the server database for
// what to remove, so of the packages under internal/vpsd it imports the store alone, never the
// daemon nor the packages the running daemon serves through (admin, agentapi, stream, proxyrelay).
func TestVpsdTeardownImportsOnlyTheStore(t *testing.T) {
	root := moduleRoot(t)
	const vpsd = module + "/internal/vpsd"
	pkgs := packagesUnder(t, root, "internal/vpsd/teardown")
	if len(pkgs) == 0 {
		t.Fatal("found no package under internal/vpsd/teardown; did it move?")
	}
	for _, pkg := range pkgs {
		for _, dep := range deps(t, root, pkg) {
			if (dep == vpsd || strings.HasPrefix(dep, vpsd+"/")) && dep != vpsd+"/store" {
				t.Errorf("%s imports %s (design.md 7a.7 節: server teardown imports only internal/vpsd/store from internal/vpsd)", pkg, dep)
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

// TestVpsdServerCheckImportsOnlyTheStore checks design.md 7a.7 節's rule for
// internal/vpsd/servercheck: `wgft server check` runs without starting the server and only reads
// the server database, so of the packages under internal/vpsd it imports the store alone, never the
// daemon nor the packages the running daemon serves through (admin, agentapi, stream, proxyrelay).
func TestVpsdServerCheckImportsOnlyTheStore(t *testing.T) {
	root := moduleRoot(t)
	const vpsd = module + "/internal/vpsd"
	pkgs := packagesUnder(t, root, "internal/vpsd/servercheck")
	if len(pkgs) == 0 {
		t.Fatal("found no package under internal/vpsd/servercheck; did it move?")
	}
	for _, pkg := range pkgs {
		for _, dep := range deps(t, root, pkg) {
			if (dep == vpsd || strings.HasPrefix(dep, vpsd+"/")) && dep != vpsd+"/store" {
				t.Errorf("%s imports %s (design.md 7a.7 節: server check imports only internal/vpsd/store from internal/vpsd)", pkg, dep)
			}
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

// TestAgentSubpackagesDoNotImportAgent checks design.md 7a.7 節's rule that internal/agent's own
// sub-packages (credentials, allowtargets, teardown, ...) never import internal/agent itself, the
// same rule TestVpsdSubpackagesDoNotImportVpsd checks for the server: the agent's runtime lives in
// internal/agent and uses its sub-packages, so an upward import is either an import cycle or ties a
// one-shot command such as agent teardown to the runtime it is meant to stay apart from.
func TestAgentSubpackagesDoNotImportAgent(t *testing.T) {
	root := moduleRoot(t)
	const agent = module + "/internal/agent"
	pkgs := packagesUnder(t, root, "internal/agent")
	var sub []string
	for _, pkg := range pkgs {
		if pkg != agent {
			sub = append(sub, pkg)
		}
	}
	if len(sub) == 0 {
		t.Fatalf("found no sub-packages under internal/agent (only %v); did they move?", pkgs)
	}
	for _, pkg := range sub {
		for _, dep := range deps(t, root, pkg) {
			if dep == agent {
				t.Errorf("%s imports %s (design.md 7a.7 節: an agent sub-package must not import agent itself)", pkg, dep)
			}
		}
	}
}

// TestWireShapesStayLeaf checks design.md 7a.7 節's rule for the two packages that hold a control
// plane's wire shapes: internal/vpsd/adminapi (the admin API's read model) and
// internal/agent/controlapi (the agent's control socket). Inside the module they import only
// proto, so a reader of the shapes (cmd/wgft, internal/vpsd/doctor) never pulls in the daemon or
// the agent that serves them. controlapi may also import internal/resource, whose Reason type the
// flow-budget refusals carry; TestPureLayersStayPure holds internal/resource to importing nothing
// from the module, so the leaf stays a leaf.
func TestWireShapesStayLeaf(t *testing.T) {
	root := moduleRoot(t)
	allowed := map[string][]string{
		module + "/internal/vpsd/adminapi":    {module + "/proto"},
		module + "/internal/agent/controlapi": {module + "/proto", module + "/internal/resource"},
	}
	for pkg, ok := range allowed {
		if _, err := os.Stat(filepath.Join(root, strings.TrimPrefix(pkg, module))); err != nil {
			t.Fatalf("%s: %v; did it move?", pkg, err)
		}
		for _, dep := range deps(t, root, pkg) {
			found := false
			for _, a := range ok {
				if dep == a {
					found = true
				}
			}
			if !found {
				t.Errorf("%s depends on %s; design.md 7a.7 節 allows only %v from the module", pkg, dep, ok)
			}
		}
	}
}

// TestAgentDataplaneBoundaryImports checks design.md 7a.7 節's rule for internal/agent/agentdp,
// the boundary between the agent's runtime and its two dataplane modes. The runtime and both modes
// import it, so it stays below all of them: from the module it imports directly only the wire
// schema, the resource budgets, the dataplane's Sensor, the userspace relay and socket-buffer types
// its reading carries, and controlapi for the kernel reading of agent doctor. Through these it never
// reaches internal/agent, another agent sub-package, or the kernel layer under
// internal/dataplane/linuxkernel.
func TestAgentDataplaneBoundaryImports(t *testing.T) {
	root := moduleRoot(t)
	const pkg = module + "/internal/agent/agentdp"
	const agent = module + "/internal/agent"
	if _, err := os.Stat(filepath.Join(root, strings.TrimPrefix(pkg, module))); err != nil {
		t.Fatalf("%s: %v; did it move?", pkg, err)
	}
	allowed := map[string]bool{
		module + "/proto":                                true,
		module + "/internal/resource":                    true,
		module + "/internal/dataplane":                   true,
		module + "/internal/dataplane/userspace/relay":   true,
		module + "/internal/dataplane/userspace/sockbuf": true,
		module + "/internal/agent/controlapi":            true,
	}
	for _, dep := range moduleImports(t, root, pkg) {
		if !allowed[dep] {
			t.Errorf("%s imports %s; design.md 7a.7 節 does not allow it", pkg, dep)
		}
	}
	for _, dep := range deps(t, root, pkg) {
		switch {
		case dep == agent:
			t.Errorf("%s depends on %s (design.md 7a.7 節: the boundary sits below the runtime)", pkg, dep)
		case strings.HasPrefix(dep, agent+"/") && dep != agent+"/controlapi":
			t.Errorf("%s depends on %s (design.md 7a.7 節: of internal/agent, the boundary imports only controlapi)", pkg, dep)
		case dep == module+"/internal/dataplane/linuxkernel" || strings.HasPrefix(dep, module+"/internal/dataplane/linuxkernel/"):
			t.Errorf("%s depends on %s (design.md 7a.7 節: the boundary does not pull in the kernel layer)", pkg, dep)
		}
	}
}

// TestAgentModesStayApart checks design.md 7a.7 節's rule for the packages that hold the agent's
// two dataplane modes, and for how internal/agent reaches them. The rule covers the non-test files
// only: directImports and deps read no _test.go file, and the tests of a mode package may import
// what its production files may not, such as internal/vpsd/doctor for a reason round trip.
//
//   - internal/agent/usermode, the userspace mode, imports from internal/agent only the boundary
//     (agentdp) and the allowlist (allowtargets). Through any import it reaches neither
//     internal/agent itself, where the runtime lives, nor internal/agent/kernelmode, nor the kernel
//     layer under internal/dataplane/linuxkernel.
//   - internal/agent/kernelmode, the kernel mode, imports from internal/agent only agentdp,
//     allowtargets, credentials and controlapi. Through any import it reaches neither
//     internal/agent itself, nor internal/agent/usermode, nor any package under internal/vpsd. It
//     does not import internal/dataplane/userspace or a package under it directly. It does depend
//     on the relay and socket-buffer packages transitively, through agentdp, whose reading carries
//     their types.
//   - internal/agent itself does not import internal/dataplane/linuxkernel or a package under it
//     directly.
//
// The last two rules look at direct imports only. A transitive path through another package is
// outside them: for example, internal/agent importing internal/agent/teardown, which imports the
// kernel layer, does not fail this test.
func TestAgentModesStayApart(t *testing.T) {
	root := moduleRoot(t)
	const agent = module + "/internal/agent"
	under := func(dep, pkg string) bool { return dep == pkg || strings.HasPrefix(dep, pkg+"/") }
	const linuxkernel = module + "/internal/dataplane/linuxkernel"
	for _, mode := range []struct {
		pkg, other string
		allowed    []string
	}{
		{agent + "/usermode", agent + "/kernelmode", []string{"agentdp", "allowtargets"}},
		{agent + "/kernelmode", agent + "/usermode", []string{"agentdp", "allowtargets", "credentials", "controlapi"}},
	} {
		pkg := mode.pkg
		if _, err := os.Stat(filepath.Join(root, strings.TrimPrefix(pkg, module))); err != nil {
			t.Fatalf("%s: %v; did it move?", pkg, err)
		}
		allowed := map[string]bool{}
		for _, a := range mode.allowed {
			allowed[agent+"/"+a] = true
		}
		for _, dep := range moduleImports(t, root, pkg) {
			if strings.HasPrefix(dep, agent+"/") && !allowed[dep] {
				t.Errorf("%s imports %s; design.md 7a.7 節 allows only %v from internal/agent", pkg, dep, mode.allowed)
			}
		}
		for _, dep := range deps(t, root, pkg) {
			switch {
			case dep == agent:
				t.Errorf("%s depends on %s (design.md 7a.7 節: a mode sits below the runtime)", pkg, dep)
			case under(dep, mode.other):
				t.Errorf("%s depends on %s (design.md 7a.7 節: the two modes do not import each other)", pkg, dep)
			case pkg == agent+"/usermode" && under(dep, linuxkernel):
				t.Errorf("%s depends on %s (design.md 7a.7 節: the userspace mode does not pull in the kernel layer)", pkg, dep)
			case pkg == agent+"/kernelmode" && under(dep, module+"/internal/vpsd"):
				t.Errorf("%s depends on %s (design.md 7a.7 節: the kernel mode does not pull in the server)", pkg, dep)
			}
		}
		if pkg == agent+"/kernelmode" {
			for _, dep := range directImports(t, root, pkg) {
				if under(dep, module+"/internal/dataplane/userspace") {
					t.Errorf("%s imports %s (design.md 7a.7 節: the kernel mode does not import the userspace layer directly)", pkg, dep)
				}
			}
		}
	}
	for _, dep := range directImports(t, root, agent) {
		if under(dep, linuxkernel) {
			t.Errorf("%s imports %s (design.md 7a.7 節: internal/agent does not import the kernel layer directly)", agent, dep)
		}
	}
}

// modeSeams lists, for each agent mode package, the names that production code outside the
// package may use. A package-level name is spelled as is, a field or method as Type.Name.
var modeSeams = map[string]map[string]bool{
	module + "/internal/agent/usermode": {"New": true},
	module + "/internal/agent/kernelmode": {
		"New": true, "Built": true, "Prerequisites": true, "ProcessNetAdmin": true, "ReadKernel": true,
	},
}

// modeTestSeams lists, for each agent mode package, the names it exports only so that
// internal/agent's tests can reach them, spelled as in modeSeams. Production code outside the
// package may not use them. A method that implements an interface of internal/agent/agentdp, the
// boundary the runtime calls through, belongs to neither list. Every other exported name of a mode
// package is in exactly one of the two lists, so a name exported later has to be placed in one.
var modeTestSeams = map[string]map[string]bool{
	module + "/internal/agent/usermode": {
		"Dataplane": true, "Dataplane.Allow": true, "Dataplane.Limits": true, "Dataplane.Tun": true,
		"Dataplane.Relay": true, "Dataplane.RelayOptions": true,
		"NewTunnel": true, "ReadTunnelStatus": true, "RuleStatuses": true,
	},
	module + "/internal/agent/kernelmode": {
		"Dataplane": true, "NewWithOps": true, "Dataplane.LinkConfig": true,
		"Dataplane.Ops": true, "Dataplane.Priv": true, "Dataplane.WG": true, "Dataplane.Pub": true,
		"Dataplane.ObserveErr": true,
		"Ops":                  true, "Ops.EnsureLink": true, "Ops.InspectLink": true, "Ops.KeyHolders": true,
		"Ops.Publish": true, "Ops.Fingerprint": true, "Ops.Lookup": true, "Ops.Probe": true,
		"Ops.ReadIPForward": true, "Ops.WriteIPForward": true, "Ops.LocalAddrs": true, "Ops.Now": true,
		"Ops.SendDatagram": true, "Ops.RouteIface": true, "Ops.ConvergeFlows": true, "Ops.Notify": true,
		"MaxUnconverged": true,
		"DoctorOps":      true, "DoctorOps.Link": true, "DoctorOps.InspectLink": true,
		"DoctorOps.InspectTable": true, "DoctorOps.ReadSysctl": true, "DoctorOps.ForwardDrops": true,
		"DoctorOps.Route": true, "DoctorOps.LocalAddrs": true, "DoctorKernelOps": true,
	},
}

// TestAgentModeTestSeamsStayInTests checks design.md 7a.7 節's rule that the names an agent mode
// package exports only for internal/agent's tests (modeTestSeams) are not used by production code
// outside that package; of a mode package, production code outside it uses only the names in
// modeSeams. Go has no visibility for tests alone, so the rule is checked here. It type-checks the
// non-test files of every package in the module that imports a mode package, for the GOOS the test
// runs on, and resolves each identifier to its object, so a field or method reached through a
// value is caught as well as a qualified name. The imports are read from export data that
// `go list -export` builds. It does not catch a use that never names the object, such as a type
// assertion to an interface the caller defines or access through reflection.
//
// It also reads each mode package's exported names from its export data and checks that every
// one is listed in exactly one of modeSeams and modeTestSeams, apart from the methods that
// implement an interface of internal/agent/agentdp. On linux, where the mode packages export the
// most, it checks too that no listed name is missing from the package.
func TestAgentModeTestSeamsStayInTests(t *testing.T) {
	root := moduleRoot(t)
	type listed struct {
		ImportPath string
		Dir        string
		GoFiles    []string
		Imports    []string
		Export     string
		Error      *struct{ Err string }
	}
	goList := func(args ...string) []listed {
		t.Helper()
		cmd := exec.Command("go", append([]string{"list", "-e", "-json=ImportPath,Dir,GoFiles,Imports,Export,Error"}, args...)...)
		cmd.Dir = root
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list %v: %v\n%s", args, err, stderr.String())
		}
		var ps []listed
		for dec := json.NewDecoder(bytes.NewReader(out)); ; {
			var p listed
			if err := dec.Decode(&p); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			ps = append(ps, p)
		}
		return ps
	}
	var importers []listed
	for _, p := range goList("./...") {
		if p.Error != nil {
			t.Fatalf("go list %s: %s", p.ImportPath, p.Error.Err)
		}
		for _, imp := range p.Imports {
			if _, ok := modeSeams[imp]; ok && p.ImportPath != imp {
				importers = append(importers, p)
				break
			}
		}
	}
	if len(importers) == 0 {
		t.Fatal("no package imports an agent mode package; did internal/agent stop using internal/agent/usermode?")
	}
	var paths []string
	for _, p := range importers {
		paths = append(paths, p.ImportPath)
	}
	exports := map[string]string{}
	for _, p := range goList(append([]string{"-export", "-deps"}, paths...)...) {
		exports[p.ImportPath] = p.Export
	}
	for _, p := range importers {
		fset := token.NewFileSet()
		var files []*ast.File
		for _, name := range p.GoFiles {
			f, err := parser.ParseFile(fset, filepath.Join(p.Dir, name), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
			if exports[path] == "" {
				return nil, errors.New("no export data for " + path)
			}
			return os.Open(exports[path])
		})
		info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
		if _, err := (&types.Config{Importer: imp}).Check(p.ImportPath, fset, files, info); err != nil {
			t.Fatalf("type-checking %s: %v", p.ImportPath, err)
		}
		for id, obj := range info.Uses {
			if obj.Pkg() == nil {
				continue
			}
			ok, isMode := modeSeams[obj.Pkg().Path()]
			if !isMode || obj.Pkg().Path() == p.ImportPath {
				continue
			}
			name := obj.Name()
			if recv := memberOf(obj); recv != "" {
				name = recv + "." + name
			}
			if !ok[name] {
				t.Errorf("%s: %s uses %s.%s, which %s exports only for internal/agent's tests (design.md 7a.7 節)",
					fset.Position(id.Pos()), p.ImportPath, obj.Pkg().Name(), name, obj.Pkg().Path())
			}
		}
	}

	imp := importer.ForCompiler(token.NewFileSet(), "gc", func(path string) (io.ReadCloser, error) {
		if exports[path] == "" {
			return nil, errors.New("no export data for " + path)
		}
		return os.Open(exports[path])
	})
	boundary, err := imp.Import(module + "/internal/agent/agentdp")
	if err != nil {
		t.Fatal(err)
	}
	// implementsBoundary reports whether method m of named is a method of an agentdp interface that
	// *named implements.
	implementsBoundary := func(named *types.Named, m string) bool {
		for _, n := range boundary.Scope().Names() {
			iface, ok := boundary.Scope().Lookup(n).Type().Underlying().(*types.Interface)
			if !ok || !types.Implements(types.NewPointer(named), iface) {
				continue
			}
			for i := 0; i < iface.NumMethods(); i++ {
				if iface.Method(i).Name() == m {
					return true
				}
			}
		}
		return false
	}
	for path, prod := range modeSeams {
		pkg, err := imp.Import(path)
		if err != nil {
			t.Fatalf("reading the export data of %s: %v", path, err)
		}
		seen := map[string]bool{}
		place := func(name string) {
			seen[name] = true
			if prod[name] == modeTestSeams[path][name] {
				t.Errorf("%s exports %s, which is in neither or both of modeSeams and modeTestSeams; list it in one (design.md 7a.7 節)", path, name)
			}
		}
		for _, n := range pkg.Scope().Names() {
			obj := pkg.Scope().Lookup(n)
			if !obj.Exported() {
				continue
			}
			place(n)
			tn, ok := obj.(*types.TypeName)
			if !ok {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok {
				continue
			}
			for i := 0; i < named.NumMethods(); i++ {
				if m := named.Method(i); m.Exported() && !implementsBoundary(named, m.Name()) {
					place(n + "." + m.Name())
				}
			}
			if st, ok := named.Underlying().(*types.Struct); ok {
				for i := 0; i < st.NumFields(); i++ {
					if f := st.Field(i); f.Exported() {
						place(n + "." + f.Name())
					}
				}
			}
		}
		if runtime.GOOS != "linux" {
			continue
		}
		for _, list := range []map[string]bool{prod, modeTestSeams[path]} {
			for name := range list {
				if !seen[name] {
					t.Errorf("modeSeams or modeTestSeams lists %s for %s, which does not export it", name, path)
				}
			}
		}
	}
}

// memberOf returns the name of the type that declares obj when obj is a field or a method, and ""
// otherwise. An embedded or anonymous struct's field is reported under the field's own name.
func memberOf(obj types.Object) string {
	var t types.Type
	switch o := obj.(type) {
	case *types.Var:
		if !o.IsField() {
			return ""
		}
		if o.Origin() != nil {
			o = o.Origin()
		}
		// A field does not record its struct; find the named type in the package that declares it.
		scope := o.Pkg().Scope()
		for _, n := range scope.Names() {
			tn, ok := scope.Lookup(n).(*types.TypeName)
			if !ok {
				continue
			}
			if st, ok := tn.Type().Underlying().(*types.Struct); ok {
				for i := 0; i < st.NumFields(); i++ {
					if st.Field(i) == o {
						return tn.Name()
					}
				}
			}
		}
		return "?"
	case *types.Func:
		sig, ok := o.Type().(*types.Signature)
		if !ok || sig.Recv() == nil {
			return ""
		}
		t = sig.Recv().Type()
	default:
		return ""
	}
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok {
		return n.Obj().Name()
	}
	return "?"
}

// TestVpsdTailnetImportsNoServerPackage checks design.md 7a.7 節's rule for
// internal/vpsd/tailnet: the --admin-tailscale listener does not depend on the daemon. It takes the
// admin API's handler and the Host check's update as function values, so it imports no package
// under internal/vpsd, not even the admin API's own; the daemon wires the two together.
func TestVpsdTailnetImportsNoServerPackage(t *testing.T) {
	root := moduleRoot(t)
	const vpsd = module + "/internal/vpsd"
	pkgs := packagesUnder(t, root, "internal/vpsd/tailnet")
	if len(pkgs) == 0 {
		t.Fatal("found no package under internal/vpsd/tailnet; did it move?")
	}
	for _, pkg := range pkgs {
		for _, dep := range deps(t, root, pkg) {
			if dep == vpsd || strings.HasPrefix(dep, vpsd+"/") {
				t.Errorf("%s imports %s (design.md 7a.7 節: the tailnet listener imports no server package)", pkg, dep)
			}
		}
	}
}

// TestControlPlanesDoNotImportEachOther checks design.md 7a.7 節's rule that the two control planes
// share code only through the layers below them: no package under internal/vpsd depends on a
// package under internal/agent, and no package under internal/agent depends on one under
// internal/vpsd. The rule reasons the agent writes and server doctor reads share their fragments
// through internal/reasontext, a leaf, rather than through either control plane.
func TestControlPlanesDoNotImportEachOther(t *testing.T) {
	root := moduleRoot(t)
	for _, side := range []struct{ from, other string }{
		{"internal/vpsd", "internal/agent"},
		{"internal/agent", "internal/vpsd"},
	} {
		pkgs := packagesUnder(t, root, side.from)
		if len(pkgs) == 0 {
			t.Fatalf("found no package under %s; did it move?", side.from)
		}
		other := module + "/" + side.other
		for _, pkg := range pkgs {
			for _, dep := range deps(t, root, pkg) {
				if dep == other || strings.HasPrefix(dep, other+"/") {
					t.Errorf("%s imports %s (design.md 7a.7 節: one control plane does not import the other)", pkg, dep)
				}
			}
		}
	}
}
