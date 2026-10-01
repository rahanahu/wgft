//go:build linux

package conntrack

import (
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/ti-mo/conntrack"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/proto"
)

// TestAgentVerdictSwitchIsExhaustive は、deleteCount がフローの判定ごとの扱いを並べる switch が、
// agentVerdict のすべての値を case に名指すことを検査する。default はどの判定でもないフローを触らずに
// 残すので、判定を足して扱いを書き忘れると、その判定のフローは黙って残る。ここで落とす。
//
// 判定の値は、この package の試験以外のファイル(今の GOOS で build するもの)すべてを型検査して、型が agentVerdict の定数を
// 集める。iota の並びの外に書いた値(agentX = agentVerdict(7) の形)や、別のファイルに置いた値も
// 数える。
func TestAgentVerdictSwitchIsExhaustive(t *testing.T) {
	fset := token.NewFileSet()
	bp, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, name := range bp.GoFiles {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	pkg, err := conf.Check("conntrack", fset, files, info)
	if err != nil {
		t.Fatalf("type-checking the package: %v", err)
	}
	verdictType := pkg.Scope().Lookup("agentVerdict")
	if verdictType == nil {
		t.Fatal("the type agentVerdict is gone; did it move?")
	}
	var verdicts []*types.Const
	for _, name := range pkg.Scope().Names() {
		if c, ok := pkg.Scope().Lookup(name).(*types.Const); ok && types.Identical(c.Type(), verdictType.Type()) {
			verdicts = append(verdicts, c)
		}
	}
	if len(verdicts) < 2 {
		t.Fatalf("found the verdicts %v; did they move?", verdicts)
	}

	var switches []*ast.SwitchStmt
	for _, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "deleteCount" || fn.Recv == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if sw, ok := n.(*ast.SwitchStmt); ok {
					switches = append(switches, sw)
				}
				return true
			})
		}
	}
	if len(switches) != 1 {
		t.Fatalf("found %d switches in deleteCount, want 1", len(switches))
	}
	handled := map[types.Object]bool{}
	for _, s := range switches[0].Body.List {
		for _, e := range s.(*ast.CaseClause).List {
			if id, ok := e.(*ast.Ident); ok {
				handled[info.Uses[id]] = true
			}
		}
	}
	for _, v := range verdicts {
		if !handled[v] {
			t.Errorf("deleteCount does not name the verdict %s in its switch; a flow with it would be left alone", v.Name())
		}
	}
}

// deleteCount は、消す判定にだけ数を返し、それ以外の値には nil を返す。convergeAgent は nil のフローを
// 消さないので、数を返さない判定が増えても panic せず、消さずに残す。
func TestDeleteCountForEachVerdict(t *testing.T) {
	for _, tc := range []struct {
		v    agentVerdict
		want func(r *AgentResult) *int // nil なら消さない
		kept int
	}{
		{agentForeign, nil, 0},
		{agentKeep, nil, 1},
		{agentRemoved, func(r *AgentResult) *int { return &r.Removed }, 0},
		{agentRetargeted, func(r *AgentResult) *int { return &r.Retargeted }, 0},
		{agentNotAllowed, func(r *AgentResult) *int { return &r.NotAllowed }, 0},
		{agentVerdict(99), nil, 0}, // classifyAgentFlow が返さない値
	} {
		var res AgentResult
		got := res.deleteCount(tc.v)
		switch {
		case tc.want == nil && got != nil:
			t.Errorf("verdict %d: deleteCount returned a count, want nil (leave the flow)", tc.v)
		case tc.want != nil && got != tc.want(&res):
			t.Errorf("verdict %d: deleteCount returned the wrong count", tc.v)
		}
		if res.Kept != tc.kept || res.Removed != 0 || res.Retargeted != 0 || res.NotAllowed != 0 || res.Failed != 0 {
			t.Errorf("verdict %d: deleteCount changed the result to %+v, want only Kept %d", tc.v, res, tc.kept)
		}
	}
}

// convergeAgent は、消した判定ごとに別の数に数える。許可一覧の外になったフロー、宛先が変わったフロー、
// 宣言から消えたフローを 1 つずつ渡し、残すフローと見分けられないフローも 1 つずつ混ぜる。
func TestConvergeAgentCountsEachVerdict(t *testing.T) {
	mc := rule("r_mc", proto.TCP, 25565, 25565, "192.168.1.22:25565")
	web := rule("r_web", proto.TCP, 8443, 8443, "192.168.1.30:443")
	gone := rule("r_gone", proto.TCP, 7000, 7000, "192.168.1.40:7000")
	webAddr := web
	webAddr.Target = "192.168.1.31:443"
	allow := allowOnly("192.168.1.30/31")
	prev := publish(nil, nil, mc, web, gone)
	cur := publish(nil, allow, mc, webAddr)
	c := &fakeAgentConn{flows: []conntrack.Flow{
		agentFlow(6, 25565, "192.168.1.22:25565"), // 宣言は変わらないが、許可一覧の外になった
		agentFlow(6, 8443, "192.168.1.30:443"),    // 宛先が変わった
		agentFlow(6, 8443, "192.168.1.31:443"),    // 新しい宛先へのフロー
		agentFlow(6, 7000, "192.168.1.40:7000"),   // 削除した
		agentFlow(6, 7000, "172.17.0.2:80"),       // 他のテーブルの DNAT
	}}
	scope := agentScope
	scope.AllowTarget = allow
	res, err := convergeAgent(c, []nft.AgentPublication{prev}, cur, scope)
	if err != nil {
		t.Fatal(err)
	}
	if want := (AgentResult{Kept: 1, Removed: 1, Retargeted: 1, NotAllowed: 1}); res != want {
		t.Errorf("result = %+v, want %+v", res, want)
	}
	if len(c.deleted) != 3 {
		t.Errorf("deleted %d flows, want 3", len(c.deleted))
	}
}
