//go:build linux

package conntrack

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/ti-mo/conntrack"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/proto"
)

// TestAgentVerdictSwitchIsExhaustive は、convergeAgent がフローの判定ごとの扱いを並べる switch が、
// agentVerdict のすべての値を case に名指すことを検査する。default はどの判定でもないフローを触らずに
// 残すので、判定を足して扱いを書き忘れると、その判定のフローは黙って残る。ここで落とす。
func TestAgentVerdictSwitchIsExhaustive(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "agent.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var verdicts []string
	for _, d := range file.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		in := false
		for _, s := range g.Specs {
			vs := s.(*ast.ValueSpec)
			switch {
			case vs.Type != nil:
				id, ok := vs.Type.(*ast.Ident)
				in = ok && id.Name == "agentVerdict"
			case len(vs.Values) > 0:
				in = false
			}
			if in {
				for _, n := range vs.Names {
					verdicts = append(verdicts, n.Name)
				}
			}
		}
	}
	if len(verdicts) < 2 {
		t.Fatalf("found the verdicts %v in agent.go; did the const block move?", verdicts)
	}

	var switches []*ast.SwitchStmt
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "convergeAgent" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			if call, ok := sw.Tag.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "classifyAgentFlow" {
					switches = append(switches, sw)
				}
			}
			return true
		})
	}
	if len(switches) != 1 {
		t.Fatalf("found %d switches on classifyAgentFlow in convergeAgent, want 1", len(switches))
	}
	handled := map[string]bool{}
	for _, s := range switches[0].Body.List {
		for _, e := range s.(*ast.CaseClause).List {
			if id, ok := e.(*ast.Ident); ok {
				handled[id.Name] = true
			}
		}
	}
	for _, v := range verdicts {
		if !handled[v] {
			t.Errorf("convergeAgent does not name the verdict %s in its switch; a flow with it would be left alone", v)
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
