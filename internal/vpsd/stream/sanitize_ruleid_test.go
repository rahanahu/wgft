package stream

import (
	"strings"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// TestAcceptedRuleIDsSurviveTheHeartbeat は、ルールの検査(proto.Rule.Validate、仕様 5.3 節)が受ける
// ID が、ハートビートの受け口を手を加えられずに通ることを確かめる。通らない ID のルールは、
// エージェントが報告しても保存した ID がルールの ID と一致せず、状態が永久に「報告なし」になる。
// 拒む側の値が受け口で変わることも確かめ、2 つの上限と文字の範囲が対応していることを示す。
// 変異の確認:maxHeartbeatIDLen を proto.MaxRuleIDLen より小さくすると、128 バイトの行が落ちる。
func TestAcceptedRuleIDsSurviveTheHeartbeat(t *testing.T) {
	accepted := []string{
		strings.Repeat("a", proto.MaxRuleIDLen),
		strings.Repeat("a", proto.MaxRuleIDLen-3) + "あ",
		"週末 サーバ 2456",
		"game:valley/#1 <a&b> 🎮",
		"r_01JABCDEFGHJKMNPQRSTVWXYZ0",
	}
	refused := []string{
		strings.Repeat("a", proto.MaxRuleIDLen+1),
		"r_a\nr_b",
		"r_\x1b[31m",
		"r_\u202e",
		"r_\xff",
	}
	check := func(id string, wantValid bool) {
		r := proto.Rule{ID: id, Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 3000, Hi: 3000},
			Target: "192.168.1.20:3000", VPSMode: proto.ModeKernel}
		if (r.Validate() == nil) != wantValid {
			t.Fatalf("Validate() with id %q = %v, want valid=%v; fix the fixture", id, r.Validate(), wantValid)
		}
		hb := sanitizeHeartbeat(&proto.Heartbeat{Rules: []proto.RuleStatus{{ID: id, State: proto.StatusOK}}})
		if got := hb.Rules[0].ID; (got == id) != wantValid {
			t.Errorf("heartbeat stored id %q for %q; unchanged=%v, want %v", got, id, got == id, wantValid)
		}
	}
	for _, id := range accepted {
		check(id, true)
	}
	for _, id := range refused {
		check(id, false)
	}
}
