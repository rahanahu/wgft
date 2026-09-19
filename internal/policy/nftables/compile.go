package nftables

import (
	"fmt"

	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

// Compile は IR と判定を付けるポートの列から行の列を作る(設計文書 7a.9 節)。
//
// 行はポートの順(ports の順。呼び出し側は Plan の順で渡す)に並び、1 つのポートの中では
// policy.Order を順に回して段ごとに作る。段の順序はこの関数自身では持たない。
//
// 行を作らない条件は次のとおりで、6.1 節のままである。deny と allow が空なら set も行も作らない
// (空の set に != を書くと全送信元が落ちる)。レートが未設定なら行を作らない。同時フロー数の上限が
// 0 のプロトコルには set も行も作らない。
//
// どの行も IPv4 のパケットにだけ一致する(Match.IPv4)。v1 は IPv4 だけを扱い、IPv6 のパケットは
// DNAT されないので、判定もトークンの消費もしない。
//
// Transparent のポートと Relay のポートは、同じ段の行を同じ順で持つ(設計文書 7a.9 節「`Forwarding`
// の値によって Admission Policy の意味は変わらない」)。Relay のポートは、frontend が待ち受けを
// 開けているものだけを呼び出し側が渡す。
//
// set の名前は deny_N、allow_N、meter_N(N は ports の順に振る連番)と、プロトコルごとに 1 つを
// 全ルールで共有する flows_udp、flows_tcp である。
//
// TCP のルールも packet の行を持つ。設計文書 7a.9 節「TCP の packet_rate」は TCP に packet の行を
// 作らないと定めており、移行の手順 5 でやめる。fixture の interim_until_step が印を付けている
// (internal/policy/testdata/admission)。
//
// ports の各ルール ID は IR(pol.Rules)に無ければならない。無ければ誤りを返す。IR に無いルールの
// ポートに判定の無い行を置くと、そのポートの通信を送信元の制限なしに通してしまうためである。
func Compile(pol policy.Policy, ports []Port) (Program, error) {
	byID := make(map[string]policy.RulePolicy, len(pol.Rules))
	for _, rp := range pol.Rules {
		byID[rp.RuleID] = rp
	}
	c := compiler{caps: pol.PerSourceFlowCaps, declared: map[string]bool{}}
	n := 0
	for _, pt := range ports {
		rp, ok := byID[pt.RuleID]
		if !ok {
			return Program{}, fmt.Errorf("rule %s: no admission policy for this port", pt.RuleID)
		}
		if rp.Proto != pt.Proto {
			return Program{}, fmt.Errorf("rule %s: port protocol %s differs from the policy's %s", pt.RuleID, pt.Proto, rp.Proto)
		}
		switch pt.Forwarding {
		case model.Transparent, model.Relay:
			// set の連番は、判定を付けるポートの順に進める。Relay のポートも Transparent と同じ段の
			// 行を持つので、同じように連番を進める(設計文書 6.1 節)。
			n++
		default:
			return Program{}, fmt.Errorf("rule %s: unknown forwarding %v", pt.RuleID, pt.Forwarding)
		}
		for _, step := range policy.Order {
			if err := c.step(step, pt, rp, n); err != nil {
				return Program{}, fmt.Errorf("rule %s: %w", pt.RuleID, err)
			}
		}
	}
	return c.prog, nil
}

type compiler struct {
	caps     policy.PerSourceFlowCaps
	prog     Program
	declared map[string]bool
}

func (c *compiler) declare(s Set) {
	if c.declared[s.Name] {
		return
	}
	c.declared[s.Name] = true
	c.prog.Sets = append(c.prog.Sets, s)
}

func (c *compiler) row(pt Port, step policy.Step, ctNew bool, st Stmt) {
	kind := step.DropKind()
	c.prog.Rows = append(c.prog.Rows, Row{
		RuleID: pt.RuleID, Step: step, Kind: kind, Comment: Comment(pt.RuleID, kind),
		Match: Match{Proto: pt.Proto, Ports: pt.Ports, CtStateNew: ctNew, IPv4: true},
		Stmt:  st,
	})
}

// step は段 1 つ分の set と行を作る。段ごとの一致条件(ct state new の有無)と文は、IR の
// 「段の適用範囲」(設計文書 7a.9 節)に従う。deny と allow はすべてのパケットに、送信元ごとの
// 新規フローレート、同時フロー数の上限、集約の新規フローレートは新しいフローの最初のパケットに、
// パケットレートはすべてのパケットに効く。
func (c *compiler) step(step policy.Step, pt Port, rp policy.RulePolicy, n int) error {
	burst := uint32(policy.TokenBucketBurst)
	switch step {
	case policy.StepSourceDeny:
		if len(rp.SourceDeny) == 0 {
			return nil
		}
		name := fmt.Sprintf("deny_%d", n)
		c.declare(Set{Name: name, Kind: SetInterval, Elements: rp.SourceDeny})
		c.row(pt, step, false, Stmt{Kind: StmtSourceInSet, Set: name})
	case policy.StepSourceAllow:
		if len(rp.SourceAllow) == 0 {
			return nil
		}
		name := fmt.Sprintf("allow_%d", n)
		c.declare(Set{Name: name, Kind: SetInterval, Elements: rp.SourceAllow})
		c.row(pt, step, false, Stmt{Kind: StmtSourceNotInSet, Set: name})
	case policy.StepPerSourceRate:
		if rp.PerSourceRate == nil {
			return nil
		}
		name := fmt.Sprintf("meter_%d", n)
		c.declare(Set{Name: name, Kind: SetMeter, Timeout: policy.PerSourceTableTTL, Size: policy.PerSourceTableSize})
		c.row(pt, step, true, Stmt{Kind: StmtPerSourceLimit, Set: name, Rate: *rp.PerSourceRate, Burst: burst})
	case policy.StepPerSourceConcurrentFlows:
		limit := c.caps.ForProto(pt.Proto)
		if limit <= 0 {
			return nil
		}
		name := FlowSetName(pt.Proto)
		c.declare(Set{Name: name, Kind: SetFlowCount, Size: policy.FlowSetSize})
		c.row(pt, step, true, Stmt{Kind: StmtPerSourceCtCount, Set: name, Count: uint32(limit)})
	case policy.StepAggregateNewFlowRate:
		if rp.NewFlowRate == nil {
			return nil
		}
		c.row(pt, step, true, Stmt{Kind: StmtLimit, Rate: *rp.NewFlowRate, Burst: burst})
	case policy.StepAggregatePacketRate:
		if rp.PacketRate == nil {
			return nil
		}
		c.row(pt, step, false, Stmt{Kind: StmtLimit, Rate: *rp.PacketRate, Burst: burst})
	default:
		return fmt.Errorf("no nftables row for admission step %v", step)
	}
	return nil
}

// FlowSetName はプロトコルごとに共有する同時フロー数の set の名前。ルール ID に依存しない固定名
// (deny_N や meter_N と違い、プロトコルごとに 1 つしか作らないため)。
func FlowSetName(p proto.Proto) string {
	if p == proto.TCP {
		return "flows_tcp"
	}
	return "flows_udp"
}
