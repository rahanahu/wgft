package interp

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rahanahu/wgft/internal/policy/admissiontest"
	polnft "github.com/rahanahu/wgft/internal/policy/nftables"
	"github.com/rahanahu/wgft/proto"
)

// NewEngine は、fixture の IR を internal/policy/nftables でコンパイルし、その行の列を解釈器で
// 実行する admissiontest.Engine を作る。
//
// fixture の Relay のルールは、どれも待ち受けを開けている前提にする(判定を付けるポートに含める)。
func NewEngine(fx *admissiontest.Fixture) (admissiontest.Engine, error) {
	plan, err := fx.Plan()
	if err != nil {
		return nil, err
	}
	ports := make([]polnft.Port, 0, len(plan.Ports))
	portOf := map[string]polnft.Port{}
	for _, pp := range plan.Ports {
		p := polnft.Port{RuleID: pp.RuleID, Proto: pp.Proto, Ports: pp.ListenPort, Forwarding: pp.Forwarding}
		ports = append(ports, p)
		portOf[pp.RuleID] = p
	}
	prog, err := polnft.Compile(plan.Admission, ports)
	if err != nil {
		return nil, err
	}
	in, err := New(prog)
	if err != nil {
		return nil, err
	}
	return &engine{in: in, portOf: portOf}, nil
}

// unroutedPort は、IR に無いルールの出来事を送るポート。どのルールのポートでもないので、
// filter_pre の行に一致せず、DNAT も待ち受けも無い。
const unroutedPort = 1

type engine struct {
	in     *Interpreter
	portOf map[string]polnft.Port
}

func (e *engine) Handle(at time.Duration, ev admissiontest.Event) (string, error) {
	if ev.Op == admissiontest.OpEnd {
		e.in.End(ev.Flow)
		return "", nil
	}
	_, established := e.in.conns[ev.Flow]
	switch {
	case ev.Op == admissiontest.OpFlow && established:
		return "", fmt.Errorf("flow %s is already established", ev.Flow)
	case ev.Op == admissiontest.OpPacket && !established:
		return "", fmt.Errorf("packet for flow %s, which is not established", ev.Flow)
	}
	// IPv4 射影のアドレス(::ffff:a.b.c.d)は Go のソケットが IPv4 の送信元を表す形であり、
	// 線上のパケットは IPv4 である。カーネルが見るのは IPv4 のアドレスなので、射影を戻す。
	src := netip.MustParseAddr(ev.Src).Unmap()

	port, known := e.portOf[ev.Rule]
	p := Packet{Proto: port.Proto, DstPort: port.Ports.Lo, Src: src, Flow: ev.Flow}
	if !known {
		p = Packet{Proto: proto.UDP, DstPort: unroutedPort, Src: src, Flow: ev.Flow}
	}
	v, err := e.in.Eval(at, p)
	if err != nil {
		return "", err
	}
	if !known || !src.Is4() {
		// filter_pre を通っても転送されない。IR に無いルールのポートには DNAT も待ち受けも無く、
		// IPv6 のパケットは `dnat ip to` に写されず、待ち受けも IPv4 だけで開く(設計文書 7a.9 節)。
		// drop カウンタにも数えない。行が落としたなら、その行は IPv4 の一致を欠いている
		if v.Dropped {
			return "", fmt.Errorf("row %s dropped a packet that no rule forwards: src %s", v.Comment, src)
		}
		e.in.End(ev.Flow)
		return admissiontest.Drop, nil
	}
	if !v.Dropped {
		return admissiontest.Admit, nil
	}
	rule, kind, ok := parseComment(v.Comment)
	if !ok {
		return "", fmt.Errorf("row comment %q is not wgft:<rule>:<kind>", v.Comment)
	}
	if rule != ev.Rule {
		// 別のルールの行が落とした。want と一致しない形で返し、食い違いとして報告させる
		return fmt.Sprintf("%s (row of rule %s)", admissiontest.DropOf(kind), rule), nil
	}
	return admissiontest.DropOf(kind), nil
}

// Drops は行のカウンタを、コメントから読んだルール ID と種類で集計する(本番の nft.ReadDrops と
// 同じく、カウンタの持ち主はコメントで特定する)。
func (e *engine) Drops() map[string]map[string]uint64 {
	out := map[string]map[string]uint64{}
	for _, c := range e.in.Counters() {
		rule, kind, ok := parseComment(c.Comment)
		if !ok {
			rule, kind = "?", c.Comment
		}
		if out[rule] == nil {
			out[rule] = map[string]uint64{}
		}
		out[rule][kind] += c.Packets
	}
	return out
}

func parseComment(c string) (rule, kind string, ok bool) {
	rest, ok := strings.CutPrefix(c, "wgft:")
	if !ok {
		return "", "", false
	}
	i := strings.LastIndexByte(rest, ':')
	if i <= 0 || i == len(rest)-1 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}
