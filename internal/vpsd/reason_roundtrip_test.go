//go:build linux

package vpsd

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/vpsd/adminapi"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/internal/vpsd/proxyrelay"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、server 自身がルールを公開しなかった理由の文言を server doctor に読ませ、doctor の
// 分類と次の手が今の値であることを固定する。doctor は管理用 API の not_active の理由を部分一致で
// 読む(設計文書 10.2a 節)。どちらかの側だけで文言を変えると、ここが落ちる。

// serverDoctorPublicPort は、server がこのルールを理由 reason で not_active にしているときの、
// server doctor の public port の検査である。
func serverDoctorPublicPort(t *testing.T, r proto.Rule, reason string) doctor.Check {
	t.Helper()
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	in := doctor.Input{Now: now, Rules: &adminapi.BatchResponse{RuleStates: map[string]adminapi.RuleApply{
		r.ID: {ApplyState: adminapi.ApplyNotActive, Reason: reason}}}}
	for _, c := range doctor.Diagnose(r, in) {
		if c.ID == doctor.CheckPublicPort {
			return c
		}
	}
	t.Fatalf("no public port check for %+v", r)
	return doctor.Check{}
}

// refusingNetwork は、どのポートの bind にも失敗する中継の Network である。
type refusingNetwork struct{}

func (refusingNetwork) ListenTCP(uint16) (net.Listener, error) {
	return nil, errors.New("address already in use")
}
func (refusingNetwork) ListenUDP(uint16) (net.PacketConn, error) {
	return nil, errors.New("address already in use")
}

// ユーザー空間モードの server の中継(UDP は relay、TCP は proxyrelay)が bind に失敗したルールの理由は、
// bind_failed に分類され、ポートを持つ他のプロセスを名指す次の手になる。
func TestServerBindFailureIsReadByServerDoctor(t *testing.T) {
	udp := proto.Rule{ID: "r_udp", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2456},
		Target: "192.168.1.30:2456", VPSMode: proto.ModeProxy, Enabled: true}
	tcp := proto.Rule{ID: "r_tcp", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 25565, Hi: 25565},
		Target: "192.168.1.30:25565", VPSMode: proto.ModeProxy, Enabled: true}

	rm := relay.New(refusingNetwork{}, relay.Options{Logf: func(string, ...any) {}})
	t.Cleanup(rm.Close)
	staged := rm.Prepare(map[relay.Key]relay.Desired{{Proto: proto.UDP, Port: 2456}: {Target: "10.200.0.2:2456", RuleID: udp.ID}})
	udpErr := staged.Failed()[udp.ID]
	staged.Rollback()

	pm := proxyrelay.New(proxyrelay.Options{Listen: func(uint16) (net.Listener, error) { return nil, errors.New("address already in use") },
		Logf: func(string, ...any) {}})
	prepared := pm.Prepare([]proxyrelay.Rule{{ID: tcp.ID, ListenPort: 25565, AgentAddr: netip.MustParseAddr("10.200.0.2"), AgentPort: 25565, Agent: "home"}})
	tcpErr := prepared.Failed()[tcp.ID]
	prepared.Rollback()

	for _, tc := range []struct {
		rule proto.Rule
		err  error
	}{{udp, udpErr}, {tcp, tcpErr}} {
		if tc.err == nil {
			t.Fatalf("%s: the bind failure left no reason", tc.rule.ID)
		}
		c := serverDoctorPublicPort(t, tc.rule, tc.err.Error())
		if c.Reason != doctor.ReasonBindFailed {
			t.Errorf("%s: reason %q: public port = %s %s, want %s", tc.rule.ID, tc.err, c.Status, c.Reason, doctor.ReasonBindFailed)
		}
		if !strings.HasPrefix(c.Next, "another process on this VPS holds that port.") {
			t.Errorf("%s: reason %q: next = %q, want the bind failure's", tc.rule.ID, tc.err, c.Next)
		}
	}
}

// server が Plan から外したルールの理由(buildPlan)は、server doctor の次の手を決める。ルール自身の
// 無効、エージェントの無効、未登録のエージェントは、直す操作がそれぞれ違う。
func TestBuildPlanReasonsAreReadByServerDoctor(t *testing.T) {
	port := func(p uint16) proto.PortRange { return proto.PortRange{Lo: p, Hi: p} }
	rules := []proto.Rule{
		{ID: "r_off", Agent: "home", Proto: proto.TCP, ListenPort: port(444), Target: "192.168.1.30:444", VPSMode: proto.ModeKernel},
		{ID: "r_agent_off", Agent: "home", Proto: proto.TCP, ListenPort: port(445), Target: "192.168.1.30:445", VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_ghost", Agent: "ghost", Proto: proto.TCP, ListenPort: port(446), Target: "192.168.1.30:446", VPSMode: proto.ModeKernel, Enabled: true},
	}
	d := &Daemon{}
	_, excluded := d.buildPlan(rules, map[string]netip.Addr{"home": netip.MustParseAddr("10.200.0.2")}, map[string]bool{"home": true})
	want := map[string]string{
		"r_off":       "enable it: wgft rule enable <rule>",
		"r_agent_off": "the agent may have just been enabled while this command read the evidence; run it again",
		"r_ghost":     "register an agent under that name: wgft agent join-string --name <agent>",
	}
	for _, r := range rules {
		reason, ok := excluded[r.ID]
		if !ok {
			t.Fatalf("%s: buildPlan did not exclude it: %v", r.ID, excluded)
		}
		// doctor は無効なルールを自分の読んだルールの enabled で先に扱う。理由の文言を読むのは、
		// server が外した後に有効化されたルールを読んだ場合なので、有効なルールとして渡す
		r.Enabled = true
		c := serverDoctorPublicPort(t, r, reason)
		if c.Reason != doctor.ReasonNotPublished || c.Next != want[r.ID] {
			t.Errorf("%s: reason %q: public port = %s, next %q; want %s, next %q", r.ID, reason, c.Reason, c.Next, doctor.ReasonNotPublished, want[r.ID])
		}
	}
}
