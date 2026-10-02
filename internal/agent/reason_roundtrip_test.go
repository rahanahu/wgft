package agent

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/usermode"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/internal/vpsd/adminapi"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/internal/vpsd/stream"
	"github.com/rahanahu/wgft/proto"
)

// このファイルと reason_roundtrip_linux_test.go は、エージェントが組み立てるルールの理由の文言を、
// hub が保存する形(stream.HeartbeatReason の 512 バイトの切り詰め)に通してから server doctor
// (internal/vpsd/doctor)に読ませ、doctor の分類が今の値であることを固定する。doctor はエージェントの
// 人の読む文言を部分一致で分類する(設計文書 10.2a 節)。どちらかの側だけで文言を変えると、ここが落ちる。

// serverDoctorReads は、エージェントの 1 本のルールの状態を、接続中のエージェントの今の報告として
// server doctor に渡し、検査の ID ごとの結果を返す。理由は hub が保存する形に通してから渡す。
func serverDoctorReads(t *testing.T, r proto.AgentRule, st proto.RuleStatus) map[string]doctor.Check {
	t.Helper()
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	at := now.Add(-5 * time.Second).Format(time.RFC3339)
	rule := proto.Rule{ID: r.ID, Agent: "home", Proto: r.Proto, ListenPort: r.ListenPort, Target: r.Target, Enabled: true}
	in := doctor.Input{Now: now,
		Rules: &adminapi.BatchResponse{AgentRuleStates: map[string]adminapi.AgentRuleStatus{
			rule.ID: {Agent: "home", State: st.State, Reason: stream.HeartbeatReason(st.Reason), At: at, Connected: true}}},
		Agents: []adminapi.AgentInfo{{Name: "home", Connected: true, LastHeartbeat: at, LastHandshake: at}},
	}
	got := map[string]doctor.Check{}
	for _, c := range doctor.Diagnose(rule, in) {
		got[c.ID] = c
	}
	return got
}

// reasonTCPRule は 1 つのポートの TCP のルールである。dataplane_kernel_test.go の tcpRule は Linux の
// 試験にだけあるので、どの OS でも組み立てる試験はこちらを使う。
func reasonTCPRule(id, target string, port uint16) proto.AgentRule {
	return proto.AgentRule{ID: id, Proto: proto.TCP, ListenPort: proto.PortRange{Lo: port, Hi: port}, Target: target, Enabled: true}
}

// reasonNetwork は中継の待ち受けを開く Network である。refuse にあるポートは、その誤りで bind に失敗する。
type reasonNetwork struct {
	refuse map[uint16]error
}

func (n reasonNetwork) ListenTCP(port uint16) (net.Listener, error) {
	if err := n.refuse[port]; err != nil {
		return nil, err
	}
	return net.Listen("tcp4", "127.0.0.1:0")
}

func (n reasonNetwork) ListenUDP(port uint16) (net.PacketConn, error) {
	if err := n.refuse[port]; err != nil {
		return nil, err
	}
	return net.ListenPacket("udp4", "127.0.0.1:0")
}

// netstackBindErr は、ユーザー空間モードの netstack が使用中のポートの bind に返すのと同じ形の誤りである。
func netstackBindErr(network string, port uint16) error {
	return &net.OpError{Op: "bind", Net: network, Addr: &net.TCPAddr{IP: net.IPv4(10, 200, 0, 2), Port: int(port)},
		Err: errors.New("port is in use")}
}

// ユーザー空間モードのエージェントの理由である。中継の状態から、ハートビートと同じ usermode.RuleStatuses で
// ルールの理由を作る。bind の失敗の理由は netstack の誤りの文言("bind tcp ..." の形)だけを持ち、
// 中継が server のために付ける "bind failed" は付かない(中継の Status は bind の誤りをそのまま返す)。
func TestUserspaceReasonsAreReadByServerDoctor(t *testing.T) {
	narrow, err := allowtargets.Parse("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		rule   proto.AgentRule
		allow  *allowtargets.List
		source string // 空でなければ、エージェントが渡す設定の名前の代わりに使う
		refuse error
		hang   bool // 宛先への試し接続が応えない
		want   string
	}{
		{name: "tcp bind failed", rule: reasonTCPRule("r1", "192.168.1.20:25565", 25565), refuse: netstackBindErr("tcp", 25565),
			want: doctor.ReasonListenerBindFailed},
		{name: "udp bind failed", rule: proto.AgentRule{ID: "r1", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2456},
			Target: "192.168.1.20:2456", Enabled: true}, refuse: netstackBindErr("udp", 2456), want: doctor.ReasonListenerBindFailed},
		{name: "target not in the allowlist", rule: reasonTCPRule("r1", "192.168.9.9:25565", 25565), allow: narrow,
			want: doctor.ReasonTargetNotAllowed},
		// 設定の名前が無い拒否の文言("is not allowed")も同じ分類になる
		{name: "target not allowed, no source name", rule: reasonTCPRule("r1", "192.168.9.9:25565", 25565), allow: narrow,
			source: "-", want: doctor.ReasonTargetNotAllowed},
		// TCP の宛先への試し接続が期限までに応えない。中継の期限(2 秒)を待つ
		{name: "tcp target did not answer", rule: reasonTCPRule("r1", "192.168.1.20:25565", 25565), hang: true,
			want: doctor.ReasonTargetTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := usermode.New(tc.allow, resource.Limits{})
			opts := d.RelayOptions(proto.WGConfig{})
			if tc.source == "-" {
				opts.AllowTargetSource = ""
			}
			opts.Logf = func(string, ...any) {}
			refuse := map[uint16]error{}
			if tc.refuse != nil {
				refuse[tc.rule.ListenPort.Lo] = tc.refuse
			}
			stop := make(chan struct{})
			if tc.hang {
				opts.Dial = func(string, string) (net.Conn, error) {
					<-stop
					return nil, errors.New("stopped")
				}
			}
			m := relay.New(reasonNetwork{refuse: refuse}, opts)
			t.Cleanup(m.Close)
			t.Cleanup(func() { close(stop) }) // m.Close より先に、応えない接続を終わらせる
			m.Apply(relay.DesiredFromRules([]proto.AgentRule{tc.rule}))
			sts := usermode.RuleStatuses(m.Status())
			if len(sts) != 1 || sts[0].State != proto.StatusError {
				t.Fatalf("rule statuses = %+v, want one error", sts)
			}
			got := serverDoctorReads(t, tc.rule, sts[0])
			if c := got[doctor.CheckTarget]; c.Reason != tc.want {
				t.Errorf("reason %q: rule.target = %s %s, want %s", sts[0].Reason, c.Status, c.Reason, tc.want)
			}
		})
	}
}

// 許可一覧の拒否の理由は、server doctor の次の手で設定の名前を名指す。
func TestAllowTargetsNameReachesServerDoctorNextStep(t *testing.T) {
	narrow, err := allowtargets.Parse("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	r := reasonTCPRule("r1", "192.168.9.9:25565", 25565)
	d := usermode.New(narrow, resource.Limits{})
	opts := d.RelayOptions(proto.WGConfig{})
	opts.Logf = func(string, ...any) {}
	m := relay.New(reasonNetwork{}, opts)
	t.Cleanup(m.Close)
	m.Apply(relay.DesiredFromRules([]proto.AgentRule{r}))
	sts := usermode.RuleStatuses(m.Status())
	if len(sts) != 1 {
		t.Fatalf("rule statuses = %+v", sts)
	}
	c := serverDoctorReads(t, r, sts[0])[doctor.CheckTarget]
	if want := "the agent refuses this target itself: " + allowtargets.Env + " on the agent host does not list it."; len(c.Next) < len(want) || c.Next[:len(want)] != want {
		t.Errorf("rule.target next = %q, want it to start with %q", c.Next, want)
	}
}
