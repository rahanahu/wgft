package agent

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/usermode"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// udpPortNetwork は中継の UDP の待ち受けを 127.0.0.1 に開き、ポートごとのアドレスを覚える Network である。
type udpPortNetwork struct {
	mu    sync.Mutex
	addrs map[uint16]net.Addr
}

func (n *udpPortNetwork) ListenTCP(uint16) (net.Listener, error) {
	return net.Listen("tcp4", "127.0.0.1:0")
}

func (n *udpPortNetwork) ListenUDP(port uint16) (net.PacketConn, error) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err == nil {
		n.mu.Lock()
		n.addrs[port] = pc.LocalAddr()
		n.mu.Unlock()
	}
	return pc, err
}

// 2 つのモードは、ブロードキャストとマルチキャストの宛先を同じ判定で拒み、同じ文言の理由を書く
// (設計文書 7 節、7b.2 節)。カーネルモードは公開の組み立て(nft.PlanAgent)で、ユーザー空間モードは
// 中継の適用と、ホスト名なら名前解決の後の接続で拒む。理由はどちらも server doctor が
// target_not_unicast に分類する。ユーザー空間モードの理由は、ハートビートと同じくリスナーの名前が頭に付く。
func TestBothModesRefuseBroadcastAndMulticastAlike(t *testing.T) {
	u := allowtargets.NewUnicast(func() ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("192.168.50.2/24")}, nil
	}, func(string, ...any) {})
	resolve := map[string][]netip.Addr{
		"bc.lan": {netip.MustParseAddr("192.168.50.255")},
		"mc.lan": {netip.MustParseAddr("239.1.2.3")},
	}
	for _, target := range []string{
		// ホスト名の宛先は、カーネルモードでは nft と kernelmode の試験が、ユーザー空間モードでは relay の試験が、
		// RefuseTarget の文言をそのまま理由にすることを確かめる。ユーザー空間モードは許可一覧が無ければ名前を
		// Go の接続に解決させるので、ここでは偽の名前を引けない
		"239.1.2.3:5000", "255.255.255.255:9", "192.168.50.255:9",
	} {
		t.Run(target, func(t *testing.T) {
			rule := proto.AgentRule{ID: "r1", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 7001, Hi: 7001}, Target: target, Enabled: true}

			// カーネルモード
			resolved := map[string]nft.Resolution{}
			for h, as := range resolve {
				resolved[h] = nft.Resolution{Addrs: as}
			}
			kpub := nft.PlanAgent(nft.AgentInput{Rules: []proto.AgentRule{rule}, Resolved: resolved},
				nft.AgentConfig{WGInterface: "wgft0", RefuseTarget: u.Refuse})
			kernel := kpub.Rules[0]
			if len(kernel.Ranges) != 0 || kernel.Reason == "" {
				t.Fatalf("kernel mode published %+v, want no DNAT and a reason", kernel)
			}

			// ユーザー空間モード。ブロードキャストとマルチキャストの判定は usermode が常に渡す。ここでは
			// ホストの帯を決めるために、同じ判定に差し替える
			d := usermode.New(nil, resource.Limits{})
			opts := d.RelayOptions(proto.WGConfig{})
			if opts.RefuseTarget == nil {
				t.Fatal("usermode must always pass the broadcast and multicast check to the relay")
			}
			opts.RefuseTarget = u.Refuse
			opts.Logf = func(string, ...any) {}
			opts.LookupTarget = func(_ context.Context, host string) ([]netip.Addr, error) { return resolve[host], nil }
			netw := &udpPortNetwork{addrs: map[uint16]net.Addr{}}
			m := relay.New(netw, opts)
			t.Cleanup(m.Close)
			m.Apply(relay.DesiredFromRules([]proto.AgentRule{rule}))
			sts := usermode.RuleStatuses(m.Status())
			if len(sts) == 1 && sts[0].State == proto.StatusOK {
				// ホスト名の宛先は待ち受けを開き、最初のデータグラムの名前解決の後に拒む
				netw.mu.Lock()
				addr := netw.addrs[7001]
				netw.mu.Unlock()
				c, err := net.Dial("udp4", addr.String())
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				if _, err := c.Write([]byte("hi")); err != nil {
					t.Fatal(err)
				}
				deadline := time.Now().Add(2 * time.Second)
				for time.Now().Before(deadline) {
					if sts = usermode.RuleStatuses(m.Status()); sts[0].State != proto.StatusOK {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			if len(sts) != 1 || sts[0].State != proto.StatusError {
				t.Fatalf("userspace rule statuses = %+v, want one error", sts)
			}
			if want := "udp/" + strconv.Itoa(7001) + ": " + kernel.Reason; sts[0].Reason != want {
				t.Errorf("userspace reason = %q\nkernel reason   = %q; want the same text after the listener name", sts[0].Reason, kernel.Reason)
			}
			for mode, reason := range map[string]string{"kernel": kernel.Reason, "userspace": sts[0].Reason} {
				got := serverDoctorReads(t, rule, proto.RuleStatus{ID: rule.ID, State: proto.StatusError, Reason: reason})
				if c := got[doctor.CheckTarget]; c.Status != doctor.StatusFailed || c.Reason != doctor.ReasonTargetNotUnicast {
					t.Errorf("%s reason %q: rule.target = %s %s, want %s %s", mode, reason, c.Status, c.Reason, doctor.StatusFailed, doctor.ReasonTargetNotUnicast)
				}
			}
		})
	}
}
