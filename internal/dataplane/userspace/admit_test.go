package userspace

import (
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

// freeUDPPort returns a UDP port nothing is bound to right now.
func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// TestRelayAppliesTheAdmissionPolicy checks that New wires the relay's two Admission Policy hooks
// to the Backend's evaluator. The relay admits everything when a hook is nil (the agent's relay
// relies on that), so a server built without them would serve every source and every packet rate
// while all other tests still pass. Admit is seen through a Transparent TCP rule whose source_deny
// holds the loopback source; AdmitPacket through a Transparent UDP rule whose packet_rate runs out
// within one established session.
func TestRelayAppliesTheAdmissionPolicy(t *testing.T) {
	tcpPort, udpPort := freeTCPPort(t), freeUDPPort(t)
	minute := proto.Rate{Count: 1, Unit: proto.PerMinute}
	rules, err := model.NormalizeRules([]proto.Rule{
		{ID: "r_tcp", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: tcpPort, Hi: tcpPort},
			Target: "192.168.1.30:80", VPSMode: proto.ModeKernel, Enabled: true,
			SourceDeny: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}},
		{ID: "r_udp", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: udpPort, Hi: udpPort},
			Target: "192.168.1.31:2456", VPSMode: proto.ModeKernel, Enabled: true, PacketRate: &minute},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := planner.Build(planner.Input{Rules: rules,
		Agents: []planner.Agent{{Name: "home", Addr: netip.MustParseAddr("10.200.0.2")}}})

	b := New(Options{Logf: t.Logf})
	defer b.relay.Close()
	// The UDP session needs a dial to the agent to succeed, so the tunnel is up; it has no peer, so
	// what the relay forwards goes nowhere.
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.EnsureDevice(dataplane.WGConfig{PrivateKey: key,
		Address: netip.MustParsePrefix("10.200.0.1/24"), MTU: 1420}); err != nil {
		t.Fatalf("EnsureDevice: %v", err)
	}
	defer b.tun.Close()
	p, err := b.Prepare(dataplane.Desired{Plan: plan})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(p.Failed()) != 0 {
		t.Fatalf("Failed = %v", p.Failed())
	}
	if _, err := p.Commit(nil); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Drops resets what it returns, so keep the total per rule and kind.
	seen := map[string]uint64{}
	waitDrop := func(ruleID, kind string) bool {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			for _, d := range b.policy.Drops() {
				seen[d.RuleID+"/"+d.Kind] += d.Packets
			}
			if seen[ruleID+"/"+kind] > 0 {
				return true
			}
			time.Sleep(20 * time.Millisecond)
		}
		return false
	}

	c, err := net.DialTimeout("tcp4", "127.0.0.1:"+strconv.Itoa(int(tcpPort)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !waitDrop("r_tcp", "deny") {
		t.Errorf("a TCP connection from a source in source_deny was not refused by the policy (drops %v); the relay's Admit is not wired", seen)
	}

	u, err := net.Dial("udp4", "127.0.0.1:"+strconv.Itoa(int(udpPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	// The first datagram opens the session through Admit and takes one token; the rest of the
	// session's datagrams are judged by AdmitPacket alone and run out of the bucket.
	for range policy.TokenBucketBurst + 5 {
		if _, err := u.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	packet := policy.StepAggregatePacketRate.DropKind()
	if !waitDrop("r_udp", packet) {
		t.Errorf("datagrams past the packet_rate were not refused (drops %v); the relay's AdmitPacket is not wired", seen)
	}
	// The refusals must come from inside one session: if the session was never established, every
	// datagram would have gone through Admit instead, and this test would say nothing about
	// AdmitPacket.
	for _, s := range b.relay.Status() {
		if s.RuleID == "r_udp" && s.Flows != 1 {
			t.Errorf("r_udp holds %d flows, want the one session", s.Flows)
		}
	}
}
