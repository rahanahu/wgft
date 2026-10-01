package userspace

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/tunnel"
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
// to the Backend's evaluator and passes the evaluator's verdict on. The relay admits everything
// when a hook is nil (the agent's relay relies on that), so a server built without them, or with
// hooks that ignore the verdict, would serve every source and every packet rate while all other
// tests still pass.
//
// An agent-side tunnel is the peer, and the test counts what reaches its listeners: a TCP
// connection from a source in the rule's source_deny must not carry any data to the agent, and a
// UDP session whose packet_rate runs out must deliver no more datagrams than the bucket holds.
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
	agentAddr := netip.MustParseAddr("10.200.0.2")
	plan := planner.Build(planner.Input{Rules: rules,
		Agents: []planner.Agent{{Name: "home", Addr: agentAddr}}})

	b := New(Options{Logf: t.Logf})
	defer b.relay.Close()
	serverKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.EnsureDevice(dataplane.WGConfig{PrivateKey: serverKey,
		Address: netip.MustParsePrefix("10.200.0.1/24"), MTU: 1420}); err != nil {
		t.Fatalf("EnsureDevice: %v", err)
	}
	defer b.tun.Close()
	wgPort, err := b.tun.ListenPort()
	if err != nil {
		t.Fatal(err)
	}

	// The agent: a userspace tunnel over 127.0.0.1 whose listeners count what the relay delivers.
	agentKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	agent, err := tunnel.New(tunnel.Config{
		PrivateKey: agentKey, ServerPublicKey: serverKey.PublicKey(), Endpoint: fmt.Sprintf("127.0.0.1:%d", wgPort),
		Address: agentAddr, ServerAddress: netip.MustParseAddr("10.200.0.1"),
		MTU: 1420, Keepalive: time.Second, Logf: func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	if _, err := b.setPeers([]dataplane.Peer{{PublicKey: agentKey.PublicKey(), Address: agentAddr}}); err != nil {
		t.Fatal(err)
	}
	var tcpData, udpData atomic.Int64
	ln, err := agent.ListenTCP(tcpPort)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				// The relay's reachability probe connects and closes without data; a relayed
				// connection carries the client's bytes.
				if n, _ := c.Read(make([]byte, 64)); n > 0 {
					tcpData.Add(1)
				}
			}()
		}
	}()
	pc, err := agent.ListenUDP(udpPort)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			udpData.Add(1)
		}
	}()
	// Wait for the handshake, so that whatever the relay admits does reach the agent.
	deadline := time.Now().Add(20 * time.Second)
	for {
		peers, err := b.tun.Peers()
		if err != nil {
			t.Fatal(err)
		}
		if !peers[agentKey.PublicKey()].LastHandshake.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no handshake with the agent tunnel within 20s")
		}
		time.Sleep(100 * time.Millisecond)
	}

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

	// TCP: the denied connection is refused at accept. The refusal resets it, which may reach the
	// dial itself (macOS reports it there), so a dial error is not a failure. An admitted connection
	// would instead stay open while the relay dials the agent and pipes the client's bytes there.
	if c, err := net.DialTimeout("tcp4", "127.0.0.1:"+strconv.Itoa(int(tcpPort)), 5*time.Second); err == nil {
		defer c.Close()
		c.Write([]byte("x"))
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, rerr := c.Read(make([]byte, 1))
		var ne net.Error
		if errors.As(rerr, &ne) && ne.Timeout() {
			t.Error("a TCP connection from a source in source_deny is still open after 2s; the relay did not refuse it")
		}
	} else {
		t.Logf("dial: %v", err)
	}
	if !waitDrop("r_tcp", "deny") {
		t.Errorf("no deny drop for a TCP connection from a source in source_deny (drops %v); the relay's Admit does not reach the evaluator", seen)
	}

	u, err := net.Dial("udp4", "127.0.0.1:"+strconv.Itoa(int(udpPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	// The first datagram opens the session through Admit and takes one token; the rest of the
	// session's datagrams are judged by AdmitPacket alone, so the bucket lets at most
	// TokenBucketBurst datagrams through in all.
	const sent = policy.TokenBucketBurst + 10
	for range sent {
		if _, err := u.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	packet := policy.StepAggregatePacketRate.DropKind()
	if !waitDrop("r_udp", packet) {
		t.Errorf("no packet_rate drop for datagrams past the rate (drops %v); the relay's AdmitPacket does not reach the evaluator", seen)
	}
	// Give whatever the relay passed on time to reach the agent.
	time.Sleep(time.Second)
	if n := udpData.Load(); n < 1 || n > policy.TokenBucketBurst {
		t.Errorf("the agent received %d of %d datagrams; want between 1 and %d, the rest refused by packet_rate", n, sent, policy.TokenBucketBurst)
	}
	if n := tcpData.Load(); n != 0 {
		t.Errorf("the agent received data on %d TCP connections; the connection from a denied source must not reach it", n)
	}
}
