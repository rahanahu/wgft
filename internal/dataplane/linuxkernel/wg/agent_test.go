//go:build linux

package wg

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/startup"
)

func mustKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// 所有は鍵だけで決まる。空の鍵はどちらの鍵とも一致させない (design.md 7b.4 節)。
func TestJudgeOwnership(t *testing.T) {
	cur, prev, other := mustKey(t), mustKey(t), mustKey(t)
	var zero wgtypes.Key
	cases := []struct {
		name               string
		kind               string
		key, current, prev wgtypes.Key
		want               Ownership
	}{
		{"current key", "wireguard", cur, cur, prev, OwnedByCurrentKey},
		{"previous key", "wireguard", prev, cur, prev, OwnedByPreviousKey},
		{"previous key with no current key", "wireguard", prev, zero, prev, OwnedByPreviousKey},
		{"another key", "wireguard", other, cur, prev, ForeignKey},
		{"another key, no previous key recorded", "wireguard", other, cur, zero, ForeignKey},
		{"zero key on the link, no previous key recorded", "wireguard", zero, cur, zero, ForeignKey},
		{"zero key on the link, zero current key", "wireguard", zero, zero, prev, ForeignKey},
		{"a dummy link with the name", "dummy", cur, cur, prev, NotWireGuard},
	}
	for _, c := range cases {
		got := judgeOwnership(c.kind, c.key, c.current, c.prev)
		if got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
		if got.Ours() != (c.want == OwnedByCurrentKey || c.want == OwnedByPreviousKey) {
			t.Errorf("%s: Ours() = %v", c.name, got.Ours())
		}
	}
}

func agentCfg(t *testing.T) AgentConfig {
	t.Helper()
	return AgentConfig{
		Interface:  "wgft0",
		PrivateKey: mustKey(t),
		Address:    netip.MustParsePrefix("10.200.0.2/24"),
		MTU:        1420,
		Server: ServerPeer{
			PublicKey: mustKey(t).PublicKey(),
			Address:   netip.MustParseAddr("10.200.0.1"),
			Endpoint:  netip.MustParseAddrPort("192.0.2.10:51820"),
			Keepalive: 25 * time.Second,
		},
	}
}

func udp(s string) *net.UDPAddr { return net.UDPAddrFromAddrPort(netip.MustParseAddrPort(s)) }

// convergedDevice is the device EnsureAgent leaves for cfg.
func convergedDevice(cfg AgentConfig) *wgtypes.Device {
	return &wgtypes.Device{
		PrivateKey: cfg.PrivateKey, PublicKey: cfg.PrivateKey.PublicKey(), ListenPort: 40123,
		Peers: []wgtypes.Peer{{
			PublicKey:                   cfg.Server.PublicKey,
			Endpoint:                    net.UDPAddrFromAddrPort(cfg.Server.Endpoint),
			PersistentKeepaliveInterval: cfg.Server.Keepalive,
			AllowedIPs:                  []net.IPNet{*prefixToIPNet(netip.PrefixFrom(cfg.Server.Address, 32))},
		}},
	}
}

// agentDeviceDiff は、読んだ装置を宣言へ動かす wgctrl の設定だけを作る。待ち受けポートには触れない。
func TestAgentDeviceDiff(t *testing.T) {
	base := agentCfg(t)
	stray := mustKey(t).PublicKey()
	prev := mustKey(t)

	cases := []struct {
		name  string
		cfg   func(c *AgentConfig)
		dev   func(d *wgtypes.Device)
		check func(t *testing.T, wc wgtypes.Config)
		notes []string // 各行に含まれるべき文字列 (順に)
	}{
		{
			name: "converged: nothing to do",
			check: func(t *testing.T, wc wgtypes.Config) {
				if wc.PrivateKey != nil || len(wc.Peers) != 0 {
					t.Errorf("wanted no change, got %+v", wc)
				}
			},
		},
		{
			name: "new device: set the key, add the server with endpoint and keepalive",
			dev:  func(d *wgtypes.Device) { *d = wgtypes.Device{} },
			check: func(t *testing.T, wc wgtypes.Config) {
				if wc.PrivateKey == nil || *wc.PrivateKey != base.PrivateKey {
					t.Error("private key not set")
				}
				if len(wc.Peers) != 1 {
					t.Fatalf("peers = %+v", wc.Peers)
				}
				p := wc.Peers[0]
				if p.PublicKey != base.Server.PublicKey || p.UpdateOnly || p.Remove || !p.ReplaceAllowedIPs {
					t.Errorf("peer = %+v", p)
				}
				if p.Endpoint == nil || p.Endpoint.String() != "192.0.2.10:51820" {
					t.Errorf("endpoint = %v", p.Endpoint)
				}
				if p.PersistentKeepaliveInterval == nil || *p.PersistentKeepaliveInterval != 25*time.Second {
					t.Errorf("keepalive = %v", p.PersistentKeepaliveInterval)
				}
				if len(p.AllowedIPs) != 1 || p.AllowedIPs[0].String() != "10.200.0.1/32" {
					t.Errorf("AllowedIPs = %v", p.AllowedIPs)
				}
			},
			notes: []string{"set private key", "add server peer"},
		},
		{
			name: "new device while the endpoint is not resolved: add the server without one",
			cfg:  func(c *AgentConfig) { c.Server.Endpoint = netip.AddrPort{} },
			dev:  func(d *wgtypes.Device) { *d = wgtypes.Device{PrivateKey: base.PrivateKey} },
			check: func(t *testing.T, wc wgtypes.Config) {
				if len(wc.Peers) != 1 || wc.Peers[0].Endpoint != nil {
					t.Errorf("peers = %+v", wc.Peers)
				}
			},
			notes: []string{"no endpoint yet"},
		},
		{
			name: "previous key: replace it with the current one, keep the peer",
			cfg:  func(c *AgentConfig) { c.PreviousKey = prev },
			dev:  func(d *wgtypes.Device) { d.PrivateKey, d.PublicKey = prev, prev.PublicKey() },
			check: func(t *testing.T, wc wgtypes.Config) {
				if wc.PrivateKey == nil || *wc.PrivateKey != base.PrivateKey {
					t.Error("private key not moved to the current key")
				}
				if len(wc.Peers) != 0 {
					t.Errorf("peers touched: %+v", wc.Peers)
				}
			},
			notes: []string{"replace the previous private key"},
		},
		{
			name: "a stray peer is removed, the server is kept",
			dev: func(d *wgtypes.Device) {
				d.Peers = append(d.Peers, wgtypes.Peer{PublicKey: stray, AllowedIPs: []net.IPNet{*prefixToIPNet(netip.MustParsePrefix("0.0.0.0/0"))}})
			},
			check: func(t *testing.T, wc wgtypes.Config) {
				if len(wc.Peers) != 1 || wc.Peers[0].PublicKey != stray || !wc.Peers[0].Remove {
					t.Errorf("peers = %+v", wc.Peers)
				}
			},
			notes: []string{"delete peer"},
		},
		{
			name: "widened AllowedIPs go back to the server's /32",
			dev: func(d *wgtypes.Device) {
				d.Peers[0].AllowedIPs = append(d.Peers[0].AllowedIPs, *prefixToIPNet(netip.MustParsePrefix("10.200.0.0/24")))
			},
			check: func(t *testing.T, wc wgtypes.Config) {
				if len(wc.Peers) != 1 || !wc.Peers[0].ReplaceAllowedIPs || !wc.Peers[0].UpdateOnly || len(wc.Peers[0].AllowedIPs) != 1 {
					t.Errorf("peers = %+v", wc.Peers)
				}
				if wc.Peers[0].Endpoint != nil || wc.Peers[0].PersistentKeepaliveInterval != nil {
					t.Errorf("touched more than AllowedIPs: %+v", wc.Peers[0])
				}
			},
			notes: []string{"fix AllowedIPs"},
		},
		{
			name: "a new resolution moves the endpoint, nothing else",
			cfg:  func(c *AgentConfig) { c.Server.Endpoint = netip.MustParseAddrPort("198.51.100.7:51820") },
			check: func(t *testing.T, wc wgtypes.Config) {
				if wc.PrivateKey != nil || len(wc.Peers) != 1 {
					t.Fatalf("config = %+v", wc)
				}
				p := wc.Peers[0]
				if !p.UpdateOnly || p.Endpoint == nil || p.Endpoint.String() != "198.51.100.7:51820" || p.ReplaceAllowedIPs || p.PersistentKeepaliveInterval != nil {
					t.Errorf("peer = %+v", p)
				}
			},
			notes: []string{"server endpoint 192.0.2.10:51820 -> 198.51.100.7:51820"},
		},
		{
			name:  "an IPv4-mapped endpoint compares equal to the plain one",
			cfg:   func(c *AgentConfig) { c.Server.Endpoint = netip.MustParseAddrPort("[::ffff:192.0.2.10]:51820") },
			check: func(t *testing.T, wc wgtypes.Config) { noChange(t, wc) },
		},
		{
			name:  "the kernel reports a mapped endpoint: no change",
			dev:   func(d *wgtypes.Device) { d.Peers[0].Endpoint = udp("[::ffff:192.0.2.10]:51820") },
			check: func(t *testing.T, wc wgtypes.Config) { noChange(t, wc) },
		},
		{
			name:  "unresolved now: keep the endpoint the kernel has",
			cfg:   func(c *AgentConfig) { c.Server.Endpoint = netip.AddrPort{} },
			dev:   func(d *wgtypes.Device) { d.Peers[0].Endpoint = udp("203.0.113.9:51820") },
			check: func(t *testing.T, wc wgtypes.Config) { noChange(t, wc) },
		},
		{
			name: "a peer without endpoint gets the resolved one",
			dev:  func(d *wgtypes.Device) { d.Peers[0].Endpoint = nil },
			check: func(t *testing.T, wc wgtypes.Config) {
				if len(wc.Peers) != 1 || wc.Peers[0].Endpoint == nil {
					t.Errorf("peers = %+v", wc.Peers)
				}
			},
			notes: []string{"server endpoint none -> 192.0.2.10:51820"},
		},
		{
			name: "keepalive drift is converged",
			dev:  func(d *wgtypes.Device) { d.Peers[0].PersistentKeepaliveInterval = 0 },
			check: func(t *testing.T, wc wgtypes.Config) {
				if len(wc.Peers) != 1 || wc.Peers[0].PersistentKeepaliveInterval == nil || *wc.Peers[0].PersistentKeepaliveInterval != 25*time.Second {
					t.Errorf("peers = %+v", wc.Peers)
				}
			},
			notes: []string{"server keepalive 0s -> 25s"},
		},
		{
			name: "a new server key replaces the peer",
			cfg:  func(c *AgentConfig) { c.Server.PublicKey = stray },
			check: func(t *testing.T, wc wgtypes.Config) {
				if len(wc.Peers) != 2 || !wc.Peers[0].Remove || wc.Peers[1].PublicKey != stray || wc.Peers[1].UpdateOnly {
					t.Errorf("peers = %+v", wc.Peers)
				}
			},
			notes: []string{"delete peer", "add server peer"},
		},
		{
			name:  "a listen port set by hand is left alone",
			dev:   func(d *wgtypes.Device) { d.ListenPort = 51999 },
			check: func(t *testing.T, wc wgtypes.Config) { noChange(t, wc) },
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := base
			if c.cfg != nil {
				c.cfg(&cfg)
			}
			dev := convergedDevice(base)
			if c.dev != nil {
				c.dev(dev)
			}
			wc, notes := agentDeviceDiff(dev, cfg)
			if wc.ListenPort != nil {
				t.Errorf("listen port set to %d", *wc.ListenPort)
			}
			if wc.ReplacePeers {
				t.Error("ReplacePeers set")
			}
			c.check(t, wc)
			if len(notes) != len(c.notes) {
				t.Fatalf("notes = %q, want %d lines containing %q", notes, len(c.notes), c.notes)
			}
			for i, want := range c.notes {
				if !strings.Contains(notes[i], want) {
					t.Errorf("note %d = %q, want it to contain %q", i, notes[i], want)
				}
			}
		})
	}
}

func noChange(t *testing.T, wc wgtypes.Config) {
	t.Helper()
	if wc.PrivateKey != nil || len(wc.Peers) != 0 {
		t.Errorf("wanted no change, got %+v", wc)
	}
}

func TestAgentConfigValidate(t *testing.T) {
	if err := agentCfg(t).validate(); err != nil {
		t.Fatalf("a valid config was rejected: %v", err)
	}
	cases := map[string]func(c *AgentConfig){
		"empty interface":        func(c *AgentConfig) { c.Interface = "" },
		"zero private key":       func(c *AgentConfig) { c.PrivateKey = wgtypes.Key{} },
		"IPv6 address":           func(c *AgentConfig) { c.Address = netip.MustParsePrefix("fd00::2/64") },
		"no address":             func(c *AgentConfig) { c.Address = netip.Prefix{} },
		"zero MTU":               func(c *AgentConfig) { c.MTU = 0 },
		"zero server key":        func(c *AgentConfig) { c.Server.PublicKey = wgtypes.Key{} },
		"no server address":      func(c *AgentConfig) { c.Server.Address = netip.Addr{} },
		"IPv6 endpoint":          func(c *AgentConfig) { c.Server.Endpoint = netip.MustParseAddrPort("[2001:db8::1]:51820") },
		"sub-second keepalive":   func(c *AgentConfig) { c.Server.Keepalive = 1500 * time.Millisecond },
		"negative keepalive":     func(c *AgentConfig) { c.Server.Keepalive = -time.Second },
		"keepalive over 65535 s": func(c *AgentConfig) { c.Server.Keepalive = 65536 * time.Second },
	}
	for name, mutate := range cases {
		c := agentCfg(t)
		mutate(&c)
		if err := c.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// 解決していないエンドポイントと keepalive の 0 は受け付ける。
	c := agentCfg(t)
	c.Server.Endpoint, c.Server.Keepalive = netip.AddrPort{}, 0
	if err := c.validate(); err != nil {
		t.Errorf("unresolved endpoint and no keepalive rejected: %v", err)
	}
}

// 他人のインタフェースは、相手が消えれば次の起動で通るので、起動の拒否 (終了コード 3) ではなく
// 普通のエラー (終了コード 1) である (design.md 7b.4、11b 節)。文面は ip link del の回復手順を示す。
func TestNotOursError(t *testing.T) {
	e := &NotOursError{Interface: "wgft0", Ownership: ForeignKey, Kind: "wireguard", DryRun: []string{"set private key", "delete peer X"}}
	s := e.Error()
	for _, want := range []string{"wgft0", "ip link del wgft0", "WGFT_WG_INTERFACE", "would have converged", "set private key / delete peer X"} {
		if !strings.Contains(s, want) {
			t.Errorf("%q lacks %q", s, want)
		}
	}
	if startup.IsRefusal(e) {
		t.Error("a foreign interface became a startup refusal")
	}
	if strings.ContainsAny(s, "()") {
		t.Errorf("parentheses in output: %q", s)
	}
	nw := (&NotOursError{Interface: "wgft0", Ownership: NotWireGuard, Kind: "dummy"}).Error()
	if !strings.Contains(nw, "dummy") || strings.Contains(nw, "ip link del") || strings.Contains(nw, "would have converged") {
		t.Errorf("not-WireGuard text: %q", nw)
	}
}

// エージェントの権限不足は、サーバと同じく prerequisite の拒否で、案内はエージェントの言葉で書く。
func TestAgentPrivilegeRefusal(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EACCES} {
		r := startup.Of(privilegeRefusal(fmt.Errorf("netlink: %w", errno), agentPrivilegeFormat))
		if r == nil || r.Category != startup.CategoryPrerequisite {
			t.Fatalf("%v: got %v", errno, r)
		}
		for _, want := range []string{"CAP_NET_ADMIN", "root", "WGFT_MODE=userspace", errno.Error()} {
			if !strings.Contains(r.Reason, want) {
				t.Errorf("reason %q lacks %q", r.Reason, want)
			}
		}
		if strings.Contains(r.Reason, "server.service") {
			t.Errorf("the agent's reason names the server's unit: %q", r.Reason)
		}
	}
	if err := privilegeRefusal(nil, agentPrivilegeFormat); err != nil {
		t.Errorf("nil became %v", err)
	}
}
