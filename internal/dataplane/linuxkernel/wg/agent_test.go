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

// サーバのトンネルアドレスへの通信を wgft0 から奪うものだけを拒む:サーバのアドレスそのもの、
// サーバのアドレスを含み wgft0 と同じかより細かいアドレスの帯と経路。帯の中でもサーバのアドレスを
// 含まないものと、wgft0 より広い経路 (既定経路を含む) は妨げない (design.md 7b.1 節)。
// 各行の後ろの注は、どの条件を外すとその行が落ちるかを示す。
func TestBandOverlap(t *testing.T) {
	own := netip.MustParsePrefix("10.200.0.2/24")
	server := netip.MustParseAddr("10.200.0.1")
	a := func(iface, p string) hostAddr { return hostAddr{Iface: iface, Prefix: netip.MustParsePrefix(p)} }
	r := func(iface, p string) hostRoute { return hostRoute{Iface: iface, Dst: netip.MustParsePrefix(p)} }
	cases := []struct {
		name   string
		addrs  []hostAddr
		routes []hostRoute
		want   string // 空なら妨げない
	}{
		{"nothing else", nil, nil, ""},
		{"own address and route", []hostAddr{a("wgft0", "10.200.0.2/24")}, []hostRoute{r("wgft0", "10.200.0.0/24")}, ""},
		// 同じ帯の LAN のアドレス:接続経路が wgft0 と並ぶ (アドレスの帯の細かさと包含の条件)
		{"LAN address in the same /24", []hostAddr{a("eth0", "10.200.0.50/24")}, nil, `address 10.200.0.50/24 on interface "eth0"`},
		// サーバのアドレスそのもの:広い帯でもローカルに届く (一致の条件)
		{"the server's own address on the same host", []hostAddr{a("wg0", "10.200.0.1/16")}, nil, `address 10.200.0.1/16 on interface "wg0"`},
		// 広い帯の LAN のアドレス:サーバを含むが接続経路は wgft0 に負ける (アドレスの帯の細かさの条件)
		{"LAN address with a wider mask", []hostAddr{a("eth0", "10.200.0.50/16")}, nil, ""},
		// 帯の上半分の bridge:サーバを含まない (アドレスの包含の条件)
		{"container bridge on the upper half", []hostAddr{a("docker0", "10.200.0.129/25")}, []hostRoute{r("docker0", "10.200.0.128/25")}, ""},
		// サーバを含む細かい経路 (経路の条件の両方が真)
		{"a narrower route covering the server", nil, []hostRoute{r("eth1", "10.200.0.0/25")}, `route 10.200.0.0/25 on interface "eth1"`},
		{"a host route to the server", nil, []hostRoute{r("tun0", "10.200.0.1/32")}, `route 10.200.0.1/32 on interface "tun0"`},
		{"the same route on another interface", nil, []hostRoute{r("eth1", "10.200.0.0/24")}, `route 10.200.0.0/24 on interface "eth1"`},
		{"a blackhole route has no interface", nil, []hostRoute{r("", "10.200.0.0/24")}, "route 10.200.0.0/24"},
		// サーバを含まない細かい経路 (経路の包含の条件)
		{"a narrower route not covering the server", nil, []hostRoute{r("eth1", "10.200.0.128/25")}, ""},
		// 網のアドレスが帯の中にある広い経路:wgft0 の /24 に負ける (経路の細かさの条件)
		{"a broader route starting inside the range", nil, []hostRoute{r("eth0", "10.200.0.0/16")}, ""},
		{"broader routes", []hostAddr{a("eth0", "192.168.1.2/24")}, []hostRoute{r("tun0", "10.0.0.0/8"), r("eth0", "0.0.0.0/0")}, ""},
		{"an address next to the range", []hostAddr{a("eth0", "10.200.1.5/24")}, []hostRoute{r("eth0", "10.200.1.0/24")}, ""},
	}
	for _, c := range cases {
		got, overlap := bandOverlap(own, server, "wgft0", c.addrs, c.routes)
		if overlap != (c.want != "") || got != c.want {
			t.Errorf("%s: got %q %v, want %q", c.name, got, overlap, c.want)
		}
	}
}

// 鍵の無いインタフェースは、エージェントのものではなく他の道具が作ったものである見込みが高いことと、
// ip link del での消し方と別の名前を使う道を示す。エージェントは鍵を書いてから名前を付けるので、
// 自分の作成の途中で鍵の無いインタフェースを残さない(設計文書 7b.4 節)。ドライランに空の鍵を
// 公開鍵として出さない。
func TestKeylessLinkText(t *testing.T) {
	cfg := agentCfg(t)
	_, notes := agentDeviceDiff(&wgtypes.Device{}, cfg)
	if len(notes) == 0 || !strings.Contains(notes[0], "public key none -> "+cfg.PrivateKey.PublicKey().String()) {
		t.Errorf("notes = %q", notes)
	}
	zero := wgtypes.Key{}
	for _, n := range notes {
		if strings.Contains(n, zero.String()) {
			t.Errorf("the zero key is printed as a public key: %q", n)
		}
	}
	s := (&NotOursError{Interface: "wgft0", Ownership: ForeignKey, Kind: "wireguard", Keyless: true, DryRun: notes}).Error()
	for _, want := range []string{"no key", "not this agent's", "another tool", "ip link del wgft0", "WGFT_WG_INTERFACE"} {
		if !strings.Contains(s, want) {
			t.Errorf("%q lacks %q", s, want)
		}
	}
	if strings.Contains(s, zero.String()) || strings.ContainsAny(s, "()") || strings.Contains(s, "left behind") {
		t.Errorf("keyless text: %q", s)
	}
}

// 作業用の名前はカーネルの上限の 15 バイトに収まり、インタフェースの名前ごとに決まる(設計文書 7b.4 節)。
func TestAgentStagingName(t *testing.T) {
	a, b := AgentStagingName("wgft0"), AgentStagingName("wgft1")
	if len(a) > 15 || len(b) > 15 {
		t.Errorf("staging names %q and %q exceed the kernel's 15 bytes", a, b)
	}
	if a == b || a == "wgft0" {
		t.Errorf("staging names %q and %q do not tell the interfaces apart", a, b)
	}
	if AgentStagingName("wgft0") != a {
		t.Error("the staging name is not the same on every call")
	}
	// 決まった値と、CRC32 が 0 で始まる名前と、カーネルの上限いっぱいの 15 バイトの名前を確かめる。
	// 桁を詰めない書式や、名前をそのまま付ける作り方では、この 3 つのどれかが外れる
	for iface, want := range map[string]string{
		"wgft0":           "wgftnew0af13fb4",
		"wg44":            "wgftnew00aa9dde",
		"abcdefghijklmno": "",
	} {
		got := AgentStagingName(iface)
		if len(got) != 15 {
			t.Errorf("AgentStagingName(%q) = %q, %d bytes; want exactly 15", iface, got, len(got))
		}
		if want != "" && got != want {
			t.Errorf("AgentStagingName(%q) = %q, want %q", iface, got, want)
		}
	}
}

// WireGuard の汎用 netlink のファミリが無いことは、種別 prerequisite の拒否になる。カーネルは知らない
// ファミリの問い合わせに ENOENT を返すので、無い名前で確かめる。ファミリの問い合わせに権限は要らない
// (design.md 7b.5 節)。
func TestGenlFamilySupport(t *testing.T) {
	err := genlFamilySupport("wgft-test-none")
	r := startup.Of(err)
	if r == nil || r.Category != startup.CategoryPrerequisite || r.Subject != "wireguard module" {
		t.Fatalf("err = %v; want a prerequisite refusal about the wireguard module", err)
	}
	if strings.ContainsAny(err.Error(), "()") {
		t.Errorf("refusal %q uses round parentheses; tool output avoids them", err)
	}
	// 汎用 netlink の制御のファミリそのものは、どのカーネルにもある
	if err := genlFamilySupport("nlctrl"); err != nil {
		t.Errorf("nlctrl: %v; want nil", err)
	}
}
