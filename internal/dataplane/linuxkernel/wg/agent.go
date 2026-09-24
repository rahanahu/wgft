//go:build linux

package wg

// エージェントのカーネルモードの WireGuard インタフェース (design.md 7b.1、7b.4 節)。ピアは VPS の
// 1 つだけで、AllowedIPs は vpsd のトンネルアドレスの /32、エンドポイントと keepalive を持ち、
// 決まった待ち受けポートを持たない。所有は鍵だけで判定し、認証情報ファイルの鍵か 1 つ前の鍵を持つ
// インタフェースだけを自分のものとみなす。サーバの wg0 と違い、鍵の一致しないインタフェースを
// 引き継ぐ手段 (--adopt-existing) は持たない。

import (
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// AgentConfig declares the agent's kernel WireGuard interface (design.md 7b.1 節).
type AgentConfig struct {
	// Interface is the link name, wgft0 unless WGFT_WG_INTERFACE says otherwise.
	Interface string
	// PrivateKey is the key in the agent's credentials file. It must not be zero: a link created
	// with the zero key could never be judged ours again.
	PrivateKey wgtypes.Key
	// PreviousKey is the key before the last rotate-key, kept in the credentials file so that a
	// link still holding it after a crash in the middle of rotate-key, or after rotate-key ran
	// while the agent was stopped, is still ours (design.md 7b.4 節). Zero when there is none;
	// the zero key never makes a link ours.
	PreviousKey wgtypes.Key
	// Address is the agent's own tunnel address with the band, as the full state's wg.address
	// gives it (10.200.0.2/24).
	Address netip.Prefix
	MTU     int
	Server  ServerPeer
}

// ServerPeer is the link's one peer, the server.
type ServerPeer struct {
	PublicKey wgtypes.Key
	// Address is vpsd's tunnel address. The peer's AllowedIPs is exactly its /32.
	Address netip.Addr
	// Endpoint is the server's address, already resolved: the caller resolves the endpoint's name
	// and decides when to resolve it again (design.md 4, 7b.1 節). The zero value means "not
	// resolved now": the endpoint the kernel has is kept, and a peer added now has none until a
	// later call supplies one. A valid value is converged to, so passing the result of each new
	// resolution moves the peer to it.
	Endpoint netip.AddrPort
	// Keepalive is the persistent keepalive, in whole seconds as the kernel keeps it. Zero turns
	// it off.
	Keepalive time.Duration
}

// Ownership is what a link with the agent's interface name is to the agent (design.md 7b.4 節).
type Ownership int

const (
	// Absent: there is no link with the name.
	Absent Ownership = iota
	// OwnedByCurrentKey: a WireGuard link holding the key in the credentials file.
	OwnedByCurrentKey
	// OwnedByPreviousKey: a WireGuard link holding the key before the last rotate-key. The next
	// EnsureAgent moves it to the current key.
	OwnedByPreviousKey
	// ForeignKey: a WireGuard link whose key is neither, including the zero key. Never touched.
	ForeignKey
	// NotWireGuard: a link of another type with the name. Never touched.
	NotWireGuard
)

// Ours reports whether the link is the agent's to converge and to delete.
func (o Ownership) Ours() bool { return o == OwnedByCurrentKey || o == OwnedByPreviousKey }

func (o Ownership) String() string {
	switch o {
	case Absent:
		return "absent"
	case OwnedByCurrentKey:
		return "owned by the current key"
	case OwnedByPreviousKey:
		return "owned by the previous key"
	case ForeignKey:
		return "held by another key"
	case NotWireGuard:
		return "not WireGuard"
	}
	return fmt.Sprintf("Ownership(%d)", int(o))
}

// judgeOwnership is the ownership rule on values already read. The zero key never matches, so a
// credentials file without a previous key, or a link whose key was never set, does not make a
// link ours.
func judgeOwnership(kind string, key, current, previous wgtypes.Key) Ownership {
	var zero wgtypes.Key
	switch {
	case kind != "wireguard":
		return NotWireGuard
	case key == zero:
		return ForeignKey
	case key == current:
		return OwnedByCurrentKey
	case key == previous:
		return OwnedByPreviousKey
	}
	return ForeignKey
}

// NotOursError is returned when a link with the agent's interface name exists but is not the
// agent's. It is a plain error, exit code 1 (design.md 7b.4, 11b 節): nothing was written, and
// once the operator removes or renames that link the next start goes through.
type NotOursError struct {
	Interface string
	Ownership Ownership // ForeignKey or NotWireGuard
	Kind      string    // the link type
	// Keyless is set for a WireGuard link that holds no private key at all.
	Keyless bool
	// DryRun lists what EnsureAgent would have changed had the link been the agent's. Empty for
	// teardown and for a link that is not WireGuard.
	DryRun []string
}

func (e *NotOursError) Error() string {
	var s string
	switch {
	case e.Ownership == NotWireGuard:
		s = fmt.Sprintf("%s exists but is a %s link, not WireGuard; wgft leaves it untouched. Set WGFT_WG_INTERFACE to another name", e.Interface, e.Kind)
	case e.Keyless:
		// エージェントは鍵を書いてから wgft0 の名前を付けるので、自分の作成の途中で鍵の無い wgft0 を
		// 残すことは無い(design.md 7b.4 節)。鍵の無いリンクは他の道具が作ったものと見るのが自然である
		s = fmt.Sprintf("%s exists as a WireGuard link with no key, so it is not this agent's and wgft leaves it untouched; another tool probably created it. "+
			"If nothing uses it, delete it with `ip link del %s`; otherwise set WGFT_WG_INTERFACE to another name", e.Interface, e.Interface)
	default:
		s = fmt.Sprintf("%s exists but holds neither this agent's WireGuard key nor its previous one, so wgft leaves it untouched. "+
			"If it was left by an earlier registration of this agent, for example after agent.json was lost, confirm that and delete it with `ip link del %s`; "+
			"otherwise set WGFT_WG_INTERFACE to another name", e.Interface, e.Interface)
	}
	if len(e.DryRun) > 0 {
		s += ". would have converged by changing: " + strings.Join(e.DryRun, " / ")
	}
	return s
}

func (cfg AgentConfig) validate() error {
	switch {
	case cfg.Interface == "":
		return errors.New("wg: agent interface name is empty")
	case cfg.PrivateKey == (wgtypes.Key{}):
		return errors.New("wg: agent private key is empty")
	case !cfg.Address.IsValid() || !cfg.Address.Addr().Is4():
		return fmt.Errorf("wg: agent address %v is not an IPv4 prefix", cfg.Address)
	case cfg.MTU <= 0:
		return fmt.Errorf("wg: agent MTU %d is not positive", cfg.MTU)
	case cfg.Server.PublicKey == (wgtypes.Key{}):
		return errors.New("wg: server public key is empty")
	case !cfg.Server.Address.Is4():
		return fmt.Errorf("wg: server address %v is not IPv4", cfg.Server.Address)
	case cfg.Server.Endpoint.IsValid() && !cfg.Server.Endpoint.Addr().Unmap().Is4():
		return fmt.Errorf("wg: server endpoint %v is not IPv4", cfg.Server.Endpoint)
	case cfg.Server.Keepalive < 0 || cfg.Server.Keepalive%time.Second != 0 || cfg.Server.Keepalive > 65535*time.Second:
		return fmt.Errorf("wg: keepalive %v is not a whole number of seconds from 0 to 65535", cfg.Server.Keepalive)
	}
	return nil
}

// agentPrivilegeFormat and agentNoWireGuardFormat are the agent's texts for the two prerequisite
// refusals Ensure makes for the server (design.md 7b.5 節).
const (
	agentPrivilegeFormat   = "kernel mode needs CAP_NET_ADMIN: %v. Run the agent as root or with that capability, or set WGFT_MODE=userspace, which needs neither"
	agentNoWireGuardFormat = "cannot create %s: this kernel has no WireGuard support; the wireguard module is missing or cannot be loaded, and `modprobe wireguard` shows why. Kernel mode needs it; without it, run the agent in userspace mode by setting WGFT_MODE=userspace"
)

// EnsureAgent converges the agent's kernel WireGuard interface to cfg and returns what it changed
// (design.md 7b.1, 7b.4 節). A missing link is created. An existing link is converged only when it
// is ours by the current or the previous key; the judgement is made before the first write, and a
// link that is not ours is left as it is and reported as *NotOursError with a dry run. A link that
// held the previous key ends up with the current one. Before the first write it also refuses, with
// a plain error, when the agent's address range overlaps an address or a route on another
// interface (design.md 7b.1 節).
//
// Converged: MTU, the IPv4 address (exactly cfg.Address), the private key, the peer set (only the
// server; any other peer is removed), the server's AllowedIPs (exactly its /32), its endpoint when
// cfg.Server.Endpoint is valid, its keepalive, and the up flag. The listen port is not converged:
// the agent dials out and has no fixed port, and setting one would rebind the socket.
//
// A link created by this call is deleted again if a later step fails. A permission failure is a
// prerequisite refusal, and so is a kernel without WireGuard.
func EnsureAgent(cfg AgentConfig) (changes []string, err error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	created := false
	defer func() {
		err = privilegeRefusal(err, agentPrivilegeFormat)
		if err != nil && created {
			if l, e := netlink.LinkByName(cfg.Interface); e == nil {
				_ = netlink.LinkDel(l)
			}
		}
	}()
	note := func(f string, a ...any) { changes = append(changes, fmt.Sprintf(f, a...)) }

	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	defer c.Close()

	link, err := netlink.LinkByName(cfg.Interface)
	_, absent := err.(netlink.LinkNotFoundError)
	if err != nil && !absent {
		return nil, fmt.Errorf("%s: %w", cfg.Interface, err)
	}
	var dev *wgtypes.Device
	if !absent {
		if link.Type() != "wireguard" {
			return nil, &NotOursError{Interface: cfg.Interface, Ownership: NotWireGuard, Kind: link.Type()}
		}
		if dev, err = c.Device(cfg.Interface); err != nil {
			return nil, fmt.Errorf("read %s: %w", cfg.Interface, err)
		}
		// 所有の判定は最初の書き込みより前に行う。
		if own := judgeOwnership(link.Type(), dev.PrivateKey, cfg.PrivateKey, cfg.PreviousKey); !own.Ours() {
			_, planned := agentDeviceDiff(dev, cfg)
			return nil, &NotOursError{Interface: cfg.Interface, Ownership: own, Kind: link.Type(),
				Keyless: dev.PrivateKey == wgtypes.Key{}, DryRun: append(addressPlan(link, cfg.MTU, cfg.Address), planned...)}
		}
	}
	// アドレス帯の重なりも、作成を含む最初の書き込みより前に判定する。
	if err := checkAgentOverlap(cfg); err != nil {
		return nil, err
	}

	if absent {
		if err := createAgentLink(c, cfg); err != nil {
			return nil, err
		}
		created = true
		note("create interface %s", cfg.Interface)
		if agentAfterCreate != nil {
			if err := agentAfterCreate(cfg.Interface); err != nil {
				return nil, err
			}
		}
		if link, err = netlink.LinkByName(cfg.Interface); err != nil {
			return nil, err
		}
		if dev, err = c.Device(cfg.Interface); err != nil {
			return nil, fmt.Errorf("read %s: %w", cfg.Interface, err)
		}
	}

	if err := convergeMTUAndAddress(link, cfg.MTU, cfg.Address, note); err != nil {
		return nil, err
	}
	wc, planned := agentDeviceDiff(dev, cfg)
	if wc.PrivateKey != nil || len(wc.Peers) > 0 {
		if err := c.ConfigureDevice(cfg.Interface, wc); err != nil {
			return nil, fmt.Errorf("configure %s: %w", cfg.Interface, err)
		}
		changes = append(changes, planned...)
	}
	if err := bringUp(link, note); err != nil {
		return nil, err
	}
	return changes, nil
}

// agentAfterCreate, when set, runs right after EnsureAgent created the link and makes it fail
// there. Only the lab tests set it, to check that a link created by a failed call is deleted.
var agentAfterCreate func(iface string) error

// agentStagingHook, when set, runs at each step of createAgentLink: "created" right after the
// staging link exists without a key, "keyed" right after it holds the key and before the rename.
// Only the lab tests set it, to stop a child process there and kill it, as a crash would.
var agentStagingHook func(step string)

// AgentStagingName is the name the agent's link has while it is being created (design.md 7b.4 節).
// It is derived from the interface name, so every start that creates the same interface uses the
// same staging name and can clear what a crash left under it. It is 15 bytes, the kernel's limit.
func AgentStagingName(iface string) string {
	return fmt.Sprintf("wgftnew%08x", crc32.ChecksumIEEE([]byte(iface)))
}

// createAgentLink creates the agent's link so that it never exists under its own name without the
// agent's key (design.md 7b.4 節). A new WireGuard link holds no key, and a keyless link is not
// the agent's, so a crash between creating the link under its own name and setting the key would
// leave a link that every later start refuses as not ours until an operator deletes it. The link is
// created under AgentStagingName, given the private key, and only then renamed; a new link is down,
// which a rename requires. A crash before the rename leaves only the staging link, which the next
// creation deletes.
//
// Anything left under the staging name is deleted first when it is a WireGuard link with no key or
// with the current or the previous key: the agent's own creation left it there. Anything else under
// that name is left alone and reported.
func createAgentLink(c *wgctrl.Client, cfg AgentConfig) error {
	tmp := AgentStagingName(cfg.Interface)
	if err := clearStaging(c, tmp, cfg); err != nil {
		return err
	}
	if err := createLink(tmp, cfg.Interface, cfg.MTU, agentNoWireGuardFormat); err != nil {
		return err
	}
	fail := func(err error) error {
		if l, e := netlink.LinkByName(tmp); e == nil {
			_ = netlink.LinkDel(l)
		}
		return err
	}
	if agentStagingHook != nil {
		agentStagingHook("created")
	}
	if err := c.ConfigureDevice(tmp, wgtypes.Config{PrivateKey: &cfg.PrivateKey}); err != nil {
		return fail(fmt.Errorf("set the key of %s while creating %s: %w", tmp, cfg.Interface, err))
	}
	if agentStagingHook != nil {
		agentStagingHook("keyed")
	}
	link, err := netlink.LinkByName(tmp)
	if err != nil {
		return fail(fmt.Errorf("read %s while creating %s: %w", tmp, cfg.Interface, err))
	}
	if err := netlink.LinkSetName(link, cfg.Interface); err != nil {
		return fail(fmt.Errorf("rename %s to %s: %w", tmp, cfg.Interface, err))
	}
	return nil
}

// clearStaging deletes what a crash of an earlier creation left under the staging name tmp.
func clearStaging(c *wgctrl.Client, tmp string, cfg AgentConfig) error {
	link, err := netlink.LinkByName(tmp)
	if _, nf := err.(netlink.LinkNotFoundError); nf {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", tmp, err)
	}
	if link.Type() != "wireguard" {
		return fmt.Errorf("cannot create %s: the agent creates it under the name %s first, and a %s link already has that name; "+
			"remove or rename that link, or set WGFT_WG_INTERFACE to another name, which also changes the name used while creating it", cfg.Interface, tmp, link.Type())
	}
	dev, err := c.Device(tmp)
	if err != nil {
		return fmt.Errorf("read %s: %w", tmp, err)
	}
	if dev.PrivateKey != (wgtypes.Key{}) && !judgeOwnership(link.Type(), dev.PrivateKey, cfg.PrivateKey, cfg.PreviousKey).Ours() {
		return fmt.Errorf("cannot create %s: the agent creates it under the name %s first, and a WireGuard interface with another key already has that name; "+
			"if it is left over from an earlier agent on this host, delete it with `ip link del %s`; "+
			"otherwise set WGFT_WG_INTERFACE to another name, which also changes the name used while creating it", cfg.Interface, tmp, tmp)
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("delete %s left over from an earlier creation of %s: %w", tmp, cfg.Interface, err)
	}
	return nil
}

// hostAddr and hostRoute are the addresses and main-table routes of the host's other interfaces,
// as checkAgentOverlap reads them. Iface is empty for a route with no single interface, such as a
// blackhole or a multipath route.
type hostAddr struct {
	Iface  string
	Prefix netip.Prefix
}

type hostRoute struct {
	Iface string
	Dst   netip.Prefix
}

// bandOverlap is the overlap rule on values already read. It reports what on another interface
// would take traffic to the server's tunnel address away from the agent's interface:
//   - an address that is the server address itself, which the local table delivers to this host;
//   - an address whose prefix contains the server address and is as specific as own or more, whose
//     connected route then wins over, or ties with, the one of the agent's interface;
//   - a main-table route that contains the server address and is as specific as own or more.
//
// Anything else is allowed: an address or route inside the range that does not cover the server
// address, such as a container bridge on the upper half of the range, and a broader route, the
// default route included, which loses to the agent's connected route.
func bandOverlap(own netip.Prefix, server netip.Addr, self string, addrs []hostAddr, routes []hostRoute) (string, bool) {
	for _, a := range addrs {
		if a.Iface == self {
			continue
		}
		if a.Prefix.Addr() == server || (a.Prefix.Bits() >= own.Bits() && a.Prefix.Masked().Contains(server)) {
			return fmt.Sprintf("address %s on interface %q", a.Prefix, a.Iface), true
		}
	}
	for _, r := range routes {
		if r.Iface == self {
			continue
		}
		if r.Dst.Bits() >= own.Bits() && r.Dst.Contains(server) {
			if r.Iface == "" {
				return fmt.Sprintf("route %s", r.Dst), true
			}
			return fmt.Sprintf("route %s on interface %q", r.Dst, r.Iface), true
		}
	}
	return "", false
}

// checkAgentOverlap refuses when an address or a main-table route on another interface of the host
// would take traffic to the server's tunnel address away from the agent's interface, by the rule
// of bandOverlap (design.md 7b.1 節). It is a plain error, exit code 1: the range
// comes from the server, so the agent's own settings cannot avoid it, and once the host's
// interface or the server's range changes the next start goes through.
func checkAgentOverlap(cfg AgentConfig) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}
	names := make(map[int]string, len(links))
	for _, l := range links {
		names[l.Attrs().Index] = l.Attrs().Name
	}
	nlAddrs, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	var addrs []hostAddr
	for _, a := range nlAddrs {
		if ip, ok := netip.AddrFromSlice(a.IPNet.IP); ok {
			ones, _ := a.IPNet.Mask.Size()
			addrs = append(addrs, hostAddr{Iface: names[a.LinkIndex], Prefix: netip.PrefixFrom(ip.Unmap(), ones)})
		}
	}
	nlRoutes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}
	var routes []hostRoute
	for _, r := range nlRoutes {
		// 既定経路は Dst が nil か長さ 0 で返ることがある。どちらも最も広い経路なので対象にならない。
		if r.Dst == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(r.Dst.IP)
		if !ok {
			continue
		}
		ones, _ := r.Dst.Mask.Size()
		routes = append(routes, hostRoute{Iface: names[r.LinkIndex], Dst: netip.PrefixFrom(ip.Unmap(), ones)})
	}
	what, overlap := bandOverlap(cfg.Address, cfg.Server.Address, cfg.Interface, addrs, routes)
	if !overlap {
		return nil
	}
	return &OverlapError{Range: cfg.Address.Masked(), What: what, Server: cfg.Server.Address, Interface: cfg.Interface}
}

// OverlapError is EnsureAgent's refusal of an address range that overlaps an address or a route on
// another interface (design.md 7b.1 節). It is a plain error, exit code 1. The agent tells it apart
// because the first convergence of the process ends the process on it, and a later one retries.
type OverlapError struct {
	Range     netip.Prefix
	What      string // the overlapping address or route and its interface
	Server    netip.Addr
	Interface string
}

func (e *OverlapError) Error() string {
	return fmt.Sprintf("the agent's WireGuard address range %s overlaps %s on this host, which covers the server at %s, so traffic to the server would not go through %s. "+
		"Remove that address or route from this host, or have the server's operator move the range with WGFT_WG_ADDRESS, "+
		"which takes `wgft server teardown --purge` and registering the agents again",
		e.Range, e.What, e.Server, e.Interface)
}

// AgentPrivilegeRefusal turns a permission failure of a read the agent makes before converging,
// such as AgentOwnership, into the same prerequisite refusal EnsureAgent returns. Other errors are
// returned as they are.
func AgentPrivilegeRefusal(err error) error {
	return privilegeRefusal(err, agentPrivilegeFormat)
}

// AgentKeyHolders lists the WireGuard devices other than iface that hold current or previous
// (design.md 7b.4 節). A link left under an old name after WGFT_WG_INTERFACE changed is one; the
// agent warns about it at startup and never deletes it. The zero key matches nothing.
func AgentKeyHolders(iface string, current, previous wgtypes.Key) ([]string, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	defer c.Close()
	devs, err := c.Devices()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range devs {
		if d.Name == iface || d.Type != wgtypes.LinuxKernel {
			continue
		}
		if judgeOwnership("wireguard", d.PrivateKey, current, previous).Ours() {
			out = append(out, d.Name)
		}
	}
	return out, nil
}

// agentDeviceDiff is the wgctrl part of EnsureAgent on a device already read: the configuration
// that moves dev to cfg, and one line per change. It never sets the listen port.
func agentDeviceDiff(dev *wgtypes.Device, cfg AgentConfig) (wgtypes.Config, []string) {
	var wc wgtypes.Config
	var notes []string
	note := func(f string, a ...any) { notes = append(notes, fmt.Sprintf(f, a...)) }

	if dev.PrivateKey != cfg.PrivateKey {
		key := cfg.PrivateKey
		wc.PrivateKey = &key
		if cfg.PreviousKey != (wgtypes.Key{}) && dev.PrivateKey == cfg.PreviousKey {
			note("replace the previous private key; public key %s -> %s", dev.PublicKey, cfg.PrivateKey.PublicKey())
		} else if dev.PrivateKey == (wgtypes.Key{}) {
			note("set private key; public key none -> %s", cfg.PrivateKey.PublicKey())
		} else {
			note("set private key; public key %s -> %s", dev.PublicKey, cfg.PrivateKey.PublicKey())
		}
	}

	allowed := []net.IPNet{*prefixToIPNet(netip.PrefixFrom(cfg.Server.Address, 32))}
	var server *wgtypes.Peer
	for i := range dev.Peers {
		p := &dev.Peers[i]
		if p.PublicKey != cfg.Server.PublicKey {
			wc.Peers = append(wc.Peers, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
			note("delete peer %s", p.PublicKey)
			continue
		}
		server = p
	}

	if server == nil {
		pc := wgtypes.PeerConfig{PublicKey: cfg.Server.PublicKey, ReplaceAllowedIPs: true, AllowedIPs: allowed}
		ka := cfg.Server.Keepalive
		pc.PersistentKeepaliveInterval = &ka
		desc := "no endpoint yet"
		if cfg.Server.Endpoint.IsValid() {
			pc.Endpoint = net.UDPAddrFromAddrPort(unmapped(cfg.Server.Endpoint))
			desc = "endpoint " + unmapped(cfg.Server.Endpoint).String()
		}
		wc.Peers = append(wc.Peers, pc)
		note("add server peer %s at %s, %s, keepalive %v", cfg.Server.PublicKey, cfg.Server.Address, desc, cfg.Server.Keepalive)
		return wc, notes
	}

	pc := wgtypes.PeerConfig{PublicKey: server.PublicKey, UpdateOnly: true}
	changed := false
	if !sameIPNets(server.AllowedIPs, allowed) {
		pc.ReplaceAllowedIPs, pc.AllowedIPs = true, allowed
		changed = true
		note("fix AllowedIPs of the server peer to %v", allowed)
	}
	if cfg.Server.Endpoint.IsValid() {
		want := unmapped(cfg.Server.Endpoint)
		have := peerEndpoint(server)
		if have != want {
			pc.Endpoint = net.UDPAddrFromAddrPort(want)
			changed = true
			if have.IsValid() {
				note("server endpoint %s -> %s", have, want)
			} else {
				note("server endpoint none -> %s", want)
			}
		}
	}
	if server.PersistentKeepaliveInterval != cfg.Server.Keepalive {
		ka := cfg.Server.Keepalive
		pc.PersistentKeepaliveInterval = &ka
		changed = true
		note("server keepalive %v -> %v", server.PersistentKeepaliveInterval, cfg.Server.Keepalive)
	}
	if changed {
		wc.Peers = append(wc.Peers, pc)
	}
	return wc, notes
}

func unmapped(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func peerEndpoint(p *wgtypes.Peer) netip.AddrPort {
	if p.Endpoint == nil {
		return netip.AddrPort{}
	}
	return unmapped(p.Endpoint.AddrPort())
}

// AgentOwnership reads what the link named iface is to an agent holding current and previous
// (design.md 7b.4 節). It changes nothing. The mode gate and teardown judge the agent's leftovers
// with it.
func AgentOwnership(iface string, current, previous wgtypes.Key) (Ownership, error) {
	own, _, _, err := readOwnership(iface, current, previous)
	return own, err
}

// readOwnership is AgentOwnership that also returns the link type and whether a WireGuard link
// holds no key, for the text of NotOursError.
func readOwnership(iface string, current, previous wgtypes.Key) (own Ownership, kind string, keyless bool, err error) {
	link, err := netlink.LinkByName(iface)
	if _, nf := err.(netlink.LinkNotFoundError); nf {
		return Absent, "", false, nil
	}
	if err != nil {
		return Absent, "", false, err
	}
	if link.Type() != "wireguard" {
		return NotWireGuard, link.Type(), false, nil
	}
	c, err := wgctrl.New()
	if err != nil {
		return Absent, "", false, fmt.Errorf("wgctrl: %w", err)
	}
	defer c.Close()
	dev, err := c.Device(iface)
	if err != nil {
		return Absent, "", false, fmt.Errorf("read %s: %w", iface, err)
	}
	return judgeOwnership(link.Type(), dev.PrivateKey, current, previous), link.Type(), dev.PrivateKey == wgtypes.Key{}, nil
}

// DeleteAgentLink deletes iface only when it is the agent's by the current or the previous key
// (design.md 10.3 節). A missing link is not an error: it returns Absent and false, so teardown can
// run again after a partial run. A link that is not ours is left as it is and reported as
// *NotOursError, whose text shows the `ip link del` recovery.
func DeleteAgentLink(iface string, current, previous wgtypes.Key) (Ownership, bool, error) {
	own, kind, keyless, err := readOwnership(iface, current, previous)
	if err != nil || own == Absent {
		return own, false, err
	}
	if !own.Ours() {
		return own, false, &NotOursError{Interface: iface, Ownership: own, Kind: kind, Keyless: keyless}
	}
	deleted, err := DeleteLink(iface)
	return own, deleted, err
}

// AgentState is what InspectAgent reads back of the agent's interface: what agent doctor's
// dataplane.interface shows and what the agent compares with the last convergence. It carries the
// public key only, never the private key.
type AgentState struct {
	Exists bool
	// Kind is the link type ("wireguard" for a WireGuard device).
	Kind      string
	Ownership Ownership
	// The rest is read only for a WireGuard device.
	PublicKey  wgtypes.Key // the public half of the key the device holds; zero if it holds none
	ListenPort int         // the port the kernel chose; shown only
	MTU        int
	Addresses  []netip.Prefix // IPv4 only, as EnsureAgent converges them
	Up         bool
	Peers      []PeerState
}

// PeerState is one peer of the agent's interface as the kernel reports it.
type PeerState struct {
	PublicKey  wgtypes.Key
	AllowedIPs []netip.Prefix
	Endpoint   netip.AddrPort // zero when the peer has none
	Keepalive  time.Duration
	// LastHandshake is a value to show, zero when there has been none. Judging whether it is
	// recent enough belongs to server doctor's tunnel.handshake (design.md 10.2c 節).
	LastHandshake time.Time
	ReceiveBytes  int64
	TransmitBytes int64
}

// InspectAgent reads iface without changing anything and judges its ownership against current
// and previous. Reading a WireGuard device needs CAP_NET_ADMIN; without it the error wraps
// os.ErrPermission, which agent doctor reports as needs_cap_net_admin.
func InspectAgent(iface string, current, previous wgtypes.Key) (AgentState, error) {
	link, err := netlink.LinkByName(iface)
	if _, nf := err.(netlink.LinkNotFoundError); nf {
		return AgentState{Ownership: Absent}, nil
	}
	if err != nil {
		return AgentState{}, err
	}
	st := AgentState{Exists: true, Kind: link.Type()}
	if st.Kind != "wireguard" {
		st.Ownership = NotWireGuard
		return st, nil
	}
	st.Up = link.Attrs().Flags&net.FlagUp != 0
	st.MTU = link.Attrs().MTU
	if st.Addresses, err = ipv4Prefixes(link); err != nil {
		return AgentState{}, err
	}
	c, err := wgctrl.New()
	if err != nil {
		return AgentState{}, fmt.Errorf("wgctrl: %w", err)
	}
	defer c.Close()
	dev, err := c.Device(iface)
	if err != nil {
		return AgentState{}, fmt.Errorf("read %s: %w", iface, err)
	}
	st.Ownership = judgeOwnership(st.Kind, dev.PrivateKey, current, previous)
	if dev.PrivateKey != (wgtypes.Key{}) {
		st.PublicKey = dev.PublicKey
	}
	st.ListenPort = dev.ListenPort
	for i := range dev.Peers {
		p := &dev.Peers[i]
		ps := PeerState{PublicKey: p.PublicKey, Endpoint: peerEndpoint(p), Keepalive: p.PersistentKeepaliveInterval,
			LastHandshake: p.LastHandshakeTime, ReceiveBytes: p.ReceiveBytes, TransmitBytes: p.TransmitBytes}
		if ps.LastHandshake.Unix() <= 0 {
			ps.LastHandshake = time.Time{}
		}
		for _, n := range p.AllowedIPs {
			if a, ok := netip.AddrFromSlice(n.IP); ok {
				ones, _ := n.Mask.Size()
				ps.AllowedIPs = append(ps.AllowedIPs, netip.PrefixFrom(a.Unmap(), ones))
			}
		}
		st.Peers = append(st.Peers, ps)
	}
	return st, nil
}

// AgentRouteInterface returns the name of the interface the kernel's routing, policy rules
// included, sends traffic to dst through (design.md 7b.1 節). The agent compares it with its own
// interface after converging: an address or route overlap check reads only the main table, so a
// rule that sends the server's tunnel address to another table, such as Tailscale's table 52, is
// seen only here.
func AgentRouteInterface(dst netip.Addr) (string, error) {
	routes, err := netlink.RouteGet(dst.AsSlice())
	if err != nil {
		return "", err
	}
	if len(routes) == 0 {
		return "", fmt.Errorf("no route to %s", dst)
	}
	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return "", err
	}
	return link.Attrs().Name, nil
}
