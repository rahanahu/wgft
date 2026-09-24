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
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/startup"
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
	// DryRun lists what EnsureAgent would have changed had the link been the agent's. Empty for
	// teardown and for a link that is not WireGuard.
	DryRun []string
}

func (e *NotOursError) Error() string {
	var s string
	if e.Ownership == NotWireGuard {
		s = fmt.Sprintf("%s exists but is a %s link, not WireGuard; wgft leaves it untouched. Set WGFT_WG_INTERFACE to another name", e.Interface, e.Kind)
	} else {
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
// held the previous key ends up with the current one.
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
	if _, notFound := err.(netlink.LinkNotFoundError); notFound {
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: cfg.Interface, MTU: cfg.MTU}}); err != nil {
			if errors.Is(err, unix.EOPNOTSUPP) {
				return nil, startup.Prerequisite("wireguard module", agentNoWireGuardFormat, cfg.Interface)
			}
			return nil, fmt.Errorf("cannot create %s: %w", cfg.Interface, err)
		}
		created = true
		note("create interface %s", cfg.Interface)
		if link, err = netlink.LinkByName(cfg.Interface); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("%s: %w", cfg.Interface, err)
	}
	if link.Type() != "wireguard" {
		return nil, &NotOursError{Interface: cfg.Interface, Ownership: NotWireGuard, Kind: link.Type()}
	}

	dev, err := c.Device(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", cfg.Interface, err)
	}
	// 所有の判定は最初の書き込みより前に行う。作ったばかりのインタフェースは鍵が空なので判定しない。
	if !created {
		if own := judgeOwnership(link.Type(), dev.PrivateKey, cfg.PrivateKey, cfg.PreviousKey); !own.Ours() {
			_, planned := agentDeviceDiff(dev, cfg)
			return nil, &NotOursError{Interface: cfg.Interface, Ownership: own, Kind: link.Type(),
				DryRun: append(addressPlan(link, cfg.MTU, cfg.Address), planned...)}
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
	link, err := netlink.LinkByName(iface)
	if _, nf := err.(netlink.LinkNotFoundError); nf {
		return Absent, nil
	}
	if err != nil {
		return Absent, err
	}
	if link.Type() != "wireguard" {
		return NotWireGuard, nil
	}
	c, err := wgctrl.New()
	if err != nil {
		return Absent, fmt.Errorf("wgctrl: %w", err)
	}
	defer c.Close()
	dev, err := c.Device(iface)
	if err != nil {
		return Absent, fmt.Errorf("read %s: %w", iface, err)
	}
	return judgeOwnership(link.Type(), dev.PrivateKey, current, previous), nil
}

// DeleteAgentLink deletes iface only when it is the agent's by the current or the previous key
// (design.md 10.3 節). A missing link is not an error: it returns Absent and false, so teardown can
// run again after a partial run. A link that is not ours is left as it is and reported as
// *NotOursError, whose text shows the `ip link del` recovery.
func DeleteAgentLink(iface string, current, previous wgtypes.Key) (Ownership, bool, error) {
	own, err := AgentOwnership(iface, current, previous)
	if err != nil || own == Absent {
		return own, false, err
	}
	if !own.Ours() {
		kind := "wireguard"
		if l, e := netlink.LinkByName(iface); e == nil {
			kind = l.Type()
		}
		return own, false, &NotOursError{Interface: iface, Ownership: own, Kind: kind}
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
