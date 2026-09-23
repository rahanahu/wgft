// Package kernel is a throwaway prototype (spike, branch spike/agent-kernel-dataplane) for
// a Linux agent kernel data plane: a kernel WireGuard interface (wgft0) plus an agent-owned
// nftables table doing DNAT to a LAN target, MASQUERADE and a forward chain limited to
// wgft0 <-> LAN. It mirrors the hand-built shape from
// an earlier hand-built lab experiment (wg-up.sh, nft-home.sh), just driven from Go so a
// real agent process can apply it. It is NOT meant to become the production implementation as-is
// (see the spike's lab notes for what should change); quality here
// favors learning over polish, and it deliberately skips things internal/vpsd/wg does for the
// VPS side (StartupRefusal on foreign ownership, listen-port conflict checks, dry-run diffs).
package kernel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/proto"
)

// ipForwardPath mirrors internal/vpsd/startup.go's ipForwardPath. Duplicated rather than
// exported from vpsd/startup.go, since that file's EnableIPForward is tied to *store.Store
// (meta bookkeeping for teardown) that the agent has no equivalent of yet.
const ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

// EnableIPForward sets net.ipv4.ip_forward to 1 if it is not already (item 7 in
// an earlier hand-built lab experiment: without it, forwarding from wgft0 to the LAN does
// not happen at all -- confirmed the hard way in this spike, see
// the spike's lab notes). Unlike the VPS side, this prototype does
// not remember whether it made the change, so it never offers to set it back to 0.
func EnableIPForward() error {
	if cur, err := os.ReadFile(ipForwardPath); err == nil && strings.TrimSpace(string(cur)) == "1" {
		return nil
	}
	return os.WriteFile(ipForwardPath, []byte("1\n"), 0)
}

// TableName is the agent-owned nftables table. Kept distinct from the VPS's "wgft" table name
// (internal/vpsd/nft.TableName) since both can exist on the same lab VM in different netns, but
// mainly so the two are never confused when reading `nft list ruleset` on a real host.
const TableName = "wgft_agent"

// Config declares the agent's own kernel WireGuard interface: a single peer (the server), keyed
// off the same credentials/state values the userspace tunnel uses (internal/agent/tunnel.Config).
type Config struct {
	Interface       string // wgft0
	PrivateKey      wgtypes.Key
	ServerPublicKey wgtypes.Key
	Endpoint        string       // server's host:port
	Address         netip.Prefix // own tunnel address, e.g. 10.200.0.2/24
	ServerAddress   netip.Addr   // server's tunnel address; AllowedIPs is this /32
	MTU             int
	Keepalive       time.Duration
}

// EnsureInterface reconciles wgft0 to cfg. If the interface already exists (any key), it is kept
// and reconfigured in place -- this is the "adopt on start" behavior the spike is measuring
// (item 2 in the spike's lab notes): unlike internal/vpsd/wg.Ensure, it does
// not refuse on a key mismatch, since the prototype has no notion of "foreign" wgft0 yet. adopted
// reports whether the interface pre-existed.
func EnsureInterface(cfg Config) (adopted bool, changes []string, err error) {
	note := func(f string, a ...any) { changes = append(changes, fmt.Sprintf(f, a...)) }

	link, err := netlink.LinkByName(cfg.Interface)
	if _, notFound := err.(netlink.LinkNotFoundError); notFound {
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: cfg.Interface, MTU: cfg.MTU}}); err != nil {
			return false, nil, fmt.Errorf("create %s: %w", cfg.Interface, err)
		}
		note("create interface %s", cfg.Interface)
		if link, err = netlink.LinkByName(cfg.Interface); err != nil {
			return false, nil, err
		}
	} else if err != nil {
		return false, nil, fmt.Errorf("%s: %w", cfg.Interface, err)
	} else {
		adopted = true
		if link.Type() != "wireguard" {
			return false, nil, fmt.Errorf("%s exists but is not a WireGuard interface (type %s)", cfg.Interface, link.Type())
		}
	}

	if link.Attrs().MTU != cfg.MTU {
		if err := netlink.LinkSetMTU(link, cfg.MTU); err != nil {
			return adopted, nil, fmt.Errorf("MTU: %w", err)
		}
		note("MTU %d -> %d", link.Attrs().MTU, cfg.MTU)
	}

	want := &netlink.Addr{IPNet: prefixToIPNet(cfg.Address)}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return adopted, nil, err
	}
	have := false
	for i := range addrs {
		a := &addrs[i]
		if a.IPNet.String() == want.IPNet.String() {
			have = true
			continue
		}
		if err := netlink.AddrDel(link, a); err != nil {
			return adopted, nil, fmt.Errorf("delete address %s: %w", a.IPNet, err)
		}
		note("delete address %s", a.IPNet)
	}
	if !have {
		if err := netlink.AddrAdd(link, want); err != nil {
			return adopted, nil, fmt.Errorf("add address %s: %w", want.IPNet, err)
		}
		note("add address %s", want.IPNet)
	}

	c, err := wgctrl.New()
	if err != nil {
		return adopted, nil, fmt.Errorf("wgctrl: %w", err)
	}
	defer c.Close()

	dev, err := c.Device(cfg.Interface)
	if err != nil {
		return adopted, nil, fmt.Errorf("read %s: %w", cfg.Interface, err)
	}
	wc := wgtypes.Config{}
	if dev.PrivateKey != cfg.PrivateKey {
		key := cfg.PrivateKey
		wc.PrivateKey = &key
		note("set private key; public key %s -> %s", dev.PublicKey, cfg.PrivateKey.PublicKey())
	}
	// Deliberately never touches ListenPort: the agent is a NAT'd client dialing out, not a
	// listener with a stable port to converge on (unlike the VPS's wg0). Setting it to a fixed
	// value (e.g. 0) here would make wgctrl.ConfigureDevice rebind to a fresh ephemeral port on
	// every apply, tearing down the handshake for no reason.
	wantAllowed := []net.IPNet{*prefixToIPNet(netip.PrefixFrom(cfg.ServerAddress, 32))}
	peerOK := false
	for _, p := range dev.Peers {
		if p.PublicKey != cfg.ServerPublicKey {
			wc.Peers = append(wc.Peers, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
			note("delete stale peer %s", p.PublicKey)
			continue
		}
		peerOK = true
		pc := wgtypes.PeerConfig{PublicKey: p.PublicKey}
		changed := false
		if !sameIPNets(p.AllowedIPs, wantAllowed) {
			pc.ReplaceAllowedIPs, pc.AllowedIPs = true, wantAllowed
			changed = true
		}
		wantEndpoint, epErr := resolveEndpoint(cfg.Endpoint)
		if epErr == nil && (p.Endpoint == nil || p.Endpoint.String() != wantEndpoint.String()) {
			pc.Endpoint = wantEndpoint
			changed = true
		}
		if cfg.Keepalive > 0 && p.PersistentKeepaliveInterval != cfg.Keepalive {
			ka := cfg.Keepalive
			pc.PersistentKeepaliveInterval = &ka
			changed = true
		}
		if changed {
			wc.Peers = append(wc.Peers, pc)
			note("reconfigure peer %s", p.PublicKey)
		}
	}
	if !peerOK {
		wantEndpoint, epErr := resolveEndpoint(cfg.Endpoint)
		if epErr != nil {
			return adopted, nil, fmt.Errorf("resolve endpoint %s: %w", cfg.Endpoint, epErr)
		}
		ka := cfg.Keepalive
		wc.Peers = append(wc.Peers, wgtypes.PeerConfig{
			PublicKey: cfg.ServerPublicKey, Endpoint: wantEndpoint,
			ReplaceAllowedIPs: true, AllowedIPs: wantAllowed, PersistentKeepaliveInterval: &ka,
		})
		note("add peer %s (%s)", cfg.ServerPublicKey, cfg.Endpoint)
	}
	if wc.PrivateKey != nil || len(wc.Peers) > 0 {
		if err := c.ConfigureDevice(cfg.Interface, wc); err != nil {
			return adopted, nil, fmt.Errorf("configure %s: %w", cfg.Interface, err)
		}
	}

	if link.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(link); err != nil {
			return adopted, nil, fmt.Errorf("up: %w", err)
		}
		note("up")
	}
	return adopted, changes, nil
}

// DeleteInterface removes iface unconditionally (used only by the prototype's mode-switch
// cleanup; the real design will likely refuse instead of guessing, see the spike README).
func DeleteInterface(iface string) error {
	link, err := netlink.LinkByName(iface)
	if _, nf := err.(netlink.LinkNotFoundError); nf {
		return nil
	}
	if err != nil {
		return err
	}
	if link.Type() != "wireguard" {
		return fmt.Errorf("%s is not a WireGuard interface but %s; refusing to delete it", iface, link.Type())
	}
	return netlink.LinkDel(link)
}

// Exists reports whether iface is present (any type, any key) -- used for the prototype's
// mode-switch heuristic ("a wgft0 from kernel mode exists").
func Exists(iface string) bool {
	_, err := netlink.LinkByName(iface)
	return err == nil
}

// ApplyTable replaces TableName atomically from rules (only enabled ones), like the server does
// for "table inet wgft" (internal/vpsd/nft.Apply): add empty -> delete -> define in one `nft -f`
// transaction, so it never fails on a first run and never leaves a half-applied table, and
// existing conntrack entries are untouched.
//
// It shells out to nft(8) instead of building the netlink messages with google/nftables, because
// the port-range shift needs an anonymous concatenated map ("dnat ip to udp dport map { ... }",
// found to work in an earlier hand-built lab experiment item 2) that the vendored
// google/nftables expr API has no typed helper for. For a spike, generating the same nft(8) text
// the experiment hand-verified is more trustworthy than hand-assembling the netlink expressions.
func ApplyTable(rules []proto.AgentRule, wgIface, lanIface string) error {
	script, err := buildScript(rules, wgIface, lanIface)
	if err != nil {
		return err
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft -f: %w: %s\n--- script ---\n%s", err, out.String(), script)
	}
	return nil
}

// DeleteTable removes TableName if present. Mirrors internal/vpsd/nft.DeleteTable, generalized
// to any table name and family.
func DeleteTable(name string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("cannot connect to nftables: %w", err)
	}
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("listing tables: %w", err)
	}
	found := false
	for _, t := range tables {
		if t.Name == name {
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: name})
	return conn.Flush()
}

// buildScript renders the nft(8) text for TableName from rules. Disabled rules get no line, same
// as the server (internal/vpsd/nft.emit).
func buildScript(rules []proto.AgentRule, wgIface, lanIface string) (string, error) {
	var dnat strings.Builder
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		host, port, err := net.SplitHostPort(r.Target)
		if err != nil {
			return "", fmt.Errorf("rule %s: target %q: %w", r.ID, r.Target, err)
		}
		basePort, err := strconv.Atoi(port)
		if err != nil {
			return "", fmt.Errorf("rule %s: target %q: bad port: %w", r.ID, r.Target, err)
		}
		l4 := string(r.Proto)
		if r.ListenPort.Lo == r.ListenPort.Hi {
			fmt.Fprintf(&dnat, "    iifname %q %s dport %d dnat ip to %s:%d\n",
				wgIface, l4, r.ListenPort.Lo, host, basePort)
			continue
		}
		// Position-preserving port shift over a range: one anonymous map from listen port to
		// "target ip . target port", built the same way an earlier hand-built lab experiment
		// item 2 hand-verified (nft-home.sh, exp2 there -- not carried into this repo).
		var elems []string
		for p := int(r.ListenPort.Lo); p <= int(r.ListenPort.Hi); p++ {
			shifted := basePort + (p - int(r.ListenPort.Lo))
			elems = append(elems, fmt.Sprintf("%d : %s . %d", p, host, shifted))
		}
		fmt.Fprintf(&dnat, "    iifname %q %s dport %d-%d dnat ip to %s dport map { %s }\n",
			wgIface, l4, r.ListenPort.Lo, r.ListenPort.Hi, l4, strings.Join(elems, ", "))
	}
	return fmt.Sprintf(`table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
  chain nat_pre {
    type nat hook prerouting priority dstnat - 1; policy accept;
%[2]s  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname %[3]q ct status dnat masquerade
  }
  chain forward {
    type filter hook forward priority filter - 10; policy accept;
    iifname %[4]q oifname %[4]q drop
    oifname %[3]q ct status dnat accept
    iifname %[3]q oifname %[4]q ct state established,related accept
    iifname %[4]q drop
    oifname %[4]q drop
  }
}
`, TableName, dnat.String(), lanIface, wgIface), nil
}

// DefaultLANInterface guesses the LAN-facing interface as the one carrying the IPv4 default
// route, excluding exclude (the wg interface, in case it somehow already has a default route
// through it). Real hosts may have more than one candidate; the prototype does not try to
// disambiguate and a real implementation would need an explicit setting (see spike README).
func DefaultLANInterface(exclude string) (string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}
	for _, r := range routes {
		if !isDefaultRoute(r) {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil {
			continue
		}
		if name := link.Attrs().Name; name != exclude {
			return name, nil
		}
	}
	return "", errors.New("no default route found; set the LAN interface explicitly")
}

// isDefaultRoute matches 0.0.0.0/0, however the kernel/netlink library happens to represent it
// (found by trial in the lab: Dst comes back nil for some default routes and a zero, zero-length
// *net.IPNet for others).
func isDefaultRoute(r netlink.Route) bool {
	if r.Dst == nil {
		return true
	}
	ones, bits := r.Dst.Mask.Size()
	return ones == 0 && bits == 32 && r.Dst.IP.Equal(net.IPv4zero)
}

func resolveEndpoint(endpoint string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("%q is not in host:port form", endpoint)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("%q has an invalid port", endpoint)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		if ip := net.ParseIP(host); ip != nil {
			return &net.UDPAddr{IP: ip, Port: port}, nil
		}
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	return &net.UDPAddr{IP: ips[0], Port: port}, nil
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func sameIPNets(a, b []net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, n := range a {
		seen[n.String()] = true
	}
	for _, n := range b {
		if !seen[n.String()] {
			return false
		}
	}
	return true
}
