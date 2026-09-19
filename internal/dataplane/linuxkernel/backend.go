// Package linuxkernel is the kernel dataplane Backend (design.md 6.1, 7a.7, 7a.8 節 Phase 3): kernel
// WireGuard (linuxkernel/wg), nftables DNAT and admission (linuxkernel/nft), and conntrack
// convergence (linuxkernel/conntrack), behind the same dataplane.Backend interface the userspace
// Backend implements. It never imports internal/vpsd or internal/agent (design.md 7a.7 節;
// internal/dataplane/deps_test.go checks this), so the future agent kernel backend (Phase 7) can
// reuse its common kernel components: WireGuard, the platform checks, and the nft and conntrack
// primitives. The table built here (public ports DNATed to an agent's wg address) and the
// convergence of those DNATed flows are server-specific; the agent needs its own nft and conntrack
// path (DNAT to the LAN target, MASQUERADE toward the LAN, agent-side convergence), to be added in
// this package next to the server's.
//
// One transaction (design.md 7a.2, 7a.3 節) runs as follows. Prepare adds the WireGuard peers the
// declaration newly needs and builds the table replacement without sending it (nft.Stage). Commit
// reads the drop counters of the table about to be replaced, sends the replacement as one
// nftables transaction (the point of no return), then removes the peers the declaration dropped
// and runs the conntrack convergence. The counters are handed out only when the replacement
// succeeded: a failed replacement keeps the old table and its counters, which the next Commit
// reads again, so nothing is accumulated twice. Rollback restores the peer set Prepare changed.
package linuxkernel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/conntrack"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
)

// Options configures a Backend. Interface と AdoptExisting は kernel の wg インタフェースだけの
// 性質なので、宣言(dataplane.WGConfig)ではなく construction 時にここで固定する(dataplane.WGConfig
// のドキュメントコメントのとおり)。
type Options struct {
	// Interface は wg インタフェース名(既定 wgft0)。
	Interface string
	// AdoptExisting が真のときだけ、鍵の一致しない既存インタフェースを引き継ぐ(design.md 9 節)。
	AdoptExisting bool
}

// kernelOps is what the Backend does to the kernel. The production implementation calls the wg,
// nft and conntrack packages; unit tests substitute a recorder, since the real calls need root and
// a lab VM.
type kernelOps interface {
	ensureWG(cfg wg.Config) ([]string, error)
	peers(iface string) ([]dataplane.Peer, error)
	stage(plan planner.Plan, relayListening map[uint16]bool, cfg nft.Config) (flusher, error)
	readDrops() ([]nft.Drop, error)
	converge(rules []conntrack.Rule, wgNet netip.Prefix) (int, error)
}

// flusher is a staged table replacement (nft.Staged).
type flusher interface{ Flush() error }

type realOps struct{}

func (realOps) ensureWG(cfg wg.Config) ([]string, error) { return wg.Ensure(cfg) }
func (realOps) peers(iface string) ([]dataplane.Peer, error) {
	dev, err := wg.Status(iface)
	if err != nil {
		return nil, err
	}
	var out []dataplane.Peer
	for _, p := range dev.Peers {
		// wgft のピアは AllowedIPs にエージェントの /32 を 1 つだけ持つ。それ以外の形のピアは
		// 宣言に無いので、アドレスを持たないピアとして扱い、次のトランザクションで消える。
		var addr netip.Addr
		if len(p.AllowedIPs) == 1 {
			if a, ok := netip.AddrFromSlice(p.AllowedIPs[0].IP); ok {
				addr = a.Unmap()
			}
		}
		out = append(out, dataplane.Peer{PublicKey: p.PublicKey, Address: addr})
	}
	return out, nil
}
func (realOps) stage(plan planner.Plan, relayListening map[uint16]bool, cfg nft.Config) (flusher, error) {
	return nft.Stage(plan, relayListening, cfg)
}
func (realOps) readDrops() ([]nft.Drop, error) { return nft.ReadDrops() }
func (realOps) converge(rules []conntrack.Rule, wgNet netip.Prefix) (int, error) {
	return conntrack.Converge(rules, wgNet)
}

// Backend is the kernel dataplane: kernel WireGuard, nftables DNAT and admission, and conntrack
// convergence (design.md 6.1 節). It implements dataplane.Backend.
type Backend struct {
	iface         string
	adoptExisting bool
	ops           kernelOps
	// network is the wg network the device was last converged to (e.g. 10.200.0.0/24); the
	// convergence uses it to tell "the server dialing out over wg0" apart from "a flow forwarded in
	// from outside" (design.md 6.1 節). EnsureDevice runs before the first transaction (design.md 9
	// 節 startup order), so it is set by the time a Commit converges.
	network netip.Prefix
}

var _ dataplane.Backend = (*Backend)(nil)

// New builds a Backend that converges opts.Interface.
func New(opts Options) *Backend {
	return &Backend{iface: opts.Interface, adoptExisting: opts.AdoptExisting, ops: realOps{}}
}

// wgConfig maps cfg to the wg package's declaration. A peer without a valid address (an observed
// peer whose AllowedIPs wgft did not declare) is left out, so restoring an observed peer set
// removes it instead of configuring an empty allowed IP.
func (b *Backend) wgConfig(cfg dataplane.WGConfig, keepPeers bool) wg.Config {
	peers := make([]wg.Peer, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		if !p.Address.IsValid() {
			continue
		}
		peers = append(peers, wg.Peer{PublicKey: p.PublicKey, Address: p.Address})
	}
	return wg.Config{
		Interface: b.iface, PrivateKey: cfg.PrivateKey, ListenPort: cfg.ListenPort,
		Address: cfg.Address, MTU: cfg.MTU, Peers: peers, AdoptExisting: b.adoptExisting,
		KeepPeers: keepPeers,
	}
}

// EnsureDevice converges the kernel wg interface, but not its peers, to cfg (design.md 4, 9 節).
// A refusal (someone else's interface, a port or address conflict) is returned as the
// *wg.StartupRefusal itself, so the caller can map it to its exit code.
func (b *Backend) EnsureDevice(cfg dataplane.WGConfig) ([]string, error) {
	changes, err := b.ops.ensureWG(b.wgConfig(cfg, true))
	if err != nil {
		return nil, err
	}
	b.network = cfg.Address.Masked()
	return changes, nil
}

// WGStatus reports the kernel wg interface's current peers.
func (b *Backend) WGStatus() (*wgtypes.Device, error) { return wg.Status(b.iface) }

// OtherDeviceWithKey reports another kernel WireGuard device with the same private key, if any
// (interface rename detection; not part of dataplane.Backend, vpsd calls it directly).
func (b *Backend) OtherDeviceWithKey(key wgtypes.Key) (string, bool) {
	return wg.OtherDeviceWithKey(b.iface, key)
}

// Dial connects to addr (an agent's wg address and port). Kernel mode routes it straight over wg0
// like any other kernel route, so this is a plain dial with no tunnel to go through (unlike the
// userspace Backend's Dial, which dials through its netstack).
func (b *Backend) Dial(network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(context.Background(), network, addr)
}

// Observe reads the peer set the kernel wg interface has now. The interface and its peers outlive
// the process (design.md 9 節), so after a restart this is what the previous process left.
func (b *Backend) Observe() (dataplane.Observed, error) {
	peers, err := b.ops.peers(b.iface)
	if err != nil {
		return dataplane.Observed{}, fmt.Errorf("%s: %w", b.iface, err)
	}
	return dataplane.Observed{Peers: peers}, nil
}

// Prepare adds the peers d newly declares and builds the table replacement without sending it
// (design.md 7a.2 節). The kernel backend has no rule-local failures: a Transparent rule needs no
// resource of its own beyond its rows in the one table, and a Relay rule's listener belongs to the
// frontend. Any error is backend-wide, and nothing stays changed when it is returned.
func (b *Backend) Prepare(d dataplane.Desired) (dataplane.Prepared, error) {
	p := &prepared{b: b, desired: d, peersChanged: d.PeersChanged()}
	if p.peersChanged {
		changes, err := b.ops.ensureWG(b.wgConfig(d.WG.WithPeers(dataplane.PeerUnion(d.WG.Peers, d.ActivePeers)), false))
		if err != nil {
			b.restorePeers(d)
			return nil, fmt.Errorf("%s: %w", b.iface, err)
		}
		p.wgChanges = changes
	}
	staged, err := b.ops.stage(d.Plan, d.RelayListening, nft.Config{WGInterface: b.iface})
	if err != nil {
		if p.peersChanged {
			b.restorePeers(d)
		}
		return nil, err
	}
	p.staged = staged
	return p, nil
}

// restorePeers puts the peer set back to d.ActivePeers after a failed Prepare or Commit. It runs
// before the point of no return, so the device must end up as it was; an error can only be
// logged by the caller's next transaction, which converges the peers again.
func (b *Backend) restorePeers(d dataplane.Desired) {
	_, _ = b.ops.ensureWG(b.wgConfig(d.WG.WithPeers(d.ActivePeers), false))
}

type prepared struct {
	b            *Backend
	desired      dataplane.Desired
	peersChanged bool
	wgChanges    []string
	staged       flusher
	done         bool
}

// Failed is always empty: see Prepare.
func (p *prepared) Failed() map[string]error { return nil }

// Commit reads the drop counters of the current table, replaces the table in one nftables
// transaction, and then removes the peers the declaration dropped and converges conntrack
// (design.md 6.1, 7a.3 節). On a failed replacement nothing is published, the counters are not
// handed out (the old table still holds them) and the Runtime rolls back.
func (p *prepared) Commit(retiring []dataplane.Retiring) (dataplane.Committed, error) {
	b, d := p.b, p.desired
	drops, dropsErr := b.ops.readDrops()
	if err := p.staged.Flush(); err != nil {
		return dataplane.Committed{}, err
	}
	p.done = true
	c := dataplane.Committed{WGChanges: p.wgChanges}
	if dropsErr != nil {
		c.Errors = append(c.Errors, fmt.Errorf("reading drop counters: %w", dropsErr))
	} else {
		for _, dr := range drops {
			c.Drops = append(c.Drops, dataplane.Drop{RuleID: dr.RuleID, Kind: dr.Kind, Packets: dr.Packets, Bytes: dr.Bytes})
		}
	}
	if p.peersChanged {
		changes, err := b.ops.ensureWG(b.wgConfig(*d.WG, false))
		if err != nil {
			c.Errors = append(c.Errors, fmt.Errorf("%s: removing peers: %w", b.iface, err))
		}
		c.WGChanges = append(c.WGChanges, changes...)
	}
	if d.WG != nil {
		b.network = d.WG.Address.Masked()
	}
	// conntrack の収束は必ずテーブルの差し替えの後に走らせる(仕様 6.1 節)。先に走らせると、
	// 旧テーブルで許可されたフローが差し替えまでの間に入る
	n, err := b.ops.converge(ConvergeRules(d.Plan, retiring), b.network)
	if err != nil {
		c.Errors = append(c.Errors, fmt.Errorf("conntrack converge: %w", err))
	}
	c.Closed = n
	return c, nil
}

// Rollback discards the unsent table replacement and restores the peer set Prepare changed.
func (p *prepared) Rollback() {
	if p.done {
		return
	}
	p.done = true
	if p.peersChanged {
		p.b.restorePeers(p.desired)
	}
}

// ConvergeRules is what the conntrack convergence judges established DNAT flows against: the
// Transparent ports of the published Plan, plus the previous Active value of every retiring
// Transparent rule, so a fail-closed rule's safe established flows are kept (design.md 7a.3 節).
// A retiring rule's flow is kept only while both its previous value and its new declaration admit
// the source.
func ConvergeRules(plan planner.Plan, retiring []dataplane.Retiring) []conntrack.Rule {
	rules := conntrack.RulesFromPlan(plan)
	for _, r := range retiring {
		pp := r.Previous
		if pp.Forwarding != model.Transparent {
			continue
		}
		rules = append(rules, conntrack.Rule{Proto: pp.Proto, ListenPort: pp.ListenPort, AgentAddr: pp.AgentAddr,
			Keep: r.SourceAllowed})
	}
	return rules
}
