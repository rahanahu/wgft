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
// Backend's Prepare stages nothing: nft.Apply's build-then-Flush is one atomic kernel operation
// (design.md 7a.2 節), so there is nothing reversible to separate out yet, and Commit alone already
// gives the "nothing is published on failure" guarantee the Prepared contract asks for. Everything
// beyond the participant (EnsureWG, Converge, ReadDrops, Dial) is called by the control plane
// around the Runtime, exactly where the pre-Backend vpsd code called it (design.md 7a.2 節); Phase 4
// folds these into the transaction.
package linuxkernel

import (
	"context"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/conntrack"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
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

// Backend is the kernel dataplane: kernel WireGuard, nftables DNAT and admission, and conntrack
// convergence (design.md 6.1 節). It implements dataplane.Backend.
type Backend struct {
	iface         string
	adoptExisting bool
	// network is the wg network EnsureWG last converged to (e.g. 10.200.0.0/24); Converge uses it
	// to tell "the server dialing out over wg0" apart from "a flow forwarded in from outside"
	// (design.md 6.1 節). EnsureWG always runs before Converge (design.md 9 節 startup order), so it
	// is set by the time Converge is first called.
	network netip.Prefix
}

var _ dataplane.Backend = (*Backend)(nil)

// New builds a Backend that converges opts.Interface.
func New(opts Options) *Backend {
	return &Backend{iface: opts.Interface, adoptExisting: opts.AdoptExisting}
}

// EnsureWG converges the kernel wg interface to cfg (design.md 4, 9 節).
func (b *Backend) EnsureWG(cfg dataplane.WGConfig) ([]string, error) {
	peers := make([]wg.Peer, len(cfg.Peers))
	for i, p := range cfg.Peers {
		peers[i] = wg.Peer{PublicKey: p.PublicKey, Address: p.Address}
	}
	changes, err := wg.Ensure(wg.Config{
		Interface: b.iface, PrivateKey: cfg.PrivateKey, ListenPort: cfg.ListenPort,
		Address: cfg.Address, MTU: cfg.MTU, Peers: peers, AdoptExisting: b.adoptExisting,
	})
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

// ReadDrops reads table inet wgft's per-rule drop counters. They are reset by the next successful
// table replacement (nft.Apply, called from Commit); if that replacement fails, the next ReadDrops
// returns the same counts again (design.md 6.1 節).
func (b *Backend) ReadDrops() ([]dataplane.Drop, error) {
	drops, err := nft.ReadDrops()
	if err != nil {
		return nil, err
	}
	out := make([]dataplane.Drop, len(drops))
	for i, d := range drops {
		out[i] = dataplane.Drop{RuleID: d.RuleID, Kind: d.Kind, Packets: d.Packets, Bytes: d.Bytes}
	}
	return out, nil
}

// Converge closes conntrack flows the committed Plan no longer admits (design.md 6.1 節). It runs
// after the Runtime's Commit (the nftables table has already been replaced).
func (b *Backend) Converge(plan planner.Plan) (int, error) {
	return conntrack.Converge(conntrack.RulesFromPlan(plan), b.network)
}

// Dial connects to addr (an agent's wg address and port). Kernel mode routes it straight over wg0
// like any other kernel route, so this is a plain dial with no tunnel to go through (unlike the
// userspace Backend's Dial, which dials through its netstack).
func (b *Backend) Dial(network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(context.Background(), network, addr)
}

// Prepare stages d without publishing it. nft.Apply's build and Flush happen together as one
// atomic kernel operation in Commit, so there is nothing to stage here yet (design.md 7a.2 節);
// moving the build into Prepare is Phase 4's job.
func (b *Backend) Prepare(d dataplane.Desired) (dataplane.Prepared, error) {
	return &prepared{b: b, desired: d}, nil
}

type prepared struct {
	b       *Backend
	desired dataplane.Desired
}

// Commit builds and replaces table inet wgft in one nftables transaction (design.md 6.1, 7a.2 節).
// On error nothing of it is published and the previous table keeps forwarding.
func (p *prepared) Commit() error {
	return nft.Apply(p.desired.Plan, p.desired.RelayListening, nft.Config{WGInterface: p.b.iface})
}

// Rollback releases nothing: Prepare staged nothing but the Desired it kept.
func (p *prepared) Rollback() {}
