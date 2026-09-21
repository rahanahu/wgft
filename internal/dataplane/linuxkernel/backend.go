//go:build linux

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
	// inspect and fingerprint read the wg interface and table inet wgft back without changing
	// them (Observe after the first Commit).
	inspect(iface string) (wg.DeviceState, error)
	fingerprint() (fp string, present bool, err error)
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
func (realOps) inspect(iface string) (wg.DeviceState, error) { return wg.Inspect(iface) }
func (realOps) fingerprint() (string, bool, error)           { return nft.Fingerprint() }

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
	// last is what the last successful Commit left in the kernel; nil before the first. Observe
	// compares the actual state with it (design.md 7a.3 節: 実際の状態への収束). The Reconciler
	// serializes Observe, Prepare and Commit, so it needs no lock of its own.
	last *committed
	// pending holds the repairs the last Commit or Repair left failed (design.md 7a.3 節: 戻れない
	// 地点の後の修復). A new Commit reruns every step, so it starts over.
	pending repairs
}

// committed is what one successful Commit left in the kernel.
type committed struct {
	// wg is the WireGuard declaration the device was converged to; nil when the Commit had none.
	wg *dataplane.WGConfig
	// table is nft.Fingerprint read right after the publication. Empty means unknown (the read-back
	// failed): Observe then reports drift, so the next transaction republishes and reads it back.
	table string
}

// repairs are the steps after the point of no return that failed and a retry can rerun.
type repairs struct {
	// peers is the declaration whose peer removal failed; nil when none is pending.
	peers *dataplane.WGConfig
	// converge is set when the conntrack convergence failed; rules is what it judges against.
	converge bool
	rules    []conntrack.Rule
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
// the process (design.md 9 節), so before the first Commit this is what the previous process left.
//
// After a Commit it also compares the kernel with what that Commit left (design.md 7a.3 節: 実際の
// 状態への収束): table inet wgft must exist with the same nft.Fingerprint, and the wg interface
// must exist with the committed key, listen port, address, up flag and peers. What differs is
// reported in Observed.Drift. An interface of that name that wgft does not own (another link
// type, or a WireGuard device with another private key) is an error, not drift: the next
// transaction would converge it, and it is someone else's (design.md 9 節: 所有判定).
func (b *Backend) Observe() (dataplane.Observed, error) {
	if b.last == nil {
		peers, err := b.ops.peers(b.iface)
		if err != nil {
			return dataplane.Observed{}, fmt.Errorf("%s: %w", b.iface, err)
		}
		return dataplane.Observed{Peers: peers}, nil
	}
	dev, err := b.ops.inspect(b.iface)
	if err != nil {
		return dataplane.Observed{}, fmt.Errorf("%s: %w", b.iface, err)
	}
	fp, present, err := b.ops.fingerprint()
	if err != nil {
		return dataplane.Observed{}, fmt.Errorf("table inet %s: %w", nft.TableName, err)
	}
	drift, err := driftOf(b.iface, *b.last, dev, fp, present, b.pending.peers != nil)
	if err != nil {
		return dataplane.Observed{}, err
	}
	return dataplane.Observed{Peers: devicePeers(dev), Drift: drift}, nil
}

// driftOf compares what Observe read with what the last Commit left. While a peer removal is a
// pending repair (peersPending), a peer set that differs from the declaration is that known repair,
// not drift: Repair converges the peers to the whole declaration (fixing a peer someone else changed
// too) without replacing the table, whereas drift would republish it and reset its meters and ct
// count sets on every retry (design.md 7a.3 節: 戻れない地点の後の修復). Every other difference is
// still drift.
func driftOf(iface string, last committed, dev wg.DeviceState, fp string, present, peersPending bool) ([]string, error) {
	var drift []string
	switch {
	case !present:
		drift = append(drift, fmt.Sprintf("table inet %s is missing", nft.TableName))
	case last.table == "":
		// 基準が分からない(直前の読み直しが失敗した)。一致とはみなさず、公開し直して読み直す
		drift = append(drift, fmt.Sprintf("table inet %s was not read back after the last publication", nft.TableName))
	case fp != last.table:
		drift = append(drift, fmt.Sprintf("table inet %s was changed", nft.TableName))
	}
	if last.wg == nil {
		return drift, nil
	}
	w := last.wg
	switch {
	case !dev.Exists:
		return append(drift, fmt.Sprintf("interface %s is missing", iface)), nil
	case dev.Kind != "wireguard":
		return nil, fmt.Errorf("%s is now a %s link, not the WireGuard interface wgft created; leaving it alone", iface, dev.Kind)
	case dev.PrivateKey != w.PrivateKey:
		return nil, fmt.Errorf("%s is now a WireGuard interface wgft does not own (its private key does not match); leaving it alone", iface)
	}
	if dev.ListenPort != w.ListenPort {
		drift = append(drift, fmt.Sprintf("%s listen port is %d, not %d", iface, dev.ListenPort, w.ListenPort))
	}
	if len(dev.Addresses) != 1 || dev.Addresses[0] != w.Address {
		drift = append(drift, fmt.Sprintf("%s addresses are %v, not [%s]", iface, dev.Addresses, w.Address))
	}
	if !dev.Up {
		drift = append(drift, fmt.Sprintf("%s is down", iface))
	}
	want := declaredPeers(w.Peers)
	if have := devicePeers(dev); !peersPending && !dataplane.PeersEqual(have, want) {
		drift = append(drift, fmt.Sprintf("%s has %d peers that differ from the %d declared", iface, len(have), len(want)))
	}
	return drift, nil
}

// devicePeers maps the peers Inspect read to dataplane peers.
func devicePeers(dev wg.DeviceState) []dataplane.Peer {
	out := make([]dataplane.Peer, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		out = append(out, dataplane.Peer{PublicKey: p.PublicKey, Address: p.Address})
	}
	return out
}

// declaredPeers is the peer set the wg package configures for peers: the ones with a valid
// address (wgConfig leaves the others out).
func declaredPeers(peers []dataplane.Peer) []dataplane.Peer {
	out := make([]dataplane.Peer, 0, len(peers))
	for _, p := range peers {
		if p.Address.IsValid() {
			out = append(out, p)
		}
	}
	return out
}

// Prepare adds the peers d newly declares and builds the table replacement without sending it
// (design.md 7a.2 節). The kernel backend has no rule-local failures: a Transparent rule needs no
// resource of its own beyond its rows in the one table, and a Relay rule's listener belongs to the
// frontend. Any error is backend-wide, and nothing stays changed when it is returned.
//
// When d.Resync is set (Observe found drift), the device is converged as a whole, the way the peer
// changes converge it: created if it is gone, and its key, listen port, address, MTU and peers set
// back to d.WG (design.md 7a.3 節: 実際の状態への収束).
func (b *Backend) Prepare(d dataplane.Desired) (dataplane.Prepared, error) {
	p := &prepared{b: b, desired: d, peersChanged: d.WG != nil && (d.PeersChanged() || d.Resync)}
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
	b       *Backend
	desired dataplane.Desired
	// peersChanged is set when Prepare converged the device (a peer change, or a resync) and
	// Commit must converge it to the declaration after the publication.
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
	// この Commit が修復の手順をすべて含むので、残っていた修復はここで数え直す。ピアの削除が残って
	// いれば、ピアの集合が変わらなくても公開の後で宣言に収束させる(公開の前の Prepare では触らない。
	// 失敗しても、この公開を妨げないため)
	peersPending := b.pending.peers != nil
	b.pending = repairs{}
	if d.WG != nil && (p.peersChanged || peersPending) {
		w := d.WG.WithPeers(append([]dataplane.Peer(nil), d.WG.Peers...))
		b.pending.peers = &w
	}
	if d.WG != nil {
		b.network = d.WG.Address.Masked()
	}
	// conntrack の収束は必ずテーブルの差し替えの後に走らせる(仕様 6.1 節)。先に走らせると、
	// 旧テーブルで許可されたフローが差し替えまでの間に入る
	b.pending.converge, b.pending.rules = true, ConvergeRules(d.Plan, retiring)
	b.runRepairs(&c)
	b.last = b.readBack(d, &c)
	c.RepairPending = b.repairPending()
	return c, nil
}

// runRepairs runs the pending repairs (the peer removal, then the conntrack convergence) and
// keeps pending only the ones that failed.
func (b *Backend) runRepairs(c *dataplane.Committed) {
	if w := b.pending.peers; w != nil {
		changes, err := b.ops.ensureWG(b.wgConfig(*w, false))
		c.WGChanges = append(c.WGChanges, changes...)
		if err != nil {
			c.Errors = append(c.Errors, fmt.Errorf("%s: removing peers: %w", b.iface, err))
		} else {
			b.pending.peers = nil
		}
	}
	if b.pending.converge {
		n, err := b.ops.converge(b.pending.rules, b.network)
		c.Closed += n
		if err != nil {
			c.Errors = append(c.Errors, fmt.Errorf("conntrack converge: %w", err))
		} else {
			b.pending.converge, b.pending.rules = false, nil
		}
	}
}

// repairPending reports whether a repair is still pending, the unknown read-back included.
func (b *Backend) repairPending() bool {
	return b.pending.peers != nil || b.pending.converge || (b.last != nil && b.last.table == "")
}

// Repair reruns the peer removal and the conntrack convergence the last Commit or Repair left
// failed, without replacing the table (design.md 7a.3 節: 戻れない地点の後の修復). An unknown
// read-back stays pending: Observe reports it as drift, and the resulting republication reads the
// table back.
func (b *Backend) Repair() dataplane.Committed {
	var c dataplane.Committed
	b.runRepairs(&c)
	c.RepairPending = b.repairPending()
	return c
}

// readBack records what a successful Commit left, for Observe to compare the kernel with.
func (b *Backend) readBack(d dataplane.Desired, c *dataplane.Committed) *committed {
	last := &committed{}
	if b.last != nil {
		last.wg = b.last.wg
	}
	if d.WG != nil {
		w := d.WG.WithPeers(append([]dataplane.Peer(nil), d.WG.Peers...))
		last.wg = &w
	}
	fp, present, err := b.ops.fingerprint()
	switch {
	case err != nil:
		c.Errors = append(c.Errors, fmt.Errorf("reading back table inet %s: %w", nft.TableName, err))
	case !present:
		c.Errors = append(c.Errors, fmt.Errorf("reading back table inet %s: the table is missing right after its publication", nft.TableName))
	default:
		last.table = fp
	}
	return last
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
