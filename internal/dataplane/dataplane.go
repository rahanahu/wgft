// Package dataplane defines the dataplane Backend contract (design.md 7a.2, 7a.7 節): what a
// DataplaneMode's forwarding implementation (userspace and the Linux kernel) offers to the control
// plane, and the dataplane participant the Runtime in internal/reconcile drives.
//
// This package holds only types, interfaces and small pure helpers. Implementations live in
// subpackages (internal/dataplane/userspace, internal/dataplane/linuxkernel) and never import each
// other, internal/vpsd or internal/agent (design.md 7a.7 節; deps_test.go checks this).
//
// A Backend receives what it converges to from the Plan (internal/planner) plus runtime inputs
// that only exist once the frontend has prepared, such as the set of Relay ports actually
// listening (Desired). It never reads configuration or rule sets through a side channel.
package dataplane

import (
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/policy"
)

// Desired is what the Runtime hands a dataplane's Prepare (design.md 7a.2 節, steps 1 and 2 of the
// fixed order): the Plan, the frontend's Prepare result, and the WireGuard declaration.
type Desired struct {
	// Plan is what to publish. Rules the frontend could not prepare are already left out of it
	// (planner.Plan.Without), so the dataplane publishes no dispatch for them (design.md 7a.3 節:
	// fail-closed).
	Plan planner.Plan
	// RelayListening is the set of Relay ports the frontend will be listening on once it commits:
	// the listeners it keeps plus the ones its Prepare newly opened. Ports being removed and ports
	// that failed to bind are not in it (design.md 6.1, 7a.4 節: ingress rows only for ports wgft
	// actually listens on). nil when the Runtime has no frontend.
	RelayListening map[uint16]bool
	// WG is the WireGuard declaration, its peer set included. nil leaves the device and its peers
	// untouched.
	WG *WGConfig
	// ActivePeers is the peer set the device has now: what the last successful Commit left, or
	// what Observe found before the first one. When WG.Peers differs from it, Prepare adds the new
	// peers before anything is published, Commit removes the peers WG no longer declares after the
	// publication, and Rollback restores this set (design.md 7a.3 節: WireGuard のピアは、公開の
	// 前に足し、公開をやめた後に消す).
	ActivePeers []Peer
}

// PeersChanged reports whether d asks for a different peer set than the device has now.
func (d Desired) PeersChanged() bool {
	return d.WG != nil && !PeersEqual(d.WG.Peers, d.ActivePeers)
}

// Observed is what Observe reads back from the dataplane itself, independent of what this process
// has committed so far (design.md 7a.3 節: 再起動時の Observe).
type Observed struct {
	// Peers is the WireGuard peer set the device has now.
	Peers []Peer
}

// Retiring is a rule made fail-closed (design.md 7a.3 節): its replacement could not be prepared,
// so it accepts no new flows, while the flows established through its previous Active value stay
// as long as they are safe.
type Retiring struct {
	// Previous is the rule's last Active value. Established flows are judged against it, not
	// against the new value, which was never published.
	Previous planner.PortPlan
	// Desired is the rule's source policy in the new declaration. A flow it no longer admits (a new
	// source_deny, for example) is not safe and is closed.
	Desired policy.RulePolicy
}

// SourceAllowed reports whether an established flow from src through the retiring rule is safe to
// keep: both its previous Active value and its new declaration admit the source.
func (r Retiring) SourceAllowed(src netip.Addr) bool {
	return r.Previous.Policy.SourceAllowed(src) && r.Desired.SourceAllowed(src)
}

// RetiringByRule indexes retiring by rule ID.
func RetiringByRule(retiring []Retiring) map[string]Retiring {
	out := make(map[string]Retiring, len(retiring))
	for _, r := range retiring {
		out[r.Previous.RuleID] = r
	}
	return out
}

// Participant is the dataplane side of the Runtime's fixed order (design.md 7a.2 節). Every
// Backend is one; internal/reconcile depends only on this narrow interface.
type Participant interface {
	// Observe reads what the dataplane has now. The Reconciler calls it once, before its first
	// transaction, since a restarted process does not know what the previous one left behind
	// (design.md 7a.3 節).
	Observe() (Observed, error)
	// Prepare stages d without publishing it. Everything that can fail belongs here (design.md 7a.2
	// 節): binding listeners, building the nftables transaction, adding WireGuard peers. An error is
	// a backend-wide failure (design.md 7a.3 節): nothing stays staged and the Runtime rolls back
	// the frontend. A failure confined to one rule (a listener that cannot bind) is not an error:
	// the rule is reported by Prepared.Failed and left out of what Commit publishes.
	Prepare(d Desired) (Prepared, error)
}

// Prepared is one staged dataplane change, finished by exactly one of Commit or Rollback.
type Prepared interface {
	// Failed returns the rules whose own Prepare failed, with the reason (design.md 7a.3 節). They
	// are not staged: Commit publishes no dispatch for them.
	Failed() map[string]error
	// Commit publishes the staged change as one atomic step (for the kernel backend, one nftables
	// transaction). On error nothing of it is published, the previous state keeps forwarding and
	// the Runtime rolls back. Success is the point of no return (design.md 7a.2 節).
	//
	// Around the publication, Commit also does what belongs to the same transaction: it reads the
	// drop counters of the state it replaces (returned only on success, so a failed publication
	// cannot hand the same counts out twice), removes the WireGuard peers the declaration dropped,
	// and closes the established flows the published Plan no longer admits (design.md 6.1, 6.3 節).
	// The flows of each retiring rule are judged against its Retiring value instead (design.md 7a.3
	// 節). These steps run after the point of no return, so they cannot fail the Commit; their
	// errors are returned in Committed.Errors.
	Commit(retiring []Retiring) (Committed, error)
	// Rollback releases what Prepare staged and restores the peer set it changed. It is called when
	// Commit was not reached or failed, never after a successful Commit, and cannot fail.
	Rollback()
}

// Committed is what a successful Commit reports back.
type Committed struct {
	// Drops are the drop counters of the replaced state, one entry per rule and kind, for the
	// control plane to accumulate.
	Drops []Drop
	// WGChanges are the WireGuard changes Prepare and Commit made, one line each, for the log.
	WGChanges []string
	// Closed is how many established flows the convergence after the publication closed.
	Closed int
	// Errors are the failures after the point of no return (reading the drop counters, removing
	// peers, convergence). They are logged; the next transaction retries what they left behind.
	Errors []error
}

// Backend is one DataplaneMode's dataplane (design.md 7a.2 節: "Backend は kernel と userspace の
// 2 つを持ち、それぞれが OS、nftables、netstack などの実装詳細を隠す").
//
// Beyond the participant, it brings the WireGuard device up at startup and exposes what the
// control plane reads back. Peer changes, drop counters and the convergence after a publication
// belong to the participant's transaction (Prepared.Commit), not to separate calls.
type Backend interface {
	Participant
	// EnsureDevice brings the WireGuard device up and converges everything but its peers (key,
	// listen port, address, MTU) to cfg, returning the changes it made, one line each, for the log.
	// It runs once at startup, before the first transaction. cfg.Peers is not applied (the kernel
	// backend only shows it in the dry run of a refusal); the peers are converged by the
	// transactions (Desired.WG).
	EnsureDevice(cfg WGConfig) ([]string, error)
	// WGStatus returns the device and its peers (endpoint, last handshake, counters).
	WGStatus() (*wgtypes.Device, error)
	// Dial connects to addr (an agent's wg address and port) through the tunnel.
	Dial(network, addr string) (net.Conn, error)
}

// WGConfig is the WireGuard declaration a Backend converges to (design.md 4, 9 節). How the device
// is named and whether a foreign device may be adopted are properties of the kernel backend, given
// when it is constructed, not part of the declaration.
type WGConfig struct {
	PrivateKey wgtypes.Key
	ListenPort int
	Address    netip.Prefix // the server's address and the wg network, e.g. 10.200.0.1/24
	MTU        int
	Peers      []Peer
}

// WithPeers returns a copy of c declaring peers instead of c.Peers.
func (c WGConfig) WithPeers(peers []Peer) WGConfig {
	c.Peers = peers
	return c
}

// Peer is one agent's WireGuard peer: its declared public key and its address on the wg network.
type Peer struct {
	PublicKey wgtypes.Key
	Address   netip.Addr
}

// PeersEqual reports whether a and b declare the same peers (public key and address), in any
// order.
func PeersEqual(a, b []Peer) bool {
	am := make(map[wgtypes.Key]netip.Addr, len(a))
	for _, p := range a {
		am[p.PublicKey] = p.Address
	}
	bm := make(map[wgtypes.Key]netip.Addr, len(b))
	for _, p := range b {
		bm[p.PublicKey] = p.Address
	}
	if len(am) != len(bm) {
		return false
	}
	for k, addr := range am {
		if other, ok := bm[k]; !ok || other != addr {
			return false
		}
	}
	return true
}

// PeerUnion returns the peers of want plus the peers of have whose key want does not declare: the
// set a Prepare installs before the publication, so that no peer an old dispatch still routes to
// disappears before the new dispatch is published. A key in both keeps want's address. A peer of
// have whose address want gives to another key (an agent that rotated its key, or an address
// reused after a revoke) is left out: one address routes to one peer only, and it is the declared
// one.
func PeerUnion(want, have []Peer) []Peer {
	out := append([]Peer(nil), want...)
	seen := make(map[wgtypes.Key]bool, len(want)+len(have))
	claimed := make(map[netip.Addr]bool, len(want))
	for _, p := range want {
		seen[p.PublicKey] = true
		claimed[p.Address] = true
	}
	for _, p := range have {
		if !seen[p.PublicKey] && !claimed[p.Address] {
			out = append(out, p)
			seen[p.PublicKey] = true
		}
	}
	return out
}

// Drop is one rule's drop counter for one kind of admission step (design.md 6.1 節).
type Drop struct {
	RuleID  string
	Kind    string // deny | allow | per_source | src_flow | new_flow | packet
	Packets uint64
	Bytes   uint64
}
