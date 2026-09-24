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
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

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
	// Resync is set when an Observe found that the state the last Commit left has drifted
	// (Observed.Drift). Prepare then converges the whole WireGuard device to WG (creating it if it is
	// gone, and its key, listen port, address, MTU and peers), not only the peer changes (design.md
	// 7a.3 節: 実際の状態への収束).
	Resync bool
}

// PeersChanged reports whether d asks for a different peer set than the device has now.
func (d Desired) PeersChanged() bool {
	return d.WG != nil && !PeersEqual(d.WG.Peers, d.ActivePeers)
}

// Observed is what Observe reads back from the dataplane itself, independent of what this process
// has committed so far (design.md 7a.3 節: 再起動時の Observe、実際の状態への収束).
type Observed struct {
	// Peers is the WireGuard peer set the device has now (none when the device is gone).
	Peers []Peer
	// Drift lists, one short phrase each, what of the state the last successful Commit left the
	// dataplane no longer has as committed: for the kernel backend, table inet wgft missing or
	// changed, the wg interface missing, or its key, listen port, address, up state or peers
	// changed. Empty before the first Commit, when nothing drifted, and always for a dataplane
	// whose state lives only inside the process (userspace).
	Drift []string
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

// Participant is the dataplane side of the Runtime's fixed order (design.md 7a.2 節). Every
// Backend is one; internal/reconcile depends only on this narrow interface.
type Participant interface {
	// Observe reads what the dataplane has now. The Reconciler calls it before its first
	// transaction, since a restarted process does not know what the previous one left behind, and
	// afterwards whenever the control plane checks the actual state against what was committed
	// (design.md 7a.3 節: 実際の状態への収束). It must be cheap (a few netlink reads) and must not
	// change anything. An error means the state could not be read, or that a resource wgft
	// converges is now held by someone else and must be left alone (design.md 9 節: 所有判定).
	Observe() (Observed, error)
	// Prepare stages d without publishing it. Everything that can fail belongs here (design.md 7a.2
	// 節): binding listeners, building the nftables transaction, adding WireGuard peers. An error is
	// a backend-wide failure (design.md 7a.3 節): nothing stays staged and the Runtime rolls back
	// the frontend. A failure confined to one rule (a listener that cannot bind) is not an error:
	// the rule is reported by Prepared.Failed and left out of what Commit publishes.
	Prepare(d Desired) (Prepared, error)
	// Repair reruns the repairs the last Commit (or Repair) left failed, without publishing
	// anything again: for the kernel backend, removing peers and the conntrack convergence, so the
	// nftables table is not replaced and its meters and ct count sets are kept (design.md 7a.3 節:
	// 戻れない地点の後の修復). A failed read-back of the published table is not repaired here: the
	// next Observe reports it as drift, which republishes. RepairPending in the result stays set
	// while anything is still pending. It does nothing when nothing is pending.
	Repair() Committed
}

// Sensor is implemented by a Backend whose state something outside wgft can change (the kernel
// backend: nftables and the wg interface). It only wakes the control plane: the control plane
// then Observes the actual state and converges if it differs. What a notification says is never
// acted on (design.md 7a.3 節: 実際の状態への収束).
type Sensor interface {
	// Watch subscribes to the kernel's change notifications and calls wake after each one, until
	// ctx is done (then it returns nil) or the subscription fails (then it returns the error, having
	// called wake once more, since a failure such as a receive buffer overflow can lose
	// notifications). wake must not block. The caller restarts Watch after a failure.
	Watch(ctx context.Context, wake func()) error
}

// Prepared is one staged dataplane change, finished by exactly one of Commit or Rollback.
type Prepared interface {
	// Failed returns the rules whose own Prepare failed, with the reason (design.md 7a.3 節). They
	// are not staged: Commit publishes no dispatch for them.
	Failed() map[string]error
	// Commit publishes the staged change as one atomic step (for the kernel backend, one nftables
	// transaction). On error the commit did not succeed; which state the kernel is still forwarding
	// depends on where it failed and cannot be told from here (design.md 11b 節: 転送 の項). The
	// Runtime rolls back regardless. Success is the point of no return (design.md 7a.2 節).
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
	// peers, convergence, reading back what was published). They are logged.
	Errors []error
	// RepairPending is set while a step after the point of no return failed in a way that a retry
	// can repair (design.md 7a.3 節: 戻れない地点の後の修復): removing the peers the declaration
	// dropped, the convergence of established flows, or reading back what was published. The
	// Reconciler then asks for a retry, which runs Participant.Repair even when it would publish
	// the same again. A failure to read the drop counters is not a repair: the replaced state is
	// gone and its counters cannot be read any more.
	RepairPending bool
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
// one. A peer of have without a valid address (one Observe found with an AllowedIPs set wgft does
// not declare) is left out too: it is not a peer an old dispatch routes to.
func PeerUnion(want, have []Peer) []Peer {
	out := append([]Peer(nil), want...)
	seen := make(map[wgtypes.Key]bool, len(want)+len(have))
	claimed := make(map[netip.Addr]bool, len(want))
	for _, p := range want {
		seen[p.PublicKey] = true
		claimed[p.Address] = true
	}
	for _, p := range have {
		if !seen[p.PublicKey] && !claimed[p.Address] && p.Address.IsValid() {
			out = append(out, p)
			seen[p.PublicKey] = true
		}
	}
	return out
}

// HeldPeer is one peer a WireGuard device has now, as InheritedEndpoint reads it: its key, the
// address its AllowedIPs route to it (invalid unless they are exactly one /32) and the endpoint
// WireGuard last saw it at (invalid when it has none).
type HeldPeer struct {
	PublicKey wgtypes.Key
	Address   netip.Addr
	Endpoint  netip.AddrPort
}

// InheritedEndpoint returns the endpoint a peer being added for key at addr takes over, and the
// key of the peer it takes it from: the endpoint of the peer of have that holds addr under another
// key. That is an agent that rotated its key (design.md 5.2 節). The new peer has no endpoint of its
// own until a handshake under the new key arrives, and the agent's first handshake under it leaves
// before the server has the new peer and is dropped, so without the old endpoint the tunnel waited
// for the agent's retry after WireGuard's REKEY_TIMEOUT. With it, the server starts the handshake
// itself as soon as it has a packet for the agent. ok is false when no peer of have holds addr
// under another key, or when that peer has no endpoint. WireGuard routes an address to one peer
// only, so at most one peer of a device's own list holds addr.
func InheritedEndpoint(have []HeldPeer, key wgtypes.Key, addr netip.Addr) (endpoint netip.AddrPort, from wgtypes.Key, ok bool) {
	if !addr.IsValid() {
		return netip.AddrPort{}, wgtypes.Key{}, false
	}
	for _, p := range have {
		if p.PublicKey != key && p.Address == addr && p.Endpoint.IsValid() {
			return p.Endpoint, p.PublicKey, true
		}
	}
	return netip.AddrPort{}, wgtypes.Key{}, false
}

// Drop is one rule's drop counter for one kind of admission step (design.md 6.1 節).
type Drop struct {
	RuleID  string
	Kind    string // deny | allow | per_source | src_flow | new_flow | packet
	Packets uint64
	Bytes   uint64
}

// UDPReply is what a Backend has seen of one UDP rule's replies: the datagrams its target sent
// back through the tunnel to this server (design.md 10.2a 節「UDP の応答の観測」). It is a passive
// observation kept in memory only, and it never decides a status.
type UDPReply struct {
	// Since is when the Backend began watching this rule without a gap: the rule's first
	// publication in this process, the publication after its identity changed (UDPReplyIdentity), or
	// the first reading after the watch was interrupted. Zero while Err is set.
	Since time.Time
	// Last is the last time a reply was seen, not before Since. Zero when none was seen since.
	Last time.Time
	// Err is set while the Backend cannot observe the rule's replies (the kernel backend could not
	// read its reply counters, for example). It is not "no reply": nothing is known either way.
	Err error
}

// UDPReplyObserver is implemented by a Backend that observes the replies of its UDP rules
// (design.md 10.2a 節「UDP の応答の観測」).
type UDPReplyObserver interface {
	// UDPReplies returns one entry per UDP rule the Backend publishes now, by rule ID. A rule it does
	// not publish (disabled, failed, or of an unregistered agent) has no entry.
	UDPReplies() map[string]UDPReply
}

// UDPReplyIdentity is what a UDP rule's reply observation belongs to, besides its rule ID: the
// agent it forwards to, that agent's address, the target and the public ports. When any of them
// changes, the replies come from somewhere else, so a Backend discards the observation and starts
// watching over (design.md 10.2a 節「UDP の応答の観測」).
func UDPReplyIdentity(pp planner.PortPlan) string {
	return fmt.Sprintf("%s|%s|%s|%s", pp.Agent, pp.AgentAddr, pp.Target, pp.ListenPort)
}
