// Package dataplane defines the dataplane Backend contract (design.md 7a.2, 7a.7 節): what a
// DataplaneMode's forwarding implementation (userspace today, the Linux kernel from Phase 3) offers
// to the control plane, and the dataplane participant the Runtime in internal/reconcile drives.
//
// This package holds only types and interfaces. Implementations live in subpackages
// (internal/dataplane/userspace; internal/dataplane/linuxkernel from Phase 3) and never import each
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
)

// Desired is what the Runtime hands a dataplane's Prepare (design.md 7a.2 節, steps 1 and 2 of the
// fixed order): the Plan, and the frontend's Prepare result.
type Desired struct {
	Plan planner.Plan
	// RelayListening is the set of Relay ports the frontend will be listening on once it commits:
	// the listeners it keeps plus the ones its Prepare newly opened. Ports being removed and ports
	// that failed to bind are not in it (design.md 6.1, 7a.4 節: ingress rows only for ports wgft
	// actually listens on). nil when the Runtime has no frontend.
	RelayListening map[uint16]bool
}

// Participant is the dataplane side of the Runtime's fixed order (design.md 7a.2 節). Every
// Backend is one; internal/reconcile depends only on this narrow interface.
type Participant interface {
	// Prepare stages d without publishing it. The contract of design.md 7a.2 節 is that everything
	// that can fail belongs here; the kernel backend meets it, the userspace backend does not yet
	// (see Prepared.Commit). An error means nothing was staged and the caller rolls back the
	// frontend.
	Prepare(d Desired) (Prepared, error)
}

// Prepared is one staged dataplane change, finished by exactly one of Commit or Rollback.
type Prepared interface {
	// Commit publishes the staged change. Success is the point of no return (design.md 7a.2 節).
	// The kernel backend publishes as one atomic step (one nftables transaction): on error nothing
	// of it is published and the previous state keeps forwarding, so the Runtime can still roll
	// back. The userspace backend does not give that guarantee yet: to keep the behaviour from
	// before the Backend existed, its Commit binds and starts serving each listener, and a port
	// that fails to bind is logged and retried rather than failing the Commit, so the change can
	// be applied partly without an error. Phase 4 (design.md 7a.3, 7a.8 節) moves binding into
	// Prepare so every backend meets the atomic contract.
	Commit() error
	// Rollback releases what Prepare staged. It is called when Commit was not reached or failed,
	// never after a successful Commit, and cannot fail.
	Rollback()
}

// Backend is one DataplaneMode's dataplane (design.md 7a.2 節: "Backend は kernel と userspace の
// 2 つを持ち、それぞれが OS、nftables、netstack などの実装詳細を隠す").
//
// Beyond the participant, it converges the WireGuard device and exposes what the control plane
// reads back. EnsureWG, Converge and ReadDrops are separate calls in this phase, made by the control
// plane around the Runtime exactly where the pre-Backend code made them. Phase 4 (design.md 7a.3,
// 7a.8 節) folds peer changes and post-commit convergence into the transaction and adds Observe.
type Backend interface {
	Participant
	// EnsureWG converges the WireGuard device to cfg and returns the changes it made, one line
	// each, for the log.
	EnsureWG(cfg WGConfig) ([]string, error)
	// WGStatus returns the device and its peers (endpoint, last handshake, counters).
	WGStatus() (*wgtypes.Device, error)
	// Converge closes established flows the committed Plan no longer admits and returns how many
	// it closed (design.md 6.1, 6.3, 7a.3 節). It runs after the Runtime's Commit.
	Converge(p planner.Plan) (int, error)
	// ReadDrops reads the drop counters of the current dataplane. The kernel backend only reads:
	// its counters are reset by the next successful table replacement, so if that replacement
	// fails, the next ReadDrops returns the same counts again. The userspace backend drains its
	// counters on read. Phase 4 ties reading the counters to the commit.
	ReadDrops() ([]Drop, error)
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

// Peer is one agent's WireGuard peer: its declared public key and its address on the wg network.
type Peer struct {
	PublicKey wgtypes.Key
	Address   netip.Addr
}

// Drop is one rule's drop counter for one kind of admission step (design.md 6.1 節).
type Drop struct {
	RuleID  string
	Kind    string // deny | allow | per_source | src_flow | new_flow | packet
	Packets uint64
	Bytes   uint64
}
