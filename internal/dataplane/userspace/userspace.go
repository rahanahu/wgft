// Package userspace is the userspace dataplane Backend (design.md 6.3, 7a.7 節). It uses neither
// kernel WireGuard nor nftables nor conntrack: a wireguard-go + netstack tunnel (utun), the Go
// admission evaluator (internal/policy/goengine) in place of nftables, and the shared relay (relay)
// turned around so that it accepts on the host's public ports and dials the agents through the
// netstack.
//
// Everything the Backend converges to comes from the Plan it is given (design.md 7a.2 節):
// Transparent ports become relay listeners, Plan.Admission feeds the evaluator, per-source flow caps
// included. Only process-wide budgets (Resource Guard, design.md 7a.5 節) are fixed at New.
package userspace

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/utun"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/policy/goengine"
	"github.com/rahanahu/wgft/internal/resource"
)

// Options configures a Backend.
type Options struct {
	// Limits gives the process-wide flow budgets and the per-rule isolation derived from them
	// (design.md 7 節 and 7a.5 節, Resource Guard). The per-source caps are Admission Policy, a
	// separate type (policy.AdmissionLimits) that comes with every Plan
	// (Plan.Admission.PerSourceFlowCaps), not a field of this one.
	Limits resource.Limits
	// Logf is where the Backend and its tunnel log. nil means log.Printf.
	Logf func(format string, args ...any)
}

// Backend is the userspace dataplane. It implements dataplane.Backend.
type Backend struct {
	logf   func(format string, args ...any)
	policy *goengine.Engine
	relay  *relay.Manager
	udpCap *resource.Counter
	// tcpCap is shared by the relay and the server's Relay frontend (proxyrelay): in userspace mode
	// both count against the same process-wide TCP budget (design.md 7 節). The per-source count is
	// the evaluator's, which the Relay frontend reaches through AdmitRelayFlow.
	tcpCap *resource.Counter

	mu  sync.Mutex
	tun *utun.Tunnel
	cfg dataplane.WGConfig // the declaration the tunnel was brought up with

	// pendingPeers is the peer set whose removal the last Commit or Repair failed to finish; nil when
	// no repair is pending (design.md 7a.3 節: 戻れない地点の後の修復). The Reconciler serializes
	// Prepare, Commit and Repair.
	pendingPeers []dataplane.Peer
	repairPeers  bool
}

var _ dataplane.Backend = (*Backend)(nil)

// hostNetwork opens the relay's listeners on all host IPv4 addresses (the public ports). v1 handles
// IPv4 only (design.md 4, 7a.9 節): a dual-stack listener would let an IPv6 source past deny lists
// that hold IPv4 prefixes only. The evaluator also refuses non-IPv4 sources on its own.
type hostNetwork struct{}

func (hostNetwork) ListenUDP(port uint16) (net.PacketConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)})
}
func (hostNetwork) ListenTCP(port uint16) (net.Listener, error) {
	return net.Listen("tcp4", ":"+strconv.Itoa(int(port)))
}

// New builds a Backend with no tunnel and no listeners; EnsureDevice brings the tunnel up, the
// first Prepare binds the listeners and its Commit serves them. The evaluator rejects every flow
// until that first Commit gives it the Plan's admission policy, before any listener serves.
func New(opts Options) *Backend {
	lim := opts.Limits.WithDefaults()
	logf := opts.Logf
	if logf == nil {
		logf = log.Printf
	}
	b := &Backend{
		logf:   logf,
		policy: goengine.New(nil),
		udpCap: &resource.Counter{Total: lim.UDPTotal},
		tcpCap: &resource.Counter{Total: lim.TCPTotal},
	}
	b.relay = relay.New(hostNetwork{}, relay.Options{
		UDPIdleTimeout: 120 * time.Second, // the default of conntrack's udp_timeout_stream
		Dial:           b.Dial,
		Logf:           logf,
		Admit: func(ruleID string, src netip.Addr, size int) (func(), bool) {
			d, t := b.policy.AdmitFlow(ruleID, src, size)
			return t.Release, d.Allow
		},
		AdmitPacket: func(ruleID string, size int) bool { return b.policy.AdmitPacket(ruleID, size).Allow },
		Limits:      lim,
		UDPCap:      b.udpCap,
		TCPCap:      b.tcpCap,
	})
	return b
}

// TCPCounter is the TCP flow counter the relay uses. The server hands it to its Relay frontend so
// that both count against one process-wide TCP budget in userspace mode (design.md 7 節).
func (b *Backend) TCPCounter() *resource.Counter { return b.tcpCap }

// AdmitRelayFlow judges a new connection of the server's Relay frontend (proxyrelay) in userspace
// mode by every Admission Policy step, exactly as a Transparent TCP connection is judged: Forwarding
// picks how a flow is carried, not whether it is admitted (design.md 7a.9 節). The evaluator counts
// the drop of whichever step refuses, and Relay connections share the per-source concurrent-flow
// count with the Transparent TCP rules (design.md 6.3 節). When it admits, the caller calls release
// once when the connection ends, or at once when a later limit (Resource Guard) refuses it.
//
// The size is 0 because a refused TCP connection counts as one packet of zero bytes (design.md 7a.9
// 節の許容差 drop_counter_units).
func (b *Backend) AdmitRelayFlow(ruleID string, src netip.Addr) (release func(), ok bool) {
	d, t := b.policy.AdmitFlow(ruleID, src, 0)
	return t.Release, d.Allow
}

// Dial connects to an agent through the netstack. The relay, the server's Relay frontend and the
// connectivity check all dial with it.
func (b *Backend) Dial(network, addr string) (net.Conn, error) {
	b.mu.Lock()
	t := b.tun
	b.mu.Unlock()
	if t == nil {
		return nil, fmt.Errorf("tunnel is not up")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return t.DialContext(ctx, network, addr)
}

// EnsureDevice brings the tunnel up on first use. The peers are converged by the transactions
// (dataplane.Desired.WG), not here.
func (b *Backend) EnsureDevice(cfg dataplane.WGConfig) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tun == nil {
		t, err := utun.New(utun.Config{PrivateKey: cfg.PrivateKey, ListenPort: uint16(cfg.ListenPort), Address: cfg.Address.Addr(), MTU: cfg.MTU, Logf: b.logf})
		if err != nil {
			return nil, err
		}
		b.tun = t
		b.cfg = cfg
		return []string{fmt.Sprintf("userspace tunnel up on port %d", cfg.ListenPort)}, nil
	}
	if b.cfg.ListenPort != cfg.ListenPort || b.cfg.PrivateKey != cfg.PrivateKey || b.cfg.Address != cfg.Address || b.cfg.MTU != cfg.MTU {
		// The key, port, address and MTU are fixed at startup, so this does not happen; refuse
		// rather than keep a tunnel that no longer matches the declaration.
		return nil, fmt.Errorf("userspace tunnel: key, port, address or MTU changed while running; restart the server")
	}
	return nil, nil
}

// setPeers converges the tunnel's peer set to peers.
func (b *Backend) setPeers(peers []dataplane.Peer) ([]string, error) {
	b.mu.Lock()
	t := b.tun
	b.mu.Unlock()
	if t == nil {
		return nil, fmt.Errorf("tunnel is not up")
	}
	return t.SetPeers(peers)
}

// Observe reports the peers the tunnel has. The tunnel lives only as long as the process, so after
// a restart it has none until the first transaction.
func (b *Backend) Observe() (dataplane.Observed, error) {
	b.mu.Lock()
	t := b.tun
	b.mu.Unlock()
	if t == nil {
		return dataplane.Observed{}, nil
	}
	return dataplane.Observed{Peers: t.DeclaredPeers()}, nil
}

// WGStatus reports the tunnel in the shape wgctrl returns for a kernel device.
func (b *Backend) WGStatus() (*wgtypes.Device, error) {
	b.mu.Lock()
	t, cfg := b.tun, b.cfg
	b.mu.Unlock()
	if t == nil {
		return nil, fmt.Errorf("tunnel is not up")
	}
	peers, err := t.Peers()
	if err != nil {
		return nil, err
	}
	dev := &wgtypes.Device{Name: "userspace", Type: wgtypes.Userspace, PrivateKey: cfg.PrivateKey, PublicKey: cfg.PrivateKey.PublicKey(), ListenPort: cfg.ListenPort}
	for _, p := range peers {
		wp := wgtypes.Peer{PublicKey: p.PublicKey, LastHandshakeTime: p.LastHandshake, ReceiveBytes: p.RxBytes, TransmitBytes: p.TxBytes}
		if p.Endpoint.IsValid() {
			wp.Endpoint = net.UDPAddrFromAddrPort(p.Endpoint)
		}
		dev.Peers = append(dev.Peers, wp)
	}
	return dev, nil
}

// Prepare stages d (design.md 7a.2 節): it adds the peers d newly declares, and binds the host
// listeners of the Transparent ports that are not open yet, without serving them. A rule with a
// port that cannot be bound is a rule-local failure (design.md 7a.3 節): it is reported by
// Failed, none of its ports is staged, and Commit leaves it out of the evaluator too. A failure
// to change the peers is backend-wide and returned as the error.
//
// d.RelayListening is not used: the kernel backend needs it to give Relay ports per-source flow
// rows (design.md 6.1 節), while in userspace mode the Relay frontend asks the evaluator through
// AdmitRelayFlow.
func (b *Backend) Prepare(d dataplane.Desired) (dataplane.Prepared, error) {
	p := &prepared{b: b, desired: d, peersChanged: d.PeersChanged()}
	if p.peersChanged {
		changes, err := b.setPeers(dataplane.PeerUnion(d.WG.Peers, d.ActivePeers))
		if err != nil {
			_, _ = b.setPeers(d.ActivePeers)
			return nil, fmt.Errorf("userspace tunnel: %w", err)
		}
		p.wgChanges = changes
	}
	p.staged = b.relay.Prepare(relayTargets(d.Plan))
	return p, nil
}

type prepared struct {
	b            *Backend
	desired      dataplane.Desired
	peersChanged bool
	wgChanges    []string
	staged       *relay.Staged
	done         bool
}

func (p *prepared) Failed() map[string]error { return p.staged.Failed() }

// Commit publishes the Plan without its failed rules: the evaluator's admission policy (the
// per-source flow caps included) first, then the relay's listener set, so that no new listener serves before its
// admission policy is in place. It then removes the peers the declaration dropped and closes the
// relay sessions the published policy no longer admits (in place of conntrack convergence,
// design.md 6.3 節); a retiring rule's sessions are judged by its Retiring value (design.md 7a.3
// 節). Nothing here can fail the Commit.
func (p *prepared) Commit(retiring []dataplane.Retiring) (dataplane.Committed, error) {
	b := p.b
	p.done = true
	c := dataplane.Committed{Drops: drops(b.policy.Drops()), WGChanges: p.wgChanges}
	failed := make(map[string]bool, len(p.staged.Failed()))
	for id := range p.staged.Failed() {
		failed[id] = true
	}
	b.policy.Update(p.desired.Plan.Without(failed).Admission)
	keep := make(map[string]func(netip.Addr) bool, len(retiring))
	for _, r := range retiring {
		keep[r.Previous.RuleID] = r.SourceAllowed
	}
	p.staged.Commit(keep)
	// ピアの削除が残っていれば、ピアの集合が変わらなくても公開の後で宣言に収束させる
	peersPending := b.repairPeers
	b.pendingPeers, b.repairPeers = nil, false
	if p.desired.WG != nil && (p.peersChanged || peersPending) {
		b.pendingPeers, b.repairPeers = append([]dataplane.Peer(nil), p.desired.WG.Peers...), true
		b.repairOnce(&c)
	}
	c.Closed = b.relay.CloseSessions(func(ruleID string, src netip.Addr) bool {
		if k, ok := keep[ruleID]; ok {
			return k(src)
		}
		return b.policy.SourceAllowed(ruleID, src)
	})
	return c, nil
}

// drops converts the evaluator's drop counts into the dataplane's.
func drops(in []goengine.Drop) []dataplane.Drop {
	if len(in) == 0 {
		return nil
	}
	out := make([]dataplane.Drop, len(in))
	for i, d := range in {
		out[i] = dataplane.Drop{RuleID: d.RuleID, Kind: d.Kind, Packets: d.Packets, Bytes: d.Bytes}
	}
	return out
}

// repairOnce removes the peers the declaration dropped (the pending repair), keeping it pending
// when it fails.
func (b *Backend) repairOnce(c *dataplane.Committed) {
	if !b.repairPeers {
		return
	}
	changes, err := b.setPeers(b.pendingPeers)
	c.WGChanges = append(c.WGChanges, changes...)
	if err != nil {
		c.Errors = append(c.Errors, fmt.Errorf("userspace tunnel: removing peers: %w", err))
		c.RepairPending = true
		return
	}
	b.pendingPeers, b.repairPeers = nil, false
}

// Repair reruns a peer removal the last Commit or Repair left failed (design.md 7a.3 節: 戻れない
// 地点の後の修復). Closing the relay sessions cannot fail, so it is never a repair.
func (b *Backend) Repair() dataplane.Committed {
	var c dataplane.Committed
	b.repairOnce(&c)
	return c
}

// Rollback closes the listeners Prepare bound and restores the peer set it changed.
func (p *prepared) Rollback() {
	if p.done {
		return
	}
	p.done = true
	p.staged.Rollback()
	if p.peersChanged {
		_, _ = p.b.setPeers(p.desired.ActivePeers)
	}
}

// relayTargets expands the Plan's Transparent ports (vps_mode = kernel rules, design.md 6.3 節)
// into one relay.Desired per individual port, since the userspace relay opens one listener per
// port and planner.PortPlan leaves that expansion to the Backend. The destination is the agent's
// wg address at the same port (design.md 6.1 節: "DNAT では宛先アドレスだけを書き換え、ポートは
// 書き換えない"; the relay follows the same rule). Relay ports belong to the frontend, not here.
func relayTargets(plan planner.Plan) map[relay.Key]relay.Desired {
	desired := map[relay.Key]relay.Desired{}
	for _, pp := range plan.Transparent() {
		for port := int(pp.ListenPort.Lo); port <= int(pp.ListenPort.Hi); port++ {
			desired[relay.Key{Proto: pp.Proto, Port: uint16(port)}] = relay.Desired{
				Target: net.JoinHostPort(pp.AgentAddr.String(), strconv.Itoa(port)), RuleID: pp.RuleID,
			}
		}
	}
	return desired
}
