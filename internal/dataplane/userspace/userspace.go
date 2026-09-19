// Package userspace is the userspace dataplane Backend (design.md 6.3, 7a.7 節). It uses neither
// kernel WireGuard nor nftables nor conntrack: a wireguard-go + netstack tunnel (utun), the Go
// admission evaluator (srcpolicy) in place of nftables, and the shared relay (relay) turned around
// so that it accepts on the host's public ports and dials the agents through the netstack.
//
// Everything the Backend converges to comes from the Plan it is given (design.md 7a.2 節):
// Transparent ports become relay listeners, Plan.Admission feeds the evaluator and the per-source
// flow caps. Only process-wide budgets (Resource Guard, design.md 7a.5 節) are fixed at New.
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
	"github.com/rahanahu/wgft/internal/dataplane/userspace/srcpolicy"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/utun"
	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/internal/planner"
)

// Options configures a Backend.
type Options struct {
	// Limits gives the process-wide flow budgets and the per-rule isolation derived from them
	// (design.md 7 節 and 7a.5 節, Resource Guard). Its per-source caps are not read here: those
	// are Admission Policy and come with every Plan (Plan.Admission.PerSourceFlowCaps).
	Limits flowcap.Limits
	// Logf is where the Backend and its tunnel log. nil means log.Printf.
	Logf func(format string, args ...any)
}

// Backend is the userspace dataplane. It implements dataplane.Backend.
type Backend struct {
	logf   func(format string, args ...any)
	policy *srcpolicy.Policy
	relay  *relay.Manager
	udpCap *flowcap.Counter
	// tcpCap is shared by the relay and the server's Relay frontend (proxyrelay): in userspace mode
	// both count against the same TCP budget (design.md 7 節).
	tcpCap *flowcap.Counter

	mu  sync.Mutex
	tun *utun.Tunnel
	cfg dataplane.WGConfig // the declaration the tunnel was brought up with
}

var _ dataplane.Backend = (*Backend)(nil)

// hostNetwork opens the relay's listeners on all host addresses (the public ports).
type hostNetwork struct{}

func (hostNetwork) ListenUDP(port uint16) (net.PacketConn, error) {
	return net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
}
func (hostNetwork) ListenTCP(port uint16) (net.Listener, error) {
	return net.Listen("tcp", ":"+strconv.Itoa(int(port)))
}

// New builds a Backend with no tunnel and no listeners; EnsureDevice brings the tunnel up, the
// first Prepare binds the listeners and its Commit serves them. The per-source caps are off until
// that first Commit sets them from its Plan, before any listener serves.
func New(opts Options) *Backend {
	lim := opts.Limits.WithDefaults()
	logf := opts.Logf
	if logf == nil {
		logf = log.Printf
	}
	b := &Backend{
		logf:   logf,
		policy: srcpolicy.New(nil),
		udpCap: &flowcap.Counter{Total: lim.UDPTotal},
		tcpCap: &flowcap.Counter{Total: lim.TCPTotal},
	}
	b.relay = relay.New(hostNetwork{}, relay.Options{
		UDPIdleTimeout: 120 * time.Second, // the default of conntrack's udp_timeout_stream
		Dial:           b.Dial,
		Logf:           logf,
		Admit: func(ruleID string, src netip.Addr) bool {
			ok, _ := b.policy.AdmitFlow(ruleID, src, 0)
			return ok
		},
		AdmitPacket: b.policy.AdmitPacket,
		Limits:      lim,
		UDPCap:      b.udpCap,
		TCPCap:      b.tcpCap,
	})
	return b
}

// TCPCounter is the TCP flow counter the relay uses. The server hands it to its Relay frontend so
// that both count against one TCP budget, per source included, in userspace mode (design.md 7 節).
func (b *Backend) TCPCounter() *flowcap.Counter { return b.tcpCap }

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
// rows (design.md 6.1 節), while in userspace mode the Relay frontend counts per source itself
// through the shared TCPCounter.
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

// Commit publishes the Plan without its failed rules: the evaluator's rules and the per-source
// flow caps first, then the relay's listener set, so that no new listener serves before its
// admission policy is in place. It then removes the peers the declaration dropped and closes the
// relay sessions the published policy no longer admits (in place of conntrack convergence,
// design.md 6.3 節); a retiring rule's sessions are judged by its Retiring value (design.md 7a.3
// 節). Nothing here can fail the Commit.
func (p *prepared) Commit(retiring []dataplane.Retiring) (dataplane.Committed, error) {
	b := p.b
	p.done = true
	c := dataplane.Committed{Drops: b.policy.Drops(), WGChanges: p.wgChanges}
	failed := make(map[string]bool, len(p.staged.Failed()))
	for id := range p.staged.Failed() {
		failed[id] = true
	}
	adm := p.desired.Plan.Without(failed).Admission
	b.policy.Update(adm.Rules)
	b.udpCap.SetPerSource(adm.PerSourceFlowCaps.UDP)
	b.tcpCap.SetPerSource(adm.PerSourceFlowCaps.TCP)
	keep := make(map[string]func(netip.Addr) bool, len(retiring))
	for _, r := range retiring {
		keep[r.Previous.RuleID] = r.SourceAllowed
	}
	p.staged.Commit(keep)
	if p.peersChanged {
		changes, err := b.setPeers(p.desired.WG.Peers)
		if err != nil {
			c.Errors = append(c.Errors, fmt.Errorf("userspace tunnel: removing peers: %w", err))
		}
		c.WGChanges = append(c.WGChanges, changes...)
	}
	c.Closed = b.relay.CloseSessions(func(ruleID string, src netip.Addr) bool {
		if k, ok := keep[ruleID]; ok {
			return k(src)
		}
		return b.policy.SourceAllowed(ruleID, src)
	})
	return c, nil
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
