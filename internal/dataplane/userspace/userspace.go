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

// New builds a Backend with no tunnel and no listeners; EnsureWG brings the tunnel up and the
// first Commit opens the listeners. The per-source caps are off until that first Commit sets them
// from its Plan, before it opens any listener.
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

// EnsureWG brings the tunnel up on first use and converges its peer set.
func (b *Backend) EnsureWG(cfg dataplane.WGConfig) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var changes []string
	if b.tun == nil {
		t, err := utun.New(utun.Config{PrivateKey: cfg.PrivateKey, ListenPort: uint16(cfg.ListenPort), Address: cfg.Address.Addr(), MTU: cfg.MTU, Logf: b.logf})
		if err != nil {
			return nil, err
		}
		b.tun = t
		b.cfg = cfg
		changes = append(changes, fmt.Sprintf("userspace tunnel up on port %d", cfg.ListenPort))
	} else if b.cfg.ListenPort != cfg.ListenPort || b.cfg.PrivateKey != cfg.PrivateKey || b.cfg.Address != cfg.Address || b.cfg.MTU != cfg.MTU {
		// The key, port, address and MTU are fixed at startup, so this does not happen; refuse
		// rather than keep a tunnel that no longer matches the declaration.
		return nil, fmt.Errorf("userspace tunnel: key, port, address or MTU changed while running; restart the server")
	}
	peerChanges, err := b.tun.SetPeers(cfg.Peers)
	if err != nil {
		return nil, err
	}
	return append(changes, peerChanges...), nil
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

// ReadDrops returns what the evaluator dropped since the previous call.
func (b *Backend) ReadDrops() ([]dataplane.Drop, error) { return b.policy.Drops(), nil }

// Prepare stages d. The userspace backend has no reversible stage yet: relay.Manager.Apply binds
// and starts serving each port in one step, and a port that fails to bind is recorded and retried
// by the relay rather than failing the whole change. So Prepare only keeps the Plan and cannot
// fail, and Commit does the work and cannot fail either. This is how the userspace mode applied
// rules before the Backend existed; Phase 4 (design.md 7a.3, 7a.8 節) moves binding into Prepare.
//
// d.RelayListening is not used: the kernel backend needs it to give Relay ports per-source flow
// rows (design.md 6.1 節), while in userspace mode the Relay frontend counts per source itself
// through the shared TCPCounter.
func (b *Backend) Prepare(d dataplane.Desired) (dataplane.Prepared, error) {
	return &prepared{b: b, plan: d.Plan}, nil
}

type prepared struct {
	b    *Backend
	plan planner.Plan
}

// Commit publishes the Plan: the evaluator's rules and the per-source flow caps first, then the
// relay's listener set, so that no new listener serves before its admission policy is in place.
func (p *prepared) Commit() error {
	adm := p.plan.Admission
	p.b.policy.Update(adm.Rules)
	p.b.udpCap.SetPerSource(adm.PerSourceFlowCaps.UDP)
	p.b.tcpCap.SetPerSource(adm.PerSourceFlowCaps.TCP)
	p.b.relay.Apply(relayTargets(p.plan))
	return nil
}

// Rollback has nothing to release: Prepare staged nothing but the Plan it kept.
func (p *prepared) Rollback() {}

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

// Converge closes the relay sessions the committed admission policy no longer allows (in place of
// conntrack convergence, design.md 6.3 節). It reads the policy Commit installed, so it does not
// need the Plan again.
func (b *Backend) Converge(planner.Plan) (int, error) {
	return b.relay.CloseSessions(b.policy.SourceAllowed), nil
}
