package linuxkernel

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/conntrack"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/proto"
)

// fakeKernel stands in for the kernel: a table with drop counters that only a successful flush
// resets, and a peer set.
type fakeKernel struct {
	calls    []string
	counters []nft.Drop // counters of the current table
	flushErr error
	stageErr error
	wgErr    func(peers []wg.Peer) error
	devPeers []wg.Peer
	rules    []conntrack.Rule
	// dev and table are what inspect and fingerprint read back (drift_test.go).
	dev   wg.DeviceState
	table string // fingerprint of the table; "" means the table is missing
	// convergeErr and fpErr make the conntrack convergence and the read-back fail (repair_test.go).
	convergeErr error
	fpErr       error
}

func (k *fakeKernel) ensureWG(cfg wg.Config) ([]string, error) {
	if cfg.KeepPeers {
		k.calls = append(k.calls, "ensure device")
		return nil, nil
	}
	k.calls = append(k.calls, "ensure peers "+peerAddrs(cfg.Peers))
	if k.wgErr != nil {
		if err := k.wgErr(cfg.Peers); err != nil {
			return nil, err
		}
	}
	k.devPeers = cfg.Peers
	return []string{"peers " + peerAddrs(cfg.Peers)}, nil
}

func peerAddrs(ps []wg.Peer) string {
	s := ""
	for i, p := range ps {
		if i > 0 {
			s += ","
		}
		s += p.Address.String()
	}
	return "[" + s + "]"
}

func (k *fakeKernel) peers(string) ([]dataplane.Peer, error) { return nil, nil }

type fakeStaged struct{ k *fakeKernel }

func (s fakeStaged) Flush() error {
	s.k.calls = append(s.k.calls, "flush")
	if s.k.flushErr != nil {
		return s.k.flushErr
	}
	s.k.counters = nil // a new table starts with zero counters
	return nil
}

func (k *fakeKernel) stage(planner.Plan, map[uint16]bool, nft.Config) (flusher, error) {
	k.calls = append(k.calls, "stage")
	if k.stageErr != nil {
		return nil, k.stageErr
	}
	return fakeStaged{k}, nil
}

func (k *fakeKernel) readDrops() ([]nft.Drop, error) {
	k.calls = append(k.calls, "read drops")
	return append([]nft.Drop(nil), k.counters...), nil
}

func (k *fakeKernel) converge(rules []conntrack.Rule, _ netip.Prefix) (int, error) {
	k.calls = append(k.calls, "converge")
	k.rules = rules
	if k.convergeErr != nil {
		return 0, k.convergeErr
	}
	return 1, nil
}

func (k *fakeKernel) inspect(string) (wg.DeviceState, error) { return k.dev, nil }

func (k *fakeKernel) fingerprint() (string, bool, error) {
	if k.fpErr != nil {
		return "", false, k.fpErr
	}
	return k.table, k.table != "", nil
}

func newTestBackend(k *fakeKernel) *Backend {
	return &Backend{iface: "wgft0", ops: k, network: netip.MustParsePrefix("10.200.0.0/24")}
}

func testPeer(t *testing.T, addr string) dataplane.Peer {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return dataplane.Peer{PublicKey: key.PublicKey(), Address: netip.MustParseAddr(addr)}
}

// A failed table swap must not hand out the drop counters: the old table keeps them, so the
// next successful swap hands out the same counts, once (design.md 6.1, 7a.3 節).
func TestDropsNotCountedTwiceOnFailedSwap(t *testing.T) {
	k := &fakeKernel{counters: []nft.Drop{{RuleID: "r_a", Kind: "deny", Packets: 5, Bytes: 300}}}
	b := newTestBackend(k)
	var accumulated uint64
	apply := func() error {
		p, err := b.Prepare(dataplane.Desired{})
		if err != nil {
			return err
		}
		c, err := p.Commit(nil)
		if err != nil {
			p.Rollback()
			return err
		}
		for _, d := range c.Drops {
			accumulated += d.Packets
		}
		return nil
	}
	k.flushErr = errors.New("table inet wgft is owned by another process")
	if err := apply(); err == nil {
		t.Fatal("want the swap failure")
	}
	if accumulated != 0 {
		t.Fatalf("a failed swap handed out %d dropped packets", accumulated)
	}
	k.flushErr = nil
	if err := apply(); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err != nil {
		t.Fatal(err)
	}
	if accumulated != 5 {
		t.Errorf("accumulated %d dropped packets, want 5 (counted once)", accumulated)
	}
}

// Peers are added before the table is published and removed after it; a failed swap restores
// the peer set the device had (design.md 7a.3 節).
func TestPeersAroundThePublication(t *testing.T) {
	old, keep, added := testPeer(t, "10.200.0.9"), testPeer(t, "10.200.0.2"), testPeer(t, "10.200.0.3")
	cfg := &dataplane.WGConfig{Address: netip.MustParsePrefix("10.200.0.1/24"), Peers: []dataplane.Peer{keep, added}}
	d := dataplane.Desired{WG: cfg, ActivePeers: []dataplane.Peer{keep, old}}

	k := &fakeKernel{}
	b := newTestBackend(k)
	p, err := b.Prepare(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Commit(nil); err != nil {
		t.Fatal(err)
	}
	want := []string{"ensure peers [10.200.0.2,10.200.0.3,10.200.0.9]", "stage", "read drops", "flush",
		"ensure peers [10.200.0.2,10.200.0.3]", "converge"}
	if !reflect.DeepEqual(k.calls, want) {
		t.Errorf("calls = %v\nwant    %v", k.calls, want)
	}

	k = &fakeKernel{flushErr: errors.New("nftables: transaction failed")}
	b = newTestBackend(k)
	p, err = b.Prepare(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Commit(nil); err == nil {
		t.Fatal("want the swap failure")
	}
	p.Rollback()
	want = []string{"ensure peers [10.200.0.2,10.200.0.3,10.200.0.9]", "stage", "read drops", "flush",
		"ensure peers [10.200.0.2,10.200.0.9]"}
	if !reflect.DeepEqual(k.calls, want) {
		t.Errorf("failed swap: calls = %v\nwant    %v", k.calls, want)
	}
}

// Unchanged peers are left alone: no WireGuard call at all.
func TestPeersUnchangedNotTouched(t *testing.T) {
	a := testPeer(t, "10.200.0.2")
	k := &fakeKernel{}
	b := newTestBackend(k)
	p, err := b.Prepare(dataplane.Desired{WG: &dataplane.WGConfig{Peers: []dataplane.Peer{a}}, ActivePeers: []dataplane.Peer{a}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Commit(nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(k.calls, []string{"stage", "read drops", "flush", "converge"}) {
		t.Errorf("calls = %v", k.calls)
	}
}

// A WireGuard failure while adding peers, or a build failure, is backend-wide: Prepare fails and
// leaves the device's peer set as it was.
func TestPrepareFailureRestoresPeers(t *testing.T) {
	a, added := testPeer(t, "10.200.0.2"), testPeer(t, "10.200.0.3")
	d := dataplane.Desired{WG: &dataplane.WGConfig{Peers: []dataplane.Peer{a, added}}, ActivePeers: []dataplane.Peer{a}}
	k := &fakeKernel{stageErr: errors.New("rule r_x: set: invalid")}
	b := newTestBackend(k)
	if _, err := b.Prepare(d); err == nil {
		t.Fatal("want the build failure")
	}
	if got := peerAddrs(k.devPeers); got != "[10.200.0.2]" {
		t.Errorf("peers after a failed Prepare = %s, want the active set", got)
	}
}

// The conntrack convergence keeps a fail-closed rule's established flows by judging them against
// its previous Active value, combined with the new source policy (design.md 7a.3 節).
func TestConvergeRulesKeepRetiring(t *testing.T) {
	prev := planner.PortPlan{RuleID: "r_x", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 8000, Hi: 8000},
		Forwarding: model.Transparent, AgentAddr: netip.MustParseAddr("10.200.0.2")}
	retiring := []dataplane.Retiring{{Previous: prev}}
	retiring[0].Desired.SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	relayPrev := prev
	relayPrev.RuleID, relayPrev.Forwarding = "r_relay", model.Relay
	retiring = append(retiring, dataplane.Retiring{Previous: relayPrev})

	rules := ConvergeRules(planner.Plan{}, retiring)
	if len(rules) != 1 {
		t.Fatalf("rules = %+v, want only the Transparent retiring rule (a Relay rule has no DNAT flows)", rules)
	}
	r := rules[0]
	if r.ListenPort.Lo != 8000 || r.AgentAddr != prev.AgentAddr || r.Keep == nil {
		t.Fatalf("rule = %+v, want the previous value with a Keep judgement", r)
	}
	if r.Keep(netip.MustParseAddr("203.0.113.9")) {
		t.Error("a source the new declaration denies must not be kept")
	}
	if !r.Keep(netip.MustParseAddr("198.51.100.9")) {
		t.Error("a safe source must be kept")
	}
}
