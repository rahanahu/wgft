//go:build linux

package linuxkernel

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
)

func testWG(t *testing.T, peers ...dataplane.Peer) dataplane.WGConfig {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return dataplane.WGConfig{PrivateKey: key, ListenPort: 51820, Address: netip.MustParsePrefix("10.200.0.1/24"),
		MTU: 1420, Peers: peers}
}

// deviceAsDeclared is what Inspect reads from a device converged to w.
func deviceAsDeclared(w dataplane.WGConfig) wg.DeviceState {
	st := wg.DeviceState{Exists: true, Kind: "wireguard", PrivateKey: w.PrivateKey, ListenPort: w.ListenPort,
		Addresses: []netip.Prefix{w.Address}, Up: true}
	for _, p := range w.Peers {
		st.Peers = append(st.Peers, wg.Peer{PublicKey: p.PublicKey, Address: p.Address})
	}
	return st
}

// committedBackend returns a kernel Backend whose first transaction committed w, with the kernel
// reading back exactly what was committed.
func committedBackend(t *testing.T, w dataplane.WGConfig) (*Backend, *fakeKernel) {
	t.Helper()
	k := &fakeKernel{table: "fp1", dev: deviceAsDeclared(w)}
	b := newTestBackend(k)
	p, err := b.Prepare(dataplane.Desired{WG: &w, ActivePeers: w.Peers})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Commit(nil); err != nil {
		t.Fatal(err)
	}
	k.calls = nil
	return b, k
}

// driftOf compares the kernel with what the last Commit left: nothing is reported when they match,
// and each kind of change outside wgft is named (design.md 7a.3 節: 実際の状態への収束).
func TestDriftOf(t *testing.T) {
	peer := testPeer(t, "10.200.0.2")
	w := testWG(t, peer)
	last := committed{wg: &w, table: "fp1"}
	cases := []struct {
		name    string
		mutate  func(dev *wg.DeviceState)
		fp      string // "" = table missing
		want    string // substring of the only drift; "" = no drift
		foreign bool
	}{
		{name: "as committed", fp: "fp1"},
		{name: "flush ruleset", fp: "", want: "table inet wgft is missing"},
		{name: "a rule deleted", fp: "fp2", want: "table inet wgft was changed"},
		{name: "ip link del", fp: "fp1", mutate: func(d *wg.DeviceState) { *d = wg.DeviceState{} }, want: "interface wgft0 is missing"},
		{name: "wg set peer remove", fp: "fp1", mutate: func(d *wg.DeviceState) { d.Peers = nil }, want: "0 peers that differ from the 1 declared"},
		{name: "wg set listen-port", fp: "fp1", mutate: func(d *wg.DeviceState) { d.ListenPort = 51821 }, want: "listen port is 51821, not 51820"},
		{name: "ip addr flush", fp: "fp1", mutate: func(d *wg.DeviceState) { d.Addresses = nil }, want: "addresses are []"},
		{name: "ip link set down", fp: "fp1", mutate: func(d *wg.DeviceState) { d.Up = false }, want: "wgft0 is down"},
		{name: "another WireGuard with the name", fp: "fp1", foreign: true, mutate: func(d *wg.DeviceState) {
			k, _ := wgtypes.GeneratePrivateKey()
			d.PrivateKey = k
		}},
		{name: "another link type with the name", fp: "fp1", foreign: true, mutate: func(d *wg.DeviceState) {
			*d = wg.DeviceState{Exists: true, Kind: "veth"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dev := deviceAsDeclared(w)
			if tc.mutate != nil {
				tc.mutate(&dev)
			}
			drift, err := driftOf("wgft0", last, dev, tc.fp, tc.fp != "", false)
			if tc.foreign {
				if err == nil || !strings.Contains(err.Error(), "leaving it alone") {
					t.Fatalf("foreign device: drift %v, err %v; want an error that leaves it alone", drift, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if len(drift) > 0 {
					t.Fatalf("drift %v, want none", drift)
				}
				return
			}
			if len(drift) != 1 || !strings.Contains(drift[0], tc.want) {
				t.Fatalf("drift %v, want one entry containing %q", drift, tc.want)
			}
		})
	}
}

// Observe after a Commit reads the kernel back and compares it with what was committed; the
// fingerprint recorded right after the publication matches the next read, so wgft's own Commit
// does not look like drift (the notifications it causes would otherwise loop).
func TestObserveAfterCommit(t *testing.T) {
	peer := testPeer(t, "10.200.0.2")
	w := testWG(t, peer)
	b, k := committedBackend(t, w)
	obs, err := b.Observe()
	if err != nil || len(obs.Drift) > 0 {
		t.Fatalf("Observe right after the commit: %+v, %v; want no drift", obs, err)
	}
	k.table = ""
	k.dev = wg.DeviceState{}
	obs, err = b.Observe()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"table inet wgft is missing", "interface wgft0 is missing"}
	if !reflect.DeepEqual(obs.Drift, want) || len(obs.Peers) != 0 {
		t.Errorf("Observe after flush and link del: %+v, want drift %v and no peers", obs, want)
	}
}

// A resync converges the device as a whole even when the peer set did not change (the device may
// be gone), and records what it committed; a transaction without resync and without a peer change
// leaves the device alone.
func TestResyncConvergesDevice(t *testing.T) {
	peer := testPeer(t, "10.200.0.2")
	w := testWG(t, peer)
	b, k := committedBackend(t, w)
	k.table = "fp2" // the table the resync publishes reads back differently

	p, err := b.Prepare(dataplane.Desired{WG: &w, ActivePeers: nil, Resync: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Commit(nil); err != nil {
		t.Fatal(err)
	}
	want := []string{"ensure peers [10.200.0.2]", "stage", "read drops", "flush", "ensure peers [10.200.0.2]", "converge"}
	if !reflect.DeepEqual(k.calls, want) {
		t.Errorf("resync calls = %v, want %v", k.calls, want)
	}
	if b.last.table != "fp2" {
		t.Errorf("recorded fingerprint %q, want the one read after the resync", b.last.table)
	}

	k.calls = nil
	p, err = b.Prepare(dataplane.Desired{WG: &w, ActivePeers: w.Peers})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Commit(nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range k.calls {
		if strings.HasPrefix(c, "ensure") {
			t.Errorf("a transaction without resync or peer change touched the device: %v", k.calls)
		}
	}
}

// While a peer removal is a pending repair, a differing peer set is not drift, but everything else
// still is.
func TestDriftOfWithPeerRepairPending(t *testing.T) {
	w := testWG(t, testPeer(t, "10.200.0.2"))
	last := committed{wg: &w, table: "fp1"}
	dev := deviceAsDeclared(w)
	dev.Peers = append(dev.Peers, wg.Peer{PublicKey: testPeer(t, "10.200.0.3").PublicKey, Address: netip.MustParseAddr("10.200.0.3")})
	if drift, err := driftOf("wgft0", last, dev, "fp1", true, true); err != nil || len(drift) > 0 {
		t.Errorf("peer difference during a pending peer repair: drift %v, err %v; want none", drift, err)
	}
	dev.Up = false
	if drift, _ := driftOf("wgft0", last, dev, "fp2", true, true); len(drift) != 2 {
		t.Errorf("table change and link down during a pending peer repair: drift %v, want both", drift)
	}
}
