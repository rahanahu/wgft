package dataplane

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func testPeer(t *testing.T, addr string) Peer {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	p := Peer{PublicKey: k.PublicKey()}
	if addr != "" {
		p.Address = netip.MustParseAddr(addr)
	}
	return p
}

// PeerUnion keeps the declared peers and the old peers an old dispatch may still route to, and
// leaves out an old peer whose address a declared peer takes over and one without an address.
func TestPeerUnion(t *testing.T) {
	a, b := testPeer(t, "10.200.0.2"), testPeer(t, "10.200.0.3")
	stale := testPeer(t, "10.200.0.9")
	rotated := testPeer(t, "10.200.0.2") // the old key of the agent at a's address
	foreign := testPeer(t, "")           // observed with AllowedIPs wgft does not declare
	got := PeerUnion([]Peer{a, b}, []Peer{a, stale, rotated, foreign})
	want := []Peer{a, b, stale}
	if !PeersEqual(got, want) || len(got) != len(want) {
		t.Errorf("PeerUnion = %v, want %v", got, want)
	}
}

func TestPeersEqual(t *testing.T) {
	a, b := testPeer(t, "10.200.0.2"), testPeer(t, "10.200.0.3")
	moved := Peer{PublicKey: a.PublicKey, Address: netip.MustParseAddr("10.200.0.4")}
	for _, tc := range []struct {
		x, y []Peer
		want bool
	}{
		{[]Peer{a, b}, []Peer{b, a}, true},
		{nil, []Peer{}, true},
		{[]Peer{a}, []Peer{a, b}, false},
		{[]Peer{a}, []Peer{moved}, false},
	} {
		if got := PeersEqual(tc.x, tc.y); got != tc.want {
			t.Errorf("PeersEqual(%v, %v) = %v, want %v", tc.x, tc.y, got, tc.want)
		}
	}
}
