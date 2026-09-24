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

// InheritedEndpoint gives a peer being added the endpoint of the peer that holds its address under
// another key (an agent that rotated its key), and nothing in every other case.
func TestInheritedEndpoint(t *testing.T) {
	old, rotated := testPeer(t, "10.200.0.2"), testPeer(t, "10.200.0.2")
	other := testPeer(t, "10.200.0.3")
	ep := netip.MustParseAddrPort("203.0.113.2:40001")
	held := func(p Peer, ep netip.AddrPort) HeldPeer {
		return HeldPeer{PublicKey: p.PublicKey, Address: p.Address, Endpoint: ep}
	}
	for _, tc := range []struct {
		name     string
		have     []HeldPeer
		add      Peer
		wantEP   netip.AddrPort
		wantFrom wgtypes.Key
	}{
		{"rotated key takes over the old peer's endpoint", []HeldPeer{held(other, netip.MustParseAddrPort("203.0.113.3:5")), held(old, ep)}, rotated, ep, old.PublicKey},
		{"the old peer has no endpoint yet", []HeldPeer{held(old, netip.AddrPort{})}, rotated, netip.AddrPort{}, wgtypes.Key{}},
		{"no peer holds the address", []HeldPeer{held(other, ep)}, rotated, netip.AddrPort{}, wgtypes.Key{}},
		{"the same key is not its own heir", []HeldPeer{held(old, ep)}, old, netip.AddrPort{}, wgtypes.Key{}},
		{"a held peer without a valid address matches nothing", []HeldPeer{{PublicKey: old.PublicKey, Endpoint: ep}}, rotated, netip.AddrPort{}, wgtypes.Key{}},
		{"a peer added without an address takes nothing", []HeldPeer{{PublicKey: old.PublicKey, Endpoint: ep}}, testPeer(t, ""), netip.AddrPort{}, wgtypes.Key{}},
		{"no peers", nil, rotated, netip.AddrPort{}, wgtypes.Key{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotEP, gotFrom, ok := InheritedEndpoint(tc.have, tc.add.PublicKey, tc.add.Address)
			if ok != tc.wantEP.IsValid() || gotEP != tc.wantEP || gotFrom != tc.wantFrom {
				t.Errorf("InheritedEndpoint = %v, %v, %v; want %v, %v", gotEP, gotFrom, ok, tc.wantEP, tc.wantFrom)
			}
		})
	}
}
