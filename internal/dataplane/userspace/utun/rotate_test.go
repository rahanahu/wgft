package utun

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
)

// An agent that rotates its key gets a new peer at the same address. The new peer takes over the
// endpoint the old peer last had, so the server can start the handshake itself (design.md 5.2 節).
// A peer added at an address no other peer held gets no endpoint.
func TestSetPeersRotatedKeyTakesOverEndpoint(t *testing.T) {
	sk, _ := wgtypes.GeneratePrivateKey()
	srv, _ := newServerTunnel(t, sk, netip.MustParseAddr("10.200.0.1"))
	defer srv.Close()
	key := func() wgtypes.Key {
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		return k.PublicKey()
	}
	oldKey, newKey, otherKey := key(), key(), key()
	addr, otherAddr := netip.MustParseAddr("10.200.0.2"), netip.MustParseAddr("10.200.0.3")
	ep := netip.MustParseAddrPort("127.0.0.1:40001")

	if _, err := srv.SetPeers([]dataplane.Peer{{PublicKey: oldKey, Address: addr}}); err != nil {
		t.Fatal(err)
	}
	// WireGuard learns the endpoint from the agent's handshake; set it the same way the uapi does.
	if err := srv.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", hex.EncodeToString(oldKey[:]), ep)); err != nil {
		t.Fatal(err)
	}

	// the union a Prepare installs for a rotation: the new key only, since it takes the address
	changes, err := srv.SetPeers([]dataplane.Peer{{PublicKey: newKey, Address: addr}, {PublicKey: otherKey, Address: otherAddr}})
	if err != nil {
		t.Fatal(err)
	}
	peers, err := srv.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := peers[oldKey]; ok {
		t.Errorf("old peer is still there: %v", peers)
	}
	if got := peers[newKey].Endpoint; got != ep {
		t.Errorf("new peer endpoint = %v, want %v taken over from the old peer", got, ep)
	}
	if got := peers[otherKey].Endpoint; got.IsValid() {
		t.Errorf("peer at an address nobody held got endpoint %v, want none", got)
	}
	want := fmt.Sprintf("add peer %s at %s, taking over endpoint %s from peer %s", newKey, addr, ep, oldKey)
	found := false
	for _, c := range changes {
		found = found || c == want
	}
	if !found {
		t.Errorf("changes = %q, want a line %q", changes, want)
	}

	// A key the tunnel already has keeps what WireGuard learned for it, even when its address moves
	// to one another peer held: only a new key takes an endpoint over.
	if _, err := srv.SetPeers([]dataplane.Peer{{PublicKey: newKey, Address: netip.MustParseAddr("10.200.0.4")}, {PublicKey: otherKey, Address: addr}}); err != nil {
		t.Fatal(err)
	}
	if peers, err = srv.Peers(); err != nil {
		t.Fatal(err)
	}
	if got := peers[otherKey].Endpoint; got.IsValid() {
		t.Errorf("a known key moved to %s took endpoint %v, want none", addr, got)
	}
}
