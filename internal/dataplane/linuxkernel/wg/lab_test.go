//go:build lab && linux

package wg

// ラボの vps ns で root として実行する(lab/lab test internal/dataplane/linuxkernel/wg)。
// 既存の「他人の wg」を作った状態で Ensure の所有判定・衝突検出・引き継ぎを確かめる。

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/startup"
)

func cleanup(names ...string) {
	for _, n := range names {
		if l, err := netlink.LinkByName(n); err == nil {
			_ = netlink.LinkDel(l)
		}
	}
}

// makeForeign は「他人の」wg インタフェースを作る(鍵・アドレス・ポート・ピア 1 つ)。
func makeForeign(t *testing.T, name, addr string, port int) (key wgtypes.Key, peer wgtypes.Key) {
	t.Helper()
	key, _ = wgtypes.GeneratePrivateKey()
	peerPriv, _ := wgtypes.GeneratePrivateKey()
	peer = peerPriv.PublicKey()
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		t.Fatalf("%s の作成: %v", name, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	a, err := netlink.ParseAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(link, a); err != nil {
		t.Fatalf("アドレス %s: %v", addr, err)
	}
	c, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, allowed, _ := net.ParseCIDR("10.99.0.2/32")
	if err := c.ConfigureDevice(name, wgtypes.Config{
		PrivateKey: &key, ListenPort: &port,
		Peers: []wgtypes.PeerConfig{{PublicKey: peer, AllowedIPs: []net.IPNet{*allowed}}},
	}); err != nil {
		t.Fatalf("%s の設定: %v", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	return key, peer
}

func device(t *testing.T, name string) *wgtypes.Device {
	t.Helper()
	c, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	d, err := c.Device(name)
	if err != nil {
		t.Fatalf("%s の読み取り: %v", name, err)
	}
	return d
}

func serverKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// 既定名 wgft0 で起動すると、既存の他人の wg0 に一切触れない。
func TestEnsureDoesNotTouchForeign(t *testing.T) {
	cleanup("wg0", "wgft0")
	defer cleanup("wg0", "wgft0")
	fkey, fpeer := makeForeign(t, "wg0", "10.99.0.1/24", 51820)

	sk := serverKey(t)
	if _, err := Ensure(Config{
		Interface: "wgft0", PrivateKey: sk, ListenPort: 51821,
		Address: netip.MustParsePrefix("10.200.0.1/24"), MTU: 1420,
	}); err != nil {
		t.Fatalf("wgft0 の作成で失敗: %v", err)
	}
	// wg0 は原状のまま。
	d := device(t, "wg0")
	if d.PrivateKey != fkey {
		t.Error("wg0 の鍵が書き換えられた")
	}
	if len(d.Peers) != 1 || d.Peers[0].PublicKey != fpeer {
		t.Errorf("wg0 のピアが変わった: %+v", d.Peers)
	}
	if !hasAddr(t, "wg0", "10.99.0.1/24") {
		t.Error("wg0 のアドレスが変わった")
	}
	// wgft0 は自分の鍵でできている。
	if device(t, "wgft0").PrivateKey != sk {
		t.Error("wgft0 が自分の鍵でない")
	}
}

// 鍵の一致しない既存 wg0 は、--adopt-existing なしでは何も書かずに拒否する。
func TestEnsureRefusesForeign(t *testing.T) {
	cleanup("wg0")
	defer cleanup("wg0")
	fkey, fpeer := makeForeign(t, "wg0", "10.99.0.1/24", 51820)

	sk := serverKey(t)
	_, err := Ensure(Config{
		Interface: "wg0", PrivateKey: sk, ListenPort: 51820,
		Address: netip.MustParsePrefix("10.200.0.1/24"), MTU: 1420,
	})
	// 資源の衝突は、相手が消えれば次の起動で通るので拒否(終了コード 3)にはしない(設計文書 11b 節)。
	if err == nil {
		t.Fatal("拒否されなかった")
	}
	if startup.IsRefusal(err) {
		t.Fatalf("他人のインタフェースとの衝突が起動の拒否になっている: %v", err)
	}
	if !strings.Contains(err.Error(), "would have converged") {
		t.Errorf("ドライランの差分が文面に無い: %v", err)
	}
	// wg0 は原状のまま(鍵・ピア・アドレス)。
	d := device(t, "wg0")
	if d.PrivateKey != fkey || len(d.Peers) != 1 || d.Peers[0].PublicKey != fpeer {
		t.Error("拒否したのに wg0 を書き換えた")
	}
	if !hasAddr(t, "wg0", "10.99.0.1/24") {
		t.Error("拒否したのに wg0 のアドレスを変えた")
	}
}

// --adopt-existing のときだけ、既存 wg0 を引き継いで自分の鍵に書き換える。
func TestEnsureAdoptExisting(t *testing.T) {
	cleanup("wg0")
	defer cleanup("wg0")
	makeForeign(t, "wg0", "10.99.0.1/24", 51820)

	sk := serverKey(t)
	if _, err := Ensure(Config{
		Interface: "wg0", PrivateKey: sk, ListenPort: 51820,
		Address: netip.MustParsePrefix("10.200.0.1/24"), MTU: 1420, AdoptExisting: true,
	}); err != nil {
		t.Fatalf("引き継ぎで失敗: %v", err)
	}
	if device(t, "wg0").PrivateKey != sk {
		t.Error("引き継いだのに鍵が自分のものになっていない")
	}
	if !hasAddr(t, "wg0", "10.200.0.1/24") {
		t.Error("引き継いだのにアドレスが収束していない")
	}
}

// 待ち受けポートが既存 WireGuard と衝突すると、作る前に拒否する。
func TestEnsurePortConflict(t *testing.T) {
	cleanup("wg0", "wgft0")
	defer cleanup("wg0", "wgft0")
	makeForeign(t, "wg0", "10.99.0.1/24", 51820)

	_, err := Ensure(Config{
		Interface: "wgft0", PrivateKey: serverKey(t), ListenPort: 51820,
		Address: netip.MustParsePrefix("10.200.0.1/24"), MTU: 1420,
	})
	if err == nil {
		t.Fatal("ポート衝突で中止されなかった")
	}
	if startup.IsRefusal(err) {
		t.Fatalf("ポートの衝突が起動の拒否になっている: %v", err)
	}
	if _, e := netlink.LinkByName("wgft0"); e == nil {
		t.Error("拒否したのに wgft0 を作ってしまった")
	}
}

// アドレス帯が既存インタフェースと重なると拒否する。
func TestEnsureAddrOverlap(t *testing.T) {
	cleanup("wg0", "wgft0")
	defer cleanup("wg0", "wgft0")
	makeForeign(t, "wg0", "10.200.0.9/24", 51820) // wgft と同じ 10.200.0.0/24

	_, err := Ensure(Config{
		Interface: "wgft0", PrivateKey: serverKey(t), ListenPort: 51821,
		Address: netip.MustParsePrefix("10.200.0.1/24"), MTU: 1420,
	})
	if err == nil {
		t.Fatal("アドレス重なりで中止されなかった")
	}
	if startup.IsRefusal(err) {
		t.Fatalf("アドレスの重なりが起動の拒否になっている: %v", err)
	}
}

func hasAddr(t *testing.T, name, addr string) bool {
	t.Helper()
	link, err := netlink.LinkByName(name)
	if err != nil {
		return false
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if a.IPNet.String() == addr {
			return true
		}
	}
	return false
}

// WireGuard 以外のプロセスが UDP ポートを使っていれば、インタフェースを作らずに中止する(仕様 9 節)。
func TestEnsureRefusesUDPPortInUse(t *testing.T) {
	cleanup("wgft0")
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 51877})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	key, _ := wgtypes.GeneratePrivateKey()
	_, err = Ensure(Config{Interface: "wgft0", Address: netip.MustParsePrefix("10.99.7.1/24"), ListenPort: 51877, MTU: 1420, PrivateKey: key})
	if err == nil {
		t.Fatal("UDP ポートを他のプロセスが使っているのに中止されなかった")
	}
	if startup.IsRefusal(err) {
		t.Fatalf("UDP ポートの衝突が起動の拒否になっている: %v", err)
	}
	if _, e := netlink.LinkByName("wgft0"); e == nil {
		t.Fatal("wgft0 was created despite the refusal")
	}
}

// 鍵の無い状態ファイル(空鍵)では、相手の鍵が空でも所有とみなさない。
func TestOwnedZeroKey(t *testing.T) {
	cleanup("wgft0")
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wgft0"}}); err != nil {
		t.Fatal(err)
	}
	defer cleanup("wgft0")
	owned, exists, err := Owned("wgft0", wgtypes.Key{})
	if err != nil || !exists || owned {
		t.Fatalf("owned=%v exists=%v err=%v; want owned=false exists=true", owned, exists, err)
	}
}

// DeleteLink は WireGuard 以外のリンクを消さない(--adopt-existing の撤去でも)。
func TestDeleteLinkRefusesNonWireGuard(t *testing.T) {
	cleanup("wgft0")
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "wgft0"}}); err != nil {
		t.Fatal(err)
	}
	defer cleanup("wgft0")
	if _, err := DeleteLink("wgft0"); err == nil {
		t.Fatal("DeleteLink deleted a dummy link named wgft0")
	}
	if _, e := netlink.LinkByName("wgft0"); e != nil {
		t.Fatal("the dummy link is gone")
	}
}

// 鍵を替えたエージェントの新しいピアは、同じアドレスを持っていた古いピアのエンドポイントを
// 引き継ぐ(設計文書 5.2 節)。古いピアを外し新しいピアを足す 1 回の Ensure で起きる。どのピアも
// 持っていなかったアドレスに足すピアは、エンドポイントを持たない。
func TestEnsureRotatedKeyTakesOverEndpoint(t *testing.T) {
	cleanup("wgft0")
	defer cleanup("wgft0")
	sk := serverKey(t)
	oldKey, newKey, otherKey := serverKey(t).PublicKey(), serverKey(t).PublicKey(), serverKey(t).PublicKey()
	addr, otherAddr := netip.MustParseAddr("10.200.0.2"), netip.MustParseAddr("10.200.0.3")
	cfg := Config{Interface: "wgft0", PrivateKey: sk, ListenPort: 51821, Address: netip.MustParsePrefix("10.200.0.1/24"), MTU: 1420,
		Peers: []Peer{{PublicKey: oldKey, Address: addr}}}
	if _, err := Ensure(cfg); err != nil {
		t.Fatal(err)
	}
	// WireGuard はエンドポイントをエージェントのハンドシェイクで学ぶ。ここでは直接書く
	ep := netip.MustParseAddrPort("203.0.113.2:40001")
	c, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.ConfigureDevice("wgft0", wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: oldKey, UpdateOnly: true, Endpoint: net.UDPAddrFromAddrPort(ep)}}}); err != nil {
		t.Fatal(err)
	}

	cfg.Peers = []Peer{{PublicKey: newKey, Address: addr}, {PublicKey: otherKey, Address: otherAddr}}
	changes, err := Ensure(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := map[wgtypes.Key]netip.AddrPort{}
	peers := device(t, "wgft0").Peers
	for i := range peers {
		got[peers[i].PublicKey] = peerEndpoint(&peers[i])
	}
	if _, ok := got[oldKey]; ok {
		t.Errorf("old peer is still there: %v", got)
	}
	if e := got[newKey]; e != ep {
		t.Errorf("new peer endpoint = %v, want %v taken over from the old peer", e, ep)
	}
	if e, ok := got[otherKey]; !ok || e.IsValid() {
		t.Errorf("peer at an address nobody held: present %v, endpoint %v; want present without an endpoint", ok, e)
	}
	want := "add peer " + newKey.String() + " at 10.200.0.2, taking over endpoint " + ep.String() + " from peer " + oldKey.String()
	if !strings.Contains(strings.Join(changes, "\n"), want) {
		t.Errorf("changes = %q, want a line %q", changes, want)
	}
}
