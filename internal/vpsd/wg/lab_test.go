//go:build lab

package wg

// ラボの vps ns で root として実行する(lab/lab test internal/vpsd/wg)。
// 既存の「他人の wg」を作った状態で Ensure の所有判定・衝突検出・引き継ぎを確かめる。

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
	var refusal *StartupRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("拒否されなかった: %v", err)
	}
	if len(refusal.DryRun) == 0 {
		t.Error("ドライランの差分が空")
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
	var refusal *StartupRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("ポート衝突で拒否されなかった: %v", err)
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
	var refusal *StartupRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("アドレス重なりで拒否されなかった: %v", err)
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
