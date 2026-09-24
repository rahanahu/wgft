//go:build lab && linux

package wg

// ラボの network namespace で root として実行する (lab/lab test internal/dataplane/linuxkernel/wg)。
// エージェントのカーネルモードの単一ピアのインタフェースについて、作成、外からの変更への収束、
// 鍵による所有の判定、1 つ前の鍵、エンドポイントの変更、撤去を確かめる。サーバの wg0 のテストと
// 名前が重ならないよう、インタフェースは wgfta0 (エージェント) と wgfts0 (試験用のサーバ) を使う。

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/startup"
)

const (
	agentIf  = "wgfta0"
	serverIf = "wgfts0"
)

func labAgentCfg(t *testing.T) AgentConfig {
	t.Helper()
	return AgentConfig{
		Interface:  agentIf,
		PrivateKey: serverKey(t),
		Address:    netip.MustParsePrefix("10.201.0.2/24"),
		MTU:        1420,
		Server: ServerPeer{
			PublicKey: serverKey(t).PublicKey(),
			Address:   netip.MustParseAddr("10.201.0.1"),
			Endpoint:  netip.MustParseAddrPort("192.0.2.10:51820"),
			Keepalive: 25 * time.Second,
		},
	}
}

func ensureAgent(t *testing.T, cfg AgentConfig) []string {
	t.Helper()
	ch, err := EnsureAgent(cfg)
	if err != nil {
		t.Fatalf("EnsureAgent: %v", err)
	}
	return ch
}

// assertConverged は、wgfta0 が cfg のとおりであることを確かめる。
func assertConverged(t *testing.T, cfg AgentConfig, wantEndpoint netip.AddrPort) {
	t.Helper()
	link, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		t.Fatal(err)
	}
	if link.Attrs().MTU != cfg.MTU {
		t.Errorf("MTU = %d, want %d", link.Attrs().MTU, cfg.MTU)
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		t.Error("link is down")
	}
	addrs, err := ipv4Prefixes(link)
	if err != nil || len(addrs) != 1 || addrs[0] != cfg.Address {
		t.Errorf("addresses = %v (%v), want only %v", addrs, err, cfg.Address)
	}
	d := device(t, cfg.Interface)
	if d.PrivateKey != cfg.PrivateKey {
		t.Error("private key is not the current key")
	}
	if len(d.Peers) != 1 {
		t.Fatalf("peers = %+v, want only the server", d.Peers)
	}
	p := d.Peers[0]
	if p.PublicKey != cfg.Server.PublicKey {
		t.Errorf("peer is %s, want the server %s", p.PublicKey, cfg.Server.PublicKey)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0].String() != cfg.Server.Address.String()+"/32" {
		t.Errorf("AllowedIPs = %v, want only %s/32", p.AllowedIPs, cfg.Server.Address)
	}
	if got := peerEndpoint(&p); got != wantEndpoint {
		t.Errorf("endpoint = %v, want %v", got, wantEndpoint)
	}
	if p.PersistentKeepaliveInterval != cfg.Server.Keepalive {
		t.Errorf("keepalive = %v, want %v", p.PersistentKeepaliveInterval, cfg.Server.Keepalive)
	}
}

// 無ければ作り、単一のピア、エンドポイント、keepalive を持たせる。2 回目は何も変えない。
func TestAgentEnsureCreates(t *testing.T) {
	cleanup(agentIf)
	defer cleanup(agentIf)
	cfg := labAgentCfg(t)
	ch := ensureAgent(t, cfg)
	if len(ch) == 0 || !strings.Contains(ch[0], "create interface "+agentIf) {
		t.Errorf("changes = %q", ch)
	}
	assertConverged(t, cfg, cfg.Server.Endpoint)
	port := device(t, agentIf).ListenPort
	if port == 0 {
		t.Error("the kernel chose no listen port for an up link")
	}
	if ch := ensureAgent(t, cfg); len(ch) != 0 {
		t.Errorf("second EnsureAgent changed %q", ch)
	}
	if got := device(t, agentIf).ListenPort; got != port {
		t.Errorf("listen port moved %d -> %d on a no-op Ensure", port, got)
	}
}

// 外から変えた MTU、アドレス、up、ピア、AllowedIPs、keepalive、エンドポイントを宣言に戻す。
// 手で決めた待ち受けポートには触れない。
func TestAgentEnsureReconcilesDrift(t *testing.T) {
	cleanup(agentIf)
	defer cleanup(agentIf)
	cfg := labAgentCfg(t)
	ensureAgent(t, cfg)

	link, err := netlink.LinkByName(agentIf)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetMTU(link, 1300); err != nil {
		t.Fatal(err)
	}
	extra, _ := netlink.ParseAddr("10.99.9.9/24")
	if err := netlink.AddrAdd(link, extra); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetDown(link); err != nil {
		t.Fatal(err)
	}
	c, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	stray := serverKey(t).PublicKey()
	_, all, _ := net.ParseCIDR("0.0.0.0/0")
	_, band, _ := net.ParseCIDR("10.201.0.0/24")
	ka := 7 * time.Second
	port := 51944
	if err := c.ConfigureDevice(agentIf, wgtypes.Config{
		ListenPort: &port,
		Peers: []wgtypes.PeerConfig{
			{PublicKey: stray, AllowedIPs: []net.IPNet{*all}},
			{PublicKey: cfg.Server.PublicKey, UpdateOnly: true, ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{*band},
				PersistentKeepaliveInterval: &ka, Endpoint: udp("203.0.113.9:51820")},
		},
	}); err != nil {
		t.Fatal(err)
	}

	ch := ensureAgent(t, cfg)
	joined := strings.Join(ch, "\n")
	for _, want := range []string{"MTU 1300 -> 1420", "delete address 10.99.9.9/24", "delete peer " + stray.String(),
		"fix AllowedIPs", "server endpoint 203.0.113.9:51820 -> 192.0.2.10:51820", "server keepalive 7s -> 25s", "up"} {
		if !strings.Contains(joined, want) {
			t.Errorf("changes lack %q:\n%s", want, joined)
		}
	}
	assertConverged(t, cfg, cfg.Server.Endpoint)
	if got := device(t, agentIf).ListenPort; got != port {
		t.Errorf("listen port %d was changed to %d", port, got)
	}
}

// 鍵の一致しないインタフェースは、何も書かずに NotOursError で返す。起動の拒否にはしない。
func TestAgentEnsureRefusesForeignKey(t *testing.T) {
	cleanup(agentIf)
	defer cleanup(agentIf)
	fkey, fpeer := makeForeign(t, agentIf, "10.99.0.1/24", 51933)
	if l, err := netlink.LinkByName(agentIf); err != nil || netlink.LinkSetMTU(l, 1300) != nil {
		t.Fatal("cannot set the foreign MTU")
	}

	cfg := labAgentCfg(t)
	cfg.PreviousKey = serverKey(t) // 1 つ前の鍵があっても、どちらとも一致しなければ他人のもの
	_, err := EnsureAgent(cfg)
	var nie *NotOursError
	if !errors.As(err, &nie) || nie.Ownership != ForeignKey {
		t.Fatalf("err = %v, want *NotOursError ForeignKey", err)
	}
	if startup.IsRefusal(err) {
		t.Fatalf("a foreign interface became a startup refusal: %v", err)
	}
	for _, want := range []string{"ip link del " + agentIf, "would have converged", "set private key", "delete peer"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	d := device(t, agentIf)
	if d.PrivateKey != fkey || d.ListenPort != 51933 || len(d.Peers) != 1 || d.Peers[0].PublicKey != fpeer {
		t.Errorf("the foreign interface was changed: %+v", d)
	}
	if !hasAddr(t, agentIf, "10.99.0.1/24") || hasAddr(t, agentIf, "10.201.0.2/24") {
		t.Error("the foreign interface's addresses were changed")
	}
	if l, _ := netlink.LinkByName(agentIf); l.Attrs().MTU != 1300 {
		t.Errorf("the foreign MTU was changed to %d", l.Attrs().MTU)
	}
}

// 鍵を持たない WireGuard (ip link add type wireguard のまま) も自分のものとみなさない。
func TestAgentEnsureRefusesZeroKey(t *testing.T) {
	cleanup(agentIf)
	defer cleanup(agentIf)
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: agentIf}}); err != nil {
		t.Fatal(err)
	}
	_, err := EnsureAgent(labAgentCfg(t))
	var nie *NotOursError
	if !errors.As(err, &nie) || nie.Ownership != ForeignKey || !nie.Keyless {
		t.Fatalf("err = %v, want a keyless *NotOursError ForeignKey", err)
	}
	var zero wgtypes.Key
	if !strings.Contains(err.Error(), "left behind") || !strings.Contains(err.Error(), "ip link del "+agentIf) || strings.Contains(err.Error(), zero.String()) {
		t.Errorf("keyless text: %v", err)
	}
	if d := device(t, agentIf); d.PrivateKey != (wgtypes.Key{}) || len(d.Peers) != 0 {
		t.Errorf("the keyless interface was configured: %+v", d)
	}
}

// 同名の WireGuard 以外のリンクには触れない。
func TestAgentEnsureRefusesNotWireGuard(t *testing.T) {
	cleanup(agentIf)
	defer cleanup(agentIf)
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: agentIf}}); err != nil {
		t.Fatal(err)
	}
	_, err := EnsureAgent(labAgentCfg(t))
	var nie *NotOursError
	if !errors.As(err, &nie) || nie.Ownership != NotWireGuard || nie.Kind != "dummy" {
		t.Fatalf("err = %v, want *NotOursError NotWireGuard dummy", err)
	}
	l, e := netlink.LinkByName(agentIf)
	if e != nil || l.Type() != "dummy" {
		t.Fatalf("the dummy link is gone or changed: %v %v", l, e)
	}
	if addrs, _ := ipv4Prefixes(l); len(addrs) != 0 {
		t.Errorf("addresses were added to the dummy link: %v", addrs)
	}
}

// rotate-key の途中で落ちた場合:インタフェースは 1 つ前の鍵のまま。1 つ前の鍵を渡せば自分のものとして
// 今の鍵へ収束させ、ピアと待ち受けポートを保つ。1 つ前の鍵を渡さなければ他人のものに見える。
func TestAgentEnsureAcceptsPreviousKey(t *testing.T) {
	cleanup(agentIf)
	defer cleanup(agentIf)
	old := labAgentCfg(t)
	ensureAgent(t, old)
	port := device(t, agentIf).ListenPort

	rotated := old
	rotated.PrivateKey = serverKey(t)

	if _, err := EnsureAgent(rotated); err == nil {
		t.Fatal("without the previous key the interface was taken as ours")
	}
	if device(t, agentIf).PrivateKey != old.PrivateKey {
		t.Fatal("the refused Ensure changed the key")
	}

	rotated.PreviousKey = old.PrivateKey
	if own, err := AgentOwnership(agentIf, rotated.PrivateKey, rotated.PreviousKey); err != nil || own != OwnedByPreviousKey {
		t.Fatalf("ownership = %v, %v; want owned by the previous key", own, err)
	}
	ch := ensureAgent(t, rotated)
	if len(ch) != 1 || !strings.Contains(ch[0], "replace the previous private key") {
		t.Errorf("changes = %q, want only the key replacement", ch)
	}
	assertConverged(t, rotated, rotated.Server.Endpoint)
	if got := device(t, agentIf).ListenPort; got != port {
		t.Errorf("listen port moved %d -> %d with the key change", port, got)
	}
	if own, _ := AgentOwnership(agentIf, rotated.PrivateKey, rotated.PreviousKey); own != OwnedByCurrentKey {
		t.Errorf("after Ensure ownership = %v", own)
	}
}

// 引き直した名前の結果を渡すとエンドポイントだけが動き、解決できていない (ゼロ値) ときはカーネルの値を保つ。
func TestAgentEnsureEndpointInputs(t *testing.T) {
	cleanup(agentIf)
	defer cleanup(agentIf)
	cfg := labAgentCfg(t)
	cfg.Server.Endpoint = netip.AddrPort{} // 起動時に名前を解決できなかった
	ensureAgent(t, cfg)
	assertConverged(t, cfg, netip.AddrPort{})

	cfg.Server.Endpoint = netip.MustParseAddrPort("192.0.2.10:51820")
	if ch := ensureAgent(t, cfg); len(ch) != 1 || !strings.Contains(ch[0], "server endpoint none -> 192.0.2.10:51820") {
		t.Errorf("changes = %q", ch)
	}
	cfg.Server.Endpoint = netip.MustParseAddrPort("198.51.100.7:51820")
	if ch := ensureAgent(t, cfg); len(ch) != 1 || !strings.Contains(ch[0], "192.0.2.10:51820 -> 198.51.100.7:51820") {
		t.Errorf("changes = %q", ch)
	}
	cfg.Server.Endpoint = netip.AddrPort{}
	if ch := ensureAgent(t, cfg); len(ch) != 0 {
		t.Errorf("an unresolved endpoint changed %q", ch)
	}
	assertConverged(t, cfg, netip.MustParseAddrPort("198.51.100.7:51820"))
}

// makeServer は、同じ namespace の中に試験用のサーバ側の WireGuard を作る (待ち受けポート、
// エージェントの公開鍵のピア)。ハンドシェイクはループバックの UDP で成立する。
func makeServer(t *testing.T, key wgtypes.Key, agentPub wgtypes.Key, port int) {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: serverIf}}); err != nil {
		t.Fatal(err)
	}
	c, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, allowed, _ := net.ParseCIDR("10.201.0.2/32")
	if err := c.ConfigureDevice(serverIf, wgtypes.Config{PrivateKey: &key, ListenPort: &port,
		Peers: []wgtypes.PeerConfig{{PublicKey: agentPub, AllowedIPs: []net.IPNet{*allowed}}}}); err != nil {
		t.Fatal(err)
	}
	l, _ := netlink.LinkByName(serverIf)
	if err := netlink.LinkSetUp(l); err != nil {
		t.Fatal(err)
	}
}

func waitHandshake(t *testing.T, cfg AgentConfig, after time.Time) AgentState {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		st, err := InspectAgent(cfg.Interface, cfg.PrivateKey, cfg.PreviousKey)
		if err != nil {
			t.Fatal(err)
		}
		if len(st.Peers) == 1 && st.Peers[0].LastHandshake.After(after) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("no handshake after %v: %+v", after, st)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// 実際にハンドシェイクが成立し、InspectAgent がその時刻を値として返す。
func TestAgentHandshake(t *testing.T) {
	cleanup(agentIf, serverIf)
	defer cleanup(agentIf, serverIf)
	sk := serverKey(t)
	cfg := labAgentCfg(t)
	cfg.Server.PublicKey = sk.PublicKey()
	cfg.Server.Endpoint = netip.MustParseAddrPort("127.0.0.1:51941")
	cfg.Server.Keepalive = time.Second
	makeServer(t, sk, cfg.PrivateKey.PublicKey(), 51941)

	start := time.Now().Add(-time.Second)
	ensureAgent(t, cfg)
	st := waitHandshake(t, cfg, start)
	if st.Ownership != OwnedByCurrentKey || st.PublicKey != cfg.PrivateKey.PublicKey() || !st.Up || st.MTU != 1420 || st.ListenPort == 0 {
		t.Errorf("state = %+v", st)
	}
	p := st.Peers[0]
	if p.PublicKey != sk.PublicKey() || p.Endpoint != cfg.Server.Endpoint || p.Keepalive != time.Second ||
		len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != netip.MustParsePrefix("10.201.0.1/32") || p.TransmitBytes == 0 || p.ReceiveBytes == 0 {
		t.Errorf("peer = %+v", p)
	}
}

// 名前の引き直しの場面:古いエンドポイントではハンドシェイクが成立しない。引き直した結果を渡すと
// エンドポイントだけが動き、次の試行でハンドシェイクが成立する。
func TestAgentHandshakeAfterReResolution(t *testing.T) {
	cleanup(agentIf, serverIf)
	defer cleanup(agentIf, serverIf)
	sk := serverKey(t)
	cfg := labAgentCfg(t)
	cfg.Server.PublicKey = sk.PublicKey()
	cfg.Server.Endpoint = netip.MustParseAddrPort("127.0.0.1:51943") // サーバはもうここにいない
	cfg.Server.Keepalive = time.Second
	makeServer(t, sk, cfg.PrivateKey.PublicKey(), 51942)

	ensureAgent(t, cfg)
	time.Sleep(3 * time.Second)
	st, err := InspectAgent(agentIf, cfg.PrivateKey, cfg.PreviousKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Peers) != 1 || !st.Peers[0].LastHandshake.IsZero() {
		t.Fatalf("handshake with a stale endpoint: %+v", st.Peers)
	}

	moved := time.Now()
	cfg.Server.Endpoint = netip.MustParseAddrPort("127.0.0.1:51942")
	ch := ensureAgent(t, cfg)
	if len(ch) != 1 || !strings.Contains(ch[0], "127.0.0.1:51943 -> 127.0.0.1:51942") {
		t.Errorf("changes = %q, want only the endpoint", ch)
	}
	st = waitHandshake(t, cfg, moved)
	if st.Peers[0].Endpoint != cfg.Server.Endpoint {
		t.Errorf("endpoint after the move = %v", st.Peers[0].Endpoint)
	}
	t.Logf("handshake %v after the endpoint moved", st.Peers[0].LastHandshake.Sub(moved).Round(time.Millisecond))
}

// 撤去は自分の鍵 (今の鍵か 1 つ前の鍵) のインタフェースだけを消す。
func TestDeleteAgentLink(t *testing.T) {
	cleanup(agentIf)
	defer cleanup(agentIf)

	own, deleted, err := DeleteAgentLink(agentIf, serverKey(t), wgtypes.Key{})
	if err != nil || deleted || own != Absent {
		t.Fatalf("absent: own=%v deleted=%v err=%v", own, deleted, err)
	}

	cfg := labAgentCfg(t)
	ensureAgent(t, cfg)
	own, deleted, err = DeleteAgentLink(agentIf, cfg.PrivateKey, wgtypes.Key{})
	if err != nil || !deleted || own != OwnedByCurrentKey {
		t.Fatalf("current key: own=%v deleted=%v err=%v", own, deleted, err)
	}
	if _, e := netlink.LinkByName(agentIf); e == nil {
		t.Fatal("still there after delete")
	}

	ensureAgent(t, cfg)
	own, deleted, err = DeleteAgentLink(agentIf, serverKey(t), cfg.PrivateKey)
	if err != nil || !deleted || own != OwnedByPreviousKey {
		t.Fatalf("previous key: own=%v deleted=%v err=%v", own, deleted, err)
	}

	fkey, _ := makeForeign(t, agentIf, "10.99.0.1/24", 51934)
	own, deleted, err = DeleteAgentLink(agentIf, cfg.PrivateKey, serverKey(t))
	var nie *NotOursError
	if deleted || own != ForeignKey || !errors.As(err, &nie) || !strings.Contains(err.Error(), "ip link del "+agentIf) {
		t.Fatalf("foreign: own=%v deleted=%v err=%v", own, deleted, err)
	}
	if device(t, agentIf).PrivateKey != fkey {
		t.Fatal("the foreign interface was changed")
	}
	cleanup(agentIf)

	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: agentIf}}); err != nil {
		t.Fatal(err)
	}
	own, deleted, err = DeleteAgentLink(agentIf, cfg.PrivateKey, wgtypes.Key{})
	if deleted || own != NotWireGuard || !errors.As(err, &nie) {
		t.Fatalf("dummy: own=%v deleted=%v err=%v", own, deleted, err)
	}
	if _, e := netlink.LinkByName(agentIf); e != nil {
		t.Fatal("the dummy link is gone")
	}
}

// InspectAgent は他人のインタフェースも読むが、所有を ForeignKey とし、秘密鍵を返さない。
func TestInspectAgentForeign(t *testing.T) {
	cleanup(agentIf)
	defer cleanup(agentIf)
	fkey, fpeer := makeForeign(t, agentIf, "10.99.0.1/24", 51935)
	st, err := InspectAgent(agentIf, serverKey(t), wgtypes.Key{})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Exists || st.Ownership != ForeignKey || st.PublicKey != fkey.PublicKey() || st.ListenPort != 51935 ||
		len(st.Peers) != 1 || st.Peers[0].PublicKey != fpeer || !st.Peers[0].LastHandshake.IsZero() {
		t.Errorf("state = %+v", st)
	}
	st, err = InspectAgent("wgftnone0", serverKey(t), wgtypes.Key{})
	if err != nil || st.Exists || st.Ownership != Absent {
		t.Errorf("absent: %+v %v", st, err)
	}
}

// CAP_NET_ADMIN の無い呼び出し元の InspectAgent は、os.ErrPermission を包んだエラーを返す
// (agent doctor の needs_cap_net_admin の材料)。setpriv で権限を落とした子プロセスで確かめる。
func TestInspectAgentUnprivileged(t *testing.T) {
	if os.Getenv("WGFT_LAB_INSPECT_CHILD") != "" {
		_, err := InspectAgent(agentIf, wgtypes.Key{}, wgtypes.Key{})
		if err == nil {
			t.Fatal("CHILD: read the device without CAP_NET_ADMIN")
		}
		if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("CHILD: err = %v (%T), want it to wrap os.ErrPermission", err, err)
		}
		t.Logf("CHILD: %v", err)
		return
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Skip("setpriv is not installed")
	}
	cleanup(agentIf)
	defer cleanup(agentIf)
	ensureAgent(t, labAgentCfg(t))
	cmd := exec.Command(setpriv, "--reuid=65534", "--regid=65534", "--clear-groups", "--inh-caps=-all", "--bounding-set=-all",
		os.Args[0], "-test.run=^TestInspectAgentUnprivileged$", "-test.v")
	cmd.Env = append(os.Environ(), "WGFT_LAB_INSPECT_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unprivileged child failed: %v\n%s", err, out)
	}
	t.Logf("child:\n%s", out)
}

const lanIf = "wgftlan0"

// makeLAN は、同じ namespace に LAN 側のインタフェースを模した dummy のリンクを作る。
func makeLAN(t *testing.T, addr string) netlink.Link {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: lanIf}}); err != nil {
		t.Fatal(err)
	}
	l, err := netlink.LinkByName(lanIf)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "" {
		a, _ := netlink.ParseAddr(addr)
		if err := netlink.AddrAdd(l, a); err != nil {
			t.Fatal(err)
		}
	}
	if err := netlink.LinkSetUp(l); err != nil {
		t.Fatal(err)
	}
	return l
}

func addRoute(t *testing.T, l netlink.Link, dst string) {
	t.Helper()
	_, n, _ := net.ParseCIDR(dst)
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: l.Attrs().Index, Dst: n}); err != nil {
		t.Fatal(err)
	}
}

// エージェントのアドレス帯と重なる LAN のアドレスや経路があれば、何も作らずに普通のエラーで止まる。
// 帯より広い経路は妨げない (design.md 7b.1 節)。
func TestAgentEnsureRefusesAddressOverlap(t *testing.T) {
	cfg := labAgentCfg(t)
	cases := []struct {
		name, addr, route string
		want              string // 空なら通る
	}{
		{"LAN address in the range", "10.201.0.50/24", "", `address 10.201.0.50/24 on interface "` + lanIf + `"`},
		{"narrower route in the range", "192.168.77.1/24", "10.201.0.128/25", `route 10.201.0.128/25 on interface "` + lanIf + `"`},
		{"broader route", "192.168.77.1/24", "10.0.0.0/8", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cleanup(agentIf, lanIf)
			defer cleanup(agentIf, lanIf)
			l := makeLAN(t, c.addr)
			if c.route != "" {
				addRoute(t, l, c.route)
			}
			_, err := EnsureAgent(cfg)
			if c.want == "" {
				if err != nil {
					t.Fatalf("a broader route refused the agent: %v", err)
				}
				assertConverged(t, cfg, cfg.Server.Endpoint)
				return
			}
			if err == nil {
				t.Fatal("the overlap was not refused")
			}
			if startup.IsRefusal(err) {
				t.Fatalf("the overlap became a startup refusal: %v", err)
			}
			for _, want := range []string{c.want, "10.201.0.0/24", "WGFT_WG_ADDRESS", "server's operator"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error lacks %q: %v", want, err)
				}
			}
			if _, e := netlink.LinkByName(agentIf); e == nil {
				t.Error("the link was created despite the overlap")
			}
		})
	}
}

// 重なりは、既にある自分のインタフェースにも最初の書き込みの前に効き、そのインタフェースを変えない。
func TestAgentEnsureOverlapLeavesOwnLink(t *testing.T) {
	cleanup(agentIf, lanIf)
	defer cleanup(agentIf, lanIf)
	cfg := labAgentCfg(t)
	ensureAgent(t, cfg)
	l, _ := netlink.LinkByName(agentIf)
	if err := netlink.LinkSetMTU(l, 1300); err != nil {
		t.Fatal(err)
	}
	makeLAN(t, "10.201.0.50/24")
	if _, err := EnsureAgent(cfg); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("err = %v", err)
	}
	if l, _ := netlink.LinkByName(agentIf); l == nil || l.Attrs().MTU != 1300 {
		t.Error("the link was changed or removed although the overlap stopped the convergence")
	}
}

// 作った直後の段で失敗したら、作ったインタフェースを残さない。既にあったインタフェースは消さない。
func TestAgentEnsureRollsBackCreatedLink(t *testing.T) {
	cleanup(agentIf)
	defer cleanup(agentIf)
	defer func() { agentAfterCreate = nil }()
	var sawLink bool
	agentAfterCreate = func(iface string) error {
		_, err := netlink.LinkByName(iface)
		sawLink = err == nil
		return fmt.Errorf("injected failure after creating %s", iface)
	}
	cfg := labAgentCfg(t)
	if _, err := EnsureAgent(cfg); err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("err = %v", err)
	}
	if !sawLink {
		t.Fatal("the hook ran before the link existed")
	}
	if _, e := netlink.LinkByName(agentIf); e == nil {
		t.Fatal("the link created by the failed call was left behind")
	}

	// 既にある自分のインタフェースでは作成の段を通らない。
	agentAfterCreate = nil
	ensureAgent(t, cfg)
	agentAfterCreate = func(string) error { return errors.New("must not run for an existing link") }
	if _, err := EnsureAgent(cfg); err != nil {
		t.Fatalf("an existing link ran the creation path: %v", err)
	}
	if _, e := netlink.LinkByName(agentIf); e != nil {
		t.Fatal("the existing link is gone")
	}
}

// CAP_NET_ADMIN の無い EnsureAgent は、エージェントの言葉の prerequisite の拒否になる。
func TestEnsureAgentUnprivileged(t *testing.T) {
	if os.Getenv("WGFT_LAB_ENSURE_CHILD") != "" {
		_, err := EnsureAgent(labAgentCfg(t))
		r := startup.Of(err)
		if r == nil || r.Category != startup.CategoryPrerequisite {
			t.Fatalf("CHILD: err = %v, want a prerequisite refusal", err)
		}
		if !strings.Contains(r.Reason, "Run the agent as root") || strings.Contains(r.Reason, "server.service") {
			t.Fatalf("CHILD: reason is not the agent's: %q", r.Reason)
		}
		t.Logf("CHILD: %v", r.Reason)
		return
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Skip("setpriv is not installed")
	}
	cleanup(agentIf)
	defer cleanup(agentIf)
	cmd := exec.Command(setpriv, "--reuid=65534", "--regid=65534", "--clear-groups", "--inh-caps=-all", "--bounding-set=-all",
		os.Args[0], "-test.run=^TestEnsureAgentUnprivileged$", "-test.v")
	cmd.Env = append(os.Environ(), "WGFT_LAB_ENSURE_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unprivileged child failed: %v\n%s", err, out)
	}
	t.Logf("child:\n%s", out)
	if _, e := netlink.LinkByName(agentIf); e == nil {
		t.Error("the unprivileged child created the link")
	}
}
