// Package wg は VPS(および将来の agent の kernel backend、Phase 7)の WireGuard インタフェースを
// 宣言に収束させる(仕様 4, 9 節、設計文書 7a.7 節)。インタフェースの作成とアドレス・MTU は
// netlink で、鍵・ポート・ピアは wgctrl で扱う。停止時には何も削除しない。internal/vpsd を
// import しない(internal/platform/linux の bind 中ポート検査だけを使う)。
package wg

import (
	"errors"
	"fmt"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/proto"
	"net"
	"net/netip"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Peer はエージェント 1 つ分のピア。AllowedIPs は Address の /32 だけ。
type Peer struct {
	PublicKey wgtypes.Key
	Address   netip.Addr
}

// Config は wg0 の宣言。
type Config struct {
	Interface  string
	PrivateKey wgtypes.Key
	ListenPort int
	Address    netip.Prefix // 10.200.0.1/24
	MTU        int
	Peers      []Peer
	// AdoptExisting が真のときだけ、鍵の一致しない既存インタフェースを引き継ぐ。
	// 既定は偽で、他人のインタフェースは収束させず StartupRefusal で中止する。
	AdoptExisting bool
}

// StartupRefusal は、他人の wg インタフェースやポート・アドレスの衝突を見つけて
// 収束を拒み、起動を中止させる理由。呼び出し側はこれを専用の終了コードに写す。
// 何も書き換える前に返るので、既存の設定は無傷のままである。
type StartupRefusal struct {
	Reason string
	DryRun []string // そのまま収束していたら加えていた変更(壊す前に見せる)
}

// Error は中止の理由と、収束するはずだった差分のドライランを 1 つの文にする。
func (e *StartupRefusal) Error() string {
	s := "refusing to start: " + e.Reason
	if len(e.DryRun) > 0 {
		s += ". would have converged by changing: " + strings.Join(e.DryRun, " / ")
	}
	return s
}

// Ensure は wg0 を宣言に収束させ、変えた点を返す。なければ作り、あれば差分だけ直す。
// 手作業で変えられたアドレス、MTU、ポート、ピア、秘密鍵はここで宣言に戻る。
// ただし収束するのは「自分が作ったインタフェース」だけで、既存の同名インタフェースは
// 鍵が一致する(=過去に自分が作った)ときにしか触らない。一致しなければ何も書かずに
// StartupRefusal を返す(仕様 9 節)。
func Ensure(cfg Config) (changes []string, err error) {
	created := false
	defer func() {
		// 作ったばかりのインタフェースは、後段で失敗したら残さない(残すと次の起動で「自分のもの」として
		// 収束はできるが、失敗の原因が消えるまで unit が再起動を繰り返す間、半端な状態が見える)
		if err != nil && created {
			if l, e := netlink.LinkByName(cfg.Interface); e == nil {
				_ = netlink.LinkDel(l)
			}
		}
	}()
	note := func(f string, a ...any) { changes = append(changes, fmt.Sprintf(f, a...)) }

	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	defer c.Close()

	// 衝突検査(何も書く前に)。他の WireGuard が同じ待ち受けポートを使っていれば、
	// そのまま起動しても ConfigureDevice が EADDRINUSE で失敗するので、先に中止する。
	if devs, e := c.Devices(); e == nil {
		if name, conflict := portConflict(devs, cfg.Interface, cfg.ListenPort); conflict {
			return nil, &StartupRefusal{Reason: fmt.Sprintf("listen port %d is already in use by existing WireGuard %q; use --wg-port to choose another port", cfg.ListenPort, name)}
		}
	}
	// WireGuard 以外のプロセスが同じ UDP ポートを bind していても ConfigureDevice が EADDRINUSE で
	// 失敗する。作ってから失敗すると unit が再起動を繰り返すので、作る前に /proc/net/udp で検出して中止する。
	if bound, e := linux.BoundPorts(); e == nil {
		if addrs := bound.Conflicts(proto.UDP, proto.PortRange{Lo: uint16(cfg.ListenPort), Hi: uint16(cfg.ListenPort)}); len(addrs) > 0 {
			if !ownsPort(c, cfg.Interface, cfg.ListenPort) {
				return nil, &StartupRefusal{Reason: fmt.Sprintf("UDP port %d is already bound by another process on %v; use --wg-port to choose another port", cfg.ListenPort, addrs[uint16(cfg.ListenPort)])}
			}
		}
	}
	// アドレス帯が他インタフェースと重なると、経路の衝突に加え 6.1 節の conntrack 収束が
	// 他人の DNAT 済みフローを消しうるので中止する。
	if refusal := checkAddrOverlap(cfg); refusal != nil {
		return nil, refusal
	}

	link, err := netlink.LinkByName(cfg.Interface)
	if _, notFound := err.(netlink.LinkNotFoundError); notFound {
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: cfg.Interface, MTU: cfg.MTU}}); err != nil {
			if errors.Is(err, unix.EOPNOTSUPP) {
				// カーネルが wireguard のリンク種別を知らない(モジュールが無い、ロードできない)。
				// 再起動しても直らないので、設定起因の中止として扱う(仕様 9 節)。
				return nil, &StartupRefusal{Reason: fmt.Sprintf("cannot create %s: this kernel has no WireGuard support (the wireguard module is missing or cannot be loaded; `modprobe wireguard` shows why). Kernel mode needs it; on a VPS without it, run the userspace mode instead (WGFT_MODE=userspace)", cfg.Interface)}
			}
			return nil, fmt.Errorf("cannot create %s: %w", cfg.Interface, err)
		}
		created = true
		note("create interface %s", cfg.Interface)
		if link, err = netlink.LinkByName(cfg.Interface); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("%s: %w", cfg.Interface, err)
	}
	if link.Type() != "wireguard" {
		return nil, fmt.Errorf("%s is not wireguard but %s", cfg.Interface, link.Type())
	}

	// 所有判定:既存インタフェースは、秘密鍵が SQLite のサーバ鍵と一致するときだけ収束させる。
	// 最初の書き込み(MTU・アドレス)より前に行う。後で読むと、他人のインタフェースを
	// 一部書き換えてから気づくことになる。
	if !created {
		dev, err := c.Device(cfg.Interface)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", cfg.Interface, err)
		}
		if dev.PrivateKey != cfg.PrivateKey && !cfg.AdoptExisting {
			return nil, &StartupRefusal{
				Reason: fmt.Sprintf("%s already exists but was not created by wgft, key does not match; use --wg-interface to pick another name, disable the unit bringing that wg up, or pass --adopt-existing to adopt it on purpose", cfg.Interface),
				DryRun: planChanges(link, dev, cfg),
			}
		}
	}

	if link.Attrs().MTU != cfg.MTU {
		if err := netlink.LinkSetMTU(link, cfg.MTU); err != nil {
			return nil, fmt.Errorf("MTU: %w", err)
		}
		note("MTU %d -> %d", link.Attrs().MTU, cfg.MTU)
	}

	want := &netlink.Addr{IPNet: prefixToIPNet(cfg.Address)}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	have := false
	for i := range addrs {
		a := &addrs[i]
		if a.IPNet.String() == want.IPNet.String() {
			have = true
			continue
		}
		if err := netlink.AddrDel(link, a); err != nil {
			return nil, fmt.Errorf("delete address %s: %w", a.IPNet, err)
		}
		note("delete address %s", a.IPNet)
	}
	if !have {
		if err := netlink.AddrAdd(link, want); err != nil {
			return nil, fmt.Errorf("add address %s: %w", want.IPNet, err)
		}
		note("add address %s", want.IPNet)
	}

	dev, err := c.Device(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", cfg.Interface, err)
	}
	wc := wgtypes.Config{}
	if dev.PrivateKey != cfg.PrivateKey {
		key := cfg.PrivateKey
		wc.PrivateKey = &key
		note("set private key; public key %s -> %s", dev.PublicKey, cfg.PrivateKey.PublicKey())
	}
	if dev.ListenPort != cfg.ListenPort {
		port := cfg.ListenPort
		wc.ListenPort = &port
		note("listen port %d -> %d", dev.ListenPort, cfg.ListenPort)
	}
	wantPeers := make(map[wgtypes.Key][]net.IPNet, len(cfg.Peers))
	for _, p := range cfg.Peers {
		wantPeers[p.PublicKey] = []net.IPNet{*prefixToIPNet(netip.PrefixFrom(p.Address, 32))}
	}
	for _, p := range dev.Peers {
		ips, ok := wantPeers[p.PublicKey]
		if !ok {
			wc.Peers = append(wc.Peers, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
			note("delete peer %s", p.PublicKey)
			continue
		}
		if !sameIPNets(p.AllowedIPs, ips) {
			wc.Peers = append(wc.Peers, wgtypes.PeerConfig{PublicKey: p.PublicKey, ReplaceAllowedIPs: true, AllowedIPs: ips})
			note("fix AllowedIPs of peer %s to %v", p.PublicKey, ips)
		}
		delete(wantPeers, p.PublicKey)
	}
	// map の順序は不定なので、宣言の順に足す
	for _, p := range cfg.Peers {
		if ips, ok := wantPeers[p.PublicKey]; ok {
			wc.Peers = append(wc.Peers, wgtypes.PeerConfig{PublicKey: p.PublicKey, ReplaceAllowedIPs: true, AllowedIPs: ips})
			note("add peer %s (%s)", p.PublicKey, p.Address)
		}
	}
	if wc.PrivateKey != nil || wc.ListenPort != nil || len(wc.Peers) > 0 {
		if err := c.ConfigureDevice(cfg.Interface, wc); err != nil {
			return nil, fmt.Errorf("configure %s: %w", cfg.Interface, err)
		}
	}

	if link.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(link); err != nil {
			return nil, fmt.Errorf("up: %w", err)
		}
		note("up")
	}
	return changes, nil
}

// Owned は iface が存在し、その秘密鍵が expectedKey と一致する(=wgft が作った)かを返す。
// 撤去(teardown)で、他人の wg を消さないための事前判定に使う。
func Owned(iface string, expectedKey wgtypes.Key) (owned, exists bool, err error) {
	link, e := netlink.LinkByName(iface)
	if _, nf := e.(netlink.LinkNotFoundError); nf {
		return false, false, nil
	}
	if e != nil {
		return false, false, e
	}
	if link.Type() != "wireguard" {
		return false, true, nil
	}
	c, e := wgctrl.New()
	if e != nil {
		return false, true, e
	}
	defer c.Close()
	dev, e := c.Device(iface)
	if e != nil {
		return false, true, e
	}
	// 鍵が無い(状態ファイルにサーバ鍵が無い)ときは、相手の鍵が空でも自分のものとはみなさない
	if expectedKey == (wgtypes.Key{}) {
		return false, true, nil
	}
	return dev.PrivateKey == expectedKey, true, nil
}

// DeleteLink は iface を削除する。無ければ false, nil(撤去を途中からでも走らせられるように)。
// 所有判定は呼び出し側(Owned)で済ませてから呼ぶこと。
func DeleteLink(iface string) (bool, error) {
	link, err := netlink.LinkByName(iface)
	if _, nf := err.(netlink.LinkNotFoundError); nf {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// --adopt-existing で所有判定を飛ばしても、WireGuard 以外のリンク(同名の veth や bridge)は消さない
	if link.Type() != "wireguard" {
		return false, fmt.Errorf("%s is not a WireGuard interface but %s; refusing to delete it", iface, link.Type())
	}
	if err := netlink.LinkDel(link); err != nil {
		return false, fmt.Errorf("delete %s: %w", iface, err)
	}
	return true, nil
}

// Status は wg0 の現在の状態(表示と監視用)。
func Status(iface string) (*wgtypes.Device, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Device(iface)
}

// OtherDeviceWithKey は、iface 以外に同じ秘密鍵を持つ WireGuard デバイス(=改名で残った自分の
// 旧インタフェース)があればその名前を返す。列挙できなければ黙って false。
func OtherDeviceWithKey(iface string, key wgtypes.Key) (string, bool) {
	c, err := wgctrl.New()
	if err != nil {
		return "", false
	}
	defer c.Close()
	devs, err := c.Devices()
	if err != nil {
		return "", false
	}
	for _, d := range devs {
		if d.Name != iface && d.PrivateKey == key {
			return d.Name, true
		}
	}
	return "", false
}

// portConflict は、iface 以外の WireGuard が port を使っていればその名前を返す。
// ownsPort は、UDP ポートを bind しているのが自分のインタフェース(再起動後の収束で同じポートを持つ)かを返す。
func ownsPort(c *wgctrl.Client, iface string, port int) bool {
	dev, err := c.Device(iface)
	return err == nil && dev.ListenPort == port
}

func portConflict(devs []*wgtypes.Device, iface string, port int) (string, bool) {
	for _, d := range devs {
		if d.Name != iface && d.ListenPort == port {
			return d.Name, true
		}
	}
	return "", false
}

// checkAddrOverlap は、cfg.Address の帯(/24)が cfg.Interface 以外のインタフェースの
// アドレスと重なっていれば StartupRefusal を返す。検査できなければ黙って通す。
func checkAddrOverlap(cfg Config) *StartupRefusal {
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}
	band := cfg.Address.Masked()
	for _, l := range links {
		if l.Attrs().Name == cfg.Interface {
			continue
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip, ok := netip.AddrFromSlice(a.IP)
			if !ok {
				continue
			}
			if band.Contains(ip.Unmap()) {
				return &StartupRefusal{Reason: fmt.Sprintf("address range %s overlaps with existing interface %q address %s; use --wg-address to choose another range", cfg.Address, l.Attrs().Name, a.IP)}
			}
		}
	}
	return nil
}

// planChanges は、そのまま収束していたら加えていた変更をドライランで列挙する。
// 所有判定で拒む前に、何を壊すところだったかを見せるために使う。
func planChanges(link netlink.Link, dev *wgtypes.Device, cfg Config) []string {
	var out []string
	if link.Attrs().MTU != cfg.MTU {
		out = append(out, fmt.Sprintf("MTU %d->%d", link.Attrs().MTU, cfg.MTU))
	}
	if addrs, err := netlink.AddrList(link, netlink.FAMILY_V4); err == nil {
		want := prefixToIPNet(cfg.Address).String()
		have := false
		for _, a := range addrs {
			if a.IPNet.String() == want {
				have = true
			} else {
				out = append(out, "delete address "+a.IPNet.String())
			}
		}
		if !have {
			out = append(out, "add address "+want)
		}
	}
	if dev.PrivateKey != cfg.PrivateKey {
		out = append(out, "replace the private key")
	}
	if dev.ListenPort != cfg.ListenPort {
		out = append(out, fmt.Sprintf("listen port %d->%d", dev.ListenPort, cfg.ListenPort))
	}
	want := make(map[wgtypes.Key]bool, len(cfg.Peers))
	for _, p := range cfg.Peers {
		want[p.PublicKey] = true
	}
	for _, p := range dev.Peers {
		if !want[p.PublicKey] {
			out = append(out, "delete peer "+p.PublicKey.String())
		}
	}
	return out
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func sameIPNets(a, b []net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, n := range a {
		seen[n.String()] = true
	}
	for _, n := range b {
		if !seen[n.String()] {
			return false
		}
	}
	return true
}
