// Package utun は、ユーザー空間モード(仕様 6.3 節)の VPS 側トンネル。
// wireguard-go の device と gVisor の netstack で listen_port を開き、10.200.0.1 を持つ。
// ピアの足し引きは IpcSet、状態の読み取りは IpcGet で行い、wgctrl もカーネルも使わない。
// エージェント側の internal/dataplane/userspace/tunnel と対になる。
package utun

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/sockbuf"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/wgbind"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/wgipc"
	"github.com/rahanahu/wgft/internal/nettun"
)

// Config はサーバ側トンネルの宣言。
type Config struct {
	PrivateKey wgtypes.Key
	ListenPort uint16
	Address    netip.Addr // 10.200.0.1
	MTU        int
	Logf       func(format string, args ...any)
}

// Tunnel は動いているサーバ側トンネル。
type Tunnel struct {
	cfg  Config
	dev  *device.Device
	tnet *nettun.Device

	mu    sync.Mutex
	peers map[wgtypes.Key]netip.Addr // 宣言済みのピア(SetPeers の差分計算用)
}

// PeerStatus は IpcGet から読んだピアの状態。カーネルモードの wgtypes.Peer に相当する。
type PeerStatus = wgipc.Peer

// New はトンネルを作って up する。listen_port が使えなければエラー(bind の失敗で分かる)。
func New(cfg Config) (*Tunnel, error) {
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.MTU <= 0 {
		cfg.MTU = 1420
	}
	tnet, err := nettun.Create(cfg.Address, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("netstack: %w", err)
	}
	t := &Tunnel{cfg: cfg, tnet: tnet, peers: map[wgtypes.Key]netip.Addr{}}
	t.dev = device.NewDevice(tnet, wgbind.New(), device.NewLogger(device.LogLevelError, "wg: "))
	ipc := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(cfg.PrivateKey[:]), cfg.ListenPort)
	if err := t.dev.IpcSet(ipc); err != nil {
		t.dev.Close()
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	if err := t.dev.Up(); err != nil {
		t.dev.Close()
		return nil, fmt.Errorf("wireguard up: %w", err)
	}
	cfg.Logf("userspace tunnel: up addr=%s mtu=%d listen=%d", cfg.Address, cfg.MTU, cfg.ListenPort)
	// CAP_NET_ADMIN を持つ server は sysctl の値を超えるバッファを得られるので、sysctl ではなく
	// 実際のソケットを測る(設計文書 7 節の「ソケットのバッファの条件」)
	sockbuf.Warn(sockbuf.MeasureDevice(t.dev.IpcGet), cfg.Logf)
	return t, nil
}

// ListenPort は実際に bind した wg の listen port を IpcGet から読み返す。Config.ListenPort が 0
// なら OS が空きポートを選ぶので(device.BindUpdate が net.ListenUDP と同じ規則で解決し、IpcGet は
// net.port が非 0 になった時点でその実際の値を返す。golang.zx2c4.com/wireguard の device/device.go
// と device/uapi.go)、この呼び出しでその値を読み返す。Config.ListenPort が 0 でなければ、その値が
// そのまま返る。
//
// Close の後に呼んでも誤りにはならず、bind していたときの listen_port を誤りとしてでは
// なく引き続き返す。wireguard-go の closeBindLocked(device/device.go)が net.port を 0 に
// 戻さず、IpcGetOperation(device/uapi.go)は net.port が非 0 の間ずっとその行を出すためである。
// 呼び出し側は戻り値を「今 bind している値」ではなく「直近に bind していた値」として扱う。
func (t *Tunnel) ListenPort() (uint16, error) {
	out, err := t.dev.IpcGet()
	if err != nil {
		return 0, err
	}
	return wgipc.ListenPort(out)
}

// SetPeers は宣言のピア集合に収束させる(足りないものを足し、余分を消す)。
// カーネルモードの wg.Ensure(internal/dataplane/linuxkernel/wg)のピア部分に相当し、変えた点を返す。
// ピアのエンドポイントは、エージェントからのハンドシェイクで学習する。例外は鍵を替えたエージェントの
// 新しいピアで、同じアドレスを持っていた古いピアのエンドポイントを引き継ぐ(設計文書 5.2 節。
// dataplane.InheritedEndpoint)。
func (t *Tunnel) SetPeers(peers []dataplane.Peer) (changes []string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	want := make(map[wgtypes.Key]netip.Addr, len(peers))
	for _, p := range peers {
		want[p.PublicKey] = p.Address
	}
	// 読めなければ引き継がずに進める。引き継ぎは断を縮めるだけで、無くてもエージェントの
	// ハンドシェイクでつながるので、ピアの変更そのものを失敗させない。
	held := t.heldPeers()
	var b strings.Builder
	for k := range t.peers {
		if _, ok := want[k]; !ok {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", hex.EncodeToString(k[:]))
			changes = append(changes, "delete peer "+k.String())
		}
	}
	for k, addr := range want {
		if have, ok := t.peers[k]; ok && have == addr {
			continue
		}
		fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n", hex.EncodeToString(k[:]), addr)
		if _, known := t.peers[k]; !known {
			if ep, from, ok := dataplane.InheritedEndpoint(held, k, addr); ok {
				fmt.Fprintf(&b, "endpoint=%s\n", ep)
				changes = append(changes, fmt.Sprintf("add peer %s at %s, taking over endpoint %s from peer %s", k, addr, ep, from))
				continue
			}
		}
		changes = append(changes, fmt.Sprintf("add peer %s at %s", k, addr))
	}
	if b.Len() == 0 {
		return nil, nil
	}
	if err := t.dev.IpcSet(b.String()); err != nil {
		return nil, fmt.Errorf("configure peers: %w", err)
	}
	t.peers = want
	return changes, nil
}

// heldPeers は、今のピアを dataplane.InheritedEndpoint が読む形で返す。アドレスは SetPeers が
// 宣言した値、エンドポイントは IpcGet が返す値である。IpcGet が失敗したら nil を返す。t.mu を
// 持って呼ぶ。
func (t *Tunnel) heldPeers() []dataplane.HeldPeer {
	if len(t.peers) == 0 {
		return nil
	}
	st, err := t.Peers()
	if err != nil {
		return nil
	}
	out := make([]dataplane.HeldPeer, 0, len(t.peers))
	for k, addr := range t.peers {
		ep := st[k].Endpoint
		out = append(out, dataplane.HeldPeer{PublicKey: k, Address: addr, Endpoint: netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port())})
	}
	return out
}

// Peers は IpcGet を解析してピアの状態を返す。
func (t *Tunnel) Peers() (map[wgtypes.Key]PeerStatus, error) {
	out, err := t.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	return wgipc.Peers(out), nil
}

// DialContext は netstack 越しにエージェントへ TCP 接続する(中継の向きの反転。仕様 6.3 節)。
// エージェントから見た送信元は t.cfg.Address の一時ポートになる。
func (t *Tunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	switch network {
	case "tcp":
		return t.tnet.DialTCP(ctx, ap)
	case "udp":
		return t.tnet.DialUDP(ap)
	}
	return nil, fmt.Errorf("dial %s: unknown network %q", addr, network)
}

// Close はトンネルを閉じる。
func (t *Tunnel) Close() { t.dev.Close() }

// DeclaredPeers は SetPeers で宣言済みのピア集合を返す(Backend の Observe が使う)。
func (t *Tunnel) DeclaredPeers() []dataplane.Peer {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]dataplane.Peer, 0, len(t.peers))
	for k, addr := range t.peers {
		out = append(out, dataplane.Peer{PublicKey: k, Address: addr})
	}
	return out
}
