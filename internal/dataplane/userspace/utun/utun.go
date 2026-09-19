// Package utun は、ユーザー空間モード(仕様 6.3 節)の VPS 側トンネル。
// wireguard-go の device と gVisor の netstack で listen_port を開き、10.200.0.1 を持つ。
// ピアの足し引きは IpcSet、状態の読み取りは IpcGet で行い、wgctrl もカーネルも使わない。
// エージェント側の internal/agent/tunnel と対になる。
package utun

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
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
type PeerStatus struct {
	PublicKey     wgtypes.Key
	Endpoint      netip.AddrPort // 未確立ならゼロ値
	LastHandshake time.Time      // ゼロなら未確立
	RxBytes       int64
	TxBytes       int64
}

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
	t.dev = device.NewDevice(tnet, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg: "))
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
	return t, nil
}

// SetPeers は宣言のピア集合に収束させる(足りないものを足し、余分を消す)。
// カーネルモードの wg.Ensure(internal/vpsd/wg)のピア部分に相当し、変えた点を返す。
// ピアのエンドポイントは指定しない(エージェントからの握手でローミング学習する)。
func (t *Tunnel) SetPeers(peers []dataplane.Peer) (changes []string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	want := make(map[wgtypes.Key]netip.Addr, len(peers))
	for _, p := range peers {
		want[p.PublicKey] = p.Address
	}
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
		changes = append(changes, fmt.Sprintf("add peer %s (%s)", k, addr))
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

// Peers は IpcGet を解析してピアの状態を返す。
func (t *Tunnel) Peers() (map[wgtypes.Key]PeerStatus, error) {
	out, err := t.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	res := map[wgtypes.Key]PeerStatus{}
	var cur *PeerStatus
	flush := func() {
		if cur != nil {
			res[cur.PublicKey] = *cur
		}
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			raw, err := hex.DecodeString(v)
			if err != nil || len(raw) != wgtypes.KeyLen {
				cur = nil
				continue
			}
			var key wgtypes.Key
			copy(key[:], raw)
			cur = &PeerStatus{PublicKey: key}
		case "endpoint":
			if cur != nil {
				if ap, err := netip.ParseAddrPort(v); err == nil {
					cur.Endpoint = ap
				}
			}
		case "last_handshake_time_sec":
			if cur != nil {
				if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
					cur.LastHandshake = time.Unix(n, 0)
				}
			}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	flush()
	return res, nil
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

// DialUDP は netstack 越しにエージェントの UDP リスナーへつなぐ。
func (t *Tunnel) DialUDP(raddr netip.AddrPort) (net.Conn, error) {
	return t.tnet.DialUDP(raddr)
}

// Close はトンネルを閉じる。
func (t *Tunnel) Close() { t.dev.Close() }
