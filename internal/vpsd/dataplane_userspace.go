package vpsd

// ユーザー空間モードの転送面(仕様 6.3 節)。カーネルの WireGuard、nftables、conntrack を使わず、
// wireguard-go + netstack のトンネル(utun)と、ホストのソケットで受けて netstack 越しに
// エージェントへ渡す中継(relay.Manager の向きの反転)で同じ dataplane インタフェースを満たす。

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/relay"
	"github.com/rahanahu/wgft/internal/vpsd/check"
	"github.com/rahanahu/wgft/internal/vpsd/conncheck"
	ctconv "github.com/rahanahu/wgft/internal/vpsd/conntrack"
	"github.com/rahanahu/wgft/internal/vpsd/nft"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/internal/vpsd/utun"
	"github.com/rahanahu/wgft/internal/vpsd/wg"
	"github.com/rahanahu/wgft/proto"
)

// flowPolicy は接続元制限とレート制限の評価器(nftables の代わり。仕様 6.3 節)。
type flowPolicy interface {
	Update(rules []proto.Rule)
	AdmitFlow(ruleID string, src netip.Addr, size int) (ok bool, kind string)
	AdmitPacket(ruleID string, size int) bool
	SourceAllowed(ruleID string, src netip.Addr) bool
	Drops() []nft.Drop
}

// userspaceDataplane はユーザー空間モードの転送面。
type userspaceDataplane struct {
	policy flowPolicy
	relay  *relay.Manager

	mu  sync.Mutex
	tun *utun.Tunnel
	cfg wg.Config // 直近の宣言(鍵、ポート、アドレス)
}

// hostNetwork はホストの全アドレスでリスナーを開く(公開ポート)。
type hostNetwork struct{}

func (hostNetwork) ListenUDP(port uint16) (net.PacketConn, error) {
	return net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
}
func (hostNetwork) ListenTCP(port uint16) (net.Listener, error) {
	return net.Listen("tcp", ":"+strconv.Itoa(int(port)))
}

func newUserspaceDataplane(policy flowPolicy) *userspaceDataplane {
	u := &userspaceDataplane{policy: policy}
	u.relay = relay.New(hostNetwork{}, relay.Options{
		UDPIdleTimeout: 120 * time.Second, // conntrack の udp_timeout_stream の既定と同じ
		Dial:           u.dial,
		Logf:           log.Printf,
		Admit: func(ruleID string, src netip.Addr) bool {
			ok, _ := policy.AdmitFlow(ruleID, src, 0)
			return ok
		},
		AdmitPacket: policy.AdmitPacket,
	})
	return u
}

// dial は netstack 越しにエージェントのリスナーへつなぐ(relay と conncheck の Dial)。
func (u *userspaceDataplane) dial(network, addr string) (net.Conn, error) {
	u.mu.Lock()
	t := u.tun
	u.mu.Unlock()
	if t == nil {
		return nil, fmt.Errorf("tunnel is not up")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return t.DialContext(ctx, network, addr)
}

// ProxyDial はプロキシモードの中継(PROXY protocol 付き TCP)が使う Dial。
func (u *userspaceDataplane) ProxyDial(addr string) (net.Conn, error) { return u.dial("tcp", addr) }

func (u *userspaceDataplane) EnsureWG(cfg wg.Config) ([]string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	var changes []string
	if u.tun == nil {
		t, err := utun.New(utun.Config{PrivateKey: cfg.PrivateKey, ListenPort: uint16(cfg.ListenPort), Address: cfg.Address.Addr(), MTU: cfg.MTU, Logf: log.Printf})
		if err != nil {
			return nil, err
		}
		u.tun = t
		u.cfg = cfg
		changes = append(changes, fmt.Sprintf("userspace tunnel up on port %d", cfg.ListenPort))
	} else if u.cfg.ListenPort != cfg.ListenPort || u.cfg.PrivateKey != cfg.PrivateKey || u.cfg.Address != cfg.Address || u.cfg.MTU != cfg.MTU {
		// 起動後に鍵やポートが変わることは無い(設定は起動時に固定)。念のため拒否する
		return nil, fmt.Errorf("userspace tunnel: key, port, address or MTU changed while running; restart the server")
	}
	peerChanges, err := u.tun.SetPeers(cfg.Peers)
	if err != nil {
		return nil, err
	}
	return append(changes, peerChanges...), nil
}

func (u *userspaceDataplane) WGStatus() (*wgtypes.Device, error) {
	u.mu.Lock()
	t, cfg := u.tun, u.cfg
	u.mu.Unlock()
	if t == nil {
		return nil, fmt.Errorf("tunnel is not up")
	}
	peers, err := t.Peers()
	if err != nil {
		return nil, err
	}
	dev := &wgtypes.Device{Name: "userspace", Type: wgtypes.Userspace, PrivateKey: cfg.PrivateKey, PublicKey: cfg.PrivateKey.PublicKey(), ListenPort: cfg.ListenPort}
	for _, p := range peers {
		wp := wgtypes.Peer{PublicKey: p.PublicKey, LastHandshakeTime: p.LastHandshake, ReceiveBytes: p.RxBytes, TransmitBytes: p.TxBytes}
		if p.Endpoint.IsValid() {
			wp.Endpoint = net.UDPAddrFromAddrPort(p.Endpoint)
		}
		dev.Peers = append(dev.Peers, wp)
	}
	return dev, nil
}

func (u *userspaceDataplane) OtherDeviceWithKey(wgtypes.Key) (string, bool) { return "", false }

// ReadUDPTimeouts はカーネルの conntrack を使わないので、既定値をそのまま配る(エージェントの UDP セッションの期限)。
func (u *userspaceDataplane) ReadUDPTimeouts() (wg.UDPTimeouts, error) {
	return wg.UDPTimeouts{Timeout: 30, TimeoutStream: 120}, nil
}

// Inspect は他テーブルの検査を行わない(nftables を使わない。仕様 6.3 節)。
func (u *userspaceDataplane) Inspect() (*check.Report, error) { return &check.Report{}, nil }

// BoundPorts は空。bind の失敗がそのまま分かる(仕様 6.3 節)。
func (u *userspaceDataplane) BoundPorts() (check.Bound, error) {
	return check.Bound{proto.TCP: {}, proto.UDP: {}}, nil
}

// InputPortSuggestions は input が policy drop なら足す行を返す。nftables を読めない(非 root)ときは提示しない。
func (u *userspaceDataplane) InputPortSuggestions(port uint16) ([]string, error) {
	lines, err := check.InputPortSuggestions(port)
	if err != nil {
		return nil, nil
	}
	return lines, nil
}

func (u *userspaceDataplane) ReadDrops() ([]nft.Drop, error) { return u.policy.Drops(), nil }

// ApplyNFT はルール集合をリスナーの宣言に写す。プロキシモード(PROXY protocol)のルールは
// Daemon の proxyrelay が受け持つので、ここでは vps_mode = kernel のルールだけを開く。
func (u *userspaceDataplane) ApplyNFT(rules []proto.Rule, agentAddr map[string]netip.Addr) error {
	u.policy.Update(rules)
	desired := map[relay.Key]relay.Desired{}
	for i := range rules {
		r := &rules[i]
		if !r.Enabled || r.VPSMode == proto.ModeProxy {
			continue
		}
		addr, ok := agentAddr[r.Agent]
		if !ok {
			continue
		}
		for p := int(r.ListenPort.Lo); p <= int(r.ListenPort.Hi); p++ {
			desired[relay.Key{Proto: r.Proto, Port: uint16(p)}] = relay.Desired{Target: net.JoinHostPort(addr.String(), strconv.Itoa(p)), RuleID: r.ID}
		}
	}
	u.relay.Apply(desired)
	return nil
}

// Converge は接続元制限を満たさなくなった進行中のセッションを閉じる(conntrack 収束の代わり。仕様 6.3 節)。
func (u *userspaceDataplane) Converge([]ctconv.Rule, netip.Prefix) (int, error) {
	return u.relay.CloseSessions(u.policy.SourceAllowed), nil
}

func (u *userspaceDataplane) EnableIPForward(*store.Store) *check.Finding { return nil }

func (u *userspaceDataplane) CheckConnectivity(addr string) conncheck.Result {
	return conncheck.Check(addr, conncheck.Options{Dial: u.dial})
}
