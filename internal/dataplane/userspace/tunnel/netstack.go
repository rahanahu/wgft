package tunnel

import (
	"fmt"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/rahanahu/wgft/internal/nettun"
	"github.com/rahanahu/wgft/internal/wgstack"
)

// エージェントの netstack の実装(設計文書 wgstack.md の「トンネルとの境目と選択」)。2 つの実装が同じ面を
// 満たすので、中継と internal/agent は実装を名指さない。この package だけが internal/nettun と
// internal/wgstack の両方を import する。

// 実装の名前。WGFT_AGENT_NETSTACK の値である。空は gvisor を指す。
const (
	NetstackGVisor  = "gvisor"
	NetstackWgstack = "wgstack"
)

// netstack は 2 つの実装が満たす非公開の面。
type netstack interface {
	tun.Device
	ListenUDP(netip.AddrPort) (net.PacketConn, error)
	ListenTCP(netip.AddrPort) (net.Listener, error)
	DialPing(laddr, raddr netip.Addr) (net.Conn, error)
	UDPReceiveFault() error
}

type gvisorNetstack struct{ *nettun.Device }

func (g gvisorNetstack) ListenTCP(ap netip.AddrPort) (net.Listener, error) {
	l, err := g.Device.ListenTCP(ap)
	if err != nil {
		return nil, err
	}
	return l, nil
}

type wgstackNetstack struct{ *wgstack.Device }

func (w wgstackNetstack) ListenTCP(ap netip.AddrPort) (net.Listener, error) {
	l, err := w.Device.ListenTCP(ap)
	if err != nil {
		return nil, err
	}
	return l, nil
}

// newNetstack は宣言の実装の Device を作る。作れなくても別の実装に切り替えない。
func newNetstack(cfg Config) (netstack, error) {
	switch cfg.Netstack {
	case "", NetstackGVisor:
		d, err := nettun.Create(cfg.Address, cfg.MTU)
		if err != nil {
			return nil, err
		}
		return gvisorNetstack{d}, nil
	case NetstackWgstack:
		d, err := wgstack.New(wgstack.Config{Addr: cfg.Address, MTU: cfg.MTU, MaxFlows: cfg.MaxTCPFlows, SendBatch: sendBatchConfig(cfg.SendBatchPackets)})
		if err != nil {
			return nil, err
		}
		return wgstackNetstack{d}, nil
	}
	return nil, fmt.Errorf("unknown netstack %q; use %s or %s", cfg.Netstack, NetstackGVisor, NetstackWgstack)
}
