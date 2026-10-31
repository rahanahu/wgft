package utun

import (
	"context"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/rahanahu/wgft/internal/nettun"
)

// netstack はサーバ側トンネルが netstack に求める非公開の面。エージェントのトンネル
// (internal/dataplane/userspace/tunnel の netstack)と同じく、実装はこの package の外へ出さない。
// 今の実装は gVisor(internal/nettun)だけである。
type netstack interface {
	tun.Device
	DialTCP(ctx context.Context, ap netip.AddrPort) (net.Conn, error)
	DialUDP(ap netip.AddrPort) (net.Conn, error)
}

// newNetstack は gVisor の Device を作る。
func newNetstack(addr netip.Addr, mtu int) (netstack, error) {
	d, err := nettun.Create(addr, mtu)
	if err != nil {
		return nil, err
	}
	return d, nil
}
