//go:build linux

// Package tailnet は server の --admin-tailscale の待ち受けを持つ(設計文書 11 節)。tailnet の
// アドレスの検出、待ち受けのインタフェースへの縛り、接続元の検査、インタフェースの作り直しの見張りを
// 行う。internal/vpsd の Daemon には依存せず、管理用 API の応答と Host の許可の更新は関数の値として
// 受け取る。
package tailnet

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
)

// ListenAdmin は --admin-tailscale の追加の待ち受けを開き、応答と見張りを始める。serve は待ち受け
// 1 つで管理用 API に応答し、setHosts は Host の検査で許す tailnet の名前を置き換える。応答の終わりの
// 誤りは errc に送る。tailnet のアドレスが見つからないときは警告をログに出して nil を返し、
// 見つかったアドレスで待ち受けを開けなかったときだけ誤りを返す。
func ListenAdmin(ctx context.Context, serve func(net.Listener) error, setHosts func([]string), errc chan<- error) error {
	return listenAdmin(ctx, detectAdminTailscale, listenTailnet, hostLinks{}, serve, setHosts, errc)
}

// listenAdmin は ListenAdmin の本体である。検出、待ち受けの開き方、インタフェースの読み取りを引数で
// 受け取るのは、実際の tailnet なしに単体テストするためである。
func listenAdmin(ctx context.Context,
	detect func(context.Context) (ip, dnsName, detail, other string, fromStatus bool),
	listen func(ctx context.Context, ip, port string) (net.Listener, tailnetIface, error),
	links tailnetLinks,
	serve func(net.Listener) error, setHosts func([]string), errc chan<- error) error {
	if ip, dnsName, detail, other, _ := detect(ctx); ip != "" {
		tsAddr := net.JoinHostPort(ip, adminTailscalePort)
		tsLn, iface, err := listen(ctx, ip, adminTailscalePort)
		if err != nil {
			return fmt.Errorf("admin API tailscale: %w", err)
		}
		setHosts(tailnetHosts(ip, dnsName))
		log.Printf("also listening for the admin API on Tailscale %s, %s; bound to interface %s index %d and accepting tailnet sources only", tsAddr, detail, iface.name, iface.index)
		ta := &tailnetAdmin{
			port:     adminTailscalePort,
			interval: tailnetWatchInterval,
			links:    links,
			detect: func(ctx context.Context) (string, string, string, bool) {
				ip, dnsName, detail, _, fromStatus := detect(ctx)
				return ip, dnsName, detail, fromStatus
			},
			listen:   listen,
			serve:    serve,
			setHosts: setHosts,
			errc:     errc,
		}
		addr, _ := netip.ParseAddr(ip)
		ta.dnsName = dnsName
		ta.start(tsLn, addr.Unmap(), iface)
		go ta.run(ctx)
	} else if other != "" {
		log.Printf("warning: --admin-tailscale set but %s has a 100.64.0.0/10 address and is not a Tailscale interface; the admin API is NOT listening there", other)
	} else {
		log.Printf("warning: --admin-tailscale set but no tailnet address within 100.64.0.0/10 found")
	}
	return nil
}
