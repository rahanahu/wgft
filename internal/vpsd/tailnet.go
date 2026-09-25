//go:build linux

package vpsd

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
)

// tailnetPrefixes は Tailscale がノードのアドレスを割り当てる帯(設計文書 11 節)。
// tailscale.com/net/tsaddr の CGNATRange と TailscaleULARange に合わせてある。
// IPv4 の帯は Tailscale 専用ではなく VPS 事業者の内部網にも使われるので、これだけでは
// 事業者の網の隣人を区別できない。その区別は待ち受けを tailnet のインタフェースに縛る
// SO_BINDTODEVICE が担い、この検査は縛りが外れた場合の二重の守りである。
var tailnetPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

// tailnetSource は接続元のアドレスが tailnetPrefixes のどれかに入るかを返す。
// IPv4 を写した IPv6 の形(::ffff:100.64.0.1)は IPv4 に戻してから比べる。
func tailnetSource(a net.Addr) bool {
	var ip net.IP
	switch v := a.(type) {
	case *net.TCPAddr:
		ip = v.IP
	case *net.UDPAddr:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	default:
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, p := range tailnetPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// tailnetListener は、接続元が tailnet の帯に無い接続を、HTTP を 1 バイトも読まずに閉じる。
// Host の検査より前の受け口で落とすので、Host を偽っても届かない。
type tailnetListener struct {
	net.Listener
	logged atomic.Bool
}

func (l *tailnetListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if tailnetSource(c.RemoteAddr()) {
			return c, nil
		}
		// 拒否のたびに書くと、接続を繰り返すだけでログを溢れさせられるので、最初の 1 回だけ書く
		if l.logged.CompareAndSwap(false, true) {
			log.Printf("warning: admin API tailscale: closed a connection from %s, which is not a tailnet address; further ones are closed without a log line", c.RemoteAddr())
		}
		c.Close()
	}
}

// ifaceHolding は ip をアドレスに持つインタフェースの名前を返す。無ければ空。
func ifaceHolding(ip netip.Addr) string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifs {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if x, ok := netip.AddrFromSlice(ipn.IP); ok && x.Unmap() == ip {
				return i.Name
			}
		}
	}
	return ""
}

// listenTailnet は --admin-tailscale の待ち受けを ip:port で開く。Linux は宛先がローカルの
// アドレスならどのインタフェースから来たパケットも受ける(weak host model)ので、アドレスに
// bind するだけでは、事業者の網など tailnet 以外のインタフェースからも届く。そこで待ち受けを、
// そのアドレスを持つインタフェースに SO_BINDTODEVICE で縛り、加えて接続元を tailnet の帯に限る
// (設計文書 11 節)。縛れなければ待ち受けを開かずに誤りを返す。
func listenTailnet(ctx context.Context, ip, port string) (net.Listener, string, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, "", err
	}
	iface := ifaceHolding(addr.Unmap())
	if iface == "" {
		return nil, "", fmt.Errorf("no interface holds the tailnet address %s", ip)
	}
	lc := net.ListenConfig{Control: bindToDevice(iface)}
	ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort(addr.String(), port))
	if err != nil {
		return nil, "", err
	}
	return &tailnetListener{Listener: ln}, iface, nil
}

// bindToDevice は、ソケットを iface に SO_BINDTODEVICE で縛る net.ListenConfig の Control を返す。
// 縛れなければ誤りを返し、待ち受けは開かれない。
func bindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("bind to device %s: %w", iface, serr)
		}
		return nil
	}
}
