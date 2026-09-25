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
	"time"

	"golang.org/x/sys/unix"
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

// tailnetIface は待ち受けを縛ったインタフェースの名前と番号(ifindex)。
type tailnetIface struct {
	name  string
	index int
}

// ifaceHolds はインタフェース i が ip をアドレスに持つかを返す。
func ifaceHolds(i *net.Interface, ip netip.Addr) bool {
	addrs, err := i.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if x, ok := netip.AddrFromSlice(ipn.IP); ok && x.Unmap() == ip {
			return true
		}
	}
	return false
}

// ifaceHolding は ip をアドレスに持つインタフェースを返す。無ければ ok は偽。
func ifaceHolding(ip netip.Addr) (tailnetIface, bool) {
	ifs, err := net.Interfaces()
	if err != nil {
		return tailnetIface{}, false
	}
	for i := range ifs {
		if ifaceHolds(&ifs[i], ip) {
			return tailnetIface{name: ifs[i].Name, index: ifs[i].Index}, true
		}
	}
	return tailnetIface{}, false
}

// listenTailnet は --admin-tailscale の待ち受けを ip:port で開く。Linux は宛先がローカルの
// アドレスならどのインタフェースから来たパケットも受ける(weak host model)ので、アドレスに
// bind するだけでは、事業者の網など tailnet 以外のインタフェースからも届く。そこで待ち受けを、
// そのアドレスを持つインタフェースに SO_BINDTOIFINDEX で縛り、加えて接続元を tailnet の帯に限る
// (設計文書 11 節)。縛れなければ待ち受けを開かずに誤りを返す。縛りはインタフェースの番号に
// 付くので、同じ名前で作り直されたインタフェースには効かない。作り直しは tailnetAdmin が見張る。
func listenTailnet(ctx context.Context, ip, port string) (net.Listener, tailnetIface, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, tailnetIface{}, err
	}
	iface, ok := ifaceHolding(addr.Unmap())
	if !ok {
		return nil, tailnetIface{}, fmt.Errorf("no interface holds the tailnet address %s", ip)
	}
	lc := net.ListenConfig{Control: bindToIfindex(iface)}
	ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort(addr.String(), port))
	if err != nil {
		return nil, tailnetIface{}, err
	}
	return &tailnetListener{Listener: ln}, iface, nil
}

// bindToIfindex は、ソケットを iface の番号に SO_BINDTOIFINDEX で縛る net.ListenConfig の Control を
// 返す。名前ではなく番号で縛るのは、見つけたインタフェースが縛るまでの間に作り直された場合に、
// 見張りが覚えた番号と縛り先を食い違わせないためである。縛れなければ誤りを返し、待ち受けは開かれない。
// 番号 0 は縛りを外す意味になるので拒む。負の番号はカーネルが EINVAL で拒む。
func bindToIfindex(iface tailnetIface) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		if iface.index == 0 {
			return fmt.Errorf("bind to interface %s: invalid index %d", iface.name, iface.index)
		}
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, iface.index)
		}); err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("bind to interface %s index %d: %w", iface.name, iface.index, serr)
		}
		return nil
	}
}

// tailnetWatchInterval は --admin-tailscale の待ち受けの縛り先を確かめる間隔。
const tailnetWatchInterval = 2 * time.Second

// tailnetWatchMaxInterval は、閉じている間に開き直しの試みが続けて失敗したときに伸ばす間隔の上限。
// 試みは `tailscale status --json` を起こすので、失敗が続く間は 2 秒ごとに起こさない。
const tailnetWatchMaxInterval = 30 * time.Second

// tailnetLinks は、見張りが読むインタフェースの状態。単体テストで差し替えるための境目。
type tailnetLinks interface {
	// state は名前 name のインタフェースの番号と、それが ip を持つかを返す。無ければ exists は偽。
	state(name string, ip netip.Addr) (index int, holds, exists bool)
	// candidate は、閉じている間に検出を試す値打ちがあるかを返す。名前 name のインタフェースか
	// tailscale で始まる名前のインタフェースが 100.64.0.0/10 のアドレスを持てば真。検出は
	// `tailscale status --json` を起こすので、見込みの無い間は 2 秒ごとに起こさない。
	candidate(name string) bool
}

type hostLinks struct{}

func (hostLinks) state(name string, ip netip.Addr) (int, bool, bool) {
	i, err := net.InterfaceByName(name)
	if err != nil {
		return 0, false, false
	}
	return i.Index, ifaceHolds(i, ip), true
}

func (hostLinks) candidate(name string) bool {
	if name != "" {
		if i, err := net.InterfaceByName(name); err == nil {
			if addrs, err := i.Addrs(); err == nil {
				if _, ip, _ := pickTailscaleAddr([]ifaceAddrs{{name: "tailscale", addrs: addrs}}); ip != "" {
					return true
				}
			}
		}
	}
	_, ip, _ := tailscaleIP()
	return ip != ""
}

// servedListener は応答中の待ち受けと、それを見張りが自分で閉じたかの印。
type servedListener struct {
	net.Listener
	closing atomic.Bool
}

// tailnetAdmin は --admin-tailscale の待ち受けを見張り、縛ったインタフェースが消えたか作り直されたか、
// そのアドレスを失ったときに閉じ、tailnet のアドレスが戻ったら開き直す(設計文書 11 節)。
// 状態は run の goroutine だけが触る。
type tailnetAdmin struct {
	port     string
	interval time.Duration
	links    tailnetLinks
	// detect は起動時と同じ検出。nameKnown は dnsName が `tailscale status` の答えであることを表す。
	// インタフェースからの検出では名前が分からないので偽になる。
	detect   func(context.Context) (ip, dnsName, detail string, nameKnown bool)
	listen   func(ctx context.Context, ip, port string) (net.Listener, tailnetIface, error)
	serve    func(net.Listener) error
	setHosts func([]string)
	errc     chan<- error

	ln      *servedListener
	ip      netip.Addr
	dnsName string // Host の許可に入れている MagicDNS 名。無ければ空
	iface   tailnetIface
	lastMsg string // 閉じている間の直前の試みの結果。同じ結果を繰り返しログに書かない
	// failures は閉じている間に続けて失敗した開き直しの試みの数。次の見張りまでの間隔を伸ばす。
	// 待ち受けを閉じるときと、見込みが無くて試みないときに 0 に戻す。開いている間は使わない
	failures int
}

func tailnetHosts(ip, dnsName string) []string {
	if dnsName != "" {
		return []string{ip, dnsName}
	}
	return []string{ip}
}

// start は開いた待ち受けで応答を始める。見張りが自分で閉じた待ち受けの Serve の終わりは誤りに
// しない。それ以外の終わりは、従来どおり errc に送って server を止める。
func (t *tailnetAdmin) start(ln net.Listener, ip netip.Addr, iface tailnetIface) {
	sl := &servedListener{Listener: ln}
	t.ln, t.ip, t.iface = sl, ip, iface
	go func() {
		err := t.serve(sl)
		if !sl.closing.Load() {
			t.errc <- fmt.Errorf("admin API tailscale: %w", err)
		}
	}()
}

// stop は待ち受けを閉じる。閉じるのは待ち受けだけで、受け付け済みの接続は応答を続け、
// TCP の待ち受けの期限(11 節)で切れる。
func (t *tailnetAdmin) stop() {
	if t.ln == nil {
		return
	}
	t.ln.closing.Store(true)
	t.ln.Close()
	t.ln = nil
}

// delay は次の見張りまでの間隔。開いている間と、閉じていても試みが失敗していない間は interval。
// 閉じている間に試みが続けて失敗すると、失敗のたびに倍にし、tailnetWatchMaxInterval で止める。
func (t *tailnetAdmin) delay() time.Duration {
	d := t.interval
	if t.ln != nil {
		return d
	}
	for i := 0; i < t.failures && d < tailnetWatchMaxInterval; i++ {
		d *= 2
	}
	return min(d, tailnetWatchMaxInterval)
}

// run は ctx が終わるまで delay ごとに check を呼ぶ。
func (t *tailnetAdmin) run(ctx context.Context) {
	timer := time.NewTimer(t.delay())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			t.stop()
			return
		case <-timer.C:
			t.check(ctx)
			timer.Reset(t.delay())
		}
	}
}

// check は 1 回の見張り。開いている間は縛り先を確かめ、食い違えば閉じる。閉じている間は検出を試し、
// tailnet のアドレスが見つかれば、古い待ち受けを閉じた後に新しい待ち受けを開く。
func (t *tailnetAdmin) check(ctx context.Context) {
	if t.ln != nil {
		index, holds, exists := t.links.state(t.iface.name, t.ip)
		var reason string
		switch {
		case !exists:
			reason = fmt.Sprintf("interface %s is gone", t.iface.name)
		case index != t.iface.index:
			reason = fmt.Sprintf("interface %s was recreated, index %d is now %d", t.iface.name, t.iface.index, index)
		case !holds:
			reason = fmt.Sprintf("interface %s no longer holds %s", t.iface.name, t.ip)
		default:
			return
		}
		addr := net.JoinHostPort(t.ip.String(), t.port)
		t.stop()
		t.lastMsg = ""
		t.failures = 0
		log.Printf("warning: admin API tailscale: %s; closed the listener on %s until a tailnet address is back", reason, addr)
	}
	if !t.links.candidate(t.iface.name) {
		t.failures = 0
		return
	}
	ip, dnsName, detail, nameKnown := t.detect(ctx)
	if ip == "" {
		t.fail("no tailnet address found yet")
		return
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		t.fail(err.Error())
		return
	}
	addr = addr.Unmap()
	// インタフェースからの検出は MagicDNS 名を知らない。アドレスが前と同じなら、前の名前を保つ。
	// アドレスが変わったなら、前の名前はもう自分を指さないので外す
	if !nameKnown && addr == t.ip {
		dnsName = t.dnsName
	}
	ln, iface, err := t.listen(ctx, ip, t.port)
	if err != nil {
		t.fail(err.Error())
		return
	}
	t.setHosts(tailnetHosts(ip, dnsName))
	t.dnsName = dnsName
	t.start(ln, addr, iface)
	t.lastMsg = ""
	log.Printf("admin API tailscale: listening again on %s, %s; bound to interface %s index %d", net.JoinHostPort(ip, t.port), detail, iface.name, iface.index)
}

// fail は閉じている間の試みの失敗を数え、直前と違うときだけログに書く。
func (t *tailnetAdmin) fail(msg string) {
	t.failures++
	if msg == t.lastMsg {
		return
	}
	t.lastMsg = msg
	log.Printf("admin API tailscale: still closed: %s", msg)
}
