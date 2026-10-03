package allowtargets

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/rahanahu/wgft/internal/reasontext"
)

// ブロードキャストとマルチキャストの宛先の判定(設計文書 7 節)。エージェントは、許可一覧の有無に
// 依らず、これらのアドレスへ転送しない。2 つのモードが同じ判定と同じ理由の文言を使う。

// limitedBroadcast は全域のブロードキャストのアドレスである。
var limitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// interfaceCacheTTL は、読んだインタフェースの一覧を読み直さずに使う長さである。ユーザー空間モードは
// 接続 1 本ごとと UDP のセッション 1 つごとに判定するので、そのたびにカーネルへ問い合わせない。
const interfaceCacheTTL = 5 * time.Second

// InterfacePrefixes はホストのインタフェースのアドレスとプレフィクス長を読む。
type InterfacePrefixes func() ([]netip.Prefix, error)

// HostPrefixes は、このホストのインタフェースのアドレスとプレフィクス長を読む。
func HostPrefixes() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		ones, bits := ipn.Mask.Size()
		if bits == 0 {
			continue // 正準でないマスク
		}
		// IPv4 のアドレスに 16 バイトのマスクが付く場合は、長さを Unmap の後のアドレスに合わせる
		if ip.Is4() && bits == 128 {
			ones -= 96
		}
		if ones < 0 || ones > ip.BitLen() {
			continue
		}
		out = append(out, netip.PrefixFrom(ip, ones))
	}
	return out, nil
}

// Unicast は、宛先のアドレスへ転送してよいかを判定する。NewUnicast で作る。nil の受け手は、
// インタフェースの一覧に依らない判定(全域のブロードキャストとマルチキャスト)だけを行う。
type Unicast struct {
	read InterfacePrefixes
	now  func() time.Time
	logf func(format string, args ...any)

	mu       sync.Mutex
	readAt   time.Time
	prefixes []netip.Prefix
	failed   bool // 直前の読み取りが失敗した。ログを変化のときだけ出す
}

// NewUnicast は判定を作る。read が nil ならこのホストの一覧(HostPrefixes)を読む。logf は一覧を
// 読めなくなったことと再び読めたことを出す先で、nil なら log.Printf である。
func NewUnicast(read InterfacePrefixes, logf func(format string, args ...any)) *Unicast {
	if read == nil {
		read = HostPrefixes
	}
	if logf == nil {
		logf = log.Printf
	}
	return &Unicast{read: read, now: time.Now, logf: logf}
}

// Refuse は、宛先のアドレス a へ転送しない理由を返す。転送してよければ空を返す。理由はそのまま
// ルールの理由になり、server doctor は reasontext.UnicastOnly で分類する。
func (u *Unicast) Refuse(a netip.Addr) string {
	a = a.Unmap()
	switch {
	case !a.IsValid():
		return ""
	case a == limitedBroadcast:
		return fmt.Sprintf("target %s is the limited broadcast address; "+reasontext.UnicastOnly, a)
	case a.IsMulticast():
		return fmt.Sprintf("target %s is a multicast address; "+reasontext.UnicastOnly, a)
	case !a.Is4() || u == nil:
		return ""
	}
	for _, p := range u.hostPrefixes() {
		if b, ok := directedBroadcast(p); ok && b == a {
			return fmt.Sprintf("target %s is the broadcast address of %s on this host; "+reasontext.UnicastOnly, a, p.Masked())
		}
	}
	return ""
}

// directedBroadcast は IPv4 の帯 p のブロードキャストのアドレス、つまり帯の末尾のアドレスを返す。
// /31 と /32 の帯は両端をホストのアドレスとして使うので、ブロードキャストのアドレスを持たない。
func directedBroadcast(p netip.Prefix) (netip.Addr, bool) {
	if !p.Addr().Is4() || p.Bits() < 0 || p.Bits() > 30 {
		return netip.Addr{}, false
	}
	b := p.Masked().Addr().As4()
	host := ^uint32(0) >> p.Bits()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
}

// hostPrefixes は、直近 interfaceCacheTTL の間に読んだ一覧を返す。古ければ読み直す。読めなければ
// 空を返し、帯のブロードキャストのアドレスの判定を行わない(設計文書 7 節)。
func (u *Unicast) hostPrefixes() []netip.Prefix {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := u.now()
	if !u.readAt.IsZero() && now.Sub(u.readAt) < interfaceCacheTTL && now.Sub(u.readAt) >= 0 {
		return u.prefixes
	}
	ps, err := u.read()
	u.readAt = now
	if err != nil {
		if !u.failed {
			u.logf("cannot read this host's interface addresses: %v; broadcast addresses of the host's networks are not refused until they can be read", err)
		}
		u.failed, u.prefixes = true, nil
		return nil
	}
	if u.failed {
		u.logf("reading this host's interface addresses again; broadcast addresses of the host's networks are refused again")
	}
	u.failed, u.prefixes = false, ps
	return ps
}
