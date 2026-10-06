package startup

import (
	"fmt"
	"net/netip"
)

// ParseServerPrefix は WGFT_WG_ADDRESS の値を解釈し、server の使える形かを確かめる。
// エージェントは server のトンネルアドレスを自分の帯の先頭の次(.1)と決め打ちするので、
// アドレス部分がそれ以外の帯は、エージェントが server に届かない。帯は IPv4 で、
// server(.1)とエージェント 1 台(.2)とブロードキャストが入る /30 以下の長さでなければならない。
// 返す誤りは値そのものの誤りで、呼び出し側が startup.Config に包む。
func ParseServerPrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		// netip の誤りは丸括弧を含む(netip.ParsePrefix("x"): ...)ので、文面に入れない
		return netip.Prefix{}, fmt.Errorf("%q is not a valid address/prefix such as 10.200.0.1/24", s)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv4 address/prefix such as 10.200.0.1/24", s)
	}
	if p.Bits() > 30 {
		return netip.Prefix{}, fmt.Errorf("%q leaves no room for an agent; use a prefix of /30 or shorter such as 10.200.0.1/24", s)
	}
	if p.Addr() != p.Masked().Addr().Next() {
		return netip.Prefix{}, fmt.Errorf("%q must use the first host address of its range as the server address, such as 10.200.0.1/24; if the database already recorded another range, changing it needs teardown --purge and re-registration", s)
	}
	return p, nil
}
