// Package allowtargets は、エージェントが接続してよい宛先の一覧(設計文書 7 節)。
// WGFT_AGENT_ALLOW_TARGETS の値を読み、(アドレス, ポート) の組が一覧に入るかを判定する。
// VPS を奪った攻撃者がルールの target を書き換えて、エージェントを自宅の LAN への踏み台に
// することを狭めるための一覧であり、エージェントのホストの設定だけにある(11 節)。
package allowtargets

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Env は一覧を渡す設定の名前。起動ログと拒否の理由に出す。
const Env = "WGFT_AGENT_ALLOW_TARGETS"

// entry は一覧の 1 項目。lo が 0 なら prefix の全ポートを許す。
type entry struct {
	prefix netip.Prefix
	lo, hi uint16
}

func (e entry) String() string {
	p := e.prefix.String()
	if e.lo == 0 {
		return p
	}
	if e.prefix.Addr().Is4() {
		p += ":"
	} else {
		p = "[" + p + "]:"
	}
	if e.lo == e.hi {
		return p + strconv.Itoa(int(e.lo))
	}
	return p + strconv.Itoa(int(e.lo)) + "-" + strconv.Itoa(int(e.hi))
}

// List は宛先の許可一覧。nil は「設定が無い」を表し、すべての宛先を許す。
type List struct{ entries []entry }

// Parse は設定の値を読む。値が空(空白だけを含む)なら nil を返す(設定が無いのと同じ扱いで、
// 制限しない。設計文書 11a 節)。構文の誤りは誤りとして返し、呼び出し側が設定起因の失敗として扱う。
// 値があるのに項目が 1 つも無い場合(コンマだけを書いた場合など)も誤りとする。守りの設定なので、
// 書いたつもりの一覧が黙って「制限なし」になるより、起動を止めるほうが安全である。
func Parse(s string) (*List, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var l List
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		e, err := parseEntry(f)
		if err != nil {
			return nil, err
		}
		l.entries = append(l.entries, e)
	}
	if len(l.entries) == 0 {
		return nil, fmt.Errorf("%s: %q has no entries; leave it unset to allow every target", Env, s)
	}
	return &l, nil
}

// Allows は宛先への接続を許すかを返す。受け手が nil なら制限しない。
func (l *List) Allows(ap netip.AddrPort) bool {
	if l == nil {
		return true
	}
	addr := ap.Addr().Unmap()
	for _, e := range l.entries {
		if !e.prefix.Contains(addr) {
			continue
		}
		if e.lo == 0 || (ap.Port() >= e.lo && ap.Port() <= e.hi) {
			return true
		}
	}
	return false
}

// String は正規化した一覧をコンマ区切りで返す。起動ログに出す。
func (l *List) String() string {
	if l == nil {
		return ""
	}
	parts := make([]string, 0, len(l.entries))
	for _, e := range l.entries {
		parts = append(parts, e.String())
	}
	return strings.Join(parts, ",")
}

// parseEntry は 1 項目を読む。形は CIDR、CIDR:port、CIDR:lo-hi で、アドレスだけなら /32 か /128 とする。
// ポートを付ける IPv6 の項目は、target の書き方(host:port)と同じく角括弧で囲む。
func parseEntry(s string) (entry, error) {
	addrPart, portPart := s, ""
	switch {
	case strings.HasPrefix(s, "["):
		i := strings.IndexByte(s, ']')
		if i < 0 {
			return entry{}, entryErr(s, "has no closing bracket")
		}
		addrPart = s[1:i]
		switch rest := s[i+1:]; {
		case rest == "":
		case strings.HasPrefix(rest, ":"):
			portPart = rest[1:]
		default:
			return entry{}, entryErr(s, "has trailing text after the brackets")
		}
	case strings.Count(s, ":") == 1:
		i := strings.IndexByte(s, ':')
		addrPart, portPart = s[:i], s[i+1:]
	case strings.Count(s, ":") > 1:
		// ポートの無い IPv6 の項目。ポートを付けるなら角括弧が要る
	}
	p, err := parsePrefix(s, addrPart)
	if err != nil {
		return entry{}, err
	}
	if portPart == "" {
		return entry{prefix: p}, nil
	}
	lo, hi, err := parsePorts(s, portPart)
	if err != nil {
		return entry{}, err
	}
	return entry{prefix: p, lo: lo, hi: hi}, nil
}

func parsePrefix(whole, addrPart string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(addrPart, "/") {
		q, err := netip.ParsePrefix(addrPart)
		if err != nil {
			return p, entryErr(whole, "is not a CIDR, CIDR:port or CIDR:lo-hi")
		}
		p = q.Masked()
	} else {
		a, err := netip.ParseAddr(addrPart)
		if err != nil {
			return p, entryErr(whole, "is not a CIDR, CIDR:port or CIDR:lo-hi")
		}
		if a.Zone() != "" {
			return p, entryErr(whole, "must not carry an IPv6 zone")
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, entryErr(whole, "is an IPv4-mapped IPv6 address; write it as IPv4")
	}
	return p, nil
}

func parsePorts(whole, portPart string) (lo, hi uint16, err error) {
	loStr, hiStr, isRange := strings.Cut(portPart, "-")
	if !isRange {
		hiStr = loStr
	}
	l, err1 := port(loStr)
	h, err2 := port(hiStr)
	if err1 != nil || err2 != nil {
		return 0, 0, entryErr(whole, "port is not an integer in 1-65535")
	}
	if l > h {
		return 0, 0, entryErr(whole, "port range is not in lo-hi order")
	}
	return l, h, nil
}

func port(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return uint16(n), nil
}

func entryErr(whole, what string) error {
	return fmt.Errorf("%s: entry %q %s", Env, whole, what)
}
