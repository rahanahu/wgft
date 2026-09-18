package proto

import (
	"fmt"
	"net/netip"
	"strings"
)

// ParseSource は接続元制限(source_deny / source_allow)の 1 項目を解釈する。
// CIDR か単独のアドレスを受け、単独のアドレスは /32(IPv6 なら /128)で補う。ホスト部は落とす。
// IPv4 かどうかはここでは見ない(Rule.Validate が見る)。CLI と Web UI が共有する。
func ParseSource(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		ip, err2 := netip.ParseAddr(s)
		if err2 != nil {
			return netip.Prefix{}, fmt.Errorf("%q is neither a CIDR nor an IP", s)
		}
		p = netip.PrefixFrom(ip, ip.BitLen())
	}
	return p.Masked(), nil
}

// ParseSourceLines は複数行のテキストを解釈する(Web UI の入力用)。
// 1 行に 1 つの CIDR かアドレスを書く。前後の空白と空行は無視する。
// 解釈できない行が 1 つでもあれば、その行番号(1 始まり、空行も数える)と内容を含むエラーで止め、
// それまでに解釈できた行があっても何も返さない(呼び出し側が入力をそのまま残せるようにするため)。
func ParseSourceLines(text string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := ParseSource(line)
		if err != nil {
			return nil, fmt.Errorf("line %d %q: %w", i+1, line, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// ParseSources は ParseSource を列に適用する。最初の誤りで止める。
func ParseSources(args []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, a := range args {
		p, err := ParseSource(a)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// AddSources は list の末尾に add を加える。list に既にある CIDR と、add の中の重複は加えない。
func AddSources(list, add []netip.Prefix) []netip.Prefix {
	out := append([]netip.Prefix{}, list...)
	for _, p := range add {
		if !containsPrefix(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// RemoveSources は list から rm に含まれる CIDR を除く。空になれば空のスライスを返す。
func RemoveSources(list, rm []netip.Prefix) []netip.Prefix {
	out := []netip.Prefix{}
	for _, p := range list {
		if !containsPrefix(rm, p) {
			out = append(out, p)
		}
	}
	return out
}

func containsPrefix(list []netip.Prefix, p netip.Prefix) bool {
	for _, q := range list {
		if q == p {
			return true
		}
	}
	return false
}
