package proto

import (
	"fmt"
	"strconv"
	"strings"
)

// PortRange は VPS で待ち受けるポートの範囲(仕様 5.3 節の listen_port)。
// 単一ポートは Lo == Hi。JSON では "2456" または "2456-2457" の文字列で表す。
type PortRange struct {
	Lo, Hi uint16
}

// ParsePortRange は "2456" または "2456-2457" を解釈する。
func ParsePortRange(s string) (PortRange, error) {
	lo, hi, found := strings.Cut(s, "-")
	if !found {
		hi = lo
	}
	l, err := parsePort(lo)
	if err != nil {
		return PortRange{}, err
	}
	h, err := parsePort(hi)
	if err != nil {
		return PortRange{}, err
	}
	if l > h {
		return PortRange{}, fmt.Errorf("port range %q has a start greater than its end", s)
	}
	return PortRange{Lo: l, Hi: h}, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("port %q is not an integer in 1-65535", s)
	}
	return uint16(n), nil
}

func (r PortRange) String() string {
	if r.Lo == r.Hi {
		return strconv.Itoa(int(r.Lo))
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// Len は範囲に含まれるポート数。
func (r PortRange) Len() int { return int(r.Hi) - int(r.Lo) + 1 }

func (r PortRange) Contains(p uint16) bool { return r.Lo <= p && p <= r.Hi }

// IsRange は単一ポートでなく範囲かどうかを返す。Rule.Split の前提(仕様 10.1 節)。
func (r PortRange) IsRange() bool { return r.Lo != r.Hi }

func (r PortRange) Overlaps(o PortRange) bool { return r.Lo <= o.Hi && o.Lo <= r.Hi }

func (r PortRange) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

func (r *PortRange) UnmarshalText(b []byte) error {
	p, err := ParsePortRange(string(b))
	if err != nil {
		return err
	}
	*r = p
	return nil
}
