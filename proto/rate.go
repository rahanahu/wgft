package proto

import (
	"fmt"
	"strconv"
	"strings"
)

// RateUnit は Rate の時間単位。nftables の limit と同じ語を使う。
type RateUnit string

const (
	PerSecond RateUnit = "second"
	PerMinute RateUnit = "minute"
	PerHour   RateUnit = "hour"
	PerDay    RateUnit = "day"
	PerWeek   RateUnit = "week"
)

// Rate はレート制限の上限(仕様 5.3 節の new_flow_rate など)。
// JSON では nftables と同じ "100/second" の文字列で表す。
type Rate struct {
	Count uint64
	Unit  RateUnit
}

// ParseRate は "100/second" を解釈する。
func ParseRate(s string) (Rate, error) {
	count, unit, found := strings.Cut(s, "/")
	if !found {
		return Rate{}, fmt.Errorf("rate %q is not in N/unit form", s)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(count), 10, 64)
	if err != nil || n == 0 {
		return Rate{}, fmt.Errorf("rate %q count is not a positive integer", s)
	}
	u := RateUnit(strings.TrimSpace(unit))
	switch u {
	case PerSecond, PerMinute, PerHour, PerDay, PerWeek:
	default:
		return Rate{}, fmt.Errorf("rate %q unit is none of second/minute/hour/day/week", s)
	}
	return Rate{Count: n, Unit: u}, nil
}

func (r Rate) String() string { return fmt.Sprintf("%d/%s", r.Count, r.Unit) }

func (r Rate) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

func (r *Rate) UnmarshalText(b []byte) error {
	p, err := ParseRate(string(b))
	if err != nil {
		return err
	}
	*r = p
	return nil
}
