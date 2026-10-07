package startup

import (
	"strconv"
	"strings"
	"testing"
)

func TestParseServerPrefix(t *testing.T) {
	ok := []string{"10.200.0.1/24", "10.9.0.1/16", "10.200.0.1/30", "192.168.50.129/25"}
	for _, s := range ok {
		if _, err := ParseServerPrefix(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := map[string]string{
		"10.200.0.5/24":   "first host address",
		"10.200.0.0/24":   "first host address",
		"10.200.0.2/24":   "first host address",
		"10.200.0.255/24": "first host address",
		"10.200.0.1/8":    "first host address",
		"10.200.0.1/31":   "no room for an agent",
		"10.200.0.1/32":   "no room for an agent",
		"fd00::1/64":      "IPv4",
		"10.200.0.1":      "not a valid",
		"nope":            "not a valid",
	}
	for s, want := range bad {
		_, err := ParseServerPrefix(s)
		if err == nil {
			t.Errorf("%s accepted", s)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %q lacks %q", s, err, want)
		}
		// 値そのものを引用する %q の外に丸括弧があってはならない
		if strings.ContainsAny(strings.ReplaceAll(err.Error(), strconv.Quote(s), ""), "()") {
			t.Errorf("%s: message has parentheses: %q", s, err)
		}
	}
}
