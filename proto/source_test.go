package proto

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestParseSource(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"203.0.113.7", "203.0.113.7/32", true},
		{"203.0.113.7/32", "203.0.113.7/32", true},
		{"198.51.100.9/24", "198.51.100.0/24", true}, // ホスト部は落とす
		{"2001:db8::1", "2001:db8::1/128", true},     // IPv4 かどうかは Validate が見る
		{"", "", false},
		{"203.0.113.300", "", false},
		{"example.com", "", false},
		{"10.0.0.0/33", "", false},
	}
	for _, c := range cases {
		p, err := ParseSource(c.in)
		if (err == nil) != c.ok {
			t.Errorf("ParseSource(%q) err = %v, want ok=%v", c.in, err, c.ok)
			continue
		}
		if c.ok && p.String() != c.want {
			t.Errorf("ParseSource(%q) = %s, want %s", c.in, p, c.want)
		}
	}
	if _, err := ParseSources([]string{"192.0.2.1", "bad"}); err == nil {
		t.Error("ParseSources must fail on the first invalid entry")
	}
}

func TestParseSourceLines(t *testing.T) {
	mp := netip.MustParsePrefix
	got, err := ParseSourceLines("  203.0.113.7 \n\n198.51.100.0/24\n   \n")
	if err != nil {
		t.Fatalf("ParseSourceLines: %v", err)
	}
	want := []netip.Prefix{mp("203.0.113.7/32"), mp("198.51.100.0/24")}
	if !slices.Equal(got, want) {
		t.Errorf("ParseSourceLines = %v, want %v", got, want)
	}
	if _, err := ParseSourceLines("192.0.2.1\nnot-a-cidr\n203.0.113.7"); err == nil {
		t.Error("ParseSourceLines must fail on an invalid line")
	} else if !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "not-a-cidr") {
		t.Errorf("ParseSourceLines error = %q, want it to name line 2 and its content", err)
	}
	if got, err := ParseSourceLines("   \n\n"); err != nil || len(got) != 0 {
		t.Errorf("ParseSourceLines of blank input = %v, %v, want empty, no error", got, err)
	}
}

func TestAddRemoveSources(t *testing.T) {
	mp := netip.MustParsePrefix
	list := []netip.Prefix{mp("192.0.2.0/24")}
	got := AddSources(list, []netip.Prefix{mp("192.0.2.0/24"), mp("203.0.113.7/32"), mp("203.0.113.7/32")})
	want := []netip.Prefix{mp("192.0.2.0/24"), mp("203.0.113.7/32")}
	if !slices.Equal(got, want) {
		t.Errorf("AddSources = %v, want %v", got, want)
	}
	if len(list) != 1 {
		t.Errorf("AddSources modified its input: %v", list)
	}
	got = RemoveSources(want, []netip.Prefix{mp("192.0.2.0/24"), mp("198.51.100.0/24")})
	if !slices.Equal(got, []netip.Prefix{mp("203.0.113.7/32")}) {
		t.Errorf("RemoveSources = %v", got)
	}
	if got = RemoveSources(got, got); got == nil || len(got) != 0 {
		t.Errorf("RemoveSources of everything = %#v, want an empty non-nil slice", got)
	}
}
