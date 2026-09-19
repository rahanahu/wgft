package allowtargets

import (
	"net/netip"
	"strings"
	"testing"
)

// 値が無い設定(空、空白だけ)は nil、つまり制限なしになる(仕様 11a 節)。
func TestParseEmptyMeansUnrestricted(t *testing.T) {
	for _, s := range []string{"", "   ", "\t"} {
		l, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if l != nil {
			t.Errorf("Parse(%q) = %v, want nil", s, l)
		}
		if !l.Allows(netip.MustParseAddrPort("192.168.1.1:22")) {
			t.Errorf("Parse(%q): an unset list must allow everything", s)
		}
	}
}

// 正しい項目は、正規化した形に読める。
func TestParseValid(t *testing.T) {
	tests := []struct{ in, want string }{
		{"192.168.1.0/24", "192.168.1.0/24"},
		{"192.168.1.20", "192.168.1.20/32"},
		{"192.168.1.20:25565", "192.168.1.20/32:25565"},
		{"192.168.1.0/24:2456-2458", "192.168.1.0/24:2456-2458"},
		{" 192.168.1.20:80 , 10.0.0.0/8 ", "192.168.1.20/32:80,10.0.0.0/8"},
		{"192.168.1.255/24", "192.168.1.0/24"}, // ホスト部は落とす
		{"2001:db8::1", "2001:db8::1/128"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"[2001:db8::/32]:8080", "[2001:db8::/32]:8080"},
		{"[2001:db8::1]:8080-8081", "[2001:db8::1/128]:8080-8081"},
	}
	for _, tt := range tests {
		l, err := Parse(tt.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", tt.in, err)
			continue
		}
		if got := l.String(); got != tt.want {
			t.Errorf("Parse(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// 値があるのに項目が 1 つも無い一覧は、黙って制限なしにせず、設定の誤りとして返す(仕様 11a 節)。
func TestParseSetButNoEntriesIsAnError(t *testing.T) {
	for _, s := range []string{",", " , ,", ", "} {
		l, err := Parse(s)
		if err == nil {
			t.Errorf("Parse(%q) = %v, want an error", s, l)
			continue
		}
		if !strings.Contains(err.Error(), "no entries") {
			t.Errorf("Parse(%q) error = %q, want it to say the value has no entries", s, err)
		}
	}
}

// 構文の誤りは誤りとして返す。呼び出し側は終了コード 3 の設定の誤りにする(仕様 11a 節)。
func TestParseInvalid(t *testing.T) {
	for _, s := range []string{
		"192.168.1.0/33",
		"192.168.1.999",
		"not a host",
		"192.168.1.20:0",
		"192.168.1.20:70000",
		"192.168.1.20:80-79",
		"192.168.1.20:80-",
		"192.168.1.20:http",
		"192.168.1.0/24:2456-2457-2458",
		"[2001:db8::1:8080",
		"[2001:db8::1]8080",
		"::ffff:192.168.1.1",
		"fe80::1%eth0",
	} {
		if l, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) = %v, want an error", s, l)
		} else if !strings.Contains(err.Error(), Env) {
			t.Errorf("Parse(%q) error %q does not name %s", s, err, Env)
		}
	}
}

// 照合は CIDR、単一ポート、ポートの範囲、IPv6 を扱う。
func TestAllows(t *testing.T) {
	l, err := Parse("192.168.1.0/24:2456-2458,192.168.2.10:25565,10.0.0.0/8,[2001:db8::/32]:8080")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		target string
		want   bool
	}{
		{"192.168.1.20:2456", true},
		{"192.168.1.20:2458", true},
		{"192.168.1.20:2459", false}, // 範囲の外
		{"192.168.1.20:22", false},
		{"192.168.3.20:2456", false}, // CIDR の外
		{"192.168.2.10:25565", true},
		{"192.168.2.10:25566", false}, // 単一ポートの外
		{"192.168.2.11:25565", false},
		{"10.1.2.3:22", true}, // ポートを書かない項目は全ポート
		{"10.1.2.3:65535", true},
		{"[2001:db8::1]:8080", true},
		{"[2001:db8::1]:8081", false},
		{"[2001:db9::1]:8080", false},
		{"[::ffff:10.1.2.3]:22", true}, // IPv4 射影は IPv4 として照合する
	}
	for _, tt := range tests {
		if got := l.Allows(netip.MustParseAddrPort(tt.target)); got != tt.want {
			t.Errorf("Allows(%s) = %v, want %v", tt.target, got, tt.want)
		}
	}
}

// 項目があって 1 つも一致しない一覧は正当な値で、すべてを拒む(仕様 11a 節)。
func TestListMatchingNothingDeniesAll(t *testing.T) {
	l, err := Parse("192.0.2.0/32:1")
	if err != nil {
		t.Fatal(err)
	}
	if l == nil {
		t.Fatal("want a list, got nil")
	}
	for _, target := range []string{"192.168.1.1:22", "192.0.2.0:2", "[2001:db8::1]:1"} {
		if l.Allows(netip.MustParseAddrPort(target)) {
			t.Errorf("Allows(%s) = true, want false", target)
		}
	}
}
