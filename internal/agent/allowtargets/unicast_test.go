package allowtargets

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/reasontext"
)

// fixedPrefixes はインタフェースの一覧の代わりに、決まった帯を返す。
func fixedPrefixes(ps ...string) InterfacePrefixes {
	return func() ([]netip.Prefix, error) {
		out := make([]netip.Prefix, len(ps))
		for i, p := range ps {
			out[i] = netip.MustParsePrefix(p)
		}
		return out, nil
	}
}

func quietUnicast(read InterfacePrefixes) *Unicast {
	return NewUnicast(read, func(string, ...any) {})
}

// ブロードキャストとマルチキャストのアドレスを拒み、理由が server doctor の読む句を含むことを固定する
// (設計文書 7 節)。帯のブロードキャストのアドレスは、インタフェースの一覧の帯の末尾だけである。
func TestUnicastRefuses(t *testing.T) {
	u := quietUnicast(fixedPrefixes(
		"192.168.50.2/24", // 末尾 192.168.50.255
		"192.168.0.10/23", // 末尾 192.168.1.255。192.168.0.255 は帯の中のホスト
		"10.0.0.0/31",     // 両端ともホスト
		"10.9.9.9/32",     // ホスト 1 つ
		"172.16.0.5/30",   // 末尾 172.16.0.7
		"127.0.0.1/8",     // ループバックの帯の末尾 127.255.255.255
		"fd00::1/64",      // IPv6 の帯にブロードキャストは無い
		"100.64.0.1/10",   // 末尾 100.127.255.255
	))
	for _, tc := range []struct {
		addr string
		want string // 空なら拒まない
	}{
		{"255.255.255.255", "target 255.255.255.255 is the limited broadcast address; " + reasontext.UnicastOnly},
		{"224.0.0.1", "target 224.0.0.1 is a multicast address; " + reasontext.UnicastOnly},
		{"239.1.2.3", "target 239.1.2.3 is a multicast address; " + reasontext.UnicastOnly},
		{"239.255.255.250", "target 239.255.255.250 is a multicast address; " + reasontext.UnicastOnly},
		{"ff02::1", "target ff02::1 is a multicast address; " + reasontext.UnicastOnly},
		{"ff05::fb", "target ff05::fb is a multicast address; " + reasontext.UnicastOnly},
		// IPv4 を写した IPv6 のアドレスも IPv4 として判定する
		{"::ffff:239.1.2.3", "target 239.1.2.3 is a multicast address; " + reasontext.UnicastOnly},
		{"::ffff:192.168.50.255", "target 192.168.50.255 is the broadcast address of 192.168.50.0/24 on this host; " + reasontext.UnicastOnly},
		{"192.168.50.255", "target 192.168.50.255 is the broadcast address of 192.168.50.0/24 on this host; " + reasontext.UnicastOnly},
		{"192.168.1.255", "target 192.168.1.255 is the broadcast address of 192.168.0.0/23 on this host; " + reasontext.UnicastOnly},
		{"172.16.0.7", "target 172.16.0.7 is the broadcast address of 172.16.0.4/30 on this host; " + reasontext.UnicastOnly},
		{"127.255.255.255", "target 127.255.255.255 is the broadcast address of 127.0.0.0/8 on this host; " + reasontext.UnicastOnly},
		{"100.127.255.255", "target 100.127.255.255 is the broadcast address of 100.64.0.0/10 on this host; " + reasontext.UnicastOnly},
		// 末尾が .255 でも、より大きな帯の中のホストなら拒まない
		{"192.168.0.255", ""},
		// /31 の両端と /32 はホストである
		{"10.0.0.0", ""},
		{"10.0.0.1", ""},
		{"10.9.9.9", ""},
		// 帯の先頭のアドレスは拒まない
		{"192.168.50.0", ""},
		{"172.16.0.4", ""},
		// ホストの帯の外の .255 は、どの帯の末尾か分からないので拒まない
		{"192.168.77.255", ""},
		{"192.168.50.20", ""},
		{"172.16.0.6", ""},
		{"fd00::ffff:ffff:ffff:ffff", ""},
		{"2001:db8::1", ""},
	} {
		if got := u.Refuse(netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Errorf("Refuse(%s) = %q, want %q", tc.addr, got, tc.want)
		}
	}
	if got := u.Refuse(netip.Addr{}); got != "" {
		t.Errorf("Refuse(zero) = %q, want empty", got)
	}
}

// 受け手が nil なら、インタフェースの一覧に依らない判定だけを行う。
func TestNilUnicastRefusesWithoutInterfaces(t *testing.T) {
	var u *Unicast
	if got := u.Refuse(netip.MustParseAddr("255.255.255.255")); !strings.Contains(got, "limited broadcast") {
		t.Errorf("limited broadcast: %q", got)
	}
	if got := u.Refuse(netip.MustParseAddr("239.1.2.3")); !strings.Contains(got, "multicast") {
		t.Errorf("multicast: %q", got)
	}
	if got := u.Refuse(netip.MustParseAddr("192.168.50.255")); got != "" {
		t.Errorf("a nil Unicast knows no interfaces, got %q", got)
	}
}

// 一覧を読めない間は帯のブロードキャストのアドレスを拒まず、全域のブロードキャストとマルチキャストは
// 拒み続ける。読めなくなったことと再び読めたことを 1 行ずつ出す(設計文書 7 節)。
func TestUnicastWhenInterfacesCannotBeRead(t *testing.T) {
	fail := true
	read := func() ([]netip.Prefix, error) {
		if fail {
			return nil, errors.New("netlink: permission denied")
		}
		return []netip.Prefix{netip.MustParsePrefix("192.168.50.2/24")}, nil
	}
	var logs []string
	u := NewUnicast(read, func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	u.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if got := u.Refuse(netip.MustParseAddr("192.168.50.255")); got != "" {
			t.Fatalf("unreadable interfaces must not refuse a directed broadcast, got %q", got)
		}
		if got := u.Refuse(netip.MustParseAddr("255.255.255.255")); got == "" {
			t.Fatal("the limited broadcast must stay refused")
		}
		if got := u.Refuse(netip.MustParseAddr("239.1.2.3")); got == "" {
			t.Fatal("multicast must stay refused")
		}
		now = now.Add(interfaceCacheTTL)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "permission denied") {
		t.Fatalf("logs = %q, want one line naming the error", logs)
	}
	fail = false
	if got := u.Refuse(netip.MustParseAddr("192.168.50.255")); got == "" {
		t.Error("once the interfaces can be read, the directed broadcast is refused")
	}
	if len(logs) != 2 || !strings.Contains(logs[1], "again") {
		t.Fatalf("logs = %q, want a second line for the recovery", logs)
	}
	now = now.Add(interfaceCacheTTL)
	u.Refuse(netip.MustParseAddr("192.168.50.255"))
	if len(logs) != 2 {
		t.Errorf("logs = %q, want no further line while reading works", logs)
	}
	// 一度読めた後に読めなくなっても、古い一覧を使い続けず、帯のブロードキャストの判定を行わない
	fail = true
	now = now.Add(interfaceCacheTTL)
	if got := u.Refuse(netip.MustParseAddr("192.168.50.255")); got != "" {
		t.Errorf("after the list became unreadable, the old list must not be used, got %q", got)
	}
	if len(logs) != 3 {
		t.Errorf("logs = %q, want a third line for the new failure", logs)
	}
}

// 読んだ一覧は interfaceCacheTTL の間は読み直さず、過ぎたら読み直す。帯が変われば判定も変わる。
func TestUnicastRereadsInterfacesAfterTTL(t *testing.T) {
	reads := 0
	prefix := "192.168.50.2/24"
	u := quietUnicast(func() ([]netip.Prefix, error) {
		reads++
		return []netip.Prefix{netip.MustParsePrefix(prefix)}, nil
	})
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	u.now = func() time.Time { return now }
	a := netip.MustParseAddr("192.168.50.255")
	for i := 0; i < 5; i++ {
		if u.Refuse(a) == "" {
			t.Fatal("directed broadcast not refused")
		}
	}
	if reads != 1 {
		t.Fatalf("reads = %d within the TTL, want 1", reads)
	}
	// ホストの帯が /23 に変わった。TTL の間は古い一覧を使い、過ぎたら新しい一覧で判定する
	prefix = "192.168.50.2/23"
	now = now.Add(interfaceCacheTTL - time.Millisecond)
	if u.Refuse(a) == "" {
		t.Error("within the TTL the cached list is used")
	}
	now = now.Add(time.Millisecond)
	if got := u.Refuse(a); got != "" {
		t.Errorf("after the TTL the new /23 makes %s a host, got %q", a, got)
	}
	if reads != 2 {
		t.Errorf("reads = %d, want 2", reads)
	}
	// 時計が戻った場合も読み直す
	now = now.Add(-time.Hour)
	u.Refuse(a)
	if reads != 3 {
		t.Errorf("reads = %d after the clock went back, want 3", reads)
	}
}

// このホストの一覧を読める。どの OS の CI でも、ループバックのアドレスは持つ見込みだが、無くても落とさない。
func TestHostPrefixes(t *testing.T) {
	ps, err := HostPrefixes()
	if err != nil {
		t.Skipf("cannot read interface addresses here: %v", err)
	}
	for _, p := range ps {
		if !p.IsValid() {
			t.Errorf("invalid prefix %v", p)
		}
		if p.Addr().Is4In6() {
			t.Errorf("prefix %v keeps the IPv4-mapped form", p)
		}
		if p.Addr() == netip.MustParseAddr("127.0.0.1") && p.Bits() != 8 {
			t.Errorf("loopback prefix %v, want /8", p)
		}
	}
}

// directedBroadcast は /30 以下の帯の末尾を返し、/31 と /32 と IPv6 では無いとする。
func TestDirectedBroadcast(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		want   string
	}{
		{"0.0.0.0/0", "255.255.255.255"},
		{"10.0.0.0/8", "10.255.255.255"},
		{"192.168.50.77/24", "192.168.50.255"},
		{"192.168.50.77/30", "192.168.50.79"},
		{"192.168.50.77/31", ""},
		{"192.168.50.77/32", ""},
		{"fd00::/64", ""},
	} {
		got, ok := directedBroadcast(netip.MustParsePrefix(tc.prefix))
		if (tc.want == "") == ok || (ok && got.String() != tc.want) {
			t.Errorf("directedBroadcast(%s) = %v %v, want %q", tc.prefix, got, ok, tc.want)
		}
	}
}
