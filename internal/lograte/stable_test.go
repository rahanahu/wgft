package lograte

import (
	"errors"
	"net"
	"testing"
)

// 名前の解決の誤りは、問い合わせごとに送信元のポートが変わっても同じ文面になる。サーバは残す。
func TestStableErrorDropsTheSocketPair(t *testing.T) {
	dnsErr := func(err string) error {
		return &net.DNSError{Err: err, Name: "game.lan", Server: "192.168.1.1:53"}
	}
	cases := []struct {
		name string
		a, b error
		want string
	}{
		{"refused", dnsErr("read udp 192.168.1.10:54285->192.168.1.1:53: read: connection refused"),
			dnsErr("read udp 192.168.1.10:48346->192.168.1.1:53: read: connection refused"),
			"lookup game.lan on 192.168.1.1:53: read: connection refused"},
		{"timeout", dnsErr("read udp 192.168.1.10:35411->192.168.1.1:53: i/o timeout"),
			dnsErr("read udp 192.168.1.10:37686->192.168.1.1:53: i/o timeout"),
			"lookup game.lan on 192.168.1.1:53: i/o timeout"},
		{"tcp fallback", dnsErr("read tcp 192.168.1.10:40000->192.168.1.1:53: read: connection reset by peer"),
			dnsErr("read tcp 192.168.1.10:40001->192.168.1.1:53: read: connection reset by peer"),
			"lookup game.lan on 192.168.1.1:53: read: connection reset by peer"},
		{"ipv6 server", dnsErr("write udp [fe80::1%eth0]:5353->[fe80::53%eth0]:53: sendto: network is unreachable"),
			dnsErr("write udp [fe80::1%eth0]:5354->[fe80::53%eth0]:53: sendto: network is unreachable"),
			"lookup game.lan on 192.168.1.1:53: sendto: network is unreachable"},
		{"inside a dial error", &net.OpError{Op: "dial", Net: "tcp", Err: dnsErr("read udp 192.168.1.10:1->192.168.1.1:53: i/o timeout")},
			&net.OpError{Op: "dial", Net: "tcp", Err: dnsErr("read udp 192.168.1.10:2->192.168.1.1:53: i/o timeout")},
			"dial tcp: lookup game.lan on 192.168.1.1:53: i/o timeout"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, b := StableError(c.a), StableError(c.b)
			if a.Error() != c.want {
				t.Errorf("StableError = %q, want %q", a, c.want)
			}
			if a.Error() != b.Error() {
				t.Errorf("two lookups that differ only in the source port read %q and %q", a, b)
			}
			var d *net.DNSError
			if !errors.As(a, &d) || d.Name != "game.lan" {
				t.Errorf("errors.As does not reach the *net.DNSError through %q", a)
			}
		})
	}
}

// DNS の誤りでないもの、組を含まないものは、そのまま返す。
func TestStableErrorLeavesOtherErrorsAlone(t *testing.T) {
	plain := errors.New("read udp 192.168.1.10:1->192.168.1.20:9000: read: connection refused")
	nx := &net.DNSError{Err: "no such host", Name: "game.lan", Server: "192.168.1.1:53", IsNotFound: true}
	for _, err := range []error{nil, plain, nx} {
		if got := StableError(err); got != err {
			t.Errorf("StableError(%v) = %v, want the same error back", err, got)
		}
	}
}
