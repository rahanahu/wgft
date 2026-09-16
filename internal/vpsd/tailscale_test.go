package vpsd

import (
	"net"
	"testing"
)

// addr は net.IPNet を作るテスト用のヘルパ。
func addr(s string) *net.IPNet {
	ip := net.ParseIP(s)
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
}

// pickTailscaleAddr:tailscale0 の CGNAT アドレスを選ぶ、eth1 の CGNAT アドレスは選ばず other に名前を返す、
// 両方あるときは tailscale0 を優先する、どちらもないときは全て空。
func TestPickTailscaleAddr(t *testing.T) {
	t.Run("tailscale0 に CGNAT アドレス", func(t *testing.T) {
		ifaces := []ifaceAddrs{
			{name: "eth0", addrs: []net.Addr{addr("203.0.113.5")}},
			{name: "tailscale0", addrs: []net.Addr{addr("100.64.1.2")}},
		}
		iface, ip, other := pickTailscaleAddr(ifaces)
		if iface != "tailscale0" || ip != "100.64.1.2" || other != "" {
			t.Fatalf("got iface=%q ip=%q other=%q", iface, ip, other)
		}
	})

	t.Run("CGNAT アドレスは eth1 だけ", func(t *testing.T) {
		ifaces := []ifaceAddrs{
			{name: "eth0", addrs: []net.Addr{addr("203.0.113.5")}},
			{name: "eth1", addrs: []net.Addr{addr("100.64.9.9")}},
		}
		iface, ip, other := pickTailscaleAddr(ifaces)
		if iface != "" || ip != "" || other != "eth1" {
			t.Fatalf("got iface=%q ip=%q other=%q", iface, ip, other)
		}
	})

	t.Run("両方あるときは tailscale0 が勝つ", func(t *testing.T) {
		ifaces := []ifaceAddrs{
			{name: "eth1", addrs: []net.Addr{addr("100.64.9.9")}},
			{name: "tailscale0", addrs: []net.Addr{addr("100.64.1.2")}},
		}
		iface, ip, other := pickTailscaleAddr(ifaces)
		if iface != "tailscale0" || ip != "100.64.1.2" || other != "" {
			t.Fatalf("got iface=%q ip=%q other=%q", iface, ip, other)
		}
	})

	t.Run("どちらもない", func(t *testing.T) {
		ifaces := []ifaceAddrs{
			{name: "eth0", addrs: []net.Addr{addr("203.0.113.5")}},
			{name: "tailscale0", addrs: []net.Addr{addr("203.0.113.6")}},
		}
		iface, ip, other := pickTailscaleAddr(ifaces)
		if iface != "" || ip != "" || other != "" {
			t.Fatalf("got iface=%q ip=%q other=%q", iface, ip, other)
		}
	})
}

// parseTailscaleStatus:`tailscale status --json` の最小構成の固定データから
// IPv4 のアドレスと MagicDNS 名(末尾のドットを外した形)を取り出す。
func TestParseTailscaleStatus(t *testing.T) {
	t.Run("IPv4 と DNSName がある", func(t *testing.T) {
		data := []byte(`{
			"Self": {
				"TailscaleIPs": ["100.64.1.2", "fd7a:115c:a1e0::1"],
				"DNSName": "myvps.tail1234.ts.net."
			}
		}`)
		ip, dnsName, ok := parseTailscaleStatus(data)
		if !ok || ip != "100.64.1.2" || dnsName != "myvps.tail1234.ts.net" {
			t.Fatalf("got ip=%q dnsName=%q ok=%v", ip, dnsName, ok)
		}
	})

	t.Run("IPv4 がない", func(t *testing.T) {
		data := []byte(`{
			"Self": {
				"TailscaleIPs": ["fd7a:115c:a1e0::1"],
				"DNSName": "myvps.tail1234.ts.net."
			}
		}`)
		if _, _, ok := parseTailscaleStatus(data); ok {
			t.Fatal("IPv4 がないので ok は偽のはず")
		}
	})

	t.Run("壊れた JSON", func(t *testing.T) {
		if _, _, ok := parseTailscaleStatus([]byte("not json")); ok {
			t.Fatal("壊れた JSON では ok は偽のはず")
		}
	})
}
