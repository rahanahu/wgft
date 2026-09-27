package tunnel

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/nettun"
)

// TestNewSetsTCPClosingCapFromConfig は、Config.TCPFlows が netstack の閉じた後の TCP の endpoint の
// 天井 K になること(設計文書 7 節)と、設定しなければ nettun の既定になることを確かめる。
func TestNewSetsTCPClosingCapFromConfig(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	server, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	quiet := func(string, ...any) {}
	for _, tc := range []struct{ flows, want int }{{123, 123}, {0, nettun.DefaultTCPClosingCap}} {
		tun, err := New(Config{
			PrivateKey: priv, ServerPublicKey: server.PublicKey(), Endpoint: "127.0.0.1:1",
			Address: netip.MustParseAddr("10.97.0.2"), ServerAddress: netip.MustParseAddr("10.97.0.1"),
			MTU: 1420, TCPFlows: tc.flows, Logf: quiet,
		})
		if err != nil {
			t.Fatal(err)
		}
		got := tun.tnet.TCPClosingCap()
		tun.Close()
		if got != tc.want {
			t.Fatalf("TCPFlows %d: closing cap %d; want %d", tc.flows, got, tc.want)
		}
	}
}
