package utun

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/nettun"
	"github.com/rahanahu/wgft/internal/resource"
)

// TestNewSetsTCPClosingCapFromConfig は、Config.TCPFlows が netstack の閉じた後の TCP の endpoint の
// 天井 K になること(設計文書 7 節)と、設定しなければ nettun の既定になることを確かめる。
func TestNewSetsTCPClosingCapFromConfig(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	quiet := func(string, ...any) {}
	for _, tc := range []struct{ flows, want int }{{123, 123}, {0, nettun.DefaultTCPClosingCap}} {
		tun, err := New(Config{PrivateKey: priv, ListenPort: 0, Address: netip.MustParseAddr("10.97.0.1"), MTU: 1420, TCPFlows: tc.flows, Logf: quiet})
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

// TestDefaultTCPClosingCapMatchesFlowBudget は、nettun の既定の天井が WGFT_MAX_TCP_FLOWS の既定と
// 同じ値であることを固定する。nettun は internal/resource を import しないので、値は 2 箇所にある。
func TestDefaultTCPClosingCapMatchesFlowBudget(t *testing.T) {
	if nettun.DefaultTCPClosingCap != resource.TCPTotal {
		t.Fatalf("nettun.DefaultTCPClosingCap %d != resource.TCPTotal %d", nettun.DefaultTCPClosingCap, resource.TCPTotal)
	}
}
