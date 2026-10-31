package usermode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// specTunnelDir は、仕様の fixture(docs/design/spec/tunnel.md)の置き場所である。
const specTunnelDir = "../../../testdata/spec/tunnel"

type specTunnelWGCase struct {
	Name string         `json:"name"`
	WG   proto.WGConfig `json:"wg"`
	Want *struct {
		Address          string `json:"address"`
		ServerAddress    string `json:"server_address"`
		Endpoint         string `json:"endpoint"`
		MTU              int    `json:"mtu"`
		KeepaliveSeconds int64  `json:"keepalive_seconds"`
		UDPIdleSeconds   int64  `json:"udp_idle_seconds"`
	} `json:"want"`
	Error bool `json:"error"`
}

// TestSpecTunnelWGConfig は、全体状態の wg 節からトンネルの宣言と UDP の無通信の期限を導く規則が、
// 仕様の fixture と同じであることを確かめる(docs/design/spec/tunnel.md)。
func TestSpecTunnelWGConfig(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(specTunnelDir, "wg-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []specTunnelWGCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("fixture has no cases")
	}
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	d := New(nil, resource.Limits{}, "", 0)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.Error == (c.Want != nil) {
				t.Fatal("a case has either want or error, not both")
			}
			cfg, err := tunnelConfig(priv, c.WG)
			if c.Error {
				if err == nil {
					t.Fatalf("tunnelConfig accepted %+v; the fixture expects an error", c.WG)
				}
				return
			}
			if err != nil {
				t.Fatalf("tunnelConfig: %v", err)
			}
			w := c.Want
			if got := cfg.Address.String(); got != w.Address {
				t.Errorf("address = %s, want %s", got, w.Address)
			}
			if got := cfg.ServerAddress.String(); got != w.ServerAddress {
				t.Errorf("server address = %s, want %s", got, w.ServerAddress)
			}
			if cfg.Endpoint != w.Endpoint {
				t.Errorf("endpoint = %q, want %q", cfg.Endpoint, w.Endpoint)
			}
			if cfg.MTU != w.MTU {
				t.Errorf("mtu = %d, want %d", cfg.MTU, w.MTU)
			}
			if want := time.Duration(w.KeepaliveSeconds) * time.Second; cfg.Keepalive != want {
				t.Errorf("keepalive = %v, want %v", cfg.Keepalive, want)
			}
			if cfg.ServerPublicKey.String() != c.WG.ServerPubkey {
				t.Errorf("server key = %s, want %s", cfg.ServerPublicKey, c.WG.ServerPubkey)
			}
			if got, want := d.RelayOptions(c.WG).UDPIdleTimeout, time.Duration(w.UDPIdleSeconds)*time.Second; got != want {
				t.Errorf("UDP idle timeout = %v, want %v", got, want)
			}
		})
	}
}
