package tunnel

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// specTunnelDir は、仕様の fixture(docs/design/spec/tunnel.md)の置き場所である。
const specTunnelDir = "../../../../testdata/spec/tunnel"

func specTunnelRead(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(specTunnelDir, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// TestSpecTunnelEndpoint は、wg.endpoint からピアのエンドポイントを決める規則が、仕様の fixture と
// 同じであることを確かめる(docs/design/spec/tunnel.md)。名前の解決はテストの値に差し替える。
func TestSpecTunnelEndpoint(t *testing.T) {
	var f struct {
		Cases []struct {
			Name     string   `json:"name"`
			Endpoint string   `json:"endpoint"`
			Lookup   []string `json:"lookup"`
			Want     string   `json:"want"`
			Error    bool     `json:"error"`
		} `json:"cases"`
	}
	specTunnelRead(t, "endpoint.json", &f)
	if len(f.Cases) == 0 {
		t.Fatal("fixture has no cases")
	}
	saved := lookupIP4
	t.Cleanup(func() { lookupIP4 = saved })
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.Error == (c.Want != "") {
				t.Fatal("a case has either want or error, not both")
			}
			looked := false
			lookupIP4 = func(context.Context, string) ([]netip.Addr, error) {
				looked = true
				out := make([]netip.Addr, 0, len(c.Lookup))
				for _, s := range c.Lookup {
					out = append(out, netip.MustParseAddr(s))
				}
				return out, nil
			}
			got, err := resolve(c.Endpoint)
			if c.Lookup == nil && looked {
				t.Errorf("resolve looked up %q; the fixture expects no lookup", c.Endpoint)
			}
			if c.Error {
				if err == nil {
					t.Fatalf("resolve(%q) = %s; the fixture expects an error", c.Endpoint, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve(%q): %v", c.Endpoint, err)
			}
			if got.String() != c.Want {
				t.Fatalf("resolve(%q) = %s, want %s", c.Endpoint, got, c.Want)
			}
		})
	}
}

// TestSpecTunnelUAPIPeer は、エージェントが wireguard-go の device に設定するピアが、仕様の fixture と
// 同じであることを、device の UAPI の get の応答から確かめる(docs/design/spec/tunnel.md)。
func TestSpecTunnelUAPIPeer(t *testing.T) {
	var f struct {
		Input struct {
			ServerPubkey     string `json:"server_pubkey"`
			Endpoint         string `json:"endpoint"`
			Address          string `json:"address"`
			ServerAddress    string `json:"server_address"`
			MTU              int    `json:"mtu"`
			KeepaliveSeconds int    `json:"keepalive_seconds"`
		} `json:"input"`
		Want struct {
			Peers             int            `json:"peers"`
			ListenPortNonzero bool           `json:"listen_port_nonzero"`
			Peer              map[string]any `json:"peer"`
		} `json:"want"`
	}
	specTunnelRead(t, "uapi-peer.json", &f)
	serverKey, err := wgtypes.ParseKey(f.Input.ServerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	agentKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tun, err := New(Config{
		PrivateKey: agentKey, ServerPublicKey: serverKey,
		Endpoint:      f.Input.Endpoint,
		Address:       netip.MustParseAddr(f.Input.Address),
		ServerAddress: netip.MustParseAddr(f.Input.ServerAddress),
		MTU:           f.Input.MTU,
		Keepalive:     time.Duration(f.Input.KeepaliveSeconds) * time.Second,
		Logf:          func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tun.Close()
	out, err := tun.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out, "public_key="); n != f.Want.Peers {
		t.Fatalf("device has %d peers, want %d:\n%s", n, f.Want.Peers, out)
	}
	// ピアの節は最初の public_key の行から始まる。その前はインタフェースの行である
	head, peer, _ := strings.Cut(out, "public_key=")
	peer = "public_key=" + peer
	if f.Want.ListenPortNonzero {
		if !strings.Contains(head, "listen_port=") || strings.Contains(head, "listen_port=0\n") {
			t.Errorf("interface lines do not report a non-zero listen_port:\n%s", head)
		}
	}
	got := map[string][]string{}
	for _, line := range strings.Split(peer, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			got[k] = append(got[k], v)
		}
	}
	for k, w := range f.Want.Peer {
		var want []string
		switch v := w.(type) {
		case string:
			want = []string{v}
		case []any:
			for _, x := range v {
				want = append(want, x.(string))
			}
		default:
			t.Fatalf("fixture peer.%s has type %T", k, w)
		}
		if !slices.Equal(got[k], want) {
			t.Errorf("peer %s = %q, want %q", k, got[k], want)
		}
	}
}
