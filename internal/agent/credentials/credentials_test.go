package credentials

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

func TestRoundTripAndKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	f, err := LoadOrNew(path)
	if err != nil {
		t.Fatal(err)
	}
	created, err := f.EnsureKey()
	if err != nil || !created {
		t.Fatalf("EnsureKey = %v, %v", created, err)
	}
	key1, _ := f.PrivateKey()
	f.LastState = &proto.State{Generation: 7, WG: proto.WGConfig{Endpoint: "vps:51820"}}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	assertFileSecured(t, path)
	if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), tempPrefix+"*")); len(matches) != 0 {
		t.Errorf("temp file left behind: %v", matches)
	}

	g, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	created, err = g.EnsureKey()
	if err != nil || created {
		t.Errorf("EnsureKey on existing = %v, %v; must keep the key", created, err)
	}
	key2, _ := g.PrivateKey()
	if key1 != key2 || g.LastState == nil || g.LastState.Generation != 7 {
		t.Errorf("round trip lost data: %+v", g)
	}
}

// モードの記録が無いファイルはユーザー空間モードの記録とみなし(仕様 9 節)、ユーザー空間モードの
// 記録は書き出さない。旧い版が書いたファイルを新しい版が読み書きしても、形が変わらない。
func TestModeAbsentMeansUserspace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte(`{"name":"home","wg_private_key":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.RecordedMode(); got != ModeUserspace {
		t.Errorf("RecordedMode = %q, want %q", got, ModeUserspace)
	}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"mode"`, `"previous_wg_private_key"`} {
		if strings.Contains(string(b), key) {
			t.Errorf("a file without a kernel-mode record gained %s:\n%s", key, b)
		}
	}
}

// KeepPreviousKey は、カーネルモードの記録を持つファイルでだけ今の鍵を 1 つ前の鍵へ移し、今の鍵が
// 空なら 1 つ前の鍵を残す(仕様 7b.4 節)。
func TestKeepPreviousKey(t *testing.T) {
	cases := []struct {
		name            string
		mode, cur, prev string
		want            string
	}{
		{"kernel moves the current key", ModeKernel, "cur", "old", "cur"},
		{"kernel with no current key keeps the previous one", ModeKernel, "", "old", "old"},
		{"kernel with neither stays empty", ModeKernel, "", "", ""},
		{"userspace keeps no previous key", ModeUserspace, "cur", "", ""},
		{"no record is userspace", "", "cur", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &Credentials{Mode: c.mode, WGPrivateKey: c.cur, PreviousWGPrivateKey: c.prev}
			f.KeepPreviousKey()
			if f.PreviousWGPrivateKey != c.want {
				t.Errorf("PreviousWGPrivateKey = %q, want %q", f.PreviousWGPrivateKey, c.want)
			}
			if f.WGPrivateKey != c.cur {
				t.Errorf("WGPrivateKey changed to %q; KeepPreviousKey only copies", f.WGPrivateKey)
			}
		})
	}
}

// 登録の応答のアドレスは、アドレスだけか帯の長さの付いた IPv4 のときだけ記録の値になる。
func TestRegisteredTunnelAddress(t *testing.T) {
	for in, want := range map[string]string{
		"10.200.0.2": "10.200.0.2", "10.200.0.2/24": "10.200.0.2/24", "::ffff:10.200.0.2": "10.200.0.2",
		"": "", "fd00::2": "", "fd00::2/64": "", "not an address": "",
	} {
		if got := RegisteredTunnelAddress(in); got != want {
			t.Errorf("RegisteredTunnelAddress(%q) = %q, want %q", in, got, want)
		}
	}
}

// 記録との照合:記録が無ければ通し、アドレスだけの記録はアドレスを、帯の長さまでの記録は長さまで比べる。
// 読めない記録は比べられないので拒む。照合は記録を書き換えない(設計文書 11 節)。
func TestCheckTunnelAddress(t *testing.T) {
	cases := []struct {
		recorded, got string
		ok            bool
	}{
		{"", "192.168.1.100/25", true},
		{"10.200.0.2/24", "10.200.0.2/24", true},
		{"10.200.0.2/24", "10.200.0.3/24", false},
		{"10.200.0.2/24", "10.200.0.2/16", false},
		{"10.200.0.2/24", "10.200.0.2/25", false},
		{"10.200.0.2/24", "192.168.1.100/25", false},
		{"10.200.0.2", "10.200.0.2/24", true},
		{"10.200.0.2", "10.200.0.2/1", true},
		{"10.200.0.2", "10.201.0.2/24", false},
		{"garbage", "10.200.0.2/24", false},
	}
	for _, c := range cases {
		f := &Credentials{TunnelAddress: c.recorded}
		err := f.CheckTunnelAddress(netip.MustParsePrefix(c.got))
		if (err == nil) != c.ok {
			t.Errorf("recorded %q, got %s: err = %v, want ok=%v", c.recorded, c.got, err, c.ok)
		}
		var mm *TunnelAddressMismatch
		if err != nil && (!errors.As(err, &mm) || strings.ContainsAny(err.Error(), "()") || !strings.Contains(err.Error(), c.got)) {
			t.Errorf("recorded %q, got %s: error %q", c.recorded, c.got, err)
		}
		if f.TunnelAddress != c.recorded {
			t.Errorf("the check rewrote the record to %q", f.TunnelAddress)
		}
	}
}

// 記録:記録が無いか、同じアドレスだけの記録なら、適用できたアドレスを帯の長さまで記録する。記録と違う
// アドレスでは何もしない。
func TestRecordTunnelAddress(t *testing.T) {
	cases := []struct {
		recorded, got, want string
		changed             bool
	}{
		{"", "10.200.0.2/24", "10.200.0.2/24", true},
		{"10.200.0.2", "10.200.0.2/24", "10.200.0.2/24", true},
		{"10.200.0.2/24", "10.200.0.2/24", "10.200.0.2/24", false},
		{"10.200.0.2/24", "192.168.1.100/25", "10.200.0.2/24", false},
		{"10.200.0.2", "10.201.0.2/24", "10.200.0.2", false},
		{"garbage", "10.200.0.2/24", "garbage", false},
	}
	for _, c := range cases {
		f := &Credentials{TunnelAddress: c.recorded}
		if got := f.RecordTunnelAddress(netip.MustParsePrefix(c.got)); got != c.changed || f.TunnelAddress != c.want {
			t.Errorf("recorded %q, got %s: changed=%v record=%q, want %v %q", c.recorded, c.got, got, f.TunnelAddress, c.changed, c.want)
		}
	}
}

// 記録は agent.json の tunnel_address に書き、読み戻せる。
func TestTunnelAddressRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := (&Credentials{TunnelAddress: "10.200.0.2/24"}).Save(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"tunnel_address": "10.200.0.2/24"`) {
		t.Errorf("agent.json = %s", b)
	}
	g, err := Load(path)
	if err != nil || g.TunnelAddress != "10.200.0.2/24" {
		t.Errorf("loaded %+v, %v", g, err)
	}
}
