package credentials

import (
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
