package credentials

import (
	"os"
	"path/filepath"
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
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perm = %o, want 600", info.Mode().Perm())
	}
	if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".wgft-state-*")); len(matches) != 0 {
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
