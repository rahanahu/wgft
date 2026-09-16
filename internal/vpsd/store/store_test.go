package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestMetaAndMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMeta("k"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetMeta(missing) = %v, want ErrNotFound", err)
	}
	calls := 0
	gen := func() ([]byte, error) { calls++; return []byte("secret"), nil }
	v, err := s.GetOrCreateMeta("k", gen)
	if err != nil || string(v) != "secret" || calls != 1 {
		t.Fatalf("first GetOrCreate = %q, %v, calls=%d", v, err, calls)
	}
	v, err = s.GetOrCreateMeta("k", gen)
	if err != nil || string(v) != "secret" || calls != 1 {
		t.Fatalf("second GetOrCreate = %q, %v, calls=%d (must not regenerate)", v, err, calls)
	}
	if err := s.SetMeta("k", []byte("new")); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// 開き直しても残っていて、マイグレーションは冪等
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v, err := s.GetMeta("k"); err != nil || string(v) != "new" {
		t.Errorf("after reopen GetMeta = %q, %v", v, err)
	}
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != len(migrations) {
		t.Errorf("user_version = %d, %v; want %d", version, err, len(migrations))
	}
}

func TestNewerSchemaIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA user_version = 999"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(path); err == nil {
		t.Error("Open with newer schema version should fail")
	}
}

// 版の順序は既存の DB との互換性そのもの。並びを固定する。
func TestMigrationOrder(t *testing.T) {
	want := []string{"CREATE TABLE meta", "CREATE TABLE rules", "CREATE TABLE agents", "CREATE TABLE agent_known_ips", "CREATE TABLE drop_counters", "CREATE TABLE warnings", "DROP TABLE IF EXISTS agent_known_ips"}
	if len(migrations) != len(want) {
		t.Fatalf("migrations = %d, want %d(新しい版は末尾に足す)", len(migrations), len(want))
	}
	for i, w := range want {
		if !strings.Contains(migrations[i], w) {
			t.Errorf("migration %d should contain %q", i+1, w)
		}
	}
}
