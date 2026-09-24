package store

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
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
	want := []string{"CREATE TABLE meta", "CREATE TABLE rules", "CREATE TABLE agents", "CREATE TABLE agent_known_ips", "CREATE TABLE drop_counters", "CREATE TABLE warnings", "DROP TABLE IF EXISTS agent_known_ips", "CREATE TABLE warning_acks", "ADD COLUMN disabled_at"}
	if len(migrations) != len(want) {
		t.Fatalf("migrations = %d, want %d(新しい版は末尾に足す)", len(migrations), len(want))
	}
	for i, w := range want {
		if !strings.Contains(migrations[i], w) {
			t.Errorf("migration %d should contain %q", i+1, w)
		}
	}
}

func TestOpenTightensExistingModesTo0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %04o, want 0600", p, fi.Mode().Perm())
		}
	}
}

// 権限は 0600 に含まれない部分だけを外す。所有者の権限は変えない(仕様 9 節)。
func TestNarrowModeKeepsOwnerBits(t *testing.T) {
	for _, c := range []struct{ from, want os.FileMode }{
		{0o644, 0o600}, {0o640, 0o600}, {0o755, 0o600}, {0o444, 0o400}, {0o400, 0o400}, {0o600, 0o600},
	} {
		p := filepath.Join(t.TempDir(), "wgft.sqlite")
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, c.from); err != nil {
			t.Fatal(err)
		}
		if err := narrowMode(p); err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Stat(p)
		if fi.Mode().Perm() != c.want {
			t.Errorf("%04o -> %04o, want %04o", c.from, fi.Mode().Perm(), c.want)
		}
	}
}

// OpenReadOnly は権限もファイルの集合も変えず、書き込みを拒む。server が止まっている DB(補助ファイル無し)と、
// 書き込み中の接続がある DB(値が WAL にだけある)の両方で読める。
func TestOpenReadOnlyChangesNothing(t *testing.T) {
	files := func(path string) map[string]os.FileMode {
		m := map[string]os.FileMode{}
		for _, p := range []string{path, path + "-wal", path + "-shm"} {
			if fi, err := os.Stat(p); err == nil {
				m[filepath.Base(p)] = fi.Mode().Perm()
			}
		}
		return m
	}
	readOnly := func(t *testing.T, path, want string) {
		t.Helper()
		before := files(path)
		s, err := OpenReadOnly(path)
		if err != nil {
			t.Fatal(err)
		}
		if v, err := s.GetMeta("k"); err != nil || string(v) != want {
			t.Errorf("GetMeta = %q %v, want %q", v, err, want)
		}
		if err := s.SetMeta("x", []byte("y")); err == nil {
			t.Error("read-only store accepted a write")
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if after := files(path); !reflect.DeepEqual(before, after) {
			t.Errorf("files changed: before %v, after %v", before, after)
		}
	}

	t.Run("stopped", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wgft.sqlite")
		s, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		s.SetMeta("k", []byte("v1"))
		s.Close()
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		readOnly(t, path, "v1")
	})
	t.Run("running", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wgft.sqlite")
		live, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer live.Close()
		live.SetMeta("k", []byte("v2"))
		readOnly(t, path, "v2")
	})
}
