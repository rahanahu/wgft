package vpsd

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

func TestPrintDBModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+"-wal", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path+"-wal", 0o640); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	printDBModes(&out, path)
	got := out.String()
	if !strings.Contains(got, "server database file mode: "+path+" is 0600\n") {
		t.Fatalf("db mode line missing: %q", got)
	}
	if !strings.Contains(got, "server database file mode: "+path+"-wal is 0640; the server narrows it to 0600 on its next start") {
		t.Fatalf("wal mode line missing: %q", got)
	}
	if strings.Contains(got, path+"-shm") {
		t.Fatalf("unexpected shm line for missing file: %q", got)
	}
}

// server check は読み取り専用:権限、補助ファイルの有無、スキーマの版を変えない(仕様 9 節)。
func TestCheckLeavesDatabaseUntouched(t *testing.T) {
	opts := func(path string) Options {
		return Options{Mode: modeUserspace, DBPath: path, WGInterface: "wgft0", WGAddress: "10.200.0.1/24"}
	}
	t.Run("current schema, broad mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wgft.sqlite")
		st, err := store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		st.SetMeta(modeMeta, []byte(modeUserspace))
		st.Close()
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := Check(opts(path), &out); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"is 0644; the server narrows it to 0600", "recorded mode: userspace"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("output lacks %q:\n%s", want, out.String())
			}
		}
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
			t.Errorf("check changed the mode to %04o", fi.Mode().Perm())
		}
		for _, p := range []string{path + "-wal", path + "-shm"} {
			if _, err := os.Stat(p); err == nil {
				t.Errorf("check left %s behind", filepath.Base(p))
			}
		}
	})
	t.Run("old schema", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wgft.sqlite")
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{"CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL)", "PRAGMA user_version = 1"} {
			if _, err := db.Exec(q); err != nil {
				t.Fatal(err)
			}
		}
		db.Close()
		var out bytes.Buffer
		if err := Check(opts(path), &out); err != nil {
			t.Fatal(err)
		}
		db, _ = sql.Open("sqlite", path)
		defer db.Close()
		var v int
		if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil || v != 1 {
			t.Errorf("check migrated the schema: user_version = %d %v", v, err)
		}
	})
}
