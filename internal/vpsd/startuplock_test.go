//go:build linux

package vpsd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/flock"
)

// server はサーバのデータベースを開く前に起動ロックを取る(設計文書 9・10.3 節)。ロックを別のプロセス、
// 例えば撤去が持っていれば、データベースを作りも開きもせずに終わる。以前はデータベースを開いて
// スキーマを上げてからロックを取ったので、撤去が --purge で消した後に空のデータベースを作って残しえた。
func TestRunTakesTheLockBeforeOpeningTheDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	held, err := flock.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()

	err = Run(Options{DBPath: path})
	if err == nil || !strings.Contains(err.Error(), "server database is in use by another process") {
		t.Fatalf("Run while the lock is held = %v", err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists after Run gave up on the lock: %v", p, err)
		}
	}
}
