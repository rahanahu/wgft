//go:build unix

package flock

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// ロックファイルがあるのに権限で開けない場合は、Unknown と非 nil の誤りになる。
// 呼び出し側はこれを Absent と区別できる。設計 10.2c 節が 2 つに別の終了コードを与えるため。
func TestInspectDistinguishesPermissionFromAbsence(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "agent.json")
	l, err := Acquire(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(LockPath(state), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(LockPath(state), 0o600) })

	got, err := Inspect(state)
	if err == nil {
		t.Fatalf("Inspect on an unreadable lock file = %v, nil; want an error", got)
	}
	if got != Unknown {
		t.Errorf("Inspect on an unreadable lock file = %v, want Unknown", got)
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("Inspect error = %v, want one wrapping fs.ErrPermission", err)
	}
	// 同じ呼び出しで、不在は誤りにならない
	absent, err := Inspect(filepath.Join(dir, "never-started.json"))
	if err != nil || absent != Absent {
		t.Fatalf("Inspect on a missing lock file = %v, %v; want Absent and no error", absent, err)
	}
}
