package credentials

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// 同じプロセス内の flock は同じ open file description を共有しないので、別 open で取り直せば衝突する。
func TestLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	l, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(path); !errors.Is(err, ErrLocked) {
		t.Errorf("second Acquire = %v, want ErrLocked", err)
	}
	// 利用者に見える呼び名は「認証情報ファイル」であって、flock 内部の「状態ファイル」ではない。
	if got := ErrLocked.Error(); got != "credentials file is in use by another process" {
		t.Errorf("ErrLocked = %q, want the credentials file wording", got)
	}
	if state, err := Inspect(path); err != nil || state != Locked {
		t.Errorf("Inspect while held = %v, %v; want Locked", state, err)
	}
	// 別プロセスからも取れない
	out, err := exec.Command("flock", "-n", LockPath(path), "true").CombinedOutput()
	if err == nil {
		t.Errorf("external flock should fail while held: %s", out)
	}
	l.Release()
	if state, err := Inspect(path); err != nil || state != Unlocked {
		t.Errorf("Inspect after release = %v, %v; want Unlocked", state, err)
	}
	again, err := Acquire(path)
	if err != nil {
		t.Errorf("Acquire after release: %v", err)
	} else {
		defer again.Release() // TempDir の掃除が開いたハンドルで失敗しないように、放す
	}
	assertFileSecured(t, LockPath(path))
}

// 一度も起動していないデータディレクトリでは、Inspect は Absent を返し、ロックファイルを作らない。
func TestInspectNeverStarted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	state, err := Inspect(path)
	if err != nil || state != Absent {
		t.Fatalf("Inspect = %v, %v; want Absent and no error", state, err)
	}
	if _, err := os.Stat(LockPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("os.Stat(%s) = %v; the lock file must not exist after Inspect", LockPath(path), err)
	}
}
