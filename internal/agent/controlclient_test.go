package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/flock"
)

// 停止中の rotate-key は、カーネルモードでは消す鍵を 1 つ前の鍵として残し、続けて 2 回実行しても
// 1 つ前の鍵を空で上書きしない。ユーザー空間モードは 1 つ前の鍵を持たない(仕様 7b.4 節)。
func TestRotateKeyWhileStoppedKeepsThePreviousKeyInKernelMode(t *testing.T) {
	for _, mode := range []string{"kernel", ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.json")
			f := &credentials.Credentials{Name: "home", Mode: mode}
			if _, err := f.EnsureKey(); err != nil {
				t.Fatal(err)
			}
			key := f.WGPrivateKey
			if err := f.Save(path); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				msg, err := RotateKey(path)
				if err != nil {
					t.Fatalf("rotate-key #%d: %v", i+1, err)
				}
				if got := strings.Contains(msg, "previous key"); got != (mode == "kernel") {
					t.Errorf("rotate-key #%d message mentions the previous key: %v, want %v: %q", i+1, got, mode == "kernel", msg)
				}
				g, err := credentials.Load(path)
				if err != nil {
					t.Fatal(err)
				}
				want := ""
				if mode == "kernel" {
					want = key
				}
				if g.WGPrivateKey != "" || g.PreviousWGPrivateKey != want {
					t.Errorf("after rotate-key #%d: key %q previous %q; want an empty key and previous %q", i+1, g.WGPrivateKey, g.PreviousWGPrivateKey, want)
				}
			}
		})
	}
}

// 停止中の rotate-key はロックを取ってから書き換える。判定の後に起動したエージェントがロックを持って
// いれば、稼働中として扱い、認証情報ファイルを書き換えない(仕様 9 節)。
func TestRotateKeyWhileStoppedTakesTheLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	f := &credentials.Credentials{Name: "home", Mode: "kernel"}
	if _, err := f.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := credentials.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	old := inspectLock
	inspectLock = func(string) (credentials.State, error) { return credentials.Unlocked, nil }
	t.Cleanup(func() { inspectLock = old })

	_, err = RotateKey(path)
	if err == nil || !strings.Contains(err.Error(), "agent is running") {
		t.Fatalf("err = %v, want the running path's error for an agent that holds the lock", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Errorf("rotate-key rewrote agent.json while another process held the lock:\n%s", after)
	}
}

// 認証情報ファイルが無ければ、停止中の rotate-key はロックファイルを作らずに誤りを返す。一度も起動して
// いないホストに、呼び出し元の権限のロックファイルを残さないためである。
func TestRotateKeyWithoutCredentialsLeavesNoLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if _, err := RotateKey(path); err == nil {
		t.Fatal("rotate-key succeeded without a credentials file")
	}
	if _, err := os.Stat(flock.LockPath(path)); !os.IsNotExist(err) {
		t.Errorf("a lock file was created: %v", err)
	}
}

// ロックファイルがあって誰も持っていなければ、停止中の rotate-key は書き換えの間ロックを持つ(仕様 9 節)。
func TestRotateKeyWhileStoppedHoldsTheLockWhileWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	f := &credentials.Credentials{Name: "home"}
	if _, err := f.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	lock, err := credentials.Acquire(path) // ロックファイルを作ってから放す。停止したエージェントの跡である
	if err != nil {
		t.Fatal(err)
	}
	lock.Release()
	var held credentials.State
	rotateKeyLockedHook = func() { held, _ = credentials.Inspect(path) }
	t.Cleanup(func() { rotateKeyLockedHook = nil })
	if _, err := RotateKey(path); err != nil {
		t.Fatal(err)
	}
	if held != credentials.Locked {
		t.Errorf("the lock state while rewriting agent.json was %v, want locked", held)
	}
}

// ロックファイルが無ければ、停止中の rotate-key はロックファイルを作らずに鍵を作り直す。作ると、
// 呼び出し元(root)の権限のロックファイルが残り、非特権で動くエージェントの起動を塞ぐ(10.2c 節)。
func TestRotateKeyWithoutALockFileLeavesNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	f := &credentials.Credentials{Name: "home", Mode: "kernel"}
	if _, err := f.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	key := f.WGPrivateKey
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := RotateKey(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(flock.LockPath(path)); !os.IsNotExist(err) {
		t.Errorf("stopped rotate-key created a lock file: %v", err)
	}
	g, err := credentials.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if g.WGPrivateKey != "" || g.PreviousWGPrivateKey != key {
		t.Errorf("key %q previous %q; want the key cleared and kept as the previous key", g.WGPrivateKey, g.PreviousWGPrivateKey)
	}
}
