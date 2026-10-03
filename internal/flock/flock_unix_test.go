//go:build unix

package flock

import (
	"errors"
	"fmt"
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

// ロックを取った後にロックファイルが消されていれば、消されたファイルのロックを返さずに開き直す。撤去の
// --purge は、ロックを持ったままロックファイルを消してから放す。消される前に古いファイルを開いた server が
// その後でロックを取ると、誰も守らない消されたファイルのロックを持つことになる(設計文書 10.3 節)。
// 差し替えられた場合も同じである。どちらの関数でも、返すロックはパスの指す今のファイルのものである。
func TestAcquireRetriesWhenTheLockFileIsRemovedOrReplaced(t *testing.T) {
	for _, tc := range []struct {
		name  string
		touch func(path string) error
	}{
		{"removed", os.Remove},
		{"replaced", func(p string) error {
			if err := os.Remove(p); err != nil {
				return err
			}
			return os.WriteFile(p, nil, 0o600)
		}},
	} {
		for _, creating := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/creating=%v", tc.name, creating), func(t *testing.T) {
				state := filepath.Join(t.TempDir(), "wgft.sqlite")
				calls := 0
				afterLockForTest = func(attempt int) {
					calls++
					if attempt == 0 {
						if err := tc.touch(LockPath(state)); err != nil {
							t.Fatal(err)
						}
					}
				}
				t.Cleanup(func() { afterLockForTest = nil })
				var l *Lock
				var err error
				if creating {
					l, _, err = AcquireCreating(state)
				} else {
					l, err = Acquire(state)
				}
				if err != nil {
					t.Fatalf("acquire: %v", err)
				}
				defer l.Release()
				if calls != 2 {
					t.Errorf("locked %d times, want 2: once on the removed file and once on the new one", calls)
				}
				fi, _ := l.Stat()
				pi, err := os.Lstat(LockPath(state))
				if err != nil || !os.SameFile(fi, pi) {
					t.Errorf("the returned lock is not on the file at the path: %v", err)
				}
				// 別の取得はパスの今のファイルで衝突する
				if _, err := Acquire(state); !errors.Is(err, ErrLocked) {
					t.Errorf("a second Acquire = %v, want ErrLocked", err)
				}
			})
		}
	}
}

// 開くたびに差し替えられ続ければ、上限の回数の後で誤りを返し、ロックを持ったままにしない。
func TestAcquireGivesUpWhenTheLockFileKeepsChanging(t *testing.T) {
	state := filepath.Join(t.TempDir(), "wgft.sqlite")
	afterLockForTest = func(int) { _ = os.Remove(LockPath(state)) }
	t.Cleanup(func() { afterLockForTest = nil })
	if _, err := Acquire(state); !errors.Is(err, errReplaced) {
		t.Fatalf("Acquire = %v, want errReplaced", err)
	}
	afterLockForTest = nil
	l, err := Acquire(state)
	if err != nil {
		t.Fatalf("Acquire after giving up: %v; the earlier attempts must not keep a lock", err)
	}
	l.Release()
}

// 照合で食い違ったときは、古い記述子を閉じてそのロックを放す。閉じ忘れると、消されたファイルのロックを
// 持ったまま新しいファイルのロックも持ち、古いファイルを開いた別のプロセスが取れなくなる。
func TestAcquireReleasesTheStaleLockOnMismatch(t *testing.T) {
	for _, creating := range []bool{false, true} {
		t.Run(fmt.Sprintf("creating=%v", creating), func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "wgft.sqlite")
			var old *os.File
			afterLockForTest = func(attempt int) {
				if attempt != 0 {
					return
				}
				var err error
				// 消す前の古いファイルを別の記述子で開いておく
				if old, err = os.OpenFile(LockPath(state), os.O_RDWR, 0); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(LockPath(state)); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { afterLockForTest = nil })
			var l *Lock
			var err error
			if creating {
				l, _, err = AcquireCreating(state)
			} else {
				l, err = Acquire(state)
			}
			if err != nil {
				t.Fatalf("acquire: %v", err)
			}
			defer l.Release()
			if old == nil {
				t.Fatal("the hook did not run")
			}
			defer old.Close()
			if err := tryLock(old); err != nil {
				t.Errorf("locking the removed file from another descriptor = %v; acquire must close the stale descriptor and release its lock", err)
			}
		})
	}
}

// ロックを取った後にロックファイルが、取ったファイルそのものへの symlink に差し替えられた場合も、パスは
// もう通常のファイルではないので照合で食い違う。照合はパスを lstat で読み、symlink を辿らない。辿ると
// 取ったファイルと同じに見えて、symlink の置かれたロックファイルのロックを返してしまう。開き直しは
// symlink を拒む。
func TestAcquireDetectsALockFileReplacedBySymlink(t *testing.T) {
	for _, creating := range []bool{false, true} {
		t.Run(fmt.Sprintf("creating=%v", creating), func(t *testing.T) {
			dir := t.TempDir()
			state := filepath.Join(dir, "wgft.sqlite")
			afterLockForTest = func(attempt int) {
				if attempt != 0 {
					return
				}
				moved := filepath.Join(dir, "moved.lock")
				if err := os.Rename(LockPath(state), moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, LockPath(state)); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { afterLockForTest = nil })
			var err error
			if creating {
				var l *Lock
				l, _, err = AcquireCreating(state)
				if err == nil {
					l.Release()
				}
			} else {
				var l *Lock
				l, err = Acquire(state)
				if err == nil {
					l.Release()
				}
			}
			if !errors.Is(err, ErrNotRegular) {
				t.Errorf("acquire after the lock file became a symlink = %v, want ErrNotRegular", err)
			}
		})
	}
}
