package flock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// symlinkOrSkip は symlink を作る。Windows で権限が無く作れなければ、その試験を飛ばす。
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}
}

// ロックファイルが symlink なら、Acquire は辿らずに拒み、symlink の先にファイルを作らない。root の CLI が
// エージェントの利用者の置いた symlink を辿ると、root の持ち物のファイルをその先に作りうる
// (設計文書 9・11 節)。
func TestAcquireDoesNotFollowASymlinkedLockFile(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "agent.json")
	target := filepath.Join(t.TempDir(), "created-through-the-link")
	symlinkOrSkip(t, target, LockPath(state))
	l, err := Acquire(state)
	if err == nil {
		l.Release()
		t.Fatal("Acquire through a symlinked lock file succeeded")
	}
	if !errors.Is(err, ErrNotRegular) {
		t.Errorf("Acquire = %v, want an error wrapping ErrNotRegular", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the symlink's target exists after Acquire: %v", err)
	}
	if _, err := Inspect(state); !errors.Is(err, ErrNotRegular) {
		t.Errorf("Inspect = %v, want an error wrapping ErrNotRegular", err)
	}
}

// symlink の先が既にある通常のファイルでも、Acquire と Inspect は開かない。
func TestAcquireDoesNotOpenAnExistingFileThroughASymlink(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "agent.json")
	target := filepath.Join(t.TempDir(), "someone-elses")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, target, LockPath(state))
	if l, err := Acquire(state); !errors.Is(err, ErrNotRegular) {
		l.Release()
		t.Errorf("Acquire = %v, want an error wrapping ErrNotRegular", err)
	}
	if st, err := Inspect(state); !errors.Is(err, ErrNotRegular) || st != Unknown {
		t.Errorf("Inspect = %v, %v; want Unknown and an error wrapping ErrNotRegular", st, err)
	}
}

// ロックファイルの名前にディレクトリがあれば、開いた後の種別の確認で拒む。
func TestOpenRegularRefusesADirectory(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "agent.json")
	if err := os.Mkdir(LockPath(state), 0o700); err != nil {
		t.Fatal(err)
	}
	if st, err := Inspect(state); !errors.Is(err, ErrNotRegular) || st != Unknown {
		t.Errorf("Inspect = %v, %v; want Unknown and an error wrapping ErrNotRegular", st, err)
	}
	if _, _, err := OpenRegular(LockPath(state), os.O_RDONLY, 0); !errors.Is(err, ErrNotRegular) {
		t.Errorf("OpenRegular = %v, want an error wrapping ErrNotRegular", err)
	}
}

// 通常のファイルはこれまでどおり開ける。返す FileInfo は開いたファイルのものである。
func TestOpenRegularOpensARegularFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, fi, err := OpenRegular(p, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if fi.Size() != 2 || !fi.Mode().IsRegular() {
		t.Errorf("FileInfo = %v, %d bytes; want the regular file of 2 bytes", fi.Mode(), fi.Size())
	}
	if _, _, err := OpenRegular(filepath.Join(t.TempDir(), "missing"), os.O_RDONLY, 0); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("OpenRegular on a missing file = %v, want os.ErrNotExist", err)
	}
}
