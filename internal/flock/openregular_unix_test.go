//go:build unix

package flock

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// ロックファイルが FIFO なら、Inspect と Acquire は書き手や読み手を待たずに拒む。root の agent doctor や
// rotate-key が、エージェントの利用者の置いた FIFO で止まらないためである(設計文書 9・11 節)。
func TestLockFileFIFOIsRefusedWithoutBlocking(t *testing.T) {
	state := filepath.Join(t.TempDir(), "agent.json")
	if err := syscall.Mkfifo(LockPath(state), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if st, err := Inspect(state); !errors.Is(err, ErrNotRegular) || st != Unknown {
			t.Errorf("Inspect = %v, %v; want Unknown and an error wrapping ErrNotRegular", st, err)
		}
		if l, err := Acquire(state); !errors.Is(err, ErrNotRegular) {
			l.Release()
			t.Errorf("Acquire = %v, want an error wrapping ErrNotRegular", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("opening a FIFO lock file blocked")
	}
}

// AcquireCreating も symlink と FIFO のロックファイルを辿らずに拒み、symlink の先にファイルを作らない。
func TestAcquireCreatingRefusesIrregularLockFiles(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "a.sqlite")
	if err := os.Symlink(filepath.Join(dir, "target"), LockPath(link)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AcquireCreating(link); !errors.Is(err, ErrNotRegular) {
		t.Errorf("AcquireCreating on a symlink = %v, want ErrNotRegular", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "target")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("AcquireCreating created the symlink's target: %v", err)
	}
	fifo := filepath.Join(dir, "b.sqlite")
	if err := syscall.Mkfifo(LockPath(fifo), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AcquireCreating(fifo); !errors.Is(err, ErrNotRegular) {
		t.Errorf("AcquireCreating on a FIFO = %v, want ErrNotRegular", err)
	}
}
