//go:build unix

package flock

import (
	"errors"
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
