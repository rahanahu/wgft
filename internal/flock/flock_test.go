package flock

import (
	"errors"
	"path/filepath"
	"testing"
)

// 2 つ目の取得は ErrLocked で止まり、放せばまた取れる。同じプロセス内でも別のファイル記述子なら排他になる。
func TestAcquireIsExclusive(t *testing.T) {
	state := filepath.Join(t.TempDir(), "agent.json")
	first, err := Acquire(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(state); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Acquire = %v, want ErrLocked", err)
	}
	if locked, err := IsLocked(state); err != nil || !locked {
		t.Fatalf("IsLocked = %v, %v; want true", locked, err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	if locked, err := IsLocked(state); err != nil || locked {
		t.Fatalf("IsLocked after release = %v, %v; want false", locked, err)
	}
	again, err := Acquire(state)
	if err != nil {
		t.Fatalf("Acquire after release: %v", err)
	}
	again.Release()
}
