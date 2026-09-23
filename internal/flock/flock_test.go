package flock

import (
	"errors"
	"os"
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

// ロックファイルが無いとき、Inspect は Absent を返し、ファイルを作らない。
// 一度も起動していないホストで診断を打っただけでロックファイルが残り、後から非特権で動く
// プロセスが起動できなくなる実害を塞ぐ(設計 10.2c 節)。
func TestInspectDoesNotCreateTheLockFile(t *testing.T) {
	state := filepath.Join(t.TempDir(), "agent.json")
	got, err := Inspect(state)
	if err != nil {
		t.Fatalf("Inspect = %v, %v; want Absent", got, err)
	}
	if got != Absent {
		t.Errorf("Inspect = %v, want Absent", got)
	}
	if _, err := os.Stat(LockPath(state)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("os.Stat(%s) = %v; the lock file must not exist after Inspect", LockPath(state), err)
	}
	// 状態ファイルそのものも作らない
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("os.Stat(%s) = %v; the state file must not exist after Inspect", state, err)
	}
}

// 排他ロックの持ち主がいれば Locked、いなければ Unlocked。共有ロックは放たれるので、
// Inspect の後も Acquire は取れる。
func TestInspectReportsTheLockState(t *testing.T) {
	state := filepath.Join(t.TempDir(), "agent.json")
	held, err := Acquire(state)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Inspect(state); err != nil || got != Locked {
		t.Fatalf("Inspect while held = %v, %v; want Locked", got, err)
	}
	if err := held.Release(); err != nil {
		t.Fatal(err)
	}
	if got, err := Inspect(state); err != nil || got != Unlocked {
		t.Fatalf("Inspect after release = %v, %v; want Unlocked", got, err)
	}
	again, err := Acquire(state)
	if err != nil {
		t.Fatalf("Acquire after Inspect: %v; Inspect must release its shared lock", err)
	}
	again.Release()
}

// Inspect が取るのは共有ロックなので、別の Inspect がロックを見ている最中でも Unlocked を返す。
// 排他ロックにすると、同時に走った 2 つの Inspect が互いを Locked と誤って答える。
// 設計 10.2c 節が許したのは、共有ロックを一瞬だけ取って放つ形である。
func TestInspectDoesNotConflictWithAnotherInspect(t *testing.T) {
	state := filepath.Join(t.TempDir(), "agent.json")
	l, err := Acquire(state) // ロックファイルを作るためだけに取る
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	// 別の Inspect がロックを見ている最中を模す。別の open file description なので、
	// 取るロックが排他なら、この後の Inspect と衝突する。
	other, err := os.Open(LockPath(state))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := trySharedLock(other); err != nil {
		t.Fatalf("taking the shared lock: %v", err)
	}
	if got, err := Inspect(state); err != nil || got != Unlocked {
		t.Fatalf("Inspect while another shared lock is held = %v, %v; want Unlocked", got, err)
	}
}

// State の零値は Unknown。誤りを落とした呼び出し側が、判定できなかった場合をロックファイルの
// 不在と読み違えないことは、この値に依る。
func TestStateZeroValueIsUnknown(t *testing.T) {
	var zero State
	if zero != Unknown {
		t.Errorf("the zero State = %d, want Unknown, which is %d", zero, Unknown)
	}
	for _, s := range []State{Absent, Unlocked, Locked} {
		if s == zero {
			t.Errorf("%v shares the zero value with Unknown", s)
		}
	}
}

func TestStateString(t *testing.T) {
	for _, tc := range []struct {
		state State
		want  string
	}{{Unknown, "unknown"}, {Absent, "absent"}, {Unlocked, "unlocked"}, {Locked, "locked"}, {State(99), "unknown"}} {
		if got := tc.state.String(); got != tc.want {
			t.Errorf("State(%d).String() = %q, want %q", tc.state, got, tc.want)
		}
	}
}
