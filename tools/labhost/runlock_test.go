package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// 2 つ目の run は断られる。断りの文にはロックファイルの場所が入る。
func TestRunLockRefusesASecondRun(t *testing.T) {
	base := filepath.Join(t.TempDir(), "labhost")
	first, err := acquireRunLock(base, 0)
	if err != nil {
		t.Fatalf("the first acquisition failed: %v", err)
	}
	defer first.Release()

	second, err := acquireRunLock(base, 0)
	if err == nil {
		second.Release()
		t.Fatal("the second acquisition succeeded; one run per Lab Host is not enforced")
	}
	if !errors.Is(err, errRunLockHeld) {
		t.Errorf("error = %v, want it to wrap errRunLockHeld", err)
	}
	if !strings.Contains(err.Error(), base+".lock") {
		t.Errorf("error %q does not name the lock file %q", err, base+".lock")
	}
}

// ロックファイルの中身は持ち主の PID で、断りの文はその PID を案内する。
func TestRunLockNamesItsHolder(t *testing.T) {
	base := filepath.Join(t.TempDir(), "labhost")
	held, err := acquireRunLock(base, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	b, err := os.ReadFile(base + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); got != strconv.Itoa(os.Getpid()) {
		t.Errorf("the lock file holds %q, want this process's pid %d", got, os.Getpid())
	}
	// comm がテストのバイナリ名 (labhost.test) なので、案内は自分の PID を含む
	if s := holderSuffix(base + ".lock"); !strings.Contains(s, strconv.Itoa(os.Getpid())) {
		t.Errorf("holderSuffix = %q, want it to name pid %d", s, os.Getpid())
	}
}

// 放せば次の run が取れる。
func TestRunLockIsReusableAfterRelease(t *testing.T) {
	base := filepath.Join(t.TempDir(), "labhost")
	first, err := acquireRunLock(base, 0)
	if err != nil {
		t.Fatal(err)
	}
	first.Release()
	second, err := acquireRunLock(base, 0)
	if err != nil {
		t.Fatalf("after the release the lock could not be taken: %v", err)
	}
	second.Release()
}

// -wait は待って取る。
func TestRunLockWaitsWhenAsked(t *testing.T) {
	base := filepath.Join(t.TempDir(), "labhost")
	first, err := acquireRunLock(base, 0)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(150 * time.Millisecond)
		first.Release()
	}()
	start := time.Now()
	second, err := acquireRunLock(base, 10*time.Second)
	if err != nil {
		t.Fatalf("waiting for the lock failed: %v", err)
	}
	second.Release()
	if time.Since(start) < 100*time.Millisecond {
		t.Errorf("the second acquisition returned after %s; it cannot have waited for the first", time.Since(start))
	}
}

// -wait の期限を過ぎれば断る。
func TestRunLockGivesUpAfterTheWait(t *testing.T) {
	base := filepath.Join(t.TempDir(), "labhost")
	first, err := acquireRunLock(base, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()
	if l, err := acquireRunLock(base, 50*time.Millisecond); err == nil {
		l.Release()
		t.Fatal("the acquisition succeeded although the lock was held for the whole wait")
	} else if !errors.Is(err, errRunLockHeld) {
		t.Errorf("error = %v, want it to wrap errRunLockHeld", err)
	}
}

// SIGKILL で死んだ持ち主のロックは残らない。PID ファイルではなくカーネルの flock なので、
// 死んだ瞬間に解放される。別のプロセスに持たせて、SIGKILL してから取り直す。
func TestRunLockDiesWithItsHolder(t *testing.T) {
	base := filepath.Join(t.TempDir(), "labhost")
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperHoldsRunLock", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), "LABHOST_TEST_HOLD_LOCK="+base)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// 子が「取った」と言うまで待つ
	buf := make([]byte, 64)
	deadline := time.Now().Add(20 * time.Second)
	got := ""
	for !strings.Contains(got, "held") && time.Now().Before(deadline) {
		n, err := out.Read(buf)
		if n > 0 {
			got += string(buf[:n])
		}
		if err != nil {
			break
		}
	}
	if !strings.Contains(got, "held") {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("the helper never reported holding the lock (read %q)", got)
	}
	if l, err := acquireRunLock(base, 0); err == nil {
		l.Release()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("the lock was free while the helper held it")
	}
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	// SIGKILL された持ち主のロックはカーネルが解放する。すぐに取れる
	l, err := acquireRunLock(base, 5*time.Second)
	if err != nil {
		t.Fatalf("the lock was still held after its holder was killed with SIGKILL: %v", err)
	}
	l.Release()
}

// TestHelperHoldsRunLock は上のテストの子プロセス。LABHOST_TEST_HOLD_LOCK が指すロックを取り、
// 取れたことを伝えて、殺されるまで持ち続ける。
func TestHelperHoldsRunLock(t *testing.T) {
	base := os.Getenv("LABHOST_TEST_HOLD_LOCK")
	if base == "" {
		t.Skip("not the helper process")
	}
	l, err := acquireRunLock(base, 0)
	if err != nil {
		fmt.Println("failed:", err)
		os.Exit(1)
	}
	fmt.Println("held")
	os.Stdout.Sync()
	_ = l
	time.Sleep(50 * time.Second)
}
