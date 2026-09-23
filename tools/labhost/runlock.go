// runlock.go は 1 台の Lab Host VM の中で `labhost run` を 1 つに限るロック。
//
// なぜ VM ごとに 1 つかというと、`exclusive-heavy` と `exclusive-timing` の分類が約束するのは
// 「Lab Host VM の中で単独で流す」ことだからである。2 つの run は互いの日程を知らないので、
// 一方の単独の仕事が他方のどの仕事とでも重なりうる。ロックを -root の下に置くと、別の -root を
// 指した 2 つの run が同時に走れてしまい、約束が崩れる。RSS と到達頻度の測定は VM 全体の資源に
// 左右されるので、名前空間が衝突しない組み合わせであっても同時には流せない。
//
// gc も同じロックを取る。gc の走査は prefix だけを頼りにするので、同じ prefix で別の -root を
// 使う run が居ると、gc はその run の生きている Sandbox の作業ディレクトリのロック
// (別の root の下にある) を見つけられず、生きている netns を消してしまう。VM ごとのロックは
// この穴も塞ぐ。
//
// ロックの実体は internal/flock、つまりカーネルが持つ flock である。持ち主のプロセスが死ねば
// (SIGKILL でも) カーネルが解放するので、PID ファイルのように残らない。ロックファイルの中身には
// 持ち主の PID を書くが、それは断るときの案内に使うだけで、判定には使わない。
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rahanahu/wgft/internal/flock"
)

// defaultRunLock は run のロックの置き場の既定。/run は tmpfs なので、VM の再起動で消える。
// -root ではなく固定の場所にするのは、この排他が VM 全体に対する約束だからである。
const defaultRunLock = "/run/wgft-labhost"

// runLock は取得済みの run のロック。
type runLock struct {
	lock *flock.Lock
	path string
}

// errRunLockHeld は他の run がロックを持っている。
var errRunLockHeld = errors.New("another labhost run holds the Lab Host lock")

// acquireRunLock は run のロックを取る。wait が 0 なら、取れなければすぐに断る。
// wait が正なら、その時間まで待つ。待つ間は黙らず、誰を待っているかを 30 秒ごとに出す。
func acquireRunLock(base string, wait time.Duration) (*runLock, error) {
	path := flock.LockPath(base)
	if err := os.MkdirAll(filepath.Dir(base), 0o755); err != nil {
		return nil, fmt.Errorf("lock directory: %w", err)
	}
	deadline := time.Now().Add(wait)
	announced := time.Time{}
	for {
		l, err := flock.Acquire(base)
		if err == nil {
			// 中身の PID は案内のためだけに書く。判定はあくまで flock が行う
			_ = os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
			return &runLock{lock: l, path: path}, nil
		}
		if !errors.Is(err, flock.ErrLocked) {
			return nil, err
		}
		if wait <= 0 {
			return nil, fmt.Errorf("%w: %s%s", errRunLockHeld, path, holderSuffix(path))
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w after waiting %s: %s%s", errRunLockHeld, wait, path, holderSuffix(path))
		}
		if announced.IsZero() || time.Since(announced) >= 30*time.Second {
			fmt.Fprintf(os.Stderr, "labhost: waiting for the Lab Host lock %s%s\n", path, holderSuffix(path))
			announced = time.Now()
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// Release はロックを放す。
func (r *runLock) Release() {
	if r == nil || r.lock == nil {
		return
	}
	r.lock.Release()
	r.lock = nil
}

// holderSuffix は、ロックファイルの中身から持ち主の PID を読んで案内の文にする。
// 中身は持ち主が取得した直後に書くので、取得と書き込みの間に読むと空のことがある。
// 生きている labhost でなければ PID を出さない。
func holderSuffix(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return ""
	}
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil || !strings.Contains(string(comm), "labhost") {
		return ""
	}
	return fmt.Sprintf(", held by pid %d", pid)
}
