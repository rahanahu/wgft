//go:build windows

package flock

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// tryLock は待たずに排他ロックを取る。他のプロセスが持っていれば ErrLocked。
// ロックはハンドルに結び付き、ファイルを閉じるかプロセスが終わると消える(flock と同じ)。
func tryLock(f *os.File) error {
	ol := new(windows.Overlapped)
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return ErrLocked
	}
	return err
}

// trySharedLock は待たずに共有ロックを取る。排他ロックの持ち主がいれば ErrLocked。
// LOCKFILE_EXCLUSIVE_LOCK を渡さない LockFileEx が共有ロックで、GENERIC_READ だけを持つ
// ハンドル、つまり os.O_RDONLY で開いたファイルでも取れる。放すのは close で足りる。
func trySharedLock(f *os.File) error {
	ol := new(windows.Overlapped)
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return ErrLocked
	}
	return err
}
