//go:build unix

package flock

import (
	"errors"
	"os"
	"syscall"
)

// tryLock は待たずに排他ロックを取る。他のプロセスが持っていれば ErrLocked。
func tryLock(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return ErrLocked
	}
	return err
}

// trySharedLock は待たずに共有ロックを取る。排他ロックの持ち主がいれば ErrLocked。
// O_RDONLY で開いた記述子でも flock は取れる。放すのは close で足りる。
func trySharedLock(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return ErrLocked
	}
	return err
}
