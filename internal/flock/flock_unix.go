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
