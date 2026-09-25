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

// noFollowFlags は OpenRegular が付ける旗である。O_NOFOLLOW は最後の要素の symlink を辿らずに ELOOP で
// 失敗させる。O_NONBLOCK は FIFO を開く時点で書き手や読み手を待たないためである。
const noFollowFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// isSymlinkRefusal は、O_NOFOLLOW が symlink を拒んだときの誤りかどうかである。Linux と macOS は ELOOP を
// 返す。FreeBSD は EMLINK を返す。
func isSymlinkRefusal(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK)
}
