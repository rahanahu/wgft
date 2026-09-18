// Package flock は、隣の .lock ファイルへの排他ロック(仕様 9 節)。Unix では flock、Windows では LockFileEx。
// vpsd と agent の両方が、稼働中の検出と外部からの書き換え防止に使う。
// 状態ファイル自体は rename で置き換わって inode が変わるので、別の .lock に flock をかけ、
// プロセスが終わるまで開いたままにする。
package flock

import (
	"errors"
	"fmt"
	"os"
)

// Lock は取得済みの排他ロック。
type Lock struct {
	f *os.File
}

// ErrLocked は別のプロセスがロックを持っている。flock は状態ファイルの呼び名を知らない
// 汎用のパッケージなので、文言は中立にする。利用者に見える呼び名(credentials の
// 「認証情報ファイル」、vpsd の「サーバのデータベース」)への言い換えは呼び出し側で行う。
var ErrLocked = errors.New("locked by another process")

// LockPath は状態ファイルに対応するロックファイルの場所。
func LockPath(statePath string) string { return statePath + ".lock" }

// Acquire はロックを取る。取れなければ ErrLocked。
func Acquire(statePath string) (*Lock, error) {
	f, err := os.OpenFile(LockPath(statePath), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock file: %w", err)
	}
	if err := tryLock(f); err != nil {
		f.Close()
		if errors.Is(err, ErrLocked) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("flock: %w", err)
	}
	return &Lock{f: f}, nil
}

// IsLocked は誰かがロックを持っているか(ロックは取らない)。
func IsLocked(statePath string) (bool, error) {
	l, err := Acquire(statePath)
	if errors.Is(err, ErrLocked) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	l.Release()
	return false, nil
}

// Release はロックを放す。
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := l.f.Close() // close でロックも消える
	l.f = nil
	return err
}
