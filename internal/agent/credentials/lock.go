package credentials

// ロックは共有の internal/flock に移した。ここは後方互換のための薄い委譲。
// エージェントの認証情報ファイルの二重起動検出と、稼働中の外部書き換え防止に使う(仕様 9 節)。

import "github.com/rahanahu/wgft/internal/flock"

// Lock は取得済みの排他ロック。
type Lock = flock.Lock

// ErrLocked は別のプロセスがロックを持っている。
var ErrLocked = flock.ErrLocked

// LockPath は認証情報ファイルに対応するロックファイルの場所。
func LockPath(path string) string { return flock.LockPath(path) }

// Acquire はロックを取る。取れなければ ErrLocked。
func Acquire(path string) (*Lock, error) { return flock.Acquire(path) }

// IsLocked は誰かがロックを持っているか(ロックは取らない)。
func IsLocked(path string) (bool, error) { return flock.IsLocked(path) }
