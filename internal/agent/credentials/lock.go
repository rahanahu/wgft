package credentials

// ロックは共有の internal/flock に移した。ここは後方互換のための薄い委譲。
// エージェントの認証情報ファイルの二重起動検出と、稼働中の外部書き換え防止に使う(仕様 9 節)。
// flock 自体は状態ファイルの呼び名を知らない汎用パッケージなので、ここで利用者向けの
// 呼び名(認証情報ファイル)に言い換える。

import (
	"errors"

	"github.com/rahanahu/wgft/internal/flock"
)

// Lock は取得済みの排他ロック。
type Lock = flock.Lock

// ErrLocked は別のプロセスがロックを持っている。
var ErrLocked = errors.New("credentials file is in use by another process")

// LockPath は認証情報ファイルに対応するロックファイルの場所。
func LockPath(path string) string { return flock.LockPath(path) }

// Acquire はロックを取る。取れなければ ErrLocked。Windows では、ロックファイル自体も
// agent.json と同じ基準(SYSTEM・BUILTIN\Administrators・実行中の利用者だけ。仕様 11a 節)
// へ secureExisting で単独に締める。Unix では secureExisting は何もしない no-op で、この
// 修正の前後で Acquire の挙動(失敗時にロックを放さないことを含め)は変わらない。
func Acquire(path string) (*Lock, error) {
	l, err := flock.Acquire(path)
	if err != nil {
		if errors.Is(err, flock.ErrLocked) {
			return nil, ErrLocked
		}
		return nil, err
	}
	if err := secureExisting(flock.LockPath(path)); err != nil {
		l.Release()
		return nil, err
	}
	return l, nil
}

// State は Inspect が読み取ったロックファイルの状態。
type State = flock.State

// 状態の値は flock のものをそのまま使う。呼び出し側が flock を直接 import せずに済ませるため。
const (
	Unknown  = flock.Unknown
	Absent   = flock.Absent
	Unlocked = flock.Unlocked
	Locked   = flock.Locked
)

// Inspect はロックファイルを作らずにロックの状態を読む。認証情報ファイルのロックファイルが
// 無ければ Absent で、そのデータディレクトリにエージェントが稼働している証拠が無い。一度も
// 起動していない場合と、運用者がロックファイルを消した場合があり、この 2 つは区別できない
// (設計文書 10.2c 節)。
func Inspect(path string) (State, error) { return flock.Inspect(path) }
