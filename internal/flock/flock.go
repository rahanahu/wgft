// Package flock は、隣の .lock ファイルへの排他ロック(仕様 9 節)。Unix では flock、Windows では LockFileEx。
// vpsd と agent の両方が、稼働中の検出と外部からの書き換え防止に使う。
// 状態ファイル自体は rename で置き換わって inode が変わるので、別の .lock に flock をかけ、
// プロセスが終わるまで開いたままにする。
package flock

import (
	"errors"
	"fmt"
	"io/fs"
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

// State は Inspect が読み取ったロックファイルの状態。
type State int

const (
	// Unknown は判定できなかった状態。Inspect が非 nil の誤りを返すときの値。
	Unknown State = iota
	// Absent はロックファイルが無い状態。その状態ファイルでは一度も起動していない。
	// 示すのはこの状態ファイルでの不在だけで、別の場所で稼働中のプロセスは見えない。
	Absent
	// Unlocked はロックファイルがあり、誰もロックを持っていない状態。
	Unlocked
	// Locked はロックファイルがあり、別のプロセスが排他ロックを持っている状態。
	Locked
)

// String は状態の名前。誤りの文言と診断の出力に載るので、値は英語の小文字にする。
func (s State) String() string {
	switch s {
	case Absent:
		return "absent"
	case Unlocked:
		return "unlocked"
	case Locked:
		return "locked"
	default:
		return "unknown"
	}
}

// Inspect はロックファイルを作らずにロックの状態を読む(設計 10.2c 節)。os.O_CREATE を渡さず、
// ファイルが既にある場合だけ共有ロックを一瞬取って放ち、排他ロックの持ち主の有無を見る。
// ロックファイルが無い場合は Absent を返し、権限などで読めない場合は Unknown と非 nil の誤りを
// 返すので、呼び出し側はこの 2 つを区別できる。
//
// 共有ロックを取る一瞬は、同時に起動したプロセスの Acquire が ErrLocked で失敗しうる期間として
// 残る。設計 10.2c 節は、この期間を無くすのではなく最小にすると決めている。配布対象の OS に
// ロックを取らずに状態だけを問い合わせる手段が揃わないためである。
func Inspect(statePath string) (State, error) {
	f, err := os.OpenFile(LockPath(statePath), os.O_RDONLY, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Absent, nil
		}
		return Unknown, fmt.Errorf("lock file: %w", err)
	}
	defer f.Close() // close で共有ロックも消える
	if err := trySharedLock(f); err != nil {
		if errors.Is(err, ErrLocked) {
			return Locked, nil
		}
		return Unknown, fmt.Errorf("flock: %w", err)
	}
	return Unlocked, nil
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
