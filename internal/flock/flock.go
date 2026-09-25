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

// ErrNotRegular は、開こうとしたパスが通常のファイルでないことを示す。symlink、FIFO、デバイス、
// ディレクトリがこれに当たる(設計文書 9・11 節)。
var ErrNotRegular = errors.New("not a regular file")

// OpenRegular は、path の最後の要素が symlink なら辿らずに失敗し、開いたものが通常のファイルでなければ
// 閉じて ErrNotRegular を返す(設計文書 9・11 節)。種別は開いた記述子に対して確かめるので、パスを
// 差し替えられても、確かめたものと返すものが食い違うことは無い。FIFO を開いた時点で止まらない
// よう、Unix では O_NONBLOCK を付けて開く。通常のファイルの読み書きには O_NONBLOCK は効かない。
// 返す FileInfo は開いた記述子の fstat である。
//
// root の CLI は、エージェントの利用者が書けるデータディレクトリの中のファイルをこれで開く。その利用者は
// ディレクトリの中の名前を自由に差し替えられるので、root はそのパスを信頼しない。
func OpenRegular(path string, flag int, perm os.FileMode) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, flag|noFollowFlags, perm)
	if err != nil {
		if isSymlinkRefusal(err) {
			if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode()&fs.ModeSymlink != 0 {
				return nil, nil, fmt.Errorf("%s is a symbolic link, which wgft does not follow: %w", path, ErrNotRegular)
			}
		}
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%s is not a regular file but %s: %w", path, describeType(fi.Mode()), ErrNotRegular)
	}
	return f, fi, nil
}

// describeType は通常のファイルでないものの種別を 1 語で表す。誤りの文言に使う。
func describeType(m fs.FileMode) string {
	switch {
	case m&fs.ModeSymlink != 0:
		return "a symbolic link"
	case m.IsDir():
		return "a directory"
	case m&fs.ModeNamedPipe != 0:
		return "a named pipe"
	case m&fs.ModeSocket != 0:
		return "a socket"
	case m&fs.ModeDevice != 0:
		return "a device"
	default:
		return "an irregular file"
	}
}

// Acquire はロックを取る。取れなければ ErrLocked。ロックファイルは OpenRegular で開くので、symlink を
// 辿らず、通常のファイルでなければ ErrNotRegular を包んだ誤りになる。symlink の先にファイルを作ることもない。
func Acquire(statePath string) (*Lock, error) {
	f, _, err := OpenRegular(LockPath(statePath), os.O_CREATE|os.O_RDWR, 0o600)
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

// State は Inspect が読み取ったロックファイルの状態。
type State int

const (
	// Unknown は判定できなかった状態。Inspect が非 nil の誤りを返すときの値。
	Unknown State = iota
	// Absent はロックファイルが無い状態。稼働している証拠が無いことだけを示す。その状態ファイルで
	// 一度も起動していない場合と、運用者がロックファイルを消した場合があり、この 2 つは区別できない
	// (設計文書 10.2c 節)。示すのはこの状態ファイルでの不在だけで、別の場所で稼働中のプロセスは
	// 見えない。
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
//
// ロックファイルは OpenRegular で開く。symlink や FIFO なら Unknown と誤りを返し、辿りも止まりもしない。
func Inspect(statePath string) (State, error) {
	f, _, err := OpenRegular(LockPath(statePath), os.O_RDONLY, 0)
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
