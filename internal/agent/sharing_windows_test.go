//go:build windows

package agent

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

// retrySharingViolation は、Windows の共有違反で失敗した f を少し待って呼び直す。Windows では、
// 認証情報ファイルを開いている間の rename による置き換えと、置き換えの途中の open が、共有違反か
// アクセス拒否で失敗しうる。並行する書き手と読み手を作る試験で、その回をやり直すために使う。主張は
// 変えない。やり直した後の結果を同じ基準で確かめる。
func retrySharingViolation(f func() error) error {
	var err error
	for i := 0; i < 200; i++ {
		err = f()
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return err
		}
		time.Sleep(time.Millisecond)
	}
	return err
}
