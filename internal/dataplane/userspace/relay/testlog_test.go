package relay

import (
	"sync"
	"testing"
)

// testLogf は t.Logf を Options.Logf に渡すための包みで、テストが終わった後の行を捨てる。
//
// Manager.Close は待ち受けと接続を閉じるが、中継の goroutine が戻るのを待たない。宛先への接続を
// 試している最中の goroutine は、Close の後で失敗を知り、その行をテストが終わった後に書く。
// t.Logf をそのまま渡すと、その行がテストの一巡 (-count の 1 回分) の終わった後に届いたとき、
// testing の「Log in goroutine after ... has completed」の panic になり、パッケージの残りの
// テストを道連れにする。終わった後の行は、どのテストの判定にも使われないので捨ててよい。
func testLogf(t *testing.T) func(format string, args ...any) {
	t.Helper()
	var (
		mu    sync.Mutex
		ended bool
	)
	t.Cleanup(func() {
		mu.Lock()
		ended = true
		mu.Unlock()
	})
	return func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if !ended {
			t.Logf(format, args...)
		}
	}
}
