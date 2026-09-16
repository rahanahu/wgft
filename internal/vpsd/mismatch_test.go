package vpsd

import "testing"

// ipMismatchStep:8 回連続の食い違いで警告、一致・片欠けで数え直し(仕様 5.2 節)。
func TestIPMismatchStep(t *testing.T) {
	// 食い違いが 8 回続くと 8 回目で警告
	count := 0
	for i := 1; i <= 8; i++ {
		var warn bool
		count, warn = ipMismatchStep(count, "1.1.1.1", "2.2.2.2")
		if count != i {
			t.Fatalf("i=%d: count=%d", i, count)
		}
		if warn != (i >= 8) {
			t.Errorf("i=%d: warn=%v", i, warn)
		}
	}
	// 一致したら 0 に戻す(警告は消さないが count はリセット)
	if n, w := ipMismatchStep(7, "1.1.1.1", "1.1.1.1"); n != 0 || w {
		t.Errorf("一致で数え直し: n=%d w=%v", n, w)
	}
	// 片方が観測できなければ数えない
	if n, _ := ipMismatchStep(7, "", "2.2.2.2"); n != 0 {
		t.Errorf("stream 欠けで数え直し: n=%d", n)
	}
	if n, _ := ipMismatchStep(7, "1.1.1.1", ""); n != 0 {
		t.Errorf("wg 欠けで数え直し: n=%d", n)
	}
}
