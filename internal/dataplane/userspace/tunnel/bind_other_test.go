//go:build !windows

package tunnel

import "testing"

// device に渡すバインドが 1 回の受信で 1 件だけを渡すことを確かめる。Linux の標準のバインドは
// 128 件なので、この試験は wgbind.BatchOne の包みが外れていないことの回帰試験になる。macOS の
// 標準のバインドはもともと 1 件で、包みは使われない(設計文書 7 節)。
func TestNewBindHandsWireGuardOneDatagramAtATime(t *testing.T) {
	if got := newBind().BatchSize(); got != 1 {
		t.Fatalf("newBind().BatchSize() = %d, want 1", got)
	}
}
