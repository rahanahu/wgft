//go:build linux

package vpsd

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

// TestClassifyWGResidue は wgResidue の誤りの分類(mode.go)が、文字列一致ではなく wgctrl が
// 約束する os.ErrNotExist の型で判定することを確かめる(design.md 10.5 節)。文字列一致だと、
// interface が本当に無いのか、netlink や権限のような別の理由で読めなかっただけなのかを
// 取り違え、モード切り替えの関門(3.3 節)を誤って通してしまう恐れがあった。
func TestClassifyWGResidue(t *testing.T) {
	if residue, known := classifyWGResidue(nil); !residue || !known {
		t.Errorf("nil error (device exists) = (%v, %v), want (true, true)", residue, known)
	}

	// wgctrl の Device() が実際に返す形(net/os のラップ経由で os.ErrNotExist を包む)。
	wrapped := fmt.Errorf("get device %s: %w", "wgft0", os.ErrNotExist)
	if residue, known := classifyWGResidue(wrapped); residue || !known {
		t.Errorf("wrapped os.ErrNotExist = (%v, %v), want (false, true)", residue, known)
	}

	// 文面には "not found" を含むが、実際には os.ErrNotExist を包んでいない、無関係な失敗
	// (例: netlink の内部エラー)。文字列一致では誤って「確認できた・残骸なし」と分類し、
	// modeGate を素通りさせてしまっていた。型判定では「確認できなかった」に倒れる。
	unrelated := errors.New("netlink: attribute not found in the response")
	if residue, known := classifyWGResidue(unrelated); residue || known {
		t.Errorf("unrelated error that merely mentions \"not found\" = (%v, %v), want (false, false) (unconfirmed, not a confirmed absence)", residue, known)
	}

	// 本当に無関係な失敗(権限など)も未確認のまま。
	other := errors.New("operation not permitted")
	if residue, known := classifyWGResidue(other); residue || known {
		t.Errorf("unrelated failure = (%v, %v), want (false, false)", residue, known)
	}
}
