package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// tempPrefix は Save が作る一時ファイルの名前の接頭辞である。Save は同じディレクトリに
// この接頭辞と乱数の名前で一時ファイルを作り、書き終えてから rename で認証情報ファイルに置き換える。
const tempPrefix = ".wgft-credentials-"

// errLockNotHeld は、ロックを持たずに RemoveLeftoverTemps を呼んだことを示す。
var errLockNotHeld = errors.New("remove leftover temporary credentials files: the credentials file lock is not held")

// RemoveLeftoverTemps は、保存の途中でプロセスが強制終了されて残った一時ファイルを消す(仕様 9 節)。
// 一時ファイルは rename の前の agent.json の写しで、wg の秘密鍵と恒久トークンを含む。
//
// 呼び出し側は Acquire で認証情報ファイルのロックを取り、その Lock を渡す。ロックを持つ別の
// プロセスが保存している途中の一時ファイルを消さないためである。ロックを取らずに保存する書き手
// (agent pubkey と、ロックファイルの無い停止中の rotate-key)と重なると、その書き手の rename が
// 失敗するが、認証情報ファイルは壊れない。この向きの失敗は許容する(仕様 9 節)。
//
// 対象は credentialsPath と同じディレクトリの直下にある、接頭辞の合う通常ファイルだけである。
// 再帰せず、名前の合うディレクトリと symlink も消さない。os.ReadDir の種別は lstat と同じで symlink を
// 辿らず、os.Remove は symlink の指す先ではなく名前そのものを消す。
//
// 消した数を返す。消せないファイルがあっても残りは続けて消し、誤りをまとめて返す。
func RemoveLeftoverTemps(held *Lock, credentialsPath string) (int, error) {
	if held == nil {
		return 0, errLockNotHeld
	}
	dir := filepath.Dir(credentialsPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	removed := 0
	var errs []error
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), tempPrefix) || !e.Type().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			errs = append(errs, err)
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}
