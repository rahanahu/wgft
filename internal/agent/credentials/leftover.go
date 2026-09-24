package credentials

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// tempPrefix は Save が作る一時ファイルの名前の接頭辞である。Save は同じディレクトリに
// この接頭辞と乱数の名前で一時ファイルを作り、書き終えてから rename で認証情報ファイルに置き換える。
const tempPrefix = ".wgft-credentials-"

// saveBeforeRenameHook は、Save が一時ファイルを書き終えて rename する直前に、その一時ファイルの
// パスを渡して呼ばれる。テストだけが、Save の一時ファイルが起動時の片付けの対象の名前であることを
// 確かめるために設定する。
var saveBeforeRenameHook func(tmpName string)

// errLockNotHeld は、ロックを持たずに RemoveLeftoverTemps を呼んだことを示す。
var errLockNotHeld = errors.New("remove leftover temporary credentials files: the credentials file lock is not held")

// RemoveLeftoverTemps は、保存の途中でプロセスが強制終了されて残った一時ファイルを消す(仕様 9 節)。
// 一時ファイルは rename の前の agent.json の写しで、wg の秘密鍵と恒久トークンを含む。
//
// 呼び出し側は Acquire で認証情報ファイルのロックを取り、その Lock を渡す。ロックを持つ別の
// プロセスが保存している途中の一時ファイルを消さないためである。ロックを取らずに保存する書き手
// (agent pubkey と、ロックファイルの無い停止中の rotate-key)と重なると、Unix ではその書き手の
// rename が失敗する。Windows では、書き手が一時ファイルを共有を許さずに開いている間はこちらの削除が
// 失敗し、閉じてから rename するまでの間だけ書き手の rename が失敗する。どちらでも認証情報ファイルは
// 壊れない。この向きの失敗は許容する(仕様 9 節)。
//
// 対象は credentialsPath と同じディレクトリの直下にある、接頭辞の合う通常ファイルだけである。
// 再帰せず、名前の合うディレクトリと symlink も消さない。os.ReadDir の種別は lstat と同じで symlink を
// 辿らず、os.Remove は symlink の指す先ではなく名前そのものを消す。
//
// 消せないファイルがあっても残りは続けて消し、消した数と消せなかった数を LeftoverResult で返す。
// 誤りを返すのは、ロックを持たない場合と、ディレクトリを読めず残りの有無を確かめられなかった場合だけ
// である。
func RemoveLeftoverTemps(held *Lock, credentialsPath string) (LeftoverResult, error) {
	if held == nil {
		return LeftoverResult{}, errLockNotHeld
	}
	dir := filepath.Dir(credentialsPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return LeftoverResult{}, err
	}
	var r LeftoverResult
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), tempPrefix) || !e.Type().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			r.Failed++
			if r.FirstFailure == nil {
				r.FirstFailure = err
			}
			continue
		}
		r.Removed++
	}
	return r, nil
}

// LeftoverResult は RemoveLeftoverTemps の結果である。
type LeftoverResult struct {
	Removed int // 消した一時ファイルの数
	Failed  int // 消せなかった一時ファイルの数
	// FirstFailure は最初に消せなかったときの誤りで、パスを含む。ログに出すときは ErrorKind で
	// パスを除く
	FirstFailure error
}

// ErrorKind は、ファイル操作の誤りからパスを除いた種類だけを返す。*fs.PathError ならその下の誤り
// (permission denied など)の文言で、それ以外はそのままの文言である。起動時の片付けのログに
// 一時ファイルのパスを出さないために使う。
func ErrorKind(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
