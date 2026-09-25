//go:build !windows

package credentials

import "os"

// secureTemp は Windows 以外では、Save の一時ファイルを開いた記述子に対して 0600 に chmod する。
// 失敗は呼び出し元に伝える。パスで chmod しないのは、root の Save の途中でエージェントの利用者が
// 一時ファイルの名前を別のファイルへの symlink に差し替えても、その先の権限を変えないためである
// (仕様 9・11 節)。
func secureTemp(f *os.File) error { return f.Chmod(0o600) }

// secureExisting は Unix では何もしない。既存の agent.json・.lock を起動のたびに chmod する
// と、管理者が意図して締めた 0400 を 0600 へ緩めてしまい、9 節の「余分な権限だけを外し、
// それ以外は変えない」という原則に反する。加えて、deploy/agent.compose.yaml のように
// cap_drop: [ALL] で動かし、ボリュームのファイルを所有していない場合に chmod が EPERM で
// 失敗し、この修正の前は起動できていた構成が起動できなくなる。Windows の Chmod(0o600)は
// 継承した ACL を止められないため retrofit が要るが(filesec_windows.go)、Unix の chmod は
// この修正より前から機能していたので、ここで retrofit する理由が無い。
func secureExisting(path string) error { return nil }

// SecureSocket は、Windows 以外ではこの修正より前と同じく chmod の失敗を無視する
// (元の os.Chmod(path, 0o600) の戻り値を見ない呼び出しと同じ)。
func SecureSocket(path string) error {
	os.Chmod(path, 0o600)
	return nil
}
