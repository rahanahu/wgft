//go:build !windows

package credentials

import "os"

// SecureFile は Windows 以外では 0600 の Chmod。Save の一時ファイルの締めに使い、この修正
// より前と同じく失敗を呼び出し元に伝える(元の tmp.Chmod(0o600) と同じ)。
func SecureFile(path string) error { return os.Chmod(path, 0o600) }

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
