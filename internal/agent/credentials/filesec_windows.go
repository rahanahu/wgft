//go:build windows

package credentials

import "fmt"

// SecureFile は path 1 つだけを、SYSTEM・BUILTIN\Administrators・今の実行者だけに絞った
// 保護 DACL(親からの継承を切ったもの)に締める。ディレクトリにも、隣のファイルにも触れ
// ない(仕様 9・11a 節)。Save が、秘密を書き込む前の一時ファイルにこれを呼ぶ。同じ
// ディレクトリ内での rename はこのファイル自身の DACL をそのまま持ち越すので、緩い ACL の
// 期間は生じない。
func SecureFile(path string) error {
	sid, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("current user sid: %w", err)
	}
	if err := applyProtectedDACL(path, sid, false); err != nil {
		return fmt.Errorf("secure %s: %w", path, err)
	}
	return nil
}

// secureExisting は、この修正より前に緩い ACL の下で作られていた既存のファイルを
// Windows でだけ締め直す。Load(agent.json)と Acquire(lock.go の .lock)が、読む・開く
// たびにこれを呼ぶ。Unix(filesec_other.go)では何もしない no-op で、Unix の Load・Acquire
// の挙動はこの修正の前後で変わらない。
func secureExisting(path string) error { return SecureFile(path) }

// SecureSocket は制御ソケット(.sock)を締める。Windows では SecureFile と同じく失敗を
// 呼び出し元に伝え、control.go がソケットを諦める(仕様 11a 節)。Unix(filesec_other.go)
// では、この修正より前と同じく chmod の失敗を無視する。
func SecureSocket(path string) error { return SecureFile(path) }
