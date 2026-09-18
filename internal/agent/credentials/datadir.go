package credentials

import "os"

// EnsureDataDir はデータディレクトリを作る(無ければ)。既に存在するディレクトリはそのまま
// にする。Unix の os.MkdirAll が既存のディレクトリを chmod しないのと同じ扱いである。
// WGFT_DATA_DIR は利用者が任意の場所を指せる設定なので、agent が作ったのではないディレクト
// リの ACL を書き換えることはしない。agent 自身が新規に作った場合だけ、Windows では
// secureNewDir が保護 DACL(SYSTEM・BUILTIN\Administrators・実行中の利用者だけ。仕様 9・
// 11a 節)を付ける。ディレクトリの下に置く各ファイル(agent.json・.lock・.sock)は、
// Save・Load・Acquire・制御ソケットがそれぞれ自分の分だけを個別に締める(SecureFile)。
func EnsureDataDir(dir string) error {
	_, statErr := os.Stat(dir)
	existed := statErr == nil
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if existed {
		return nil
	}
	return secureNewDir(dir)
}
