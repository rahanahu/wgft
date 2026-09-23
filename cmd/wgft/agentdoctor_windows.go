//go:build windows

package main

import "errors"

// dirCreateAccess は、Windows では判定しない。unix.Access に当たる呼び出しが無く、ACL を読んで
// 判定を自前で組むほかに手段が無い。7a.11 節が Windows のエージェントを暫定としているので、その
// 判定は組まず、Windows だけ黙って OK を返す形にもしない。副作用なしには判定できない検査は、成功
// でも失敗でもない UNKNOWN とし、判定できない理由を添える(設計文書 10.2c 節)。
func dirCreateAccess(dir string) (accessResult, error) {
	return accessNotDetermined, errors.New("this host offers no way to test it without creating a file, and ACLs are not evaluated here")
}
