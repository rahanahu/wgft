//go:build windows

package credentials

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// createSecureTemp は os.CreateTemp と同じ命名規則(pattern の最後の "*" を乱数に置き換え、
// 無ければ末尾に付け足す)で一時ファイルを作るが、Windows では作成の瞬間から保護 DACL
// (SYSTEM・BUILTIN\Administrators・今の実行者だけにフルアクセス、親からの継承なし)を
// 付けた状態で作る。CreateTemp で作ってから SecureFile で締め直す 2 段階では、作成直後
// から締め直すまでの間、その一時ファイルは親ディレクトリから継承した ACL のままであり、
// その間に別の利用者がハンドルを開けば、後から DACL を締めてもその接続は取り消せない
// (レビュー指摘。Windows はアクセス可否をハンドルを開く瞬間にだけ判定するため)。
// windows.CreateFile に SECURITY_ATTRIBUTES を渡すことで、この期間を無くす。
func createSecureTemp(dir, pattern string) (*os.File, error) {
	sid, err := currentUserSID()
	if err != nil {
		return nil, fmt.Errorf("current user sid: %w", err)
	}
	sd, err := protectedSecurityDescriptor(sid, false)
	if err != nil {
		return nil, fmt.Errorf("build security descriptor: %w", err)
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	prefix, suffix := splitTempPattern(pattern)
	const maxAttempts = 10000
	for i := 0; i < maxAttempts; i++ {
		name := filepath.Join(dir, prefix+randomSuffix()+suffix)
		namep, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, err
		}
		// 共有モード 0(share mode なし):作った直後からこの呼び出しだけがハンドルを持ち、
		// 他のプロセスは(同じ利用者であっても)開けない。CREATE_NEW は既存のファイルがあれば
		// ERROR_FILE_EXISTS で失敗するので、乱数が衝突した場合だけ名前を変えて再試行する。
		h, err := windows.CreateFile(namep,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			sa,
			windows.CREATE_NEW,
			windows.FILE_ATTRIBUTE_NORMAL,
			0)
		if err != nil {
			if errors.Is(err, windows.ERROR_FILE_EXISTS) {
				continue
			}
			return nil, &os.PathError{Op: "createsecuretemp", Path: name, Err: err}
		}
		return os.NewFile(uintptr(h), name), nil
	}
	return nil, fmt.Errorf("createSecureTemp: too many name collisions in %s", dir)
}

// splitTempPattern は os.CreateTemp と同じ規則で pattern を前後に分ける。
func splitTempPattern(pattern string) (prefix, suffix string) {
	if i := strings.LastIndexByte(pattern, '*'); i != -1 {
		return pattern[:i], pattern[i+1:]
	}
	return pattern, ""
}

// randomSuffix は一時ファイル名の衝突を避けるための乱数文字列(16 進 24 文字)。
func randomSuffix() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand の失敗は通常起きないが、万一の場合も CreateFile の
		// ERROR_FILE_EXISTS による再試行で衝突を吸収できるよう、何らかの文字列を返す。
		return fmt.Sprintf("%x-%x", os.Getpid(), time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
