//go:build windows

package credentials

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// secureNewDir は、EnsureDataDir が新規に作ったデータディレクトリだけに、保護された
// (親からの継承を切った)DACL を付ける。SYSTEM(SY)・BUILTIN\Administrators(BA)・
// 今の実行者の 3 者だけにフルアクセス(FA)を許し、OICI(Object Inherit・Container
// Inherit)を添えて、これから中に作る子にも同じ権利が継承されるようにする。既に存在した
// ディレクトリには決して呼ばない(仕様 11a 節。管理者が意図して加えた ACL を消さないため)。
func secureNewDir(dir string) error {
	sid, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("current user sid: %w", err)
	}
	if err := applyProtectedDACL(dir, sid, true); err != nil {
		return fmt.Errorf("secure new data dir %s: %w", dir, err)
	}
	return nil
}

// currentUserSID は今のプロセスのトークンに結びついた利用者の SID。エージェントを
// Windows サービスとして SYSTEM で動かす場合は SYSTEM の SID になり、下の DACL の SY の
// 項目と重なるが、同じ権利を重ねて許すだけなので害はない。
func currentUserSID() (*windows.SID, error) {
	// GetCurrentProcessToken は閉じる必要のない疑似トークン(TOKEN_QUERY 相当)を返す。
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid, nil
}

// applyProtectedDACL は、SYSTEM(SY)・BUILTIN\Administrators(BA)・userSID の 3 者だけに
// フルアクセス(FA)を許す DACL を path に付け、PROTECTED_DACL_SECURITY_INFORMATION で
// 親からの継承を切る。forContainer が真なら、これから作る子にも同じ権利が継承されるよう
// OICI を添える。SecureFile(filesec_windows.go)は、既に存在するファイルを事後に締めるため
// forContainer=false でこれを呼ぶ。新規に作るファイルは、事後に締めるこの経路ではなく
// createSecureTemp(createtemp_windows.go)が作成の瞬間から保護する(仕様 11a 節。事後に
// 締める経路には、作成直後から締めるまでの間、別の利用者がハンドルを開けてしまう、緩い ACL のままの期間がある)。
func applyProtectedDACL(path string, userSID *windows.SID, forContainer bool) error {
	sd, err := protectedSecurityDescriptor(userSID, forContainer)
	if err != nil {
		return fmt.Errorf("build security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read dacl: %w", err)
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

// protectedSecurityDescriptor は、SYSTEM(SY)・BUILTIN\Administrators(BA)・userSID だけに
// フルアクセス(FA)を許し、SDDL の "P" で最初から継承を切った(親の継承可能な ACE を
// 合成させない)セキュリティ記述子を返す。applyProtectedDACL はここから DACL だけを取り出して
// 事後に付け直す(protected は別途 SetNamedSecurityInfo の引数で指定するので、SDDL 側の "P" は
// この経路では効果を持たない)。createSecureTemp(createtemp_windows.go)はこの記述子を
// CreateFile にそのまま渡し、作成の瞬間から "P" を効かせる。forContainer が真なら、
// これから作る子にも同じ権利が継承されるよう OICI を添える。
func protectedSecurityDescriptor(userSID *windows.SID, forContainer bool) (*windows.SECURITY_DESCRIPTOR, error) {
	flags := ""
	if forContainer {
		flags = "OICI"
	}
	sddl := fmt.Sprintf("D:P(A;%s;FA;;;SY)(A;%s;FA;;;BA)(A;%s;FA;;;%s)", flags, flags, flags, userSID.String())
	return windows.SecurityDescriptorFromString(sddl)
}
