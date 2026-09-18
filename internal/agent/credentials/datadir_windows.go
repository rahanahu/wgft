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
// OICI を添える。SecureFile(filesec_windows.go)は、単独のファイルを締めるために
// forContainer=false でこれを呼ぶ。
func applyProtectedDACL(path string, userSID *windows.SID, forContainer bool) error {
	flags := ""
	if forContainer {
		flags = "OICI"
	}
	sddl := fmt.Sprintf("D:(A;%s;FA;;;SY)(A;%s;FA;;;BA)(A;%s;FA;;;%s)", flags, flags, flags, userSID.String())
	sd, err := windows.SecurityDescriptorFromString(sddl)
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
