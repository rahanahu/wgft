//go:build windows

package credentials

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dacl SIDs and the protected flag are read directly via GetNamedSecurityInfo/GetAce rather
// than by parsing icacls's text output, which is localized on non-English Windows.

// aclSIDs returns the DACL's principals (as canonical SID strings, e.g. "S-1-5-18") and
// whether the DACL is protected (SE_DACL_PROTECTED, i.e. not inheriting from the parent).
func aclSIDs(t *testing.T, path string) (sids []string, protected bool) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("Control(%s): %v", path, err)
	}
	protected = control&windows.SE_DACL_PROTECTED != 0
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL(%s): %v", path, err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("GetAce(%s, %d): %v", path, i, err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		sids = append(sids, sid.String())
	}
	sort.Strings(sids)
	return sids, protected
}

// wantProtectedSIDs is the exact principal set our DACL should ever contain: SYSTEM,
// BUILTIN\Administrators, and whichever user this test process runs as.
func wantProtectedSIDs(t *testing.T) []string {
	t.Helper()
	sys, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	me, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{sys.String(), admins.String(), me.String()}
	sort.Strings(want)
	return want
}

// assertProtectedTo3 fails the test unless path's DACL is protected and contains exactly
// SYSTEM, BUILTIN\Administrators and the current user -- no more, no less (so BUILTIN\Users,
// Everyone, or anyone else is confirmed absent).
func assertProtectedTo3(t *testing.T, path string) {
	t.Helper()
	got, protected := aclSIDs(t, path)
	want := wantProtectedSIDs(t)
	if !protected {
		t.Errorf("%s: DACL is not protected (still inherits from the parent)", path)
	}
	if !equalStrings(got, want) {
		t.Errorf("%s: DACL principals = %v, want exactly %v", path, got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// setLooseDACL grants SYSTEM/Administrators/the current user full control plus
// BUILTIN\Users(BU) generic read, and marks it inheritable (OICI), reproducing the
// %ProgramData% default this fix was written against (design.md revision record).
func setLooseDACL(t *testing.T, path string) {
	t.Helper()
	me, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(
		"D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + me.String() + ")(A;OICI;GR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// hasSID reports whether path's DACL grants the well-known BUILTIN\Users alias (BU) any
// access at all.
func hasBuiltinUsers(t *testing.T, path string) bool {
	t.Helper()
	bu, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	sids, _ := aclSIDs(t, path)
	for _, s := range sids {
		if s == bu.String() {
			return true
		}
	}
	return false
}

// TestEnsureDataDirNewDirectoryIsProtected は、EnsureDataDir が新規に作るディレクトリだけを
// 対象にすることを確かめる。新規なら保護 DACL が付く。
func TestEnsureDataDirNewDirectoryIsProtected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wgft")
	if err := EnsureDataDir(dir); err != nil {
		t.Fatalf("EnsureDataDir: %v", err)
	}
	assertProtectedTo3(t, dir)
}

// TestEnsureDataDirLeavesExistingDirectoryAlone は、redesign の核心を確かめる。既に存在する
// ディレクトリ(WGFT_DATA_DIR が利用者の指す任意の場所であり得る)は、緩い ACL であっても
// EnsureDataDir が書き換えないことを検証する。Unix の MkdirAll が既存のディレクトリを
// chmod しないのと同じ扱いにするための回帰テスト。
func TestEnsureDataDirLeavesExistingDirectoryAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "existing")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	setLooseDACL(t, dir)
	if !hasBuiltinUsers(t, dir) {
		t.Fatal("setup: directory does not have the loose ACE we set up")
	}

	if err := EnsureDataDir(dir); err != nil {
		t.Fatalf("EnsureDataDir: %v", err)
	}

	if !hasBuiltinUsers(t, dir) {
		t.Error("EnsureDataDir rewrote the ACL of a directory that already existed; it must leave it alone (design.md 11a)")
	}
}

// TestSecureFileTightensExistingLooseFile は、この修正より前に緩い ACL の下で作られていた
// 既存の agent.json(この PC の実機がまさにその状態だった)を、SecureFile が単独で
// 締め直すことを確かめる。
func TestSecureFileTightensExistingLooseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	setLooseDACL(t, path)
	if !hasBuiltinUsers(t, path) {
		t.Fatal("setup: file does not have the loose ACE we set up")
	}

	if err := SecureFile(path); err != nil {
		t.Fatalf("SecureFile: %v", err)
	}
	assertProtectedTo3(t, path)
}

// TestSecureFileDoesNotTouchSiblings は、redesign が対象を単一ファイルに絞ったことを確かめる。
// SecureFile(agent.json) は同じディレクトリの他のファイルの ACL には触れない。
func TestSecureFileDoesNotTouchSiblings(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "agent.json")
	sibling := filepath.Join(dir, "unrelated.txt")
	for _, p := range []string{target, sibling} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		setLooseDACL(t, p)
	}

	if err := SecureFile(target); err != nil {
		t.Fatalf("SecureFile: %v", err)
	}

	if hasBuiltinUsers(t, target) {
		t.Error("SecureFile did not tighten its own target")
	}
	if !hasBuiltinUsers(t, sibling) {
		t.Error("SecureFile touched a sibling file it was never asked to secure")
	}
}

// TestLoadTightensExistingLooseFile は、Load が起動時に secureExisting 経由で agent.json を
// 単独で締め直すことを確かめる(実機で見つかった、この修正前の状態そのもの)。Unix では
// secureExisting は no-op なので、この挙動は Windows 固有である
// (securitycheck_other_test.go / filesec_other.go の TestLoadDoesNotChmodOnUnix を参照)。
func TestLoadTightensExistingLooseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := (&Credentials{Name: "loose"}).Save(path); err != nil {
		t.Fatal(err)
	}
	setLooseDACL(t, path)
	if !hasBuiltinUsers(t, path) {
		t.Fatal("setup: file does not have the loose ACE we set up")
	}

	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertProtectedTo3(t, path)
}

// TestCreateSecureTempHasProtectedDACLAtCreation は、createSecureTemp が返すファイルが、
// 作成した直後(他の呼び出しを何も挟まない時点)で、既に保護 DACL(SYSTEM・
// BUILTIN\Administrators・今の実行者だけ)になっていることを確かめる。os.CreateTemp して
// から SecureFile で締め直す旧い手順では、締め直すまでの間、緩い(親から継承した)ACL の
// ままハンドルを開ける窓があった(レビュー指摘)。この窓が無いことを、作成直後の 1 点だけを
// 見て確認する。
func TestCreateSecureTempHasProtectedDACLAtCreation(t *testing.T) {
	dir := t.TempDir()
	// setLooseDACL でディレクトリ自体を緩くしておく。作成直後の DACL が保護されているのが
	// createSecureTemp 自身の仕事であって、たまたまディレクトリが厳しいからではないことを
	// はっきりさせるため。
	setLooseDACL(t, dir)

	tmp, err := createSecureTemp(dir, ".wgft-credentials-*")
	if err != nil {
		t.Fatalf("createSecureTemp: %v", err)
	}
	defer tmp.Close()
	defer os.Remove(tmp.Name())

	assertProtectedTo3(t, tmp.Name())
}

// TestSaveSecuresTempFileBeforeRename は、Save が秘密を書く前に一時ファイルを締め、
// 同じディレクトリ内での rename がその DACL をそのまま持ち越すことを確かめる
// (design.md 11a 節が前提にしている挙動)。
func TestSaveSecuresTempFileBeforeRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	f := &Credentials{}
	if _, err := f.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	assertProtectedTo3(t, path)

	// 2 回目の Save(rotate-key の書き換えを模す)でも変わらないことも確かめる。
	f.WGPrivateKey = "" // force EnsureKey to make a new one
	if _, err := f.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	assertProtectedTo3(t, path)
}

// assertFileSecured is credentials_test.go's cross-platform entry point (see
// securitycheck_other_test.go for the Unix counterpart): on Windows a 0600-equivalent means
// the DACL is protected and grants only SYSTEM/Administrators/the current user.
func assertFileSecured(t *testing.T, path string) {
	t.Helper()
	assertProtectedTo3(t, path)
}

// TestAcquireSecuresLockFile は、Acquire が secureExisting 経由で隣の .lock を単独で締める
// ことを確かめる。Unix では secureExisting は no-op なので、この挙動は Windows 固有である。
func TestAcquireSecuresLockFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	l, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	assertProtectedTo3(t, LockPath(path))
}

// TestSecureSocketAppliesProtectedDACL は、control.go が使う SecureSocket が、Windows では
// SecureFile と同じ保護 DACL を適用し、失敗を呼び出し元に伝えることを確かめる
// (Unix では chmod の失敗を無視する。filesec_other.go の TestSecureSocketIgnoresChmodFailure
// を参照)。
func TestSecureSocketAppliesProtectedDACL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json.sock")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	setLooseDACL(t, path)
	if err := SecureSocket(path); err != nil {
		t.Fatalf("SecureSocket: %v", err)
	}
	assertProtectedTo3(t, path)
}
