package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeLeftoverTestFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func pathExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	if err == nil {
		return true
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return false
}

// 保存の途中で残った一時ファイルだけを消し、認証情報ファイル、ロックファイル、名前の違うファイル、
// 名前の合うディレクトリとその中身、名前の合う symlink とその指す先は残す。
func TestRemoveLeftoverTemps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := (&Credentials{Name: "a"}).Save(path); err != nil {
		t.Fatal(err)
	}
	l, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()

	var leftovers []string
	for range 2 {
		f, err := createSecureTemp(dir, tempPrefix+"*")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		leftovers = append(leftovers, f.Name())
	}
	keep := []string{
		path,
		LockPath(path),
		filepath.Join(dir, "wgft-credentials-x"),   // 先頭の点が無い
		filepath.Join(dir, ".wgft-credentials"),    // 接頭辞の途中まで
		filepath.Join(dir, "x.wgft-credentials-y"), // 途中に含むだけ
	}
	for _, p := range keep[2:] {
		writeLeftoverTestFile(t, p)
	}
	subdir := filepath.Join(dir, tempPrefix+"dir")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(subdir, tempPrefix+"inner")
	writeLeftoverTestFile(t, inner)
	keep = append(keep, subdir, inner)

	// symlink は Windows では権限が無いと作れないので、作れたときだけ確かめる。
	outside := filepath.Join(t.TempDir(), tempPrefix+"target")
	writeLeftoverTestFile(t, outside)
	link := filepath.Join(dir, tempPrefix+"link")
	if err := os.Symlink(outside, link); err == nil {
		keep = append(keep, link, outside)
	} else if runtime.GOOS != "windows" {
		t.Fatal(err)
	}

	r, err := RemoveLeftoverTemps(l, path)
	if err != nil {
		t.Fatal(err)
	}
	if r.Removed != len(leftovers) || r.Failed != 0 {
		t.Errorf("result %+v, want %d removed and none failed", r, len(leftovers))
	}
	for _, p := range leftovers {
		if pathExists(t, p) {
			t.Errorf("%s is left", p)
		}
	}
	for _, p := range keep {
		if !pathExists(t, p) {
			t.Errorf("%s was removed", p)
		}
	}
	// 片付けの後も認証情報ファイルは読めて、保存も続けられる
	if _, err := Load(path); err != nil {
		t.Errorf("Load after cleanup: %v", err)
	}
	if err := (&Credentials{Name: "b"}).Save(path); err != nil {
		t.Errorf("Save after cleanup: %v", err)
	}

	// 残りが無ければ 0 を返す
	if r, err := RemoveLeftoverTemps(l, path); r != (LeftoverResult{}) || err != nil {
		t.Errorf("second run = %+v, %v; want nothing removed and no error", r, err)
	}
}

// ロックを持たずに呼べば、何も消さずに誤りを返す。
func TestRemoveLeftoverTempsNeedsLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	leftover := filepath.Join(dir, tempPrefix+"123")
	writeLeftoverTestFile(t, leftover)
	r, err := RemoveLeftoverTemps(nil, path)
	if !errors.Is(err, errLockNotHeld) || r != (LeftoverResult{}) {
		t.Errorf("RemoveLeftoverTemps without lock = %+v, %v; want nothing and errLockNotHeld", r, err)
	}
	if !pathExists(t, leftover) {
		t.Error("the leftover was removed without the lock")
	}
}

// データディレクトリを読めなければ、誤りを返す。呼び出し側は警告にとどめる。
func TestRemoveLeftoverTempsMissingDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gone", "agent.json")
	if _, err := RemoveLeftoverTemps(&Lock{}, path); err == nil {
		t.Error("want an error for a missing directory")
	}
}

// 消せない一時ファイルがあれば、その数と最初の誤りを返す。誤りの種類はパスを含まない。呼び出し側は警告にとどめる。
// 書き込みの権限の無いディレクトリで確かめるので、Unix の非 root でだけ流す。
func TestRemoveLeftoverTempsReportsFailure(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix directory permissions and a non-root user")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	leftover := filepath.Join(dir, tempPrefix+"123")
	writeLeftoverTestFile(t, leftover)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	r, err := RemoveLeftoverTemps(&Lock{}, path)
	if err != nil || r.Removed != 0 || r.Failed != 1 || r.FirstFailure == nil {
		t.Fatalf("RemoveLeftoverTemps in a read-only directory = %+v, %v; want 1 failed and its error", r, err)
	}
	if kind := ErrorKind(r.FirstFailure); kind != "permission denied" {
		t.Errorf("ErrorKind = %q, want permission denied without the path", kind)
	}
	if !pathExists(t, leftover) {
		t.Error("the leftover is gone")
	}
}

// Save の一時ファイルは、起動時の片付けが消す名前と置き場所で作られる。rename の直前に一時ファイルを
// 見て、同じディレクトリの直下にあり、名前が tempPrefix で始まる通常ファイルであることを確かめる。
func TestSaveTempFileMatchesTheCleanup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	var seen string
	saveBeforeRenameHook = func(tmpName string) {
		seen = tmpName
		fi, err := os.Lstat(tmpName)
		if err != nil || !fi.Mode().IsRegular() {
			t.Errorf("temp file before rename: %v, %v; want a regular file", fi, err)
		}
	}
	t.Cleanup(func() { saveBeforeRenameHook = nil })
	if err := (&Credentials{Name: "a"}).Save(path); err != nil {
		t.Fatal(err)
	}
	if seen == "" {
		t.Fatal("Save did not reach the rename")
	}
	if filepath.Dir(seen) != dir || !strings.HasPrefix(filepath.Base(seen), tempPrefix) {
		t.Errorf("temp file %s is not %s%s* that the startup cleanup removes", seen, filepath.Join(dir, ""), tempPrefix)
	}
}
