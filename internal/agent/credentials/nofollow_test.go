package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rahanahu/wgft/internal/flock"
)

// どの OS でも、agent.json が symlink なら Load は辿らず、Save は置き換えずに拒む(仕様 9・11 節)。
// Windows では FILE_FLAG_OPEN_REPARSE_POINT で symlink 自身を開き、種別の確認で拒む。Windows で
// symlink を作る権限が無ければ飛ばす。
func TestSymlinkedCredentialsFileIsRefusedOnEveryOS(t *testing.T) {
	real := filepath.Join(t.TempDir(), "real.json")
	if err := (&Credentials{Name: "elsewhere"}).Save(real); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.Symlink(real, path); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}
	if f, err := Load(path); !errors.Is(err, flock.ErrNotRegular) {
		t.Errorf("Load = %+v, %v; want an error wrapping ErrNotRegular", f, err)
	}
	if _, _, err := ReadFile(path); !errors.Is(err, flock.ErrNotRegular) {
		t.Errorf("ReadFile = %v, want an error wrapping ErrNotRegular", err)
	}
	if err := (&Credentials{Name: "home"}).Save(path); !errors.Is(err, flock.ErrNotRegular) {
		t.Errorf("Save = %v, want an error wrapping ErrNotRegular", err)
	}
	after, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("the symlink's target changed")
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("agent.json is no longer the symlink: %v, %v", fi, err)
	}
}

// どの OS でも、agent.json の名前にあるディレクトリは読まずに拒む。
func TestCredentialsDirectoryIsRefusedOnEveryOS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, flock.ErrNotRegular) {
		t.Errorf("Load = %v, want an error wrapping ErrNotRegular", err)
	}
	if err := (&Credentials{Name: "home"}).Save(path); !errors.Is(err, flock.ErrNotRegular) {
		t.Errorf("Save = %v, want an error wrapping ErrNotRegular", err)
	}
}
