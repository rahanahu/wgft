//go:build !windows

package credentials

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSaveKeepsTheOwnerWhenRoot は、root のプロセスの Save が元の agent.json の持ち主とグループを
// 新しいファイルに移すことを確かめる(仕様 9 節)。root でないと他の持ち主へ chown できないので、
// root の実行と chown を差し替えて、渡した値を見る。
func TestSaveKeepsTheOwnerWhenRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the file would be owned by root, which keepOwner leaves alone")
	}
	path := filepath.Join(t.TempDir(), "agent.json")
	f := &Credentials{Name: "home"}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	type call struct {
		name     string
		uid, gid int
	}
	var calls []call
	defer func(e func() int, c func(*os.File, int, int) error) { geteuid, fchown = e, c }(geteuid, fchown)
	geteuid = func() int { return 0 }
	fchown = func(f *os.File, uid, gid int) error {
		calls = append(calls, call{f.Name(), uid, gid})
		return nil
	}
	f.Mode = ModeKernel
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Fatalf("chown calls = %v, want one for the temp file", calls)
	}
	if calls[0].uid != os.Getuid() || calls[0].gid != os.Getgid() {
		t.Errorf("chown to %d:%d, want the original owner %d:%d", calls[0].uid, calls[0].gid, os.Getuid(), os.Getgid())
	}
	if calls[0].name == path {
		t.Errorf("chown on %s itself; it must be the temp file, before the rename", path)
	}

	// 元のファイルが無ければ chown しない。root が新しく作るファイルは root のものでよい
	calls = nil
	if err := f.Save(filepath.Join(t.TempDir(), "new.json")); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Errorf("chown on a new file: %v", calls)
	}

	// root でなければ何もしない
	geteuid = func() int { return 1000 }
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Errorf("chown when not root: %v", calls)
	}
}

// root の Save で chown が失敗しても、警告を出して保存は成功させる。root で常駐するエージェントの保存を
// 持ち主の移し替えの失敗で止めないためである。
func TestSaveGoesOnWhenChownFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the file would be owned by root, which keepOwner leaves alone")
	}
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := (&Credentials{Name: "home"}).Save(path); err != nil {
		t.Fatal(err)
	}
	var warned []string
	defer func(e func() int, c func(*os.File, int, int) error, l func(string, ...any)) {
		geteuid, fchown, logf = e, c, l
	}(geteuid, fchown, logf)
	geteuid = func() int { return 0 }
	fchown = func(*os.File, int, int) error { return os.ErrPermission }
	logf = func(f string, a ...any) { warned = append(warned, fmt.Sprintf(f, a...)) }
	if err := (&Credentials{Name: "renamed"}).Save(path); err != nil {
		t.Fatalf("Save failed on a chown failure: %v", err)
	}
	g, err := Load(path)
	if err != nil || g.Name != "renamed" {
		t.Fatalf("the file was not saved: %+v, %v", g, err)
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "cannot keep the owner") {
		t.Errorf("warnings = %q, want one about the owner", warned)
	}
}
