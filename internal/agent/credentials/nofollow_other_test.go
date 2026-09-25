//go:build !windows

package credentials

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/flock"
)

// root の CLI は、エージェントの利用者が書けるデータディレクトリの中のパスを信頼しない(仕様 9・11 節)。
// この一群は、agent.json と一時ファイルの名前を差し替えられても、Load と Save がその先を辿らないこと、
// 通常のファイルでないものと大きすぎるものを拒むこと、権限と持ち主を開いた記述子に対して設定することを
// 確かめる。

// victimFile は、差し替え先として狙われるファイルを作る。中身と 0644 の権限を返して、後で変わって
// いないことを比べる。
func victimFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(p, []byte("not the agent's\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func assertVictimUntouched(t *testing.T, p string) {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("the file behind the swapped name changed its mode to %o; Save must set the mode on the descriptor it created", fi.Mode().Perm())
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "not the agent's\n" {
		t.Errorf("the file behind the swapped name was written: %q", b)
	}
}

// swapTempForSymlink は、Save が一時ファイルを作った直後にその名前を target への symlink に差し替える
// 試験用の差し込みを置く。差し替える前の一時ファイルの inode を返す関数も返す。
func swapTempForSymlink(t *testing.T, target string) func() uint64 {
	t.Helper()
	var ino uint64
	saveAfterCreateHook = func(tmpName string) {
		fi, err := os.Lstat(tmpName)
		if err != nil {
			t.Fatal(err)
		}
		ino = fi.Sys().(*syscall.Stat_t).Ino
		if err := os.Remove(tmpName); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, tmpName); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { saveAfterCreateHook = nil })
	return func() uint64 { return ino }
}

// 一時ファイルの名前を差し替えられても、Save は差し替え先の権限を変えない。パスで chmod すると、
// symlink の先が 0600 になる。
func TestSaveDoesNotChmodThroughASwappedTempFile(t *testing.T) {
	victim := victimFile(t)
	path := filepath.Join(t.TempDir(), "agent.json")
	swapTempForSymlink(t, victim)
	// 差し替えの後の rename は symlink を agent.json に移すだけで、Save 自体は成功する。守るのは
	// 差し替え先であり、rename の結果ではない
	if err := (&Credentials{Name: "home"}).Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	assertVictimUntouched(t, victim)
}

// root の Save は、持ち主を一時ファイルの名前ではなく開いた記述子に移す。root でない実行では chown を
// 差し替え、渡された記述子が Save の作った一時ファイルのものであることを inode で確かめる。
func TestKeepOwnerChownsTheDescriptorItCreated(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the file would be owned by root, which keepOwner leaves alone; TestRootSaveDoesNotChownThroughASwappedTempFile covers root")
	}
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := (&Credentials{Name: "home"}).Save(path); err != nil {
		t.Fatal(err)
	}
	victim := victimFile(t)
	createdIno := swapTempForSymlink(t, victim)
	var chowned []uint64
	defer func(e func() int, c func(*os.File, int, int) error) { geteuid, fchown = e, c }(geteuid, fchown)
	geteuid = func() int { return 0 }
	fchown = func(f *os.File, uid, gid int) error {
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		chowned = append(chowned, fi.Sys().(*syscall.Stat_t).Ino)
		return nil
	}
	if err := (&Credentials{Name: "renamed"}).Save(path); err != nil {
		t.Fatal(err)
	}
	if len(chowned) != 1 {
		t.Fatalf("chown calls on descriptors = %d, want 1; keepOwner must chown the descriptor, not the name", len(chowned))
	}
	if chowned[0] != createdIno() {
		t.Errorf("chown on inode %d, want %d, the temp file Save created", chowned[0], createdIno())
	}
}

// root で走らせたときだけ、本物の chown で確かめる。agent.json の持ち主をエージェントの利用者に見立てた
// uid にし、一時ファイルを root のファイルへの symlink に差し替える。差し替え先の持ち主は root のまま残る。
func TestRootSaveDoesNotChownThroughASwappedTempFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown to another user")
	}
	const agentUID, agentGID = 4242, 4242
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := (&Credentials{Name: "home"}).Save(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, agentUID, agentGID); err != nil {
		t.Fatal(err)
	}
	victim := victimFile(t)
	swapTempForSymlink(t, victim)
	if err := (&Credentials{Name: "renamed"}).Save(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != 0 || st.Gid != 0 {
		t.Errorf("the root-owned file behind the swapped name is now owned by %d:%d", st.Uid, st.Gid)
	}
	assertVictimUntouched(t, victim)

	// 差し替えの無い保存では、持ち主はこれまでどおり移る
	saveAfterCreateHook = nil
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := (&Credentials{Name: "home"}).Save(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, agentUID, agentGID); err != nil {
		t.Fatal(err)
	}
	if err := (&Credentials{Name: "again"}).Save(path); err != nil {
		t.Fatal(err)
	}
	fi, err = os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != agentUID || st.Gid != agentGID {
		t.Errorf("agent.json is owned by %d:%d after a root save, want %d:%d", st.Uid, st.Gid, agentUID, agentGID)
	}
}

// irregular は、agent.json の名前に置かれうる通常のファイルでないものである。
func irregular(t *testing.T) map[string]func(path string) {
	t.Helper()
	return map[string]func(string){
		"symlink to a credentials file": func(path string) {
			real := filepath.Join(t.TempDir(), "real.json")
			if err := (&Credentials{Name: "elsewhere"}).Save(real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, path); err != nil {
				t.Fatal(err)
			}
		},
		"dangling symlink": func(path string) {
			if err := os.Symlink(filepath.Join(t.TempDir(), "nowhere"), path); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(path string) {
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		},
	}
}

// withinDeadline は f を別の goroutine で走らせ、止まったら失敗にする。FIFO を開く読み手は、書き手が
// 現れるまで止まるためである。
func withinDeadline(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s blocked; opening a FIFO must not wait for a writer", what)
	}
}

// Load と ReadFile は、通常のファイルでないものを辿らず、開いた後の種別の確認で拒む。
func TestLoadRefusesWhatIsNotARegularFile(t *testing.T) {
	for name, place := range irregular(t) {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.json")
			place(path)
			withinDeadline(t, "Load", func() {
				if f, err := Load(path); !errors.Is(err, flock.ErrNotRegular) {
					t.Errorf("Load = %+v, %v; want an error wrapping ErrNotRegular", f, err)
				}
				if _, _, err := ReadFile(path); !errors.Is(err, flock.ErrNotRegular) {
					t.Errorf("ReadFile = %v, want an error wrapping ErrNotRegular", err)
				}
				// LoadOrNew は、symlink を無いものとみなして空の中身を返さない
				if f, err := LoadOrNew(path); err == nil {
					t.Errorf("LoadOrNew = %+v, nil; want the refusal", f)
				}
			})
		})
	}
}

// Save は、agent.json の名前にある通常のファイルでないものを置き換えずに拒む。symlink の先も変えない。
func TestSaveRefusesToReplaceWhatIsNotARegularFile(t *testing.T) {
	for name, place := range irregular(t) {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.json")
			place(path)
			before, _ := os.Lstat(path)
			withinDeadline(t, "Save", func() {
				if err := (&Credentials{Name: "home"}).Save(path); !errors.Is(err, flock.ErrNotRegular) {
					t.Errorf("Save = %v, want an error wrapping ErrNotRegular", err)
				}
			})
			after, err := os.Lstat(path)
			if err != nil || after.Mode() != before.Mode() || !os.SameFile(before, after) {
				t.Errorf("Save replaced %s: before %v, after %v, %v", path, before.Mode(), after, err)
			}
			entries, _ := os.ReadDir(filepath.Dir(path))
			for _, e := range entries {
				if e.Name() != "agent.json" {
					t.Errorf("Save left %s behind", e.Name())
				}
			}
		})
	}
}

// root の Save は、agent.json が root 以外の持ち物のファイルへの symlink でも、その持ち主を読まずに拒む。
// Stat で読むと、symlink の先の持ち主を新しいファイルに移してしまう。
func TestKeepOwnerDoesNotReadTheOwnerThroughASymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.Symlink(victimFile(t), path); err != nil {
		t.Fatal(err)
	}
	called := false
	defer func(e func() int, c func(*os.File, int, int) error) { geteuid, fchown = e, c }(geteuid, fchown)
	geteuid = func() int { return 0 }
	fchown = func(*os.File, int, int) error { called = true; return nil }
	if err := (&Credentials{Name: "home"}).Save(path); !errors.Is(err, flock.ErrNotRegular) {
		t.Errorf("Save = %v, want an error wrapping ErrNotRegular", err)
	}
	if called {
		t.Error("Save moved the owner of the symlink's target to the new file")
	}
}

// 大きすぎる agent.json は読まずに拒む。疎なファイルなら、エージェントの利用者はディスクを使わずに
// どんな大きさのファイルでも作れるので、上限が無いと root の CLI がメモリを使い切る。
func TestLoadRefusesAFileLargerThanTheLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxFileSize + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Load(path); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Load = %v, want ErrTooLarge", err)
	}
	if _, _, err := ReadFile(path); !errors.Is(err, ErrTooLarge) {
		t.Errorf("ReadFile = %v, want ErrTooLarge", err)
	}
}

// 上限を小さくして、読み書きの両方で上限が効くことを確かめる。fstat の後に伸びたファイルも、上限を
// 超えたところで読むのをやめて拒む。Save は上限を超える中身を書かないので、wgft が書いたファイルを
// wgft が読めなくなることはない。
func TestTheSizeLimitHoldsForReadsAndWrites(t *testing.T) {
	defer func(l int64) { fileSizeLimit = l }(fileSizeLimit)
	fileSizeLimit = 4096
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")

	if err := (&Credentials{Name: "small"}).Save(path); err != nil {
		t.Fatalf("Save of a small file: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load of a small file: %v", err)
	}
	big := &Credentials{Name: string(make([]byte, 5000))}
	if err := big.Save(path); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Save of a file over the limit = %v, want ErrTooLarge", err)
	}
	if g, err := Load(path); err != nil || g.Name != "small" {
		t.Errorf("after the refused Save, Load = %+v, %v; want the small file untouched", g, err)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// fstat の大きさが上限を超えていれば、中身を読む前に拒む。疎なファイルを上限まで読まないためである
	if _, err := readLimited(f, sizedInfo{fileSizeLimit + 1}, path); !errors.Is(err, ErrTooLarge) {
		t.Errorf("readLimited with fstat over the limit = %v, want ErrTooLarge before reading", err)
	}
	small, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(3 * fileSizeLimit); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := readLimited(f, small, path); !errors.Is(err, ErrTooLarge) {
		t.Errorf("readLimited = %v, want ErrTooLarge for a file that grew after fstat", err)
	}
	// 伸びたファイルでも、上限を 1 バイト超えたところで読むのをやめる。読み切ってから拒むと、疎な
	// ファイルを伸ばされたとき、上限の分のメモリでは済まない
	if off, err := f.Seek(0, io.SeekCurrent); err != nil || off > fileSizeLimit+1 {
		t.Errorf("readLimited read up to offset %d, %v; want at most %d, one byte past the limit", off, err, fileSizeLimit+1)
	}
	if _, err := Load(path); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Load of a file over the limit = %v, want ErrTooLarge", err)
	}
}

// sizedInfo は大きさだけを持つ FileInfo である。
type sizedInfo struct{ size int64 }

func (i sizedInfo) Name() string       { return "agent.json" }
func (i sizedInfo) Size() int64        { return i.size }
func (i sizedInfo) Mode() os.FileMode  { return 0o600 }
func (i sizedInfo) ModTime() time.Time { return time.Time{} }
func (i sizedInfo) IsDir() bool        { return false }
func (i sizedInfo) Sys() any           { return nil }
