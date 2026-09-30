//go:build unix

package admin

import (
	"bytes"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// 変異の確認は各テストの上に書く。どれも設計文書 11 節の管理用 API の Unix ソケットの作り方である。

// TestListenUnixLeavesANonSocketInPlace は、ソケットのパスにソケットでない物があれば、消さずに
// 誤りにすることを確かめる。WGFT_ADMIN を誤ってデータベースのファイルに向けた場合に、そのファイルを
// 消さないためである。
// 変異の確認:種別の判定を外して前と同じく無条件に消すと落ちる。
func TestListenUnixLeavesANonSocketInPlace(t *testing.T) {
	p := filepath.Join(t.TempDir(), "wgft.sqlite")
	if err := os.WriteFile(p, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("unix://"+p, true)
	if err == nil {
		ln.Close()
		t.Fatal("Listen replaced a regular file with the admin socket")
	}
	if !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("error = %v, want it to say the path is not a socket", err)
	}
	if b, rerr := os.ReadFile(p); rerr != nil || string(b) != "data" {
		t.Errorf("the file at the socket path was changed: %q, %v", b, rerr)
	}
}

// TestListenUnixLeavesASymlinkAndItsTarget は、ソケットのパスが symlink なら、symlink も、その先の
// ファイルの権限も変えないことを確かめる。
// 変異の確認:種別の判定を外すと symlink が消えて落ちる。
func TestListenUnixLeavesASymlinkAndItsTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "admin.sock")
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	if ln, err := Listen("unix://"+p, true); err == nil {
		ln.Close()
		t.Fatal("Listen accepted a symlink at the socket path")
	}
	if fi, err := os.Lstat(p); err != nil || fi.Mode().Type() != fs.ModeSymlink {
		t.Errorf("the symlink at the socket path was removed or replaced: %v, %v", fi, err)
	}
	if fi, err := os.Stat(target); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("the symlink's target changed: %v, %v", fi, err)
	}
}

// TestListenUnixReplacesAStaleSocket は、前の起動が残したソケットは消して作り直し、0600 になることを
// 確かめる。
// 変異の確認:ソケットの枝で消さないと、bind が address already in use で落ちる。
func TestListenUnixReplacesAStaleSocket(t *testing.T) {
	p := filepath.Join(t.TempDir(), "admin.sock")
	stale, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	ln, err := Listen("unix://"+p, true)
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	defer ln.Close()
	fi, err := os.Lstat(p)
	if err != nil || fi.Mode().Type() != fs.ModeSocket || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket = %v, %v; want a socket with mode 0600", fi, err)
	}
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatalf("dial the new socket: %v", err)
	}
	c.Close()
}

// TestListenUnixSocketIsPrivateFromTheStart は、ソケットが作られた瞬間から他の利用者の権限を持たない
// ことを確かめる。前の実装は net.Listen が umask の権限で作った後に chmod しており、その間は
// umask 022 なら 0755 だった。
// 変異の確認:umask を狭めずに作ると、作った直後の権限が 0755 になって落ちる。
func TestListenUnixSocketIsPrivateFromTheStart(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	var atCreate fs.FileMode
	listenedHook = func(socket string) {
		if fi, err := os.Lstat(socket); err == nil {
			atCreate = fi.Mode().Perm()
		}
	}
	defer func() { listenedHook = nil }()
	ln, err := Listen("unix://"+filepath.Join(t.TempDir(), "admin.sock"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if atCreate&0o077 != 0 {
		t.Errorf("the socket was created with mode %04o, open to other users until the chmod", atCreate)
	}
	if m := syscall.Umask(0o022); m != 0o022 {
		t.Errorf("Listen left the process umask at %04o", m)
	}
}

// TestListenUnixWarnsAboutAWritableDirectory は、置き場のディレクトリに他の利用者が書き込めて sticky
// ビットも無いときだけ警告することを確かめる。
// 変異の確認:判定を外すと警告が出ず落ちる。sticky の判定を外すと、sticky の場合に警告が出て落ちる。
func TestListenUnixWarnsAboutAWritableDirectory(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	for _, tc := range []struct {
		mode fs.FileMode
		warn bool
	}{
		{0o700, false},
		{0o777, true},
		{0o777 | fs.ModeSticky, false},
	} {
		buf.Reset()
		dir := filepath.Join(t.TempDir(), "run")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, tc.mode); err != nil {
			t.Fatal(err)
		}
		ln, err := Listen("unix://"+filepath.Join(dir, "admin.sock"), true)
		if err != nil {
			t.Fatal(err)
		}
		ln.Close()
		if got := strings.Contains(buf.String(), "writable by other users"); got != tc.warn {
			t.Errorf("directory mode %v: warned = %v, want %v; log:\n%s", tc.mode, got, tc.warn, buf.String())
		}
	}
}
