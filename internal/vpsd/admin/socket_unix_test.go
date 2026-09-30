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

// shortSocketDir は、ソケットを置くための短い一時ディレクトリを /tmp に作る。macOS の t.TempDir() は
// テストの名前を含む長いパスになり、ソケットのパスが sun_path の 104 バイトを超えて bind が invalid
// argument で落ちる。$TMPDIR も長いことがあるので使わない。/tmp に作れないときだけ $TMPDIR に作る。
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "as")
	if err != nil {
		dir, err = os.MkdirTemp("", "as")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

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
	dir := shortSocketDir(t)
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

// TestListenUnixLeavesASymlinkToASocket は、ソケットのパスが別のソケットを指す symlink でも、前の起動の
// ソケットとは見なさず、symlink を消さずに誤りにすることを確かめる。前の起動が symlink を残すことは無く、
// symlink は誰かが置いた物だからである。
// 変異の確認:最初の確認を os.Lstat から os.Stat に変えると、symlink の先のソケットを見て symlink を消し、
// 新しいソケットに置き換えて落ちる。
func TestListenUnixLeavesASymlinkToASocket(t *testing.T) {
	dir := shortSocketDir(t)
	other := filepath.Join(dir, "other.sock")
	oln, err := net.Listen("unix", other)
	if err != nil {
		t.Fatal(err)
	}
	defer oln.Close()
	p := filepath.Join(dir, "admin.sock")
	if err := os.Symlink(other, p); err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("unix://"+p, true)
	if err == nil {
		ln.Close()
		t.Fatal("Listen replaced a symlink to a socket with the admin socket")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("error = %v, want it to say the path is a symbolic link", err)
	}
	if dest, lerr := os.Readlink(p); lerr != nil || dest != other {
		t.Errorf("the symlink at the socket path was removed or replaced: %q, %v", dest, lerr)
	}
	if fi, serr := os.Lstat(other); serr != nil || fi.Mode().Type() != fs.ModeSocket {
		t.Errorf("the socket the symlink points at changed: %v, %v", fi, serr)
	}
}

// TestListenUnixRefusesAPathReplacedRightAfterListen は、ソケットを作った直後にパスが別の物に
// 差し替えられたら、起動の誤りにし、差し替えられた物を消さないことを確かめる。
// 変異の確認:作った後の確認を外すと Listen が通って落ちる。閉じるときにパスを消すと、差し替えられた
// 物が消えて落ちる。
func TestListenUnixRefusesAPathReplacedRightAfterListen(t *testing.T) {
	for _, kind := range []string{"regular file", "symlink to a socket"} {
		dir := shortSocketDir(t)
		p := filepath.Join(dir, "admin.sock")
		other := filepath.Join(dir, "other.sock")
		oln, err := net.Listen("unix", other)
		if err != nil {
			t.Fatal(err)
		}
		listenedHook = func(socket string) {
			if err := os.Remove(socket); err != nil {
				t.Error(err)
			}
			if kind == "regular file" {
				err = os.WriteFile(socket, []byte("data"), 0o600)
			} else {
				err = os.Symlink(other, socket)
			}
			if err != nil {
				t.Error(err)
			}
		}
		ln, err := Listen("unix://"+p, true)
		listenedHook = nil
		oln.Close()
		if err == nil {
			ln.Close()
			t.Errorf("%s: Listen accepted a path replaced right after the socket was created", kind)
			continue
		}
		if !strings.Contains(err.Error(), "was replaced") {
			t.Errorf("%s: error = %v, want it to say the path was replaced", kind, err)
		}
		fi, lerr := os.Lstat(p)
		switch {
		case lerr != nil:
			t.Errorf("%s: the replacement was removed: %v", kind, lerr)
		case kind == "regular file" && !fi.Mode().IsRegular():
			t.Errorf("%s: the replacement changed: %v", kind, fi)
		case kind == "symlink to a socket" && fi.Mode().Type() != fs.ModeSymlink:
			t.Errorf("%s: the replacement changed: %v", kind, fi)
		}
	}
}

// TestListenUnixReplacesAStaleSocket は、前の起動が残したソケットは消して作り直し、0600 になることを
// 確かめる。
// 変異の確認:ソケットの枝で消さないと、bind が address already in use で落ちる。
func TestListenUnixReplacesAStaleSocket(t *testing.T) {
	p := filepath.Join(shortSocketDir(t), "admin.sock")
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

// TestListenUnixRefusesASocketThatIsNot0600 は、作ったソケットが 0600 でなければ、chmod で直さずに起動の
// 誤りにすることを確かめる。bind が umask に従わない環境への守りで、試験では作った直後に権限を変えて
// その環境を模す。
// 変異の確認:作った後の確認から権限の比較を外すと、Listen が通って落ちる。
func TestListenUnixRefusesASocketThatIsNot0600(t *testing.T) {
	listenedHook = func(socket string) {
		if err := os.Chmod(socket, 0o666); err != nil {
			t.Error(err)
		}
	}
	defer func() { listenedHook = nil }()
	ln, err := Listen("unix://"+filepath.Join(shortSocketDir(t), "admin.sock"), true)
	if err == nil {
		ln.Close()
		t.Fatal("Listen accepted a socket with mode 0666")
	}
	if !strings.Contains(err.Error(), "not 0600") {
		t.Errorf("error = %v, want it to say the mode is not 0600", err)
	}
}

// TestListenUnixSocketIsPrivateFromTheStart は、ソケットが作られた瞬間から 0600 であることを確かめる。
// 前の実装は net.Listen が umask の権限で作った後に chmod しており、その間は umask 022 なら 0755 だった。
// 今の実装は chmod をしないので、作った瞬間の権限がそのまま最後の権限になる。
// 変異の確認:umask を 022 にすると 0755 に、0077 にすると 0700 になって落ちる。
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
	ln, err := Listen("unix://"+filepath.Join(shortSocketDir(t), "admin.sock"), true)
	if atCreate != 0o600 {
		t.Errorf("the socket was created with mode %04o, want 0600 from the start", atCreate)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
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
		dir := filepath.Join(shortSocketDir(t), "run")
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
