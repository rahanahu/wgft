//go:build unix

package admin

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// umaskMu は、管理用 API の Unix ソケットを作る間だけ umask を狭めることを直列にする。umask は
// プロセス全体の値なので、その間に他の goroutine が作るファイルも狭い権限で作られる。狭める向きなので
// ファイルには害が無い。0177 は所有者の実行ビットも外すので、その間に作ったディレクトリは辿れなくなるが、
// server がディレクトリを作るのは起動の前(データのディレクトリ)と listenUnix の中の umask を狭める前
// だけである。
var umaskMu sync.Mutex

// listenedHook は、ソケットを作った直後、パスを確かめる前に呼ぶ。作った瞬間の権限を見る試験と、
// 作った直後にパスを差し替える試験のためだけにある。
var listenedHook func(socket string)

// listenUnix は管理用 API の Unix ソケットを socket に作る(設計文書 11 節)。パスに対する操作は、
// どれも symlink を辿らない。
//
//   - 置き場のディレクトリが無ければ 0700 で作る。既にあって他の利用者が書き込め、sticky ビットも
//     無ければ、その利用者がソケットを差し替えられるので警告する。止めはしない
//   - パスに前の起動のソケットが残っていれば消す。ソケットでない物(設定の誤りで指したデータ
//     ベースのファイル、symlink など)は、symlink の先がソケットでも消さず、誤りにする
//   - umask を 0177 に狭めてソケットを作る。bind は 0777 から umask を除いた権限でソケットを作る
//     ので、作った瞬間から 0600 になる。パスに chmod はしない。chmod は symlink を辿るので、
//     確かめた後に差し替えられた symlink の先の権限を変えうるためである
//   - 作った直後に、パスにあるのが 0600 のソケットであることを確かめる。違えば、パスにある物を
//     消さずに誤りにする
func listenUnix(socket string) (net.Listener, error) {
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if fi, err := os.Stat(dir); err == nil && fi.Mode().Perm()&0o022 != 0 && fi.Mode()&fs.ModeSticky == 0 {
		log.Printf("warning: admin api socket directory %s is writable by other users, mode %04o, so they can replace the socket; use a directory only the server's user can write, as the provided server.service does", dir, fi.Mode().Perm())
	}
	switch fi, err := os.Lstat(socket); {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	case fi.Mode().Type() != fs.ModeSocket:
		return nil, fmt.Errorf("%s exists and is %s, not a socket, so it was left in place; point WGFT_ADMIN at another path, or remove it if it is not needed", socket, fileKind(fi.Mode()))
	default:
		// 前の起動が残したソケット
		if err := os.Remove(socket); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	umaskMu.Lock()
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", socket)
	syscall.Umask(old)
	umaskMu.Unlock()
	if err != nil {
		return nil, err
	}
	if listenedHook != nil {
		listenedHook(socket)
	}
	if fi, err := os.Lstat(socket); err != nil || fi.Mode().Type() != fs.ModeSocket || fi.Mode().Perm() != 0o600 {
		// パスにあるのは作ったソケットと限らないので、閉じるときに消さない
		ln.(*net.UnixListener).SetUnlinkOnClose(false)
		ln.Close()
		if err == nil && fi.Mode().Type() == fs.ModeSocket {
			return nil, fmt.Errorf("%s was created with mode %04o, not 0600; refusing to use it", socket, fi.Mode().Perm())
		}
		return nil, fmt.Errorf("%s was replaced right after the socket was created; refusing to use it", socket)
	}
	log.Printf("admin api: unix://%s, permissions 0600", socket)
	return ln, nil
}

// fileKind は、誤りの文言のために、ソケットでない物の種別を英語で返す。
func fileKind(m fs.FileMode) string {
	switch m.Type() {
	case 0:
		return "a regular file"
	case fs.ModeSymlink:
		return "a symbolic link"
	case fs.ModeDir:
		return "a directory"
	default:
		return "a special file"
	}
}
