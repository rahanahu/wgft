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
// プロセス全体の値なので、その間に他の goroutine が作るファイルも狭い権限で作られる。狭める向き
// なので、害は無い。
var umaskMu sync.Mutex

// listenedHook は、ソケットを作った直後、権限を揃える前に呼ぶ。作った瞬間の権限を試験が見るため
// だけにある。
var listenedHook func(socket string)

// listenUnix は管理用 API の Unix ソケットを socket に作る(設計文書 11 節)。
//
//   - 置き場のディレクトリが無ければ 0700 で作る。既にあって他の利用者が書き込め、sticky ビットも
//     無ければ、その利用者がソケットを差し替えられるので警告する。止めはしない
//   - パスに前の起動のソケットが残っていれば消す。ソケットでない物(設定の誤りで指したデータ
//     ベースのファイルなど)は消さず、誤りにする
//   - umask を 0077 に狭めてソケットを作るので、作った瞬間から他の利用者は接続できない。作った物が
//     ソケットであることを symlink を辿らずに確かめてから、文書どおりの 0600 に揃える
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
		return nil, fmt.Errorf("%s exists and is not a socket, so it was left in place; point WGFT_ADMIN at another path, or remove it if it is not needed", socket)
	default:
		// 前の起動が残したソケット
		if err := os.Remove(socket); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	umaskMu.Lock()
	old := syscall.Umask(0o077)
	ln, err := net.Listen("unix", socket)
	syscall.Umask(old)
	umaskMu.Unlock()
	if err != nil {
		return nil, err
	}
	if listenedHook != nil {
		listenedHook(socket)
	}
	fi, err := os.Lstat(socket)
	if err != nil || fi.Mode().Type() != fs.ModeSocket {
		ln.Close()
		return nil, fmt.Errorf("%s was replaced right after the socket was created; refusing to use it", socket)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	log.Printf("admin api: unix://%s, permissions 0600", socket)
	return ln, nil
}
