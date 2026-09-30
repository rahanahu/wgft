//go:build !unix

package admin

import (
	"log"
	"net"
	"os"
	"path/filepath"
)

// listenUnix は管理用 API の Unix ソケットを socket に作る。server は Linux だけで動く
// ので、この版は Unix でない OS のビルドを通すためだけにある。
func listenUnix(socket string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(socket)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	log.Printf("admin api: unix://%s", socket)
	return ln, nil
}
