// Package netpipe は 2 つの接続を双方向に中継する(ハーフクローズ維持)。
// エージェントの TCP 中継(仕様 7 節)と、vpsd のプロキシモードの中継(仕様 6.2 節)が共有する。
package netpipe

import (
	"io"
	"net"
	"sync"
)

type closeWriter interface{ CloseWrite() error }

// Pipe は a と b を双方向に中継する。片方向の EOF は CloseWrite で反対側に伝え、
// 両方向が閉じたら両方を閉じる。
func Pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	half := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(2)
	go half(a, b)
	go half(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}
