// Package netpipe は 2 つの接続を双方向に中継する(ハーフクローズ維持)。
// エージェントの TCP 中継(仕様 7 節)と、vpsd のプロキシモードの中継(仕様 6.2 節)が共有する。
package netpipe

import (
	"io"
	"net"
	"sync"
	"time"
)

type closeWriter interface{ CloseWrite() error }

// Pipe は a と b を双方向に中継する。片方向の EOF は CloseWrite で反対側に伝え、
// 両方向が閉じたら両方を閉じる。
func Pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	half := func(dst, src net.Conn) {
		defer wg.Done()
		copyConn(dst, src)
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

const (
	idleBufSize = 2048     // 無通信の接続が持ち続けるバッファ(仕様 7 節)
	bulkBufSize = 32 << 10 // データが続く間だけプールから借りるバッファ
	// bulkWait は、借りたバッファを持ったまま次のデータを待つ時間。過ぎたら返して小さいバッファに戻る
	bulkWait = 200 * time.Millisecond
)

var bulkPool = sync.Pool{New: func() any { b := make([]byte, bulkBufSize); return &b }}

// copyConn は src を dst へ写す。io.Copy は接続ごと、方向ごとに 32 KiB を持ち続けるので、
// 開いたまま黙っている接続の費用を抑えるために、待つ間は小さいバッファだけを持つ。
func copyConn(dst, src net.Conn) {
	// カーネルの TCP 同士は io.Copy が splice を使い、ユーザー空間のバッファを持たない
	if _, ok := src.(*net.TCPConn); ok {
		if _, ok := dst.(*net.TCPConn); ok {
			io.Copy(dst, src)
			return
		}
	}
	idle := make([]byte, idleBufSize)
	for {
		n, err := src.Read(idle)
		if n > 0 {
			if _, werr := dst.Write(idle[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
		if n == len(idle) && !copyBulk(dst, src) {
			return
		}
	}
}

// copyBulk はプールの大きいバッファで写す。データが途切れたらバッファを返して真を返す。
// 偽は接続の終わり(EOF か誤り)。
func copyBulk(dst, src net.Conn) bool {
	bp := bulkPool.Get().(*[]byte)
	defer bulkPool.Put(bp)
	defer src.SetReadDeadline(time.Time{})
	var armed time.Time
	for {
		// 期限の更新はタイマーの操作なので、読むたびには行わない
		if now := time.Now(); now.Sub(armed) > bulkWait/2 {
			src.SetReadDeadline(now.Add(bulkWait))
			armed = now
		}
		n, err := src.Read(*bp)
		if n > 0 {
			if _, werr := dst.Write((*bp)[:n]); werr != nil {
				return false
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return true
			}
			return false
		}
	}
}
