// Package netpipe は 2 つの接続を双方向に中継する(ハーフクローズ維持)。
// エージェントの TCP 中継(仕様 7 節)と、vpsd のプロキシモードの中継(仕様 6.2 節)が共有する。
package netpipe

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type closeWriter interface{ CloseWrite() error }

// relayEndCloser は、中継の終わりに通常の Close の代わりに呼ぶ閉じ方を持つ接続が満たす
// (nettun.TCPConn.CloseAfterRelay。設計文書 7 節の「送り残しを持って閉じた netstack の接続」)。
type relayEndCloser interface{ CloseAfterRelay() error }

// closeEnd は中継の終わりに c を閉じる。
func closeEnd(c net.Conn) {
	if r, ok := c.(relayEndCloser); ok {
		r.CloseAfterRelay()
		return
	}
	c.Close()
}

// Pipe は a と b を双方向に中継する。片方向の EOF は CloseWrite で反対側に伝え、
// 両方向が閉じたら両方を閉じる。片方向が EOF 以外で終わったとき(読み取りが RST などの誤りで
// 失敗したとき、書き込みが失敗したとき)は、すぐに両方を閉じる。ハーフクローズとして扱うと、
// 反対向きは黙ったままの相手を読み続け、相手が閉じるまで中継が終わらない(仕様 6.2 節)。
// 両方を閉じる 2 か所は、CloseAfterRelay を持つ接続ではそれを呼ぶ。片方向の EOF の CloseWrite は変えない。
func Pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	half := func(dst, src net.Conn) {
		defer wg.Done()
		if err := copyConn(dst, src); err != nil {
			closeEnd(a)
			closeEnd(b)
			return
		}
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
	closeEnd(a)
	closeEnd(b)
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
// src の EOF で終わったときは nil を、読み取りか書き込みの誤りで終わったときはその誤りを返す。
func copyConn(dst, src net.Conn) error {
	// カーネルの TCP 同士は io.Copy が splice を使い、ユーザー空間のバッファを持たない
	if _, ok := src.(*net.TCPConn); ok {
		if _, ok := dst.(*net.TCPConn); ok {
			_, err := io.Copy(dst, src)
			return err
		}
	}
	idle := make([]byte, idleBufSize)
	for {
		n, err := src.Read(idle)
		if n > 0 {
			if _, werr := dst.Write(idle[:n]); werr != nil {
				return werr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if n == len(idle) {
			if more, err := copyBulk(dst, src); !more {
				return err
			}
		}
	}
}

// copyBulk はプールの大きいバッファで写す。データが途切れたらバッファを返して真を返す。
// 偽は接続の終わりで、誤りは copyConn と同じく EOF なら nil、それ以外はその誤りである。
func copyBulk(dst, src net.Conn) (bool, error) {
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
				return false, werr
			}
		}
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return true, nil
			}
			return false, err
		}
	}
}
