// Package netpipe は 2 つの接続を双方向に中継する(ハーフクローズ維持)。
// エージェントの TCP 中継(仕様 7 節)と、vpsd のプロキシモードの中継(仕様 6.2 節)が共有する。
package netpipe

import (
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
)

type closeWriter interface{ CloseWrite() error }

// Pipe は a と b を双方向に中継する。片方向の EOF は CloseWrite で反対側に伝え、
// 両方向が閉じたら両方を閉じる。片方向が EOF 以外で終わったとき(読み取りが RST などの誤りで
// 失敗したとき、書き込みが失敗したとき)は、すぐに両方を閉じる。ハーフクローズとして扱うと、
// 反対向きは黙ったままの相手を読み続け、相手が閉じるまで中継が終わらない(仕様 6.2 節)。
func Pipe(a, b net.Conn) { PipeResetB(a, b, nil) }

// PipeResetB は Pipe と同じく中継する。加えて、a の読み取りか a への書き込みが RST による誤り
// (isReset)で失敗して中継が終わるときは、その向きが両方を閉じる前に resetB を呼ぶ。resetB は、
// 続く通常の Close の代わりに b を RST で切るためのもの(netstack の接続の Abort、実ソケットの
// SetLinger(0))で、nil なら Pipe と同じである。b の読み書きの誤りでは呼ばない。
//
// 「閉じる前」はその向きの中だけの順序である。もう一方の向きは先に終わり、すでに b を CloseWrite
// か Close で閉じていることがある。例えば a への書き込みが RST の誤りを先に受け取ると、a の
// 読み取りは誤りではなく EOF を返し、その向きが CloseWrite(b) で FIN を送る。b にはその FIN の後に
// resetB の RST が届く。
//
// カーネルの TCP 同士の io.Copy(splice)は、誤りがどちらの接続の操作のものかを返さないので、その
// 経路では RST による誤りを a のものとして扱う。誤りが b のものなら、b は RST を受けて既に CLOSED に
// あり、Linux の tcp_close はその状態のソケットに RST を送らないので、resetB の後の Close は何も
// 送らない。これはカーネルのコードから導き、network namespace の Tcp OutRsts の計数器が増えない
// ことでも確かめた。パケットのキャプチャでは確かめていない。
func PipeResetB(a, b net.Conn, resetB func()) { pipe(a, b, resetB, nil) }

// pipe は PipeResetB と PipeHold の本体である。end は中継を終えるときに両側を閉じる関数で、nil なら
// a、b の順に通常の Close で閉じる。誤りで終わる向きは、もう一方の向きの読み書きを解くために、その場で
// end を呼ぶ。
func pipe(a, b net.Conn, resetB func(), end func()) {
	if end == nil {
		end = func() {
			a.Close()
			b.Close()
		}
	}
	var wg sync.WaitGroup
	half := func(dst, src net.Conn) {
		defer wg.Done()
		if at, err := copyConn(dst, src); err != nil {
			onA := at == onEither || (at == onSrc && src == a) || (at == onDst && dst == a)
			if resetB != nil && onA && isReset(err) {
				resetB()
			}
			end()
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
	end()
}

// isReset は、カーネルのソケットが RST を受けて読み書きが失敗した誤り(ECONNRESET)かを返す。
// PipeResetB の a は公開側のカーネルのソケットなので、カーネルの誤りだけを見る。Windows の
// WSAECONNRESET は syscall.ECONNRESET と別の値なので、isPlatformReset で比べる。
func isReset(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == syscall.ECONNRESET || isPlatformReset(errno)
}

// errSide は、copyConn の誤りがどちらの接続の操作で起きたかである。
type errSide int

const (
	onSrc    errSide = iota // src の読み取り
	onDst                   // dst への書き込み
	onEither                // 分からない(splice の io.Copy)
)

const (
	idleBufSize = 2048     // 無通信の接続が持ち続けるバッファ(仕様 7 節)
	bulkBufSize = 32 << 10 // データが続く間だけプールから借りるバッファ
	// bulkWait は、借りたバッファを持ったまま次のデータを待つ時間。過ぎたら返して小さいバッファに戻る
	bulkWait = 200 * time.Millisecond
)

var bulkPool = sync.Pool{New: func() any { b := make([]byte, bulkBufSize); return &b }}

// copyConn は src を dst へ写す。io.Copy は接続ごと、方向ごとに 32 KiB を持ち続けるので、
// 開いたまま黙っている接続の費用を抑えるために、待つ間は小さいバッファだけを持つ。
// src の EOF で終わったときは nil の誤りを、読み取りか書き込みの誤りで終わったときは、誤りが src と
// dst のどちらの操作で起きたかとその誤りを返す。
func copyConn(dst, src net.Conn) (errSide, error) {
	// カーネルの TCP 同士は io.Copy が splice を使い、ユーザー空間のバッファを持たない
	if _, ok := src.(*net.TCPConn); ok {
		if _, ok := dst.(*net.TCPConn); ok {
			_, err := io.Copy(dst, src)
			return onEither, err
		}
	}
	idle := make([]byte, idleBufSize)
	for {
		n, err := src.Read(idle)
		if n > 0 {
			if _, werr := dst.Write(idle[:n]); werr != nil {
				return onDst, werr
			}
		}
		if errors.Is(err, io.EOF) {
			return onSrc, nil
		}
		if err != nil {
			return onSrc, err
		}
		if n == len(idle) {
			if more, at, err := copyBulk(dst, src); !more {
				return at, err
			}
		}
	}
}

// copyBulk はプールの大きいバッファで写す。データが途切れたらバッファを返して真を返す。
// 偽は接続の終わりで、誤りとその側は copyConn と同じく EOF なら nil、それ以外はその誤りである。
func copyBulk(dst, src net.Conn) (bool, errSide, error) {
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
				return false, onDst, werr
			}
		}
		if errors.Is(err, io.EOF) {
			return false, onSrc, nil
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return true, onSrc, nil
			}
			return false, onSrc, err
		}
	}
}
