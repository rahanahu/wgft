package netpipe

import (
	"net"
	"sync"
	"time"
)

// 中継が終わった後の末尾の配送(設計文書 7 節)。ユーザー空間モードの中継は、中継が終わった後も、組の
// 接続が送ったデータを相手に届け終えるまで Resource Guard の枠を持つ。PipeHold は Linux のカーネルの
// TCP の接続を閉じずに読み書きだけを止めて返し、AwaitDelivered は組が届け終えるまで待つ。

// 値はどれも設定項目にしない(設計文書 7 節)。
const (
	// deliveryPollMin と deliveryPollMax は、届け終えたかを見直す間隔の初めと上限。届け終えたことを
	// gVisor も Linux も知らせないので、間隔を倍に伸ばしながら見直す。上限は、届け終えた組の枠が
	// 返るのが最大でどれだけ遅れるかを決める。最適値として探した値ではない
	deliveryPollMin = 50 * time.Millisecond
	deliveryPollMax = 2 * time.Second
)

// deliverer は、閉じた後に送ったデータを届け終えたかを答える netstack の接続が満たす
// (nettun.TCPConn.Delivered)。
type deliverer interface{ Delivered() bool }

// PipeHold は PipeResetB と同じく中継する。違いは終わり方で、Linux のカーネルの TCP の接続
// (*net.TCPConn)を閉じずに返す。そのような接続は、読まれていない受信のデータを持てば今までどおり
// Close で閉じ(Linux は RST を送る)、それ以外は shutdown(SHUT_RDWR)で読み書きだけを止め、送信の
// キューの後ろに FIN を置いたまま残す。呼び出し側は AwaitDelivered で待った後か、中継を切るときに
// Close で閉じる。それ以外の接続(netstack の接続と、Linux 以外のカーネルの接続)は PipeResetB と同じく
// Close で閉じる。終わるときは、閉じる接続を先に閉じてから、カーネルの接続を止める。止める方を先に
// すると、もう一方の向きが EOF を受けて netstack の接続に FIN を送り、resetB の RST の前に FIN が
// 出うるためである。
//
// 止めるのに読み書きの期限を使わないのは、copyBulk が読みの期限を自分で置き直し、終わるときに消すので、
// 外から置いた期限が消えて向きが終わらなくなるためである。
func PipeHold(a, b net.Conn, resetB func()) {
	var once [2]sync.Once
	stop := func(i int, c net.Conn) {
		once[i].Do(func() {
			if tc, ok := holdable(c); ok {
				stopKernel(tc)
			} else {
				c.Close()
			}
		})
	}
	end := func() {
		_, ha := holdable(a)
		_, hb := holdable(b)
		if !ha {
			stop(0, a)
		}
		if !hb {
			stop(1, b)
		}
		if ha {
			stop(0, a)
		}
		if hb {
			stop(1, b)
		}
	}
	pipe(a, b, resetB, end)
}

// Delivered は、PipeHold で終えた接続 c が、送ったデータと FIN を相手に届け終えたか、もう何も持たない
// かを返す。netstack の接続はその Delivered に従う。Linux のカーネルの TCP の接続は、送信のキューの
// 量(SIOCOUTQ。自分の FIN を含む)が 0 か、状態が CLOSE か、閉じられて読めないときに真である。相手の
// RST と再送の打ち切りでは送信のキューの量が 0 に戻らないので、状態でも見る。それ以外の接続は、
// PipeHold が閉じているので真である。
func Delivered(c net.Conn) bool {
	if d, ok := c.(deliverer); ok {
		return d.Delivered()
	}
	if tc, ok := holdable(c); ok {
		return kernelDelivered(tc)
	}
	return true
}

// AwaitDelivered は、conns のすべてが Delivered になるまで待ち、真を返す。wake が閉じたら待つのを
// やめて偽を返す。中継を切る経路が、切った後に wake を閉じる。最初は呼ばれた直後に確かめ、その後は
// deliveryPollMin から deliveryPollMax まで間隔を倍に伸ばして確かめ直す。錠は持たず、timer は 1 つで、
// 戻る前に止める。
func AwaitDelivered(wake <-chan struct{}, conns ...net.Conn) bool {
	d := deliveryPollMin
	var t *time.Timer
	defer func() {
		if t != nil {
			t.Stop()
		}
	}()
	for {
		done := true
		for _, c := range conns {
			if !Delivered(c) {
				done = false
				break
			}
		}
		if done {
			return true
		}
		if t == nil {
			t = time.NewTimer(d)
		} else {
			t.Reset(d)
		}
		select {
		case <-wake:
			return false
		case <-t.C:
		}
		d = min(2*d, deliveryPollMax)
	}
}
