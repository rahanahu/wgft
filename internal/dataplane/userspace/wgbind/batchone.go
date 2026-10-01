// Package wgbind は、wireguard-go の device に渡す UDP のバインド(conn.Bind)の作り方と包みを持つ。
// エージェントのトンネル(internal/dataplane/userspace/tunnel)と `vpsd` のユーザー空間モードの
// トンネル(internal/dataplane/userspace/utun)は、どちらも New でバインドを作る。
package wgbind

import (
	"net"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
)

// maxDatagram は 1 件の datagram の大きさの上限で、wireguard-go の MaxMessageSize(Linux では
// 65535)と同じ値である。内側のバインドが GRO でまとめて読んだ結果を分けた 1 件も、この大きさを
// 超えない。
const maxDatagram = 1<<16 - 1

// BatchOne は inner を包み、wireguard-go の 1 回の受信の呼び出しに 1 件の datagram だけを渡す
// バインドを返す。inner の BatchSize が既に 1 なら inner をそのまま返す。
//
// wireguard-go は、1 回の受信の結果を 1 つの入れ物として peer ごとの受信のキュー(入れ物 1024 個)に
// 入れ、1 件ごとに MaxMessageSize のバッファを持つ。Linux の標準のバインドは 1 回に 128 件まで
// 読むので、そのままでは peer ごとの受信の滞留の上限が 1024 × 128 × 64 KiB になる。1 回に 1 件
// なら 1024 × 64 KiB である(設計文書 7 節)。
//
// 包みは inner を inner の BatchSize 個の自前のバッファで読み、呼び出しごとに 1 件ずつ写して渡す。
// 読み取りの syscall の数は変わらない。inner の 1 回の読み取り(recvmmsg、GRO)と sticky socket は
// そのまま残る。失うのは wireguard-go の Linux の経路の監視だけである。監視は inner の型が
// *conn.StdNetBind であるときだけ始まり、包むと始まらない(設計文書 7 節の「WireGuard の受信の
// 1 回の件数」)。
//
// 送信は inner に素通しする。
func BatchOne(inner conn.Bind) conn.Bind {
	if inner.BatchSize() <= 1 {
		return inner
	}
	return &batchOne{Bind: inner}
}

// batchOne は BatchOne が返すバインド。conn.Bind の残りの method(Send、SetMark、ParseEndpoint)は
// 埋め込んだ inner のものをそのまま使う。
type batchOne struct {
	conn.Bind

	mu  sync.Mutex
	cur *generation // 最後の Open が作った受信の状態。Close で印を付ける
}

// generation は 1 回の Open から Close までの受信の状態。Close は受信の goroutine とは別の
// goroutine から呼ばれるので、印は atomic で持つ。
type generation struct {
	closed atomic.Bool
}

var _ conn.Bind = (*batchOne)(nil)

// BatchSize は 1 を返す。wireguard-go はこの値で受信の入れ物の容量と受信の goroutine のバッファの
// 数を決める。
func (b *batchOne) BatchSize() int { return 1 }

// Open は inner を開き、inner の受信の関数を 1 件ずつ渡す関数に包んで返す。
func (b *batchOne) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, actual, err
	}
	gen := &generation{}
	b.mu.Lock()
	b.cur = gen
	b.mu.Unlock()
	n := b.Bind.BatchSize()
	out := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		out[i] = newReceiver(gen, fn, n).receive
	}
	return out, actual, nil
}

// Close は受信の状態に閉じた印を付けてから inner を閉じる。印の後の受信は、手持ちの datagram を
// 捨てて net.ErrClosed を返す(conn.Bind の契約)。
func (b *batchOne) Close() error {
	b.mu.Lock()
	gen := b.cur
	b.mu.Unlock()
	if gen != nil {
		gen.closed.Store(true)
	}
	return b.Bind.Close()
}

// receiver は inner の受信の関数 1 つ分の状態。wireguard-go は受信の関数 1 つを 1 つの goroutine
// からだけ呼ぶので、手持ちの状態に錠は要らない。
type receiver struct {
	gen   *generation
	recv  conn.ReceiveFunc
	bufs  [][]byte
	sizes []int
	eps   []conn.Endpoint
	held  int // 最後の inner の読み取りで得た件数
	next  int // 次に渡す手持ちの位置
}

func newReceiver(gen *generation, recv conn.ReceiveFunc, n int) *receiver {
	r := &receiver{
		gen:   gen,
		recv:  recv,
		bufs:  make([][]byte, n),
		sizes: make([]int, n),
		eps:   make([]conn.Endpoint, n),
	}
	for i := range r.bufs {
		r.bufs[i] = make([]byte, maxDatagram)
	}
	return r
}

// receive は conn.ReceiveFunc として wireguard-go から呼ばれ、1 件だけを bufs[0]、sizes[0]、eps[0] に
// 置いて 1 を返す。手持ちが無ければ inner を自前のバッファ全部で呼ぶ。inner には inner の
// BatchSize 個ちょうどのバッファを渡す。標準のバインドは、渡された数だけ読み取りの領域を付け、
// 残りは前回の領域のまま recvmmsg に渡すので、少なく渡すと他の呼び出しのバッファに書き込みうる。
//
// inner の誤りは同じ値のまま返す。wireguard-go は net.Error への直接の型の判定で一時的な誤りか
// どうかを見るので、包むと非一時的な誤りを一時的と誤って読む。
func (r *receiver) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if r.gen.closed.Load() {
		r.drop()
		return 0, net.ErrClosed
	}
	// inner は 0 件で (0, nil) を返すことがある。標準のバインドは、GRO でまとめて読んだ先頭が
	// 0 byte の datagram のとき 0 件を返すので、1 件得られるまで読み直す。
	for r.next >= r.held {
		n, err := r.recv(r.bufs, r.sizes, r.eps)
		if err != nil {
			return 0, err
		}
		r.held, r.next = n, 0
	}
	i := r.next
	r.next++
	sizes[0] = copy(bufs[0], r.bufs[i][:r.sizes[i]])
	eps[0] = r.eps[i]
	r.eps[i] = nil
	return 1, nil
}

// drop は手持ちの datagram を捨てる。
func (r *receiver) drop() {
	for i := r.next; i < r.held; i++ {
		r.eps[i] = nil
	}
	r.held, r.next = 0, 0
}
