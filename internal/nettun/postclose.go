package nettun

// 閉じた後の TCP の接続の表(設計文書の tcp-retention.md の「閉じた後の接続の表」)。通常の Close で
// 閉じた netstack の接続は、stack が手放すまで残る。中継の接続は届け終えた後に入るので TIME_WAIT か
// FIN_WAIT_2 で、gVisor の既定で 60 秒残る。K に数えない接続は最初の Close で入るので、FIN_WAIT_1、
// CLOSING、LAST_ACK の行もある。中継が枠を返した
// 後のこの接続は同時フロー数の上限 K に数えないので、Device ごとに固定の postCloseEntries 行の表に
// 入れて数を抑える。表は入れた順に並べ、相手の通信で順を変えない。満杯のときは最も古い行の接続を
// Abort(RST)で終えてポートを返し、新しい行を入れる。Device の 1 秒の sweeper(ingress.go)が、
// 公開の State() が CLOSED か ERROR になった行を外す。

import (
	"sync"
	"sync/atomic"

	"github.com/rahanahu/wgft/internal/lograte"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// postCloseEntries は表の行の数で、設定項目にしない。閉じた後の接続に許す生きているヒープ 128 MiB を、
// 1 行の量の上限 10 KiB で割った値である(設計文書)。
const postCloseEntries = (128 << 20) / (10 << 10)

// postCloseTable は、閉じた後の接続を入れた順に持つ固定の長さの環である。ring は最初の add で作る。
// mu は末端の錠で、持ったまま endpoint の錠を取る操作(Abort)をしない。State() は gVisor の
// 原子的な読み取りで、錠を取らない。
type postCloseTable struct {
	mu     sync.Mutex
	size   int
	ring   []tcpip.Endpoint
	head   int // 最も古い行
	n      int
	closed bool

	evicted  atomic.Uint64 // 満杯で Abort した数。Device を作ってからの累計
	evictLog lograte.Gate
}

func newPostCloseTable(size int) *postCloseTable { return &postCloseTable{size: size} }

// finished は、ep がもう表に入れておく必要の無い状態か。
func finished(ep tcpip.Endpoint) bool {
	switch tcp.EndpointState(ep.State()) {
	case tcp.StateClose, tcp.StateError:
		return true
	}
	return false
}

// add は閉じた ep を最も新しい行に入れる。満杯なら最も古い行を外し、錠の外で Abort する。
func (t *postCloseTable) add(ep tcpip.Endpoint) {
	if finished(ep) {
		return
	}
	var old tcpip.Endpoint
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	if t.ring == nil {
		t.ring = make([]tcpip.Endpoint, t.size)
	}
	if t.n == t.size {
		old, t.ring[t.head] = t.ring[t.head], nil
		t.head = (t.head + 1) % t.size
		t.n--
	}
	t.ring[(t.head+t.n)%t.size] = ep
	t.n++
	t.mu.Unlock()
	if old == nil || finished(old) {
		return
	}
	old.Abort()
	n := t.evicted.Add(1)
	if t.evictLog.Allow() {
		logf("userspace tunnel: reset closed TCP connections that the network stack had not yet released "+
			"because the tunnel keeps at most %d of them; %d reset since the tunnel was built", t.size, n)
	}
}

// sweep は CLOSED か ERROR になった行を外し、残りを順を保って詰める。
func (t *postCloseTable) sweep() {
	t.mu.Lock()
	defer t.mu.Unlock()
	kept := 0
	for i := 0; i < t.n; i++ {
		j := (t.head + i) % t.size
		ep := t.ring[j]
		t.ring[j] = nil
		if !finished(ep) {
			t.ring[(t.head+kept)%t.size] = ep
			kept++
		}
	}
	t.n = kept
}

// len は今の行の数。
func (t *postCloseTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.n
}

// close は表を捨て、以後の add を何もしないようにする。Device.Close が stack を閉じた後に呼ぶ。
// stack の Close がすべての endpoint を終えるので、ここでは Abort しない。
func (t *postCloseTable) close() {
	t.mu.Lock()
	t.closed, t.ring, t.head, t.n = true, nil, 0, 0
	t.mu.Unlock()
}
