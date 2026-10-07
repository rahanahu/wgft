package nettun

import (
	"math/bits"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestWritePiece(t *testing.T) {
	for _, c := range []struct{ n, want int }{
		{1, 1}, {63, 63}, {64, 64}, {65, 64}, {102, 64}, {103, 103}, {1024, 1024}, {1025, 1024}, {1448, 1024},
		{1638, 1024}, {1639, 1639}, {2049, 2048}, {16385, 16384}, {32768, 32768},
		{65535, 65535}, {65536, 65536}, {65537, 65536}, {200000, 196608},
	} {
		if got := writePiece(c.n); got != c.want {
			t.Errorf("writePiece(%d) = %d, want %d", c.n, got, c.want)
		}
	}
	// どの長さでも、返す長さの chunk の余りは長さの 1/4 以下か、最小の chunk の中に収まる
	for n := 1; n <= 1<<17; n++ {
		k := writePiece(n)
		if k < 1 || k > n {
			t.Fatalf("writePiece(%d) = %d", n, k)
		}
		c := max(chunkMin, 1<<bits.Len(uint(k-1)))
		if k >= 1<<16 {
			c = k
		}
		if k > chunkMin && c-k > k/4 {
			t.Fatalf("writePiece(%d) = %d wastes %d of a %d-byte chunk", n, k, c-k, c)
		}
	}
}

// 相手が確認しない接続の送信のキューの生きているヒープは、chunk の余りの大きい長さの書き込みでも
// floor の 2 倍を超えない。gVisor に書き込みをそのまま渡していたときは、1,025 byte の書き込みで
// floor の約 2.7 倍だった。
func TestTCPWriteChunkHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("measures the heap")
	}
	for _, sz := range []int{1025, 1448, 2049, 16385} {
		per, queued := sendQueueHeap(t, 64, sz)
		t.Logf("write=%d: live heap per flow %.1f KiB for %.1f KiB queued", sz, per/1024, queued/1024)
		if per > 2*tcpSendFloor {
			t.Errorf("write=%d: the send queue holds %.1f KiB of heap per flow, more than twice the %d KiB floor", sz, per/1024, tcpSendFloor>>10)
		}
	}
}

// sendQueueHeap は、n 本の接続に握手の後のすべての packet を捨てたまま sz byte の書き込みを続け、
// 送信のキューが満ちたときの接続 1 本あたりの生きているヒープの増分と、キューの byte を返す。
func sendQueueHeap(t *testing.T, n, sz int) (perHeap, perQueued float64) {
	var drop atomic.Bool
	p := newTCPPairOpts(t, 0, nil, func([]byte) bool { return drop.Load() })
	cs := make([]net.Conn, n)
	for i := range cs {
		cs[i], _ = p.dial(t)
	}
	drop.Store(true)
	base := liveHeap()
	buf := make([]byte, sz)
	var written atomic.Int64
	for _, c := range cs {
		go func() {
			for {
				m, err := c.Write(buf)
				written.Add(int64(m))
				if err != nil {
					return
				}
			}
		}()
	}
	// 確認される byte は無いので、書いた byte がそのままキューに残る。400 ms 変わらなければ満ちた
	last, since := written.Load(), time.Now()
	for deadline := time.Now().Add(time.Minute); time.Since(since) < 400*time.Millisecond; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the send queues did not fill")
		}
		if v := written.Load(); v != last {
			last, since = v, time.Now()
		}
	}
	perHeap = float64(int64(liveHeap())-int64(base)) / float64(n)
	for _, c := range cs {
		c.(*TCPConn).Abort()
	}
	return perHeap, float64(last) / float64(n)
}
