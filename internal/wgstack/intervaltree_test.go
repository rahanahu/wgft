package wgstack

import (
	"testing"
)

// 区間の表の木の高さの試験。segment 1 つの手間は木の高さに比例するので、相手が区間を作る順によらず、高さが
// 区間の数の対数の程度に留まることを確かめる(wgstack-performance.md の「区間の数に比例する手間」)。

func (b *recvBuf) height(t int16) int {
	if t == 0 {
		return 0
	}
	return 1 + max(b.height(b.node(t).l), b.height(b.node(t).r))
}

func fullIntervalTable(order string) *recvBuf {
	var p chunkPool
	b := &recvBuf{r: ring{pool: &p, cap: boostSize}, iv: make([]interval, boostIntervals), seed: 12345}
	one := []byte{1}
	for i := 0; i < boostIntervals; i++ {
		k := i
		switch order {
		case "down":
			k = boostIntervals - 1 - i
		case "zigzag":
			if i%2 == 0 {
				k = i / 2
			} else {
				k = boostIntervals - 1 - i/2
			}
		}
		b.insert(uint64(2+2*k), one, boostSize)
	}
	return b
}

func TestIntervalTreeStaysShallow(t *testing.T) {
	for _, order := range []string{"up", "down", "zigzag"} {
		b := fullIntervalTable(order)
		if b.n != boostIntervals {
			t.Fatalf("%s: %d intervals", order, b.n)
		}
		// 3,913 節の treap の高さの期待値は約 2.99 ln n の 25 程度。60 を超えるのは木が偏ったとき
		if h := b.height(b.root); h > 60 {
			t.Errorf("%s: tree height %d for %d intervals", order, h, b.n)
		}
	}
}

// BenchmarkOutOfOrderSegmentAtFullTable は、区間が H 個ある boost の接続で、新しい区間を要する(捨てられる)
// 1 byte の segment 1 つの処理の手間を測る。
func BenchmarkOutOfOrderSegmentAtFullTable(bm *testing.B) {
	b := fullIntervalTable("up")
	one := []byte{1}
	var blocks [4]sackBlock
	bm.ResetTimer()
	for i := 0; bm.Loop(); i++ {
		b.insert(uint64(2*boostIntervals+10+2*(i%1000)), one, boostSize)
		b.sackBlocks(blocks[:0], 0)
	}
}
