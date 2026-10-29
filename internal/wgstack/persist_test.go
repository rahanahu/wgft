package wgstack

import (
	"testing"
	"time"
)

// RTO の後に窓が 0 になり、probe に応答のある persist が再送の打ち切りの時間より長く続いても、窓が開いた後の
// 1 つの損失で接続を終えないことを確かめる。persist に入るときに再送の打ち切りの起点を消す。
func TestPersistDoesNotKeepAStaleRetransmitStart(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Write(make([]byte, 3000))
	outs := n.drain() // 相手は受けない(失う)
	if len(outs) == 0 {
		t.Fatal("nothing sent")
	}
	// RTO で先頭を送り直させる
	n.advance(1100 * time.Millisecond)
	n.drain()
	// 相手は何も確認せずに窓を 0 にする(窓の引き戻し)
	p.wnd = 0
	p.ack(nil)
	n.drain()
	// 次の RTO の後は窓が 0 なので persist に入る。相手は probe に応え続ける
	for i := 0; i < 1200; i++ {
		n.advance(time.Second)
		for _, o := range n.drain() {
			if o.seg.has(flagRST) {
				t.Fatalf("RST during persist at %d s", i)
			}
			p.ack(nil)
		}
	}
	cs := &n.d.s.conns[c.c.id]
	_ = cs
	// 窓を開く。DUT はデータを送るが、それを失う
	p.wnd = 65535
	p.ack(nil)
	if got := n.drain(); len(got) == 0 {
		t.Fatal("no data after the window opened")
	}
	// 1 回目の RTO
	for i := 0; i < 3000; i++ {
		n.advance(time.Millisecond)
		for _, o := range n.drain() {
			if o.seg.has(flagRST) {
				t.Fatalf("connection reset after one lost segment, %d ms after the window opened; stats %+v", i, n.d.Stats())
			}
		}
	}
}
