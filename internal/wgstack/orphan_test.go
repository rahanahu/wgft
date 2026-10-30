package wgstack

import (
	"testing"
	"time"
)

// 閉じた接続の FIN を窓が 0 の相手が受けず、相手が probe に応え続けても、Linux の tcp_orphan_retries と同じく
// 後退の回数で打ち切り、RST で枠を返すことを確かめる。
func TestOrphanHeldFINIsBoundedAgainstAZeroWindowPeer(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	p.wnd = 0
	p.ack(nil)
	c.Close()
	fins := 0
	for i := 0; i < 2*3600; i++ { // 2 時間
		n.advance(time.Second)
		for _, o := range n.drain() {
			if o.seg.has(flagRST) {
				if st := n.d.Stats(); st.Conns != 0 || !c.Delivered() {
					t.Fatalf("after the RST: %+v, delivered %v", st, c.Delivered())
				}
				if i > 120 {
					t.Errorf("orphan aborted only after %d s", i)
				}
				return
			}
			if o.seg.has(flagFIN) {
				fins++
			}
			p.ack(nil)
		}
	}
	st := n.d.Stats()
	t.Logf("after 2 h: conns %d, FINs sent %d, delivered %v, state %v", st.Conns, fins, c.Delivered(), n.d.s.conns[c.c.id].state)
	if st.Conns != 0 {
		t.Errorf("a closed connection still holds its slot after 2 h against a zero-window peer that answers probes")
	}
}
