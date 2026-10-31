package wgstack

import "testing"

// RFC 6937 の DeliveredData は (SND.UNA の差) + (SACK 済みの byte の差) で、先に SACK した byte が累積の確認で
// 外れるとき差は負になる。prrDelivered が回復の間に受け手へ届いた byte の数を超えないかを確かめる。
func TestPRRDeliveredDataCountsSACKedBytesOnce(t *testing.T) {
	n, c, q, outs := sackConn(t, 10)
	cs := c.c
	// 2 つの穴:segment 0 と 5。ほかは届いて SACK される
	lost := map[int]bool{0: true, 5: true}
	q.deliver(outs, func(i int, o out) bool { return lost[i] })
	if !cs.inRecovery {
		t.Fatal("not in recovery")
	}
	t.Logf("after SACKs: prrDelivered %d (%d segments)", cs.prrDelivered, cs.prrDelivered/testSegPayload)
	// 最初の穴の再送だけを届ける(部分の確認が SACK 済みの 1-4 を累積で覆う)
	got := n.drain()
	if len(got) == 0 || got[0].seg.seq != outs[0].seg.seq {
		t.Fatalf("first resend %v", got)
	}
	q.recv(got[0])
	q.ack()
	if !cs.inRecovery {
		t.Fatal("recovery ended at a partial ACK")
	}
	// 回復の間に受け手に届いたのは 9 segment(8 つの SACK 済みと再送した 0)
	delivered := uint32(9 * testSegPayload)
	t.Logf("after the partial ACK: prrDelivered %d (%.1f segments), receiver holds %d segments", cs.prrDelivered, float64(cs.prrDelivered)/testSegPayload, 9)
	if cs.prrDelivered > delivered {
		t.Errorf("prrDelivered %d counts SACKed bytes again when the cumulative ACK covers them; RFC 6937 DeliveredData gives %d", cs.prrDelivered, delivered)
	}
}
