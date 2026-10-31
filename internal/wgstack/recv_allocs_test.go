package wgstack

import "testing"

// 受ける向きの速い経路も確保しない(wgstack-batching.md の「確保しない計画」)。確立した接続への順序どおりの data
// の segment を 1 回の Write に 1 個ずつ渡し、Poll で ACK を作り、アプリケーションが Conn.Read で読む。相手の
// segment は測る前に作る。どの回も ACK を少なくとも 1 つ作ることも確かめる。
func TestReceiveFastPathAllocs(t *testing.T) {
	const perRound, rounds = 8, 120
	n := newTestNet(t, smallLimits())
	d := n.d
	c, p := n.accepted(true, true)
	payload := make([]byte, 1368)
	pkts := make([][][]byte, rounds)
	for j := range pkts {
		pkts[j] = make([][]byte, perRound)
		for i := range pkts[j] {
			pkts[j][i] = buildPeer(p.seg(flagACK, payload))
			p.snd += uint32(len(payload))
		}
	}
	out := make([]byte, 65535)
	rd := make([]byte, perRound*len(payload))
	in := [][]byte{nil}
	acks, j := 0, 0
	round := func() {
		for _, pkt := range pkts[j] {
			in[0] = pkt
			if _, err := d.Write(in, 0); err != nil {
				panic(err)
			}
		}
		j++
		for d.Poll(out) > 0 {
			acks++
		}
		for read := 0; read < len(rd); {
			m, err := c.Read(rd[read:])
			if err != nil {
				panic(err)
			}
			read += m
		}
	}
	round()
	allocs := testing.AllocsPerRun(rounds-2, round)
	if acks < rounds {
		t.Fatalf("the receiver sent %d ACKs over %d rounds, want at least one a round", acks, rounds)
	}
	if allocs != 0 {
		t.Fatalf("%.1f allocations per round of %d in-order segments, their ACKs and the application's reads, want 0", allocs, perRound)
	}
}
