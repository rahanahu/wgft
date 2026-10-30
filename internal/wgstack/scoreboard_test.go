package wgstack

import (
	"math/bits"
	"math/rand/v2"
	"testing"
	"time"
)

// TestScoreboardAgainstRecount は、損失、並べ替え、SACK の取り消し、RTO、PMTU の引き下げを無作為に起こす
// 相手に対して、scoreboard の欄が記録を数え直した値と一致し続け、IsLost の境目が RFC 6675 の定義の
// 範囲より手前に留まらないことを確かめる。
func TestScoreboardAgainstRecount(t *testing.T) {
	seeds := uint64(40)
	if streamSeedsFull() {
		seeds = 400
	}
	forSeeds(t, 1, seeds, func(t *testing.T, seed uint64) {
		rng := rand.New(rand.NewPCG(seed, 99))
		n := newTestNet(t, smallLimits())
		l := listen(t, n, 80)
		p := n.handshake(40000, 80, true, true, true)
		c := acceptOne(t, l)
		cs := c.c
		q := newSackPeer(p)
		total := 300 * testSegPayload
		written := 0
		var net []out
		for step := 0; step < 20000 && (written < total || cs.sndUna != cs.sndMax); step++ {
			switch r := rng.IntN(100); {
			case r < 15:
				if written < total {
					k, _ := c.Write(make([]byte, min(total-written, 1+rng.IntN(30000), int(room(c)))))
					written += k
				}
			case r < 40:
				for _, o := range n.drain() {
					if rng.IntN(100) >= 8 {
						net = append(net, o)
					}
				}
			case r < 80:
				if len(net) == 0 {
					break
				}
				i := 0
				if rng.IntN(4) == 0 {
					i = rng.IntN(len(net))
				}
				o := net[i]
				net = append(net[:i], net[i+1:]...)
				q.recv(o)
				if rng.IntN(100) >= 5 {
					q.ack()
				}
			case r < 82 && cs.sackOK:
				// 相手が順序外のデータを捨てる(SACK の取り消し)
				q.ivs = nil
				q.ack()
			case r < 83:
				if cs.sndUna != cs.sndMax && cs.pmtu > 700 {
					cs.mu.Lock()
					cs.pmtuDrop(cs.sndUna, cs.pmtu-100-rng.IntN(200), int64(n.clk.Now()))
					cs.mu.Unlock()
				}
			default:
				n.advance(time.Duration(1+rng.IntN(60)) * time.Millisecond)
			}
			if cs.state == stFree || cs.state == stClosed {
				t.Fatalf("seed %d: connection ended at step %d", seed, step)
			}
			checkScoreboard(t, cs)
			checkLossFrontier(t, cs)
		}
		if written < total || cs.sndUna != cs.sndMax {
			t.Fatalf("seed %d: sent %d of %d, una %d max %d", seed, written, total, cs.sndUna, cs.sndMax)
		}
		checkHeld(t, n)
	})
}

// checkLossFrontier は、境目より先の SACK 済みの記録の数と byte が、境目の記録を損失とみなす RFC 6675 の
// 閾値に届いていないことを確かめる。届いていれば境目は進んでいなければならない。
func checkLossFrontier(t testing.TB, c *tcb) {
	t.Helper()
	i := int(c.lossIdx)
	if i >= c.recs.n || c.reorderSeen {
		return // 並べ替えを見た後は RACK だけが損失を決める
	}
	var cnt int
	var by uint32
	for k := i + 1; k < c.recs.n; k++ {
		if r := c.recs.at(k); c.isSacked(r) {
			cnt++
			by += uint32(r.length)
		}
	}
	if cnt >= dupThresh || by > uint32((dupThresh-1)*c.segMSS()) {
		t.Fatalf("loss frontier at record %d of %d stays behind %d SACKed records of %d bytes", i, c.recs.n, cnt, by)
	}
}

// floodConn は boost を持ち、boost の記録の輪を満たすほど小さな segment で送った接続を返す。
func floodConn(t *testing.T) (*testNet, *Conn, *sackPeer, *tcb) {
	t.Helper()
	n := newTestNet(t, smallLimits())
	n.d.s.boostPolicy = BoostAtAccept
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	c := acceptOne(t, l)
	cs := c.c
	if !cs.boosted {
		t.Fatal("not boosted")
	}
	n.drain()
	cs.mu.Lock()
	cs.peerMSS = minSegPayload + tsOptionLen // segment の中身を minSegPayload にする
	cs.cwnd = 1 << 30
	cs.sndWnd = 1 << 30
	cs.maxSndWnd = 1 << 30
	cs.mu.Unlock()
	if _, err := c.Write(make([]byte, boostSize)); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		if len(n.drain()) == 0 {
			break
		}
	}
	if cs.recs.n != boostRecords {
		t.Fatalf("%d records, want %d", cs.recs.n, boostRecords)
	}
	return n, c, newSackPeer(p), cs
}

// TestPerACKCostUnderSACKFlood は、相手が選ぶ SACK の block の洪水で、ACK 1 つの scoreboard の手間が
// block の数 x log(記録の数) と印付けの均した手間の和に留まることを確かめる(wgstack-performance.md の
// 「ACK 1 つの手間の上界」)。
func TestPerACKCostUnderSACKFlood(t *testing.T) {
	type pattern struct {
		name   string
		blocks func(rng *rand.Rand, cs *tcb, k int) []sackBlock
	}
	rec := func(cs *tcb, i int) (uint32, uint32) {
		r := cs.recs.at(i)
		return r.seq, r.seq + uint32(r.length)
	}
	patterns := []pattern{
		{"whole range repeated", func(rng *rand.Rand, cs *tcb, k int) []sackBlock {
			l, _ := rec(cs, 1)
			return []sackBlock{{l, cs.sndMax}, {l, cs.sndMax}, {l, cs.sndMax}}
		}},
		{"every other record", func(rng *rand.Rand, cs *tcb, k int) []sackBlock {
			var bs []sackBlock
			for j := range 3 {
				i := 1 + (2*(3*k+j))%(cs.recs.n-1)
				l, r := rec(cs, i)
				bs = append(bs, sackBlock{l, r})
			}
			return bs
		}},
		{"partial records", func(rng *rand.Rand, cs *tcb, k int) []sackBlock {
			var bs []sackBlock
			for range 3 {
				l, r := rec(cs, 1+rng.IntN(cs.recs.n-1))
				bs = append(bs, sackBlock{l + 1, r - 1})
			}
			return bs
		}},
		{"random ranges", func(rng *rand.Rand, cs *tcb, k int) []sackBlock {
			var bs []sackBlock
			for range 3 {
				a, b := 1+rng.IntN(cs.recs.n-1), 1+rng.IntN(cs.recs.n-1)
				if a > b {
					a, b = b, a
				}
				l, _ := rec(cs, a)
				_, r := rec(cs, b)
				bs = append(bs, sackBlock{l, r})
			}
			return bs
		}},
	}
	const acks = 20000
	for _, pt := range patterns {
		t.Run(pt.name, func(t *testing.T) {
			n, _, q, cs := floodConn(t)
			rng := rand.New(rand.NewPCG(1, 2))
			nrec := cs.recs.n
			logN := uint64(bits.Len(uint(nrec)))
			perBlock := 3 * (logN + 3)
			var worstExcess uint64
			start := cs.scoreSteps
			for k := range acks {
				s := q.p.seg(flagACK, nil)
				s.sack = pt.blocks(rng, cs, k)
				before, marked := cs.scoreSteps, cs.sacked
				q.p.n.inject(s)
				n.drain()
				steps := cs.scoreSteps - before
				newly := uint64(cs.sacked-marked) / minSegPayload
				// 印を付けた記録と境目を進めた記録の分を除いた手間が、block ごとの上限を超えないこと
				if fixed := 3 * perBlock; steps > fixed+4*newly {
					worstExcess = max(worstExcess, steps-fixed-4*newly)
				}
			}
			total := cs.scoreSteps - start
			// 均した手間:記録ごとの印付け、境目の通過、再送の手がかりの通過、経路の圧縮
			budget := uint64(acks)*3*perBlock*3 + uint64(nrec)*8*logN
			t.Logf("%d records, %d ACKs: %d steps, %.1f per ACK, worst excess %d", nrec, acks, total, float64(total)/acks, worstExcess)
			if total > budget {
				t.Fatalf("total steps %d exceed the amortized budget %d", total, budget)
			}
			checkScoreboard(t, cs)
			checkHeld(t, n)
		})
	}
}

// TestPerACKCostUnderRenegeFlapping は、SACK した範囲を取り消しては知らせ直す相手が、ACK 1 つの手間も
// 保持も上界の外へ押し出せないことを確かめる。取り消しの処理は RTO の期限でだけ起き、印を世代の番号で
// 消すので、記録の数によらない。
func TestPerACKCostUnderRenegeFlapping(t *testing.T) {
	n, _, q, cs := floodConn(t)
	nrec := cs.recs.n
	logN := uint64(bits.Len(uint(nrec)))
	first := cs.recs.at(1).seq
	ackTo := cs.sndUna
	var worst uint64
	for k := range 300 {
		// 全体を SACK で知らせ、次の ACK で先頭の記録の内側まで累積で確認して SACK を外す
		s := q.p.seg(flagACK, nil)
		s.ack = ackTo
		s.sack = []sackBlock{{first, cs.sndMax}}
		before := cs.scoreSteps
		q.p.n.inject(s)
		n.drain()
		if d := cs.scoreSteps - before; k > 0 {
			worst = max(worst, d)
		}
		if cs.recs.n > 2 {
			ackTo = cs.recs.at(1).seq + 1 // SACK 済みの記録の内側
			s = q.p.seg(flagACK, nil)
			s.ack = ackTo
			before = cs.scoreSteps
			q.p.n.inject(s)
			n.drain()
			worst = max(worst, cs.scoreSteps-before)
			first = cs.recs.at(1).seq
		}
		// 取り消しを疑った期限まで進めて RTO の処理に入る
		n.advance(time.Duration(cs.tdl[tmrRetrans]-int64(n.clk.Now())) + time.Millisecond)
		n.drain()
		checkScoreboard(t, cs)
		if k%100 == 0 {
			checkHeld(t, n)
		}
	}
	st := n.d.Stats()
	t.Logf("%d records, worst steps for one ACK after the first %d, %d renegings, %d RTOs", nrec, worst, st.SACKReneging, st.RTOs)
	if st.SACKReneging < 290 {
		t.Fatalf("%d renegings in 300 rounds", st.SACKReneging)
	}
	// 1 回目より後の ACK は、印の付いていない記録をすべて印付けし直す手間(記録の数)と block の手間を超えない
	if worst > uint64(nrec)*4+8*logN {
		t.Fatalf("worst per-ACK steps %d with %d records", worst, nrec)
	}
	checkHeld(t, n)
}
