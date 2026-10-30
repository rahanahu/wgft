package wgstack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"testing"
	"time"
)

// guardedDrain は期限つきで送る packet を引き取り、Poll が回り続けたら試験を落とす。
func guardedDrain(t *testing.T, n *testNet, what string) []out {
	t.Helper()
	type res struct {
		o   []out
		err string
	}
	ch := make(chan res, 1)
	go func() {
		var r []out
		buf := make([]byte, 65536)
		for i := 0; i < 200000; i++ {
			k := n.d.Poll(buf)
			if k == 0 {
				ch <- res{o: r}
				return
			}
			pkt := append([]byte(nil), buf[:k]...)
			ip, d := parseIPv4(pkt)
			if d != ipv4OK {
				ch <- res{err: "bad ipv4"}
				return
			}
			if ip.proto != protoTCP {
				continue
			}
			seg, td := parseTCP(&ip)
			if td != tcpOK {
				ch <- res{err: "bad tcp"}
				return
			}
			r = append(r, out{ip: ip, seg: seg})
		}
		ch <- res{err: "kept sending"}
	}()
	select {
	case r := <-ch:
		if r.err != "" {
			t.Fatalf("%s: %s", what, r.err)
		}
		return r.o
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: Poll livelocked", what)
	}
	return nil
}

func icmpFragNeeded(cs *tcb, seq uint32, mtu int) []byte {
	// quoted IPv4+TCP header of a DUT segment
	q := make([]byte, 28)
	q[0] = 0x45
	binary.BigEndian.PutUint16(q[2:4], 1400)
	q[8] = 64
	q[9] = protoTCP
	binary.BigEndian.PutUint32(q[12:16], cs.tup.laddr)
	binary.BigEndian.PutUint32(q[16:20], cs.tup.raddr)
	binary.BigEndian.PutUint16(q[20:22], cs.tup.lport)
	binary.BigEndian.PutUint16(q[22:24], cs.tup.rport)
	binary.BigEndian.PutUint32(q[24:28], seq)
	msg := make([]byte, 8+len(q))
	msg[0], msg[1] = icmpDstUnreach, 4
	binary.BigEndian.PutUint16(msg[6:8], uint16(mtu))
	copy(msg[8:], q)
	return buildICMP(peerAddr, msg)
}

type auditCfg struct {
	seed           uint64
	ts, sack, ws   bool
	closeWrite     bool
	length         int
	advSteps       int
	lieTS, lieDSK  bool
	icmp, zeroWnd  bool
	peerData, boos bool
	nr             bool
}

func runAudit(t *testing.T, cfg auditCfg) {
	rng := rand.New(rand.NewPCG(cfg.seed, cfg.seed*7+1))
	n := newTestNet(t, smallLimits())
	if cfg.nr {
		n.d.s.ccPolicy = CongestionNewReno
	}
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, cfg.ts, cfg.sack, cfg.ws)
	c := acceptOne(t, l)
	cs := c.c
	gen := c.gen
	base := p.rcv
	q := newSackPeer(p)
	stream := make([]byte, cfg.length)
	for i := range stream {
		stream[i] = byte(rng.Uint32())
	}
	written := 0
	closed := false
	var netq []out
	alive := func() bool { return cs.gen == gen && cs.state != stFree && cs.state != stClosed }
	check := func(step int, what string) {
		t.Helper()
		if alive() {
			if seqGT(cs.sndUna, cs.sndNxt) || seqGT(cs.sndNxt, cs.sndMax) {
				t.Fatalf("seed %d step %d %s: una %d nxt %d max %d", cfg.seed, step, what, cs.sndUna, cs.sndNxt, cs.sndMax)
			}
			if cs.cwnd == 0 {
				t.Fatalf("seed %d step %d %s: cwnd 0", cfg.seed, step, what)
			}
			if cs.pipe() > (cs.sndMax-cs.sndUna)*2+1 {
				t.Fatalf("seed %d step %d %s: pipe %d flight %d", cfg.seed, step, what, cs.pipe(), cs.sndMax-cs.sndUna)
			}
			checkScoreboard(t, cs)
			if cs.qMid {
				if cs.lostQ.n == 0 {
					t.Fatalf("seed %d step %d %s: qMid with empty lost queue (qOff %d)", cfg.seed, step, what, cs.qOff)
				}
				if h := cs.recs.at(cs.recIdx(cs.lostQ.head)); cs.qOff >= uint32(h.length) {
					t.Fatalf("seed %d step %d %s: qOff %d beyond lost queue head length %d", cfg.seed, step, what, cs.qOff, h.length)
				}
			}
			if cs.rxtMid && int(cs.rxtIdx) < cs.recs.n {
				if h := cs.recs.at(int(cs.rxtIdx)); cs.rxtOff >= uint32(h.length) {
					t.Fatalf("seed %d step %d %s: rxtOff %d beyond record length %d", cfg.seed, step, what, cs.rxtOff, h.length)
				}
			}
		}
		checkHeld(t, n)
	}
	recv := func(o out) {
		if o.seg.tup.lport != 40000 {
			return
		}
		off := int(int32(o.seg.seq - base))
		if pl := o.seg.payload; len(pl) > 0 && off >= 0 {
			if off+len(pl) > len(stream) || !bytes.Equal(pl, stream[off:off+len(pl)]) {
				t.Fatalf("seed %d: wrong bytes at %d len %d", cfg.seed, off, len(pl))
			}
		}
		q.recv(o)
	}
	honest := false
	peerFin := false
	var oooEnd uint32
	haveOOO := false
	steps := cfg.advSteps + 40000
	for step := 0; step < steps; step++ {
		if step == cfg.advSteps {
			honest = true
			p.wnd = 65535
		}
		if closed && int(int32(q.p.rcv-base)) == len(stream)+1 && (honest || !alive()) {
			break
		}
		if !alive() && cs.state != stTimeWait {
			if cs.gen != gen || cs.state == stFree {
				// slot left; acceptable only if the stream completed
				break
			}
		}
		r := rng.IntN(100)
		switch {
		case r < 15:
			if written < len(stream) {
				if w := int(room(c)); w > 0 {
					k := min(w, 1+rng.IntN(30000), len(stream)-written)
					if rng.IntN(4) == 0 {
						k = min(k, 1+rng.IntN(40))
					}
					m, err := c.Write(stream[written : written+k])
					if err != nil {
						t.Fatalf("seed %d: write %v", cfg.seed, err)
					}
					written += m
				}
			} else if !closed && (honest || rng.IntN(20) == 0) {
				closed = true
				if cfg.closeWrite {
					c.CloseWrite()
				} else {
					c.Close()
				}
			}
		case r < 35:
			for _, o := range guardedDrain(t, n, fmt.Sprintf("seed %d step %d", cfg.seed, step)) {
				if e := o.seg.seq + uint32(len(o.seg.payload)); len(o.seg.payload) > 0 && seqGT(e, cs.sndMax) && alive() {
					t.Fatalf("seed %d step %d: segment past SND.MAX %v", cfg.seed, step, o)
				}
				if o.seg.has(flagRST) && alive() {
					t.Fatalf("seed %d step %d: DUT sent RST %v state %v gen %d/%d peerFin %v closed %v st %+v", cfg.seed, step, o, cs.state, cs.gen, gen, peerFin, closed, n.d.Stats())
				}
				if !honest && rng.IntN(100) < 10 {
					continue
				}
				netq = append(netq, o)
				if !honest && rng.IntN(30) == 0 {
					netq = append(netq, o)
				}
			}
		case r < 60:
			if len(netq) == 0 {
				break
			}
			i := 0
			if rng.IntN(4) == 0 {
				i = rng.IntN(len(netq))
			}
			o := netq[i]
			netq = append(netq[:i], netq[i+1:]...)
			recv(o)
			if honest || rng.IntN(10) != 0 {
				q.ack()
			}
		case r < 70 && !honest:
			// lying ACK: never acks beyond what the peer holds
			s := q.p.seg(flagACK, nil)
			s.ack = q.p.rcv - uint32(rng.IntN(3000))
			if cfg.zeroWnd && rng.IntN(3) == 0 {
				s.wnd = 0
			} else {
				s.wnd = uint16(rng.IntN(65536))
			}
			if cfg.lieTS && rng.IntN(2) == 0 {
				s.tsEcr = q.p.dutTS - uint32(rng.IntN(1<<20))
			}
			hi := cs.sndMax
			una := cs.sndUna
			for len(s.sack) < 3 && rng.IntN(2) == 0 {
				a := una + uint32(rng.IntN(int(hi-una)+1))
				b := a + uint32(rng.IntN(int(hi-a)+1))
				if cfg.lieDSK && rng.IntN(3) == 0 {
					a = una - uint32(rng.IntN(5000))
					b = a + uint32(1+rng.IntN(3000))
				}
				s.sack = append(s.sack, sackBlock{a, b})
			}
			n.inject(s)
		case r < 74 && !honest && cfg.icmp:
			cs.mu.Lock()
			ok := alive() && cs.sndUna != cs.sndMax
			una, mx, pm := cs.sndUna, cs.sndMax, cs.pmtu
			cs.mu.Unlock()
			if ok && pm > 600 {
				n.write(icmpFragNeeded(cs, una+uint32(rng.IntN(int(mx-una))), pm-1-rng.IntN(100)))
			}
		case r < 76 && cfg.closeWrite && !peerFin && rng.IntN(8) == 0:
			peerFin = true
			if haveOOO && seqGT(oooEnd, q.p.snd) {
				q.p.ack(make([]byte, oooEnd-q.p.snd))
			}
			q.p.fin()
		case r < 78 && cfg.peerData:
			if !peerFin && (!closed || cfg.closeWrite) {
				q.p.ack(make([]byte, 1+rng.IntN(1300)))
			}
		case r < 79 && cfg.peerData && !peerFin:
			// out-of-order peer data so that DUT segments carry SACK blocks
			sg := q.p.seg(flagACK, make([]byte, 1+rng.IntN(200)))
			sg.seq += uint32(1 + rng.IntN(3000))
			n.inject(sg)
			if e := sg.seq + uint32(len(sg.payload)); !haveOOO || seqGT(e, oooEnd) {
				oooEnd, haveOOO = e, true
			}
		case r < 80 && cfg.peerData:
			buf := make([]byte, 8192)
			if readable(c) {
				c.Read(buf)
			}
		case r < 82 && cfg.boos:
			n.d.s.tryBoost(cs, gen, boostSend)
			cs.mu.Lock()
			if cs.gen == gen {
				cs.lastDemand = -1 << 60
				if cs.demote(0) {
					n.d.s.pool.release(cs)
				}
			}
			cs.mu.Unlock()
		case r < 84 && !honest && cs.sackOK:
			q.ivs = nil // renege
			q.ack()
		default:
			d := time.Duration(1+rng.IntN(60)) * time.Millisecond
			if rng.IntN(20) == 0 {
				d = time.Duration(rng.IntN(3000)) * time.Millisecond
			}
			n.advance(d)
		}
		check(step, "after op")
	}
	if f := n.d.Stats().AccountingFaults; f != 0 {
		t.Fatalf("seed %d: %d accounting faults", cfg.seed, f)
	}
	if got := int(int32(q.p.rcv - base)); got != len(stream)+1 {
		t.Fatalf("seed %d: peer got %d of %d (+FIN); written %d closed %v state %v una %d max %d persist %v wnd %d cwnd %d pipe %d recs %d tlp %v rto %d tdl %v",
			cfg.seed, got, len(stream), written, closed, cs.state, cs.sndUna-base, cs.sndMax-base, cs.persist, cs.sndWnd, cs.cwnd, cs.pipe(), cs.recs.n, cs.tlpProbe, cs.rtoAt, cs.tdl)
	}
}

// TestAdversarialSender は、嘘の ACK、SACK、D-SACK、timestamp、窓、ICMP、SACK の取り消し、boost の切り替えを
// 混ぜた相手に stream を送らせ、Poll が回り続けず、SND.MAX の先を送らず、相手が stream を正しく受け取り、
// scoreboard の数え直しと分けた位置が合うことを確かめる。WGFT_WGSTACK_AUDIT_SEEDS と
// WGFT_WGSTACK_AUDIT_START で種を変える。
func TestAdversarialSender(t *testing.T) {
	seeds := uint64(200)
	if v := os.Getenv("WGFT_WGSTACK_AUDIT_SEEDS"); v != "" {
		x, _ := strconv.Atoi(v)
		seeds = uint64(x)
	}
	start := uint64(1)
	if v := os.Getenv("WGFT_WGSTACK_AUDIT_START"); v != "" {
		x, _ := strconv.Atoi(v)
		start = uint64(x)
	}
	for seed := start; seed < start+seeds; seed++ {
		cfg := adversaryCfg(seed)
		t.Run(fmt.Sprint(seed), func(t *testing.T) { runAudit(t, cfg) })
		if t.Failed() {
			return
		}
	}
}

// FuzzAdversarialSender は TestAdversarialSender の種を fuzzing で探す。
func FuzzAdversarialSender(f *testing.F) {
	for seed := uint64(1); seed <= 8; seed++ {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, seed uint64) { runAudit(t, adversaryCfg(seed)) })
}

// adversaryCfg は種から相手の振る舞いの組み合わせを決める。
func adversaryCfg(seed uint64) auditCfg {
	return auditCfg{
		seed:       seed,
		ts:         seed%2 == 0,
		sack:       seed%3 != 0,
		ws:         seed%5 != 0,
		closeWrite: seed%2 == 1 || seed%3 == 2 || seed%5 == 1,
		length:     2000 + int(seed*7919)%200000,
		advSteps:   2000 + int(seed%5)*1000,
		lieTS:      seed%4 == 0,
		lieDSK:     seed%3 == 1,
		icmp:       seed%2 == 0,
		zeroWnd:    seed%7 == 0,
		peerData:   seed%3 == 2 || seed%5 == 1,
		boos:       seed%4 == 1,
		nr:         seed%6 == 5,
	}
}
