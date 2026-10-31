package wgstack

import (
	"net/netip"
	"testing"
	"time"
)

// FuzzCore は手で進める時計の下で、任意の packet と時刻の進みとアプリケーションの操作の列を核に与え、各段の
// 後に保持が上界の内側にあり、表の数と予約が一致することを確かめる。最後に Device の Close の後に予約が 0 に
// 戻ることを確かめる(wgstack-verification.md の fuzzing)。
func FuzzCore(f *testing.F) {
	f.Add([]byte{0, 1, 3, 0, 1, 1, 0, 2, 5, 3, 1, 4, 2, 9, 3, 2, 1, 5, 6, 7})
	f.Add([]byte{0, 0, 0, 1, 1, 1, 1, 1, 2, 200, 4, 0, 1, 3, 3, 3, 0, 2, 255, 2, 255})
	f.Fuzz(func(t *testing.T, prog []byte) { fuzzCoreBody(t, prog) })
}

// fuzzCoreBody は FuzzCore の 1 回分。ベンチマークからも呼ぶ。
func fuzzCoreBody(t testing.TB, prog []byte) {
	n := newTestNet(t, fuzzLimits())
	l, err := n.d.ListenTCP(netip.AddrPortFrom(dutAddr, 80))
	if err != nil {
		t.Fatal(err)
	}
	peers := map[uint16]*peerConn{}
	var conns []*Conn
	next := func() byte {
		if len(prog) == 0 {
			return 0
		}
		b := prog[0]
		prog = prog[1:]
		return b
	}
	for steps := 0; len(prog) > 0 && steps < 500; steps++ {
		op, arg := next(), next()
		port := 1000 + uint16(arg%8)
		p := peers[port]
		switch op % 8 {
		case 0: // SYN
			n.inject(tseg{sport: port, dport: 80, seq: uint32(arg) << 20, flags: flagSYN, wnd: 65535, mss: 1380, ws: 7, sackOK: arg&1 == 0, ts: arg&2 == 0, tsVal: 1})
			for _, o := range n.drain() {
				if o.seg.flags == flagSYN|flagACK && o.seg.tup.lport == port {
					peers[port] = &peerConn{n: n, sport: port, dport: 80, snd: o.seg.ack, rcv: o.seg.seq + 1, ts: o.seg.opt.hasTS, tsVal: 2, dutTS: o.seg.opt.tsVal, wnd: 65535}
				}
			}
		case 1: // 中身つきの ACK、ずらした番号
			if p != nil {
				s := p.seg(flagACK, make([]byte, int(arg)*7))
				s.seq += uint32(int8(next())) * 100
				n.inject(s)
				if s.seq == p.snd {
					p.snd += uint32(len(s.payload))
				}
			}
		case 2: // 時刻
			n.advance(time.Duration(arg) * 10 * time.Millisecond)
		case 3: // flag を変えた segment
			if p != nil {
				flags := []uint8{flagACK | flagFIN, flagRST, flagSYN, flagACK, flagRST | flagACK, flagSYN | flagACK}[arg%6]
				s := p.seg(flags, nil)
				if arg&8 != 0 {
					s.ack += uint32(arg) * 1000
				}
				n.inject(s)
				if flags&flagFIN != 0 {
					p.snd++
				}
			}
		case 4: // 受け取る
			for {
				s := n.d.s
				s.tmu.Lock()
				ready := l.l.qhead >= 0
				s.tmu.Unlock()
				if !ready {
					break
				}
				conns = append(conns, acceptOne(t, l))
			}
		case 5: // アプリケーションの操作
			if len(conns) > 0 {
				c := conns[int(arg)%len(conns)]
				switch next() % 6 {
				case 0:
					c.Close()
				case 1:
					c.Abort()
				case 2:
					c.CloseWrite()
				case 3:
					if room(c) > 1000 {
						c.Write(make([]byte, 1000))
					}
				case 4:
					if readable(c) {
						c.Read(make([]byte, 3000))
					}
				case 5:
					c.Delivered()
				}
			}
		case 6: // 出力を読み、相手が確認する
			for _, o := range n.drain() {
				if q := peers[o.seg.tup.lport]; q != nil {
					q.absorb([]out{o})
				}
			}
			if p != nil && arg&1 == 0 {
				p.ack(nil)
			}
		case 7: // 古い番号と窓の 0
			if p != nil {
				p.wnd = uint16(arg) * 64
				p.ack(nil)
			}
		}
		checkHeld(t, n)
	}
	n.drain()
	n.d.Close()
	st := n.d.s.stats()
	if st.Conns != 0 || st.SynRows != 0 || st.TWRows != 0 || st.ChunkBytes != 0 || st.HeldChunksInPool != 0 || st.RecordBytes != 0 || st.IntervalBytes != 0 {
		t.Fatalf("after Close %+v", st)
	}
}

// room は待たずに書ける byte を返す。
func room(h *Conn) uint64 {
	if !h.lock() {
		return 0
	}
	defer h.c.mu.Unlock()
	c := h.c
	if c.appClosed || c.sndShut || c.err != nil || (c.state != stEstablished && c.state != stCloseWait) {
		return 0
	}
	return c.sndCap - (c.tailOff - c.unaOff)
}

// readable は Read が待たずに戻るかを返す。
func readable(h *Conn) bool {
	if !h.lock() {
		return true
	}
	defer h.c.mu.Unlock()
	c := h.c
	return c.appClosed || c.rcv.unread() > 0 || c.finRcvd || c.state == stClosed || c.err != nil
}

// fuzzLimits は smallLimits から、FuzzCore が触れない UDP の枠と断片の表を小さくした値。FuzzCore は TCP の
// segment だけを与えるので、これらの表は使われないまま Device ごとに数百 KB を確保して消す。経路は変わらない。
func fuzzLimits() limits {
	l := smallLimits()
	l.maxFlows, l.acceptQ = 8, 4
	l.udpRxDgrams, l.udpTxDgrams = 8, 8
	l.fragEntries, l.fragPieces = 4, 8
	return l
}
