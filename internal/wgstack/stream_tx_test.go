package wgstack

import (
	"bytes"
	"math/rand/v2"
	"testing"
	"time"
)

// 送信の stream の試験:アプリケーションが既知の stream を書き、相手の側で DUT の segment を落とし、並べ替え、重複させ、
// 部分の確認と窓の変化を返す。DUT が送ったどの byte も stream のその位置の byte と一致し、最後に相手が
// stream と FIN をすべて受けることを確かめる。

type txCfg struct {
	seed     uint64
	ts, sack bool
	ws       int // -1 なら付けない
	dutISS   uint32
	length   int
	loss     int // 百分率
	zeroWnd  bool
	small    bool // 相手の窓を小さくする
	boost    bool
}

func runTx(t *testing.T, cfg txCfg) {
	rng := rand.New(rand.NewPCG(cfg.seed, cfg.seed^0x5bd1))
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	stream := make([]byte, cfg.length)
	for i := range stream {
		stream[i] = byte(rng.Uint32())
	}
	// DUT の ISS を cfg.dutISS の近くにする:isn = now/4000 + hash
	tup := tuple{laddr: addrBits(dutAddr), raddr: addrBits(peerAddr), lport: 80, rport: 5000}
	h := uint32(n.d.s.isnKey.hashTuple(tup))
	k := cfg.dutISS - h
	n.clk.Advance(time.Duration(k) * 4000)
	n.d.Tick()
	tsVal := uint32(100)
	peerISS := uint32(0x7fff0000)
	n.inject(tseg{sport: 5000, dport: 80, seq: peerISS, flags: flagSYN, wnd: 65535, mss: 1380, ws: cfg.ws, sackOK: cfg.sack, ts: cfg.ts, tsVal: tsVal})
	outs := n.drain()
	if len(outs) != 1 {
		t.Fatalf("syn-ack %v", outs)
	}
	iss := outs[0].seg.seq
	if d := int32(iss - cfg.dutISS); d < -10 || d > 10 {
		t.Fatalf("ISS %x not near %x", iss, cfg.dutISS)
	}
	base := iss + 1
	dutTS := outs[0].seg.opt.tsVal
	sh := 0
	if cfg.ws >= 0 {
		sh = cfg.ws
	}
	// 相手の受信の状態
	rcvOff := 0
	var ooo [][2]int // 届いた順序外の区間(簡単のため重なりを許す)
	finGot := false
	maxEdge := 0
	wndField := uint16(65535)
	pickWnd := func() {
		switch {
		case cfg.zeroWnd && rng.IntN(6) == 0:
			wndField = 0
		case cfg.small:
			wndField = uint16(1 + rng.IntN(4000>>sh+1))
		default:
			wndField = uint16(rng.IntN(65536))
			if rng.IntN(3) == 0 {
				wndField = 65535
			}
		}
	}
	mkAck := func() tseg {
		s := tseg{sport: 5000, dport: 80, seq: peerISS + 1, ack: base + uint32(rcvOff), flags: flagACK, wnd: wndField, ws: -1, ts: cfg.ts, tsVal: tsVal, tsEcr: dutTS}
		if finGot {
			s.ack++
		}
		if cfg.sack && len(ooo) > 0 {
			for i := len(ooo) - 1; i >= 0 && len(s.sack) < 3; i-- {
				if ooo[i][1] > rcvOff {
					s.sack = append(s.sack, sackBlock{base + uint32(max(ooo[i][0], rcvOff)), base + uint32(ooo[i][1])})
				}
			}
		}
		if e := rcvOff + int(wndField)<<sh; e > maxEdge {
			maxEdge = e
		}
		return s
	}
	n.inject(mkAck())
	c := acceptOne(t, l)
	gen := c.gen
	written := 0
	closed := false
	var net []out // 相手へ向かう途中の DUT の segment
	var acks []tseg
	violations := 0
	recvSeg := func(o out) {
		seg := o.seg
		if seg.opt.hasTS {
			dutTS = seg.opt.tsVal
		}
		off := int(int32(seg.seq - base))
		pl := seg.payload
		if len(pl) > 0 {
			if off < 0 || off+len(pl) > cfg.length {
				t.Fatalf("seed %d: segment off %d len %d outside the stream", cfg.seed, off, len(pl))
			}
			if !bytes.Equal(pl, stream[off:off+len(pl)]) {
				t.Fatalf("seed %d: DUT sent wrong bytes at off %d len %d", cfg.seed, off, len(pl))
			}
			if off+len(pl) > maxEdge+1 && off >= rcvOff {
				violations++
			}
		}
		if seg.has(flagFIN) && off+len(pl) != cfg.length {
			t.Fatalf("seed %d: FIN at %d, stream is %d", cfg.seed, off+len(pl), cfg.length)
		}
		if seg.has(flagFIN) && !closed {
			t.Fatalf("seed %d: FIN before CloseWrite", cfg.seed)
		}
		// 相手の窓の内側だけを受ける
		lim := rcvOff + int(wndField)<<sh
		end := min(off+len(pl), lim)
		if off <= rcvOff && end > rcvOff {
			rcvOff = end
		} else if off > rcvOff && end > off {
			ooo = append(ooo, [2]int{off, end})
		}
		for changed := true; changed; {
			changed = false
			for _, iv := range ooo {
				if iv[0] <= rcvOff && iv[1] > rcvOff {
					rcvOff = iv[1]
					changed = true
				}
			}
		}
		if seg.has(flagFIN) && off+len(pl) == rcvOff {
			finGot = true
		}
	}
	steps := 0
	for ; steps < 600000; steps++ {
		if finGot && rcvOff == cfg.length && c.Delivered() {
			break
		}
		switch r := rng.IntN(100); {
		case r < 20: // アプリケーションが書く
			if written < cfg.length {
				if w := int(room(c)); w > 0 {
					k := min(w, 1+rng.IntN(20000), cfg.length-written)
					if rng.IntN(5) == 0 {
						k = min(k, 1+rng.IntN(50))
					}
					m, err := c.Write(stream[written : written+k])
					if err != nil {
						t.Fatalf("seed %d: Write: %v", cfg.seed, err)
					}
					written += m
				}
			} else if !closed {
				closed = true
				if rng.IntN(2) == 0 {
					c.CloseWrite()
				} else {
					c.Close()
				}
			}
		case r < 45: // DUT の出力を網へ
			for _, o := range n.drain() {
				if o.seg.has(flagRST) {
					t.Fatalf("seed %d: DUT sent RST %v (rcvOff %d of %d)", cfg.seed, o, rcvOff, cfg.length)
				}
				if rng.IntN(100) < cfg.loss {
					continue
				}
				net = append(net, o)
				if rng.IntN(20) == 0 {
					net = append(net, o)
				}
			}
		case r < 70: // 網から相手へ
			if len(net) == 0 {
				break
			}
			i := 0
			if rng.IntN(4) == 0 {
				i = rng.IntN(len(net))
			}
			o := net[i]
			net = append(net[:i], net[i+1:]...)
			recvSeg(o)
			if rng.IntN(8) == 0 {
				pickWnd()
			}
			if rng.IntN(100) >= cfg.loss {
				acks = append(acks, mkAck())
			}
		case r < 85: // 相手の ACK を DUT へ
			if len(acks) == 0 {
				break
			}
			i := 0
			if rng.IntN(5) == 0 {
				i = rng.IntN(len(acks))
			}
			a := acks[i]
			acks = append(acks[:i], acks[i+1:]...)
			n.inject(a)
		case r < 88 && cfg.boost:
			n.d.s.tryBoost(c.c, gen, boostSend)
			c.c.mu.Lock()
			if c.c.gen == gen {
				c.c.lastDemand = -1 << 60
				if c.c.demote(0) {
					n.d.s.pool.release(c.c)
				}
			}
			c.c.mu.Unlock()
		case r < 92: // 窓の更新
			pickWnd()
			n.inject(mkAck())
		default:
			n.advance(time.Duration(1+rng.IntN(400)) * time.Millisecond)
			tsVal++
		}
	}
	if !finGot || rcvOff != cfg.length {
		t.Fatalf("seed %d: after %d steps peer has %d of %d, fin %v, written %d, state %v", cfg.seed, steps, rcvOff, cfg.length, finGot, written, c.c.state)
	}
	if violations > 0 {
		t.Logf("seed %d: %d segments beyond the largest advertised right edge", cfg.seed, violations)
	}
}

func TestSendStreamIntegrity(t *testing.T) {
	seeds := uint64(600)
	if testing.Short() || raceEnabled {
		seeds = 50
	}
	for seed := uint64(1); seed <= seeds; seed++ {
		ws := []int{-1, 0, 2, 7, 14}[seed%5]
		cfg := txCfg{
			seed:    seed,
			ts:      seed%2 == 0,
			sack:    seed%3 == 0,
			ws:      ws,
			dutISS:  uint32(0xffffffff - (seed*5000)%300000),
			length:  5000 + int(seed*6151)%400000,
			loss:    []int{0, 3, 10, 25}[seed%4],
			zeroWnd: seed%7 == 0,
			small:   seed%11 == 0,
			boost:   seed%2 == 1,
		}
		runTx(t, cfg)
		if t.Failed() {
			return
		}
	}
}
