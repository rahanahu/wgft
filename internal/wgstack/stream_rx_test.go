package wgstack

import (
	"bytes"
	"io"
	"math/rand/v2"
	"testing"
	"time"
)

// 受信の stream の試験:相手が既知の stream を任意に分け、並べ替え、重ね、重複させて送り、アプリケーションが
// 読んだ byte が stream と一致することを確かめる。boost の取得と floor への戻りも混ぜる。

type rxCfg struct {
	seed      uint64
	ts, sack  bool
	ws        bool
	iss       uint32
	length    int
	earlyFin  bool
	readSmall bool
	boostFlip bool
	halfClose bool
	rec       recSpec
}

func runRx(t *testing.T, cfg rxCfg) {
	rng := rand.New(rand.NewPCG(cfg.seed, cfg.seed^0x9e37))
	n := newTestNet(t, smallLimits())
	n.record(cfg.rec)
	l := listen(t, n, 80)
	stream := make([]byte, cfg.length)
	for i := range stream {
		stream[i] = byte(rng.Uint32())
	}
	wsv := -1
	if cfg.ws {
		wsv = 7
	}
	tsVal := uint32(100)
	n.inject(tseg{sport: 4000, dport: 80, seq: cfg.iss, flags: flagSYN, wnd: 65535, mss: 1380, ws: wsv, sackOK: cfg.sack, ts: cfg.ts, tsVal: tsVal})
	outs := n.drain()
	if len(outs) != 1 {
		t.Fatalf("syn-ack %v", outs)
	}
	dutNxt := outs[0].seg.seq + 1
	dutTS := outs[0].seg.opt.tsVal
	base := cfg.iss + 1
	mk := func(off, ln int, fin bool) tseg {
		s := tseg{sport: 4000, dport: 80, seq: base + uint32(off), ack: dutNxt, flags: flagACK, wnd: 65535, ws: -1, ts: cfg.ts, tsVal: tsVal, tsEcr: dutTS}
		if ln > 0 {
			s.payload = append([]byte(nil), stream[off:off+ln]...)
		}
		if fin {
			s.flags |= flagFIN
		}
		return s
	}
	n.inject(mk(0, 0, false))
	c := n.accept(l)
	if cfg.halfClose {
		n.closeWrite(c)
	}

	var got []byte
	ackOff := 0
	edge := 65535
	var pool []tseg
	finAcked := false
	rbuf := make([]byte, 70000)
	eof := false
	demotes := 0
	absorb := func() {
		for _, o := range n.drain() {
			if o.seg.has(flagRST) {
				t.Fatalf("seed %d: DUT sent RST %v", cfg.seed, o)
			}
			a := int(int32(o.seg.ack - base))
			if a > ackOff {
				ackOff = a
			}
			if o.seg.opt.hasTS {
				dutTS = o.seg.opt.tsVal
			}
			if o.seg.has(flagFIN) && o.seg.seq == dutNxt {
				dutNxt++
			}
			sh := 0
			if cfg.ws {
				sh = 7
			}
			if e := a + int(o.seg.wnd)<<sh; e > edge {
				edge = e
			}
			if ackOff == cfg.length+1 {
				finAcked = true
			}
		}
	}
	read := func() {
		for readable(c) {
			b := rbuf
			if cfg.readSmall {
				b = rbuf[:1+rng.IntN(3000)]
			}
			k, err := n.read(c, b)
			got = append(got, b[:k]...)
			if !bytes.Equal(got, stream[:len(got)]) {
				for i := range got {
					if got[i] != stream[i] {
						t.Fatalf("seed %d: delivered byte %d differs (got %d bytes)", cfg.seed, i, len(got))
					}
				}
			}
			if err == io.EOF {
				eof = true
				return
			}
			if err != nil {
				t.Fatalf("seed %d: Read: %v", cfg.seed, err)
			}
			if k == 0 {
				return
			}
		}
	}
	for step := 0; step < 400000 && !(eof && finAcked); step++ {
		switch r := rng.IntN(100); {
		case r < 40: // 新しい segment を作る
			lo := max(0, ackOff-3000)
			hi := min(cfg.length, edge+2000)
			if ackOff > cfg.length {
				break
			}
			if hi <= lo {
				hi = lo + 1
			}
			off := lo + rng.IntN(hi-lo)
			if off >= cfg.length {
				off = cfg.length - 1
			}
			if off < 0 {
				break
			}
			ln := 1 + rng.IntN(1500)
			if rng.IntN(10) == 0 {
				ln = 1 + rng.IntN(5)
			}
			ln = min(ln, cfg.length-off)
			fin := off+ln == cfg.length && (rng.IntN(2) == 0 || cfg.earlyFin)
			pool = append(pool, mk(off, ln, fin))
		case r < 45: // 裸の FIN
			if cfg.earlyFin || ackOff >= cfg.length {
				pool = append(pool, mk(cfg.length, 0, true))
			}
		case r < 80: // 届ける
			if len(pool) == 0 {
				break
			}
			i := rng.IntN(len(pool))
			s := pool[i]
			if rng.IntN(5) != 0 {
				pool[i] = pool[len(pool)-1]
				pool = pool[:len(pool)-1]
			}
			s.ack = dutNxt
			n.inject(s)
		case r < 88:
			absorb()
		case r < 95:
			read()
		case r < 97 && cfg.boostFlip:
			n.internal("an internal boost flip")
			if rng.IntN(2) == 0 {
				n.d.s.tryBoost(c.c, c.gen, boostRecv)
			} else {
				c.c.mu.Lock()
				if c.c.gen == c.gen {
					c.c.lastDemand = -1 << 60
					if c.c.demote(0) {
						demotes++
						n.d.s.pool.release(c.c)
					}
				}
				c.c.mu.Unlock()
			}
		default:
			n.advance(time.Duration(1+rng.IntN(300)) * time.Millisecond)
			tsVal += 1
			// 進みを保つ:累積の確認の位置から送り直す
			if ackOff < cfg.length {
				ln := min(1400, cfg.length-ackOff)
				pool = append(pool, mk(ackOff, ln, ackOff+ln == cfg.length))
			} else if !finAcked {
				pool = append(pool, mk(cfg.length, 0, true))
			}
			if len(pool) > 400 {
				pool = pool[len(pool)-200:]
			}
		}
	}
	absorb()
	read()
	if cfg.seed%25 == 0 {
		st := n.d.Stats()
		t.Logf("demotes %d seed %d len %d ooodrop %d trimmed %d boost %d chal %d", demotes, cfg.seed, cfg.length, st.OOODropped, st.RecvTrimmed, st.BoostGranted, st.ChallengeLimited)
	}
	if cfg.halfClose && eof {
		n.closeConn(c)
		if st := n.d.Stats(); st.Conns != 0 || st.TWRows != 1 {
			t.Fatalf("seed %d: after Close of a half-closed conn %+v", cfg.seed, st)
		}
	}
	if !eof || !bytes.Equal(got, stream) {
		t.Fatalf("seed %d: eof=%v got %d of %d bytes, ackOff %d finAcked %v state %v", cfg.seed, eof, len(got), cfg.length, ackOff, finAcked, c.c.state)
	}
}

func TestReceiveStreamIntegrity(t *testing.T) {
	seeds := uint64(100)
	if streamSeedsFull() {
		seeds = 2000
	}
	forSeeds(t, 1, seeds, func(t *testing.T, seed uint64) { runRx(t, rxStreamCfg(seed)) })
}

// rxStreamCfg は TestReceiveStreamIntegrity の種の選択。記録 (recordings_test.go) も使う。
func rxStreamCfg(seed uint64) rxCfg {
	return rxCfg{
		seed:      seed,
		ts:        seed%2 == 0,
		sack:      seed%3 != 0,
		ws:        seed%5 != 0,
		iss:       uint32(0xffffffff - seed*3000),
		length:    20000 + int(seed*7919)%600000,
		earlyFin:  seed%4 == 0,
		readSmall: seed%3 == 1,
		boostFlip: seed%2 == 1,
		halfClose: seed%7 < 3,
	}
}
