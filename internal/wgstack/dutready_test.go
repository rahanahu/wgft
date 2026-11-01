package wgstack

// dutserve の待たない操作の確かめ。公開の Accept、Read、Write、UDP の ReadFrom と WriteTo、echo の Read
// が待たずに戻るかを、錠を取って状態から答える。dutserve はこれが真の時だけ公開の操作を呼び、偽なら呼ばずに
// WOULD_BLOCK を返す (test-tooling.md の 3 節)。各確かめは操作の冒頭の分岐を同じ順で写したもので、
// TestDutserveReadyMatchesBlocking が実際の操作の振る舞いと照らす。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

// acceptReady は TCPListener.Accept が待たずに戻るかを返す。閉じた待ち受けと閉じた Device では誤りで、
// 待ち行列に接続があればそれで戻る。待ち行列の接続は、枠を返す時に待ち行列から外れる (tcb の release と
// freeSlotLocked) ので、1 つの流れで呼ぶ dutserve では、Accept が先頭を外した後に読み飛ばす場合は無い。
func acceptReady(t *TCPListener) bool {
	l := t.l
	s := l.s
	s.tmu.Lock()
	defer s.tmu.Unlock()
	return l.closed || s.closed || l.qhead >= 0
}

// readReady は Conn.Read が待たずに戻るかを返す。FuzzCore の readable に、閉じた Device と期限を足した形。
func readReady(h *Conn) bool {
	if !h.lock() {
		return true
	}
	defer h.c.mu.Unlock()
	c := h.c
	return c.appClosed || h.s.isClosed() || c.rdl.expired() || c.rcv.unread() > 0 || c.finRcvd || c.state == stClosed || c.err != nil
}

// writeRoom は Conn.Write が待たずに受け取れる byte の数と、接続が書ける状態かを返す。書けない状態の Write
// は待たずに誤りを返す。書ける状態で空きが 0 なら Write は待つ。FuzzCore の room は 2 つを区別しない。
func writeRoom(h *Conn) (room uint64, writable bool) {
	if !h.lock() {
		return 0, false
	}
	defer h.c.mu.Unlock()
	c := h.c
	if c.appClosed || h.s.isClosed() || c.err != nil || c.sndShut || (c.state != stEstablished && c.state != stCloseWait) || c.wdl.expired() {
		return 0, false
	}
	return c.sndCap - (c.tailOff - c.unaOff), true
}

// udpRecvReady は UDPConn.ReadFrom が待たずに戻るかを返す。
func udpRecvReady(c *UDPConn) bool {
	ep := c.ep
	u := &ep.s.udp
	u.mu.Lock()
	defer u.mu.Unlock()
	return ep.closed || u.closed || ep.rdl.expired() || ep.rxHead >= 0
}

// udpSendReady は UDPConn.WriteTo(b, addr) が待たずに戻るかを返す。予約の判定は udpReserve の前半を状態を
// 変えずに写す。予約できない WriteTo は待つ前に txWaited を立てるので、dutserve は呼ばない。
func udpSendReady(c *UDPConn, b []byte, addr *net.UDPAddr) bool {
	if addr == nil || addr.Port <= 0 || addr.Port > 65535 || addr.IP.To4() == nil || len(b) > udpMaxPayload {
		return true
	}
	ep := c.ep
	s := ep.s
	u := &s.udp
	u.mu.Lock()
	defer u.mu.Unlock()
	if ep.closed || u.closed || u.fault != nil || ep.wdl.expired() {
		return true
	}
	return udpCanReserve(s, ep, dirTx, len(b))
}

// udpCanReserve は udpReserve(ep, dir, n) が予約できるかを、状態を変えずに返す。udp.mu を持って呼ぶ。
func udpCanReserve(s *stack, ep *udpEndpoint, dir, n int) bool {
	u := &s.udp
	dev, own := &u.budget[dir], &ep.budget[dir]
	if len(u.dgFree[dir]) == 0 || !dev.fits(0, 1) || !own.fits(0, 1) {
		return false
	}
	c := udpClassOf(n)
	var need int64
	switch {
	case c == udpLarge:
		need = int64((n + chunkSize - 1) / chunkSize * chunkSize)
	default:
		if cur := ep.cur[dir][c]; cur < 0 || u.ck[cur].next >= chunkSize/udpClasses[c] {
			need = chunkSize
		}
	}
	if need > 0 && (!dev.fits(need, 0) || !own.fits(need, 0) || int64(len(u.ckFree))*chunkSize < need) {
		return false
	}
	return true
}

// pingRecvReady は PingConn.Read が待たずに戻るかを返す。閉じた Device では待ちが s.done で解ける。
func pingRecvReady(c *PingConn) bool {
	p := &c.s.ping
	p.mu.Lock()
	defer p.mu.Unlock()
	e := c.ep()
	return e == nil || c.s.isClosed() || e.rdl.expired() || e.n > 0
}

// 照らしの期限。待たないと言った操作には長い期限を置き、それでも期限で戻れば食い違いとする。待つと言った
// 操作には短い期限を置き、期限の誤りで戻ることを求める。期限は未来に置くので、操作の冒頭の期限の確かめでは
// 戻らず、期限で戻ったなら操作は待っていた。負荷で操作の始まりが遅れると、待たない操作も期限で戻りうるが、
// それは待つと言った場合の照らしを見逃すだけで、誤って落とすことはない。
const (
	readyDeadline   = 5 * time.Second
	blockedDeadline = 5 * time.Millisecond
	opGuard         = 30 * time.Second
)

// readyProbe は 1 つの Device の上で、確かめと操作の振る舞いを照らす。
type readyProbe struct {
	t      *testing.T
	n      *testNet
	seed   uint64
	step   int
	counts map[string][2]int // 確かめの名前ごとの偽と真の回数
}

func (p *readyProbe) count(name string, ready bool) {
	c := p.counts[name]
	if ready {
		c[1]++
	} else {
		c[0]++
	}
	p.counts[name] = c
}

func (p *readyProbe) fail(name string, ready bool, format string, args ...any) {
	p.t.Helper()
	p.t.Errorf("seed %d step %d: %s said ready=%v, but %s", p.seed, p.step, name, ready, fmt.Sprintf(format, args...))
}

// runOp は op を別の goroutine で流し、opGuard の内に戻らなければ試験を止める。
func (p *readyProbe) runOp(name string, op func() (int, error)) (int, error) {
	p.t.Helper()
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		n, err := op()
		ch <- res{n, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-time.After(opGuard):
		p.t.Fatalf("seed %d step %d: %s did not return within %v", p.seed, p.step, name, opGuard)
	}
	return 0, nil
}

// timedOp は期限を持つ操作を照らす。setDL は操作の向きの期限を置く。
func (p *readyProbe) timedOp(name string, ready bool, setDL func(time.Time), op func() (int, error)) (int, error) {
	p.t.Helper()
	p.count(name, ready)
	d := blockedDeadline
	if ready {
		d = readyDeadline
	}
	setDL(time.Now().Add(d))
	n, err := p.runOp(name, op)
	setDL(time.Time{})
	timedOut := errors.Is(err, os.ErrDeadlineExceeded)
	switch {
	case ready && timedOut:
		// 待たないと言った操作が待った後は、同じ食い違いで毎回期限まで待つので、この列を止める
		p.fail(name, ready, "the operation waited until its deadline")
		p.t.FailNow()
	case !ready && !timedOut:
		p.fail(name, ready, "the operation returned without waiting: n=%d err=%v", n, err)
	case !ready && n != 0:
		p.fail(name, ready, "the operation took %d bytes before its deadline", n)
	}
	return n, err
}

// acceptOp は期限を持たない Accept を照らす。待つと言った場合は、Accept が待っていることを確かめた後、相手の
// 新しい接続で待ちを解く。解けなければ待ち受けを閉じて解き、同じポートで待ち受け直す。
func (p *readyProbe) acceptOp(l **TCPListener, w *readyWalk) *Conn {
	p.t.Helper()
	ready := acceptReady(*l)
	p.count("acceptReady", ready)
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := (*l).Accept()
		ch <- res{c, err}
	}()
	var r res
	if ready {
		select {
		case r = <-ch:
		case <-time.After(opGuard):
			p.t.Fatalf("seed %d step %d: acceptReady said ready=true, but Accept did not return within %v", p.seed, p.step, opGuard)
		}
	} else {
		select {
		case r = <-ch:
			p.fail("acceptReady", ready, "Accept returned without waiting: err=%v", r.err)
		case <-time.After(blockedDeadline):
			w.syn(uint16(2000+p.step), true)
			select {
			case r = <-ch:
			case <-time.After(2 * time.Second):
				(*l).Close()
				r = <-ch
				nl, err := p.n.d.ListenTCP(netip.AddrPortFrom(dutAddr, 80))
				if err != nil {
					p.t.Fatalf("listening again: %v", err)
				}
				*l = nl
			}
		}
	}
	if r.err != nil {
		return nil
	}
	return r.c.(*Conn)
}

// readyWalk は FuzzCore に似た操作の列で Device を動かす。相手は TCP の接続、UDP の datagram、echo の応答を返す。
type readyWalk struct {
	p     *readyProbe
	r     *rand.Rand
	l     *TCPListener
	us    []*UDPConn // 5 つの socket。1 つの socket の予算は Device の 4 分の 1 なので、Device の予算も尽きる
	pings []*PingConn
	conns []*Conn
	peers map[uint16]*peerConn
}

// syn は相手のポート port から SYN を送る。complete なら SYN-ACK に ACK を返して握手を終える。
func (w *readyWalk) syn(port uint16, complete bool) {
	n := w.p.n
	n.inject(tseg{sport: port, dport: 80, seq: uint32(port) << 16, flags: flagSYN, wnd: 65535, mss: 1380, ws: 7, sackOK: true, ts: true, tsVal: 1})
	w.drain()
	if q := w.peers[port]; complete && q != nil {
		q.ack(nil)
	}
}

// drain は Device の出力を読み、相手が答える。SYN-ACK から相手の接続を作り、順序どおりの segment を数え、echo
// request に reply を返す。
func (w *readyWalk) drain() {
	n := w.p.n
	for range 100000 {
		k := n.d.Poll(n.buf)
		if k == 0 {
			return
		}
		pkt := append([]byte(nil), n.buf[:k]...)
		ip, d := parseIPv4(pkt)
		if d != ipv4OK {
			w.p.t.Fatalf("Device sent a bad IPv4 packet: %v", d)
		}
		switch ip.proto {
		case protoTCP:
			seg, td := parseTCP(&ip)
			if td != tcpOK {
				w.p.t.Fatalf("Device sent a bad TCP segment: %v", td)
			}
			o := out{ip: ip, seg: seg}
			port := seg.tup.lport
			if seg.flags == flagSYN|flagACK {
				w.peers[port] = &peerConn{n: n, sport: port, dport: 80, snd: seg.ack, rcv: seg.seq + 1, ts: seg.opt.hasTS, tsVal: 2, dutTS: seg.opt.tsVal, wnd: 65535}
				continue
			}
			if q := w.peers[port]; q != nil {
				q.absorb([]out{o})
			}
		case protoICMP:
			msg := ip.payload
			if len(msg) >= 8 && msg[0] == icmpEcho {
				reply := append([]byte(nil), msg...)
				reply[0] = 0
				n.write(buildICMP(peerAddr, reply))
			}
		}
	}
	w.p.t.Fatal("Device kept sending")
}

func (w *readyWalk) conn() *Conn {
	if len(w.conns) == 0 {
		return nil
	}
	return w.conns[w.r.IntN(len(w.conns))]
}

func (w *readyWalk) peer() *peerConn {
	port := uint16(1000 + w.r.IntN(8))
	return w.peers[port]
}

// probeRead、probeWrite、probeUDP*、probePing* は、確かめを読んでから操作を 1 回流して照らす。
func (w *readyWalk) probeRead(c *Conn) {
	ready := readReady(c)
	b := make([]byte, 1+w.r.IntN(3000))
	w.p.timedOp("readReady", ready, func(t time.Time) { c.SetReadDeadline(t) }, func() (int, error) { return c.Read(b) })
}

// probeWrite は書けるだけ書き、空きが尽きた後の 1 回までを照らす。
func (w *readyWalk) probeWrite(c *Conn) {
	for range 8 {
		room, writable := writeRoom(c)
		ready := !writable || room > 0
		size := 1 + w.r.IntN(70000)
		if writable && room > 0 {
			size = int(min(uint64(size), room))
		}
		w.p.timedOp("writeRoom", ready, func(t time.Time) { c.SetWriteDeadline(t) }, func() (int, error) { return c.Write(make([]byte, size)) })
		if !writable || room == 0 {
			return
		}
	}
}

func (w *readyWalk) probeUDPRecv(u *UDPConn) {
	ready := udpRecvReady(u)
	b := make([]byte, 2000)
	w.p.timedOp("udpRecvReady", ready, func(t time.Time) { u.SetReadDeadline(t) }, func() (int, error) {
		n, _, err := u.ReadFrom(b)
		return n, err
	})
}

// probeUDPSend は予算が尽きるまで送り、尽きた後の 1 回までを照らす。tiny なら小さな datagram だけを送り、
// byte より先に件数の予算を尽くす。
func (w *readyWalk) probeUDPSend(u *UDPConn, tiny bool) {
	for range 600 {
		size := []int{10, 1000, 4000, 60000}[w.r.IntN(4)]
		if tiny {
			size = 10
		}
		to := net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerAddr, 9))
		b := make([]byte, size)
		ready := udpSendReady(u, b, to)
		w.p.timedOp("udpSendReady", ready, func(t time.Time) { u.SetWriteDeadline(t) }, func() (int, error) { return u.WriteTo(b, to) })
		if !ready {
			// 予算が尽きていても、大きすぎる datagram は待たずに誤りで戻る
			big := make([]byte, udpMaxPayload+1)
			w.p.timedOp("udpSendReady", udpSendReady(u, big, to), func(t time.Time) { u.SetWriteDeadline(t) }, func() (int, error) { return u.WriteTo(big, to) })
			return
		}
	}
}

func (w *readyWalk) udp() *UDPConn { return w.us[w.r.IntN(len(w.us))] }

func (w *readyWalk) probePingRecv(c *PingConn) {
	ready := pingRecvReady(c)
	b := make([]byte, 2000)
	w.p.timedOp("pingRecvReady", ready, func(t time.Time) { c.SetReadDeadline(t) }, func() (int, error) { return c.Read(b) })
}

// probeAll は今の物すべての確かめを照らす。
func (w *readyWalk) probeAll() {
	if c := w.p.acceptOp(&w.l, w); c != nil {
		w.conns = append(w.conns, c)
	}
	for _, c := range w.conns {
		w.probeRead(c)
		w.probeWrite(c)
	}
	for _, u := range w.us {
		w.probeUDPRecv(u)
		w.probeUDPSend(u, false)
	}
	for _, c := range w.pings {
		w.probePingRecv(c)
	}
}

func (w *readyWalk) run(steps int) {
	n := w.p.n
	for i := range steps {
		w.p.step = i
		op, arg := w.r.IntN(16), w.r.IntN(256)
		p := w.peer()
		switch op {
		case 0:
			w.syn(uint16(1000+arg%8), arg&1 == 0)
		case 1:
			if p != nil {
				p.ack(make([]byte, arg*11%3000))
			}
		case 2:
			n.advance(time.Duration(arg) * 10 * time.Millisecond)
		case 3:
			if p != nil {
				if arg&1 == 0 {
					p.fin()
				} else {
					n.inject(p.seg(flagRST, nil))
				}
			}
		case 4:
			if c := w.p.acceptOp(&w.l, w); c != nil {
				w.conns = append(w.conns, c)
			}
		case 5:
			if c := w.conn(); c != nil {
				w.probeRead(c)
			}
		case 6:
			if c := w.conn(); c != nil {
				w.probeWrite(c)
			}
		case 7:
			if c := w.conn(); c != nil {
				switch arg % 3 {
				case 0:
					c.Close()
				case 1:
					c.CloseWrite()
				case 2:
					c.Abort()
				}
			}
		case 8:
			w.drain()
			if p != nil {
				p.ack(nil)
			}
		case 9:
			if p != nil {
				p.wnd = uint16(arg%4) * 64
				p.ack(nil)
			}
		case 10:
			n.write(buildUDP(netip.AddrPortFrom(peerAddr, 7000), uint16(53+arg%len(w.us)), make([]byte, arg*5)))
		case 11:
			w.probeUDPRecv(w.udp())
		case 12:
			w.probeUDPSend(w.udp(), arg&1 == 0)
		case 13:
			if len(w.pings) < 3 && arg&1 == 0 {
				pc, err := n.d.DialPing(dutAddr, peerAddr)
				if err == nil {
					w.pings = append(w.pings, pc.(*PingConn))
				}
			} else if len(w.pings) > 0 {
				c := w.pings[arg%len(w.pings)]
				msg := make([]byte, 8+arg)
				msg[0] = icmpEcho
				binary.BigEndian.PutUint16(msg[6:8], uint16(i))
				c.Write(msg)
			}
		case 14:
			if len(w.pings) > 0 {
				w.probePingRecv(w.pings[arg%len(w.pings)])
			}
		case 15:
			switch {
			case arg < 8 && len(w.pings) > 0:
				w.pings[0].Close()
			case arg < 12:
				// 予算の尽きた socket を閉じる。閉じた socket の WriteTo は予算によらず待たずに誤りで戻る
				u := w.udp()
				w.probeUDPSend(u, true)
				u.Close()
				w.probeUDPSend(u, false)
				w.probeUDPRecv(u)
			case arg < 14:
				w.l.Close()
			}
		}
	}
}

// TestDutserveReadyMatchesBlocking は、dutserve の待たない操作の確かめが、公開の操作が待たずに戻る時と
// ちょうど一致することを確かめる (test-tooling.md の 9 節が未確認としていた点)。確かめが真なら操作は期限を
// 待たずに戻り、偽なら期限まで待つ。Device を閉じた後は、すべての確かめが真で、すべての操作が待たずに戻る。
// 各確かめが真と偽の両方を少なくとも 1 回見たことも求める。
func TestDutserveReadyMatchesBlocking(t *testing.T) {
	seeds, steps := 24, 300
	if testing.Short() {
		seeds = 6
	}
	var mu sync.Mutex
	total := map[string][2]int{}
	t.Run("walk", func(t *testing.T) {
		for seed := range uint64(seeds) {
			t.Run(fmt.Sprint(seed), func(t *testing.T) {
				t.Parallel()
				n := newTestNet(t, smallLimits())
				if seed%2 == 1 {
					// boost の無い接続は送信のバッファが floor のまま増えないので、空きの尽きた Write を多く見る
					n.d.s.boostPolicy = BoostNever
				}
				p := &readyProbe{t: t, n: n, seed: seed, counts: map[string][2]int{}}
				l, err := n.d.ListenTCP(netip.AddrPortFrom(dutAddr, 80))
				if err != nil {
					t.Fatal(err)
				}
				w := &readyWalk{p: p, r: rand.New(rand.NewPCG(seed, 0x5eed)), l: l, peers: map[uint16]*peerConn{}}
				for port := range uint16(5) {
					pc, err := n.d.ListenUDP(netip.AddrPortFrom(dutAddr, 53+port))
					if err != nil {
						t.Fatal(err)
					}
					w.us = append(w.us, pc.(*UDPConn))
				}
				w.run(steps)
				p.step = steps
				// すべての socket の件数の予算を尽くし、Device の件数の予算にも届かせる
				for _, u := range w.us {
					w.probeUDPSend(u, true)
				}
				w.probeAll()
				n.d.Close()
				p.step = steps + 1
				if !acceptReady(w.l) {
					t.Errorf("seed %d: after Close acceptReady says Accept would wait", seed)
				}
				for _, u := range w.us {
					if !udpRecvReady(u) || !udpSendReady(u, nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerAddr, 9))) {
						t.Errorf("seed %d: after Close a UDP check says an operation would wait", seed)
					}
				}
				for _, c := range w.conns {
					if _, writable := writeRoom(c); !readReady(c) || writable {
						t.Errorf("seed %d: after Close a connection check says an operation would wait", seed)
					}
				}
				for _, c := range w.pings {
					if !pingRecvReady(c) {
						t.Errorf("seed %d: after Close an echo check says Read would wait", seed)
					}
				}
				// 閉じた後の確かめはすべて真で、操作は待たずに誤りを返す
				w.probeAll()
				mu.Lock()
				for k, v := range p.counts {
					c := total[k]
					c[0] += v[0]
					c[1] += v[1]
					total[k] = c
				}
				mu.Unlock()
			})
		}
	})
	for _, name := range []string{"acceptReady", "readReady", "writeRoom", "udpRecvReady", "udpSendReady", "pingRecvReady"} {
		c := total[name]
		t.Logf("%s: %d probes said it would wait, %d said it would not", name, c[0], c[1])
		if !t.Failed() && (c[0] == 0 || c[1] == 0) {
			t.Errorf("%s was not seen both ways: %d waits, %d returns; the walk does not cover it", name, c[0], c[1])
		}
	}
}
