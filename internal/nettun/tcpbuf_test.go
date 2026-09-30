package nettun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// tcpPair は、同じプロセスの中で互いに packet を渡す 2 つの Device。a が dial し(vpsd の側)、b が
// 待ち受ける(エージェントの側)。枠の集まりは Device ごとに別にし、2 つのプロセスを模す。
type tcpPair struct {
	a, b *Device
	ln   *TCPListener
}

var tcpPairN atomic.Int32

func newTCPPair(t *testing.T, q int) *tcpPair {
	return newTCPPairOpts(t, q, nil, nil)
}

// newTCPPairOpts は、a の書き込みの hook と、2 つの Device の間を渡る packet を見る inspect を付ける。
func newTCPPairOpts(t *testing.T, q int, hookA func(*tcpConn), inspect func([]byte)) *tcpPair {
	t.Helper()
	n := tcpPairN.Add(1)
	a, err := Create(netip.MustParseAddr(fmt.Sprintf("10.97.%d.1", n)), 1420)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Create(netip.MustParseAddr(fmt.Sprintf("10.97.%d.2", n)), 1420)
	if err != nil {
		t.Fatal(err)
	}
	a.pool, b.pool = newBoostPool(q), newBoostPool(q)
	a.pool.writeHook = hookA
	var wg sync.WaitGroup
	fwd := func(from, to *Device) {
		defer wg.Done()
		buf := make([]byte, 1500)
		sizes := []int{0}
		for {
			n, err := from.Read([][]byte{buf}, sizes, 0)
			if err != nil || n != 1 {
				return
			}
			if inspect != nil {
				inspect(buf[:sizes[0]])
			}
			to.Write([][]byte{buf[:sizes[0]]}, 0)
		}
	}
	wg.Add(2)
	go fwd(a, b)
	go fwd(b, a)
	ln, err := b.ListenTCP(netip.AddrPortFrom(b.local, 9000))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ln.Close()
		a.Close()
		b.Close()
		wg.Wait()
	})
	return &tcpPair{a: a, b: b, ln: ln}
}

// dial は a から b へつなぎ、dial した接続と accept した接続を返す。
func (p *tcpPair) dial(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := p.ln.Accept()
		if err != nil {
			c = nil
		}
		ch <- c
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := p.a.DialTCP(ctx, netip.AddrPortFrom(p.b.local, 9000))
	if err != nil {
		t.Fatal(err)
	}
	s := <-ch
	if s == nil {
		t.Fatal("accept failed")
	}
	return c, s
}

func connOf(c net.Conn) *tcpConn {
	switch v := c.(type) {
	case *tcpConn:
		return v
	case *TCPConn:
		return v.tcpConn
	}
	return nil
}

func bufSizes(c net.Conn) (snd, rcv int64) {
	so := connOf(c).ep.SocketOptions()
	return so.GetSendBufferSize(), so.GetReceiveBufferSize()
}

func boosted(c net.Conn) bool { return connOf(c).boosted.Load() }

func (p *boostPool) inUse() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, s := range p.slots {
		if s != nil {
			n++
		}
	}
	return n
}

// scanReturnable は取得の要求と同じ走査で返せる枠を空け、空けた数を返す。
func (p *boostPool) scanReturnable() int {
	before := p.inUse()
	p.mu.Lock()
	snap := append([]*tcpConn(nil), p.slots...)
	p.mu.Unlock()
	p.takeReturnable(snap, nil)
	return before - p.inUse()
}

func bulk(t *testing.T, w, r net.Conn, n int) {
	t.Helper()
	if err := bulkErr(w, r, n); err != nil {
		t.Fatal(err)
	}
}

func bulkErr(w, r net.Conn, n int) error {
	done := make(chan error, 1)
	go func() {
		_, err := io.CopyN(io.Discard, r, int64(n))
		done <- err
	}()
	buf := make([]byte, 32<<10)
	for sent := 0; sent < n; sent += len(buf) {
		if _, err := w.Write(buf); err != nil {
			return fmt.Errorf("write: %v", err)
		}
	}
	if err := <-done; err != nil {
		return fmt.Errorf("read: %v", err)
	}
	return nil
}

func recvQueue(c net.Conn) int {
	v, _ := connOf(c).ep.GetSockOptInt(tcpip.ReceiveQueueSizeOption)
	return v
}

func state(c net.Conn) tcp.EndpointState { return tcp.EndpointState(connOf(c).ep.State()) }

// fillNonReader は、読まない相手へ書けなくなるまで書き、書いた byte 数を返す。
func fillNonReader(c net.Conn) int {
	buf := make([]byte, 32<<10)
	sent := 0
	for {
		c.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := c.Write(buf)
		sent += n
		if err != nil {
			c.SetWriteDeadline(time.Time{})
			return sent
		}
	}
}

// floodOneByte は、読まない相手へ 1 byte の書き込みを、1 回が 2 秒止まるまで繰り返す。
func floodOneByte(c net.Conn) (accepted int) {
	b := []byte{'x'}
	for accepted < 1<<16 { // 上限の 4096 回より十分に多く、上限が効かないときもメモリを使い切らない回数
		c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(b); err != nil {
			break
		}
		accepted++
	}
	c.SetWriteDeadline(time.Time{})
	return accepted
}

// 握手の後は両端とも floor で、boost を持たない。小さいやり取りでは boost を求めない。dial した接続も
// accept した接続も Abort を持つ(中継は netstack の側を RST で切る)。
func TestTCPFloorAfterHandshake(t *testing.T) {
	p := newTCPPair(t, tcpBoostSlots)
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	for _, x := range []net.Conn{c, s} {
		if snd, rcv := bufSizes(x); snd != tcpSendFloor || rcv != tcpRecvFloor || boosted(x) {
			t.Fatalf("after handshake: snd=%d rcv=%d boosted=%v, want the floor", snd, rcv, boosted(x))
		}
	}
	if _, ok := c.(interface{ Abort() }); !ok {
		t.Fatal("dialed conn does not offer Abort")
	}
	if _, ok := s.(interface{ Abort() }); !ok {
		t.Fatal("accepted conn does not offer Abort")
	}
	for i := 0; i < 50; i++ {
		c.Write([]byte("ping"))
		io.ReadFull(s, make([]byte, 4))
	}
	if boosted(c) || boosted(s) || p.a.pool.inUse() != 0 || p.b.pool.inUse() != 0 {
		t.Fatal("small traffic boosted")
	}
}

// 握手の窓の scale は受信の上限(boost)から決まり、floor を固定した後に boost を得ても広い窓を
// 広告できる。SYN と SYN-ACK の window scale を見る。4 MiB を 16 bit の窓で表すには 7 が要り、
// floor の 256 KiB から決めると 3 になる。
func TestTCPHandshakeScaleFromBoost(t *testing.T) {
	var mu sync.Mutex
	scales := map[bool]int{} // SYN-ACK か
	p := newTCPPairOpts(t, 1, nil, func(pkt []byte) {
		ip := header.IPv4(pkt)
		if !ip.IsValid(len(pkt)) || ip.TransportProtocol() != header.TCPProtocolNumber {
			return
		}
		th := header.TCP(ip.Payload())
		if f := th.Flags(); f.Contains(header.TCPFlagSyn) {
			isAck := f.Contains(header.TCPFlagAck)
			mu.Lock()
			scales[isAck] = header.ParseSynOptions(th.Options(), isAck).WS
			mu.Unlock()
		}
	})
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(scales) != 2 || scales[false] < 7 || scales[true] < 7 {
		t.Fatalf("window scale SYN=%d SYN-ACK=%d seen=%d, want >= 7 on both", scales[false], scales[true], len(scales))
	}
}

// bulk の転送で両端が boost を得る。枠は各プロセスに 1 つ。
func TestTCPBoostOnDemand(t *testing.T) {
	p := newTCPPair(t, tcpBoostSlots)
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	bulk(t, c, s, 4<<20)
	cs, _ := bufSizes(c)
	_, sr := bufSizes(s)
	if !boosted(c) || !boosted(s) || cs != tcpBoostSize || sr != tcpBoostSize {
		t.Fatalf("bulk: sender boosted=%v snd=%d, receiver boosted=%v rcv=%d", boosted(c), cs, boosted(s), sr)
	}
	if p.a.pool.inUse() != 1 || p.b.pool.inUse() != 1 {
		t.Fatalf("slots A=%d B=%d, want 1 each", p.a.pool.inUse(), p.b.pool.inUse())
	}
	// boost の受信のバッファが効く。読むのを止めた受信の側は、floor の受信のバッファでは入らない
	// 量を受け入れる(gVisor はバッファの半分を窓として広告する)
	fillNonReader(c)
	if q := recvQueue(s); q < tcpBoostSize/2-tcpRecvFloor || q > tcpBoostSize {
		t.Fatalf("boosted receiver that stopped reading holds %d, want about %d", q, tcpBoostSize/2)
	}
}

// 枠を得られない接続は、bulk の転送の後も floor のまま。gVisor の自動調整で広がらない。
func TestTCPNoSlotStaysAtFloor(t *testing.T) {
	p := newTCPPair(t, 0)
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	bulk(t, c, s, 8<<20)
	bulk(t, s, c, 8<<20)
	for _, x := range []net.Conn{c, s} {
		if snd, rcv := bufSizes(x); snd != tcpSendFloor || rcv != tcpRecvFloor || boosted(x) {
			t.Fatalf("without a slot: snd=%d rcv=%d boosted=%v, want the floor", snd, rcv, boosted(x))
		}
	}
}

// 枠を超える数の同時の転送でも、枠は Q を超えず、どの接続も floor を下回らない。
func TestTCPBoostCap(t *testing.T) {
	p := newTCPPair(t, tcpBoostSlots)
	const flows = tcpBoostSlots + 8
	var conns [][2]net.Conn
	for i := 0; i < flows; i++ {
		c, s := p.dial(t)
		conns = append(conns, [2]net.Conn{c, s})
	}
	defer func() {
		for _, cc := range conns {
			cc[0].Close()
			cc[1].Close()
		}
	}()
	stop := make(chan struct{})
	var maxA, maxB, maxBoosted, belowFloor int
	var sw sync.WaitGroup
	sw.Add(1)
	go func() {
		defer sw.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			maxA, maxB = max(maxA, p.a.pool.inUse()), max(maxB, p.b.pool.inUse())
			nA, nB := 0, 0
			for _, cc := range conns {
				for i, x := range cc {
					snd, rcv := bufSizes(x)
					if snd < tcpSendFloor || rcv < tcpRecvFloor {
						belowFloor++
					}
					if boosted(x) {
						if i == 0 {
							nA++
						} else {
							nB++
						}
					}
				}
			}
			maxBoosted = max(maxBoosted, nA, nB)
		}
	}()
	var wg sync.WaitGroup
	for _, cc := range conns {
		wg.Add(1)
		go func(cc [2]net.Conn) {
			defer wg.Done()
			if err := bulkErr(cc[0], cc[1], 4<<20); err != nil {
				t.Error(err)
			}
		}(cc)
	}
	wg.Wait()
	close(stop)
	sw.Wait()
	t.Logf("%d flows: max slots A=%d B=%d, max boosted per side=%d, below-floor samples=%d", flows, maxA, maxB, maxBoosted, belowFloor)
	if maxA > tcpBoostSlots || maxB > tcpBoostSlots || maxBoosted > tcpBoostSlots || belowFloor != 0 {
		t.Fatal("slot cap or floor violated")
	}
	if maxBoosted == 0 {
		t.Fatal("no flow boosted")
	}
}

// Q 本が枠を持ったまま a の側から閉じると、a の endpoint は TIME_WAIT(既定の 60 秒)に、b の
// endpoint は CLOSED に入る。新しい転送は両端ですぐに boost を得て、残りの枠もすべて返せる。
func TestTCPTimeWaitReturn(t *testing.T) {
	p := newTCPPair(t, tcpBoostSlots)
	var conns [][2]net.Conn
	for i := 0; i < tcpBoostSlots; i++ {
		c, s := p.dial(t)
		bulk(t, c, s, 1<<20)
		conns = append(conns, [2]net.Conn{c, s})
	}
	if p.a.pool.inUse() != tcpBoostSlots || p.b.pool.inUse() != tcpBoostSlots {
		t.Fatalf("setup: slots A=%d B=%d, want Q each", p.a.pool.inUse(), p.b.pool.inUse())
	}
	for _, cc := range conns {
		cc[0].Close()
		cc[1].Close()
	}
	time.Sleep(200 * time.Millisecond)
	for _, cc := range conns {
		if st := state(cc[0]); st != tcp.StateTimeWait {
			t.Fatalf("setup: closer in %v, want TIME-WAIT", st)
		}
	}
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	bulk(t, c, s, 2<<20)
	if !boosted(c) || !boosted(s) {
		t.Fatalf("new flow boosted a=%v b=%v, want both", boosted(c), boosted(s))
	}
	p.a.pool.scanReturnable()
	p.b.pool.scanReturnable()
	if p.a.pool.inUse() != 1 || p.b.pool.inUse() != 1 {
		t.Fatalf("slots A=%d B=%d after the scan, want only the new flow's", p.a.pool.inUse(), p.b.pool.inUse())
	}
}

// 読まない相手へ書いたまま閉じた接続は、FIN が未確認のデータの後ろで待つ。データが確認されて
// TIME_WAIT に入るまで、枠を返さない。
func TestTCPNoReturnWithUnacked(t *testing.T) {
	p := newTCPPair(t, 1)
	c, s := p.dial(t)
	defer s.Close()
	bulk(t, c, s, 2<<20)
	if !boosted(c) {
		t.Fatal("setup: sender not boosted")
	}
	fillNonReader(c)
	c.Close()
	time.Sleep(200 * time.Millisecond)
	if st := state(c); st == tcp.StateTimeWait || st == tcp.StateClose {
		t.Fatalf("setup: closer in %v, want an unacknowledged state", st)
	}
	if connOf(c).returnable() || p.a.pool.scanReturnable() != 0 {
		t.Fatal("slot returned while sent data is unacknowledged")
	}
	io.Copy(io.Discard, s)
	s.Close()
	time.Sleep(200 * time.Millisecond)
	if st := state(c); st != tcp.StateTimeWait || !connOf(c).returnable() {
		t.Fatalf("after the drain: state=%v returnable=%v, want TIME-WAIT and true", st, connOf(c).returnable())
	}
}

// a が閉じ、b が開いたままなら a は FIN_WAIT_2 にいる。FIN_WAIT_2 では枠を返さない。
func TestTCPNoReturnFinWait2(t *testing.T) {
	p := newTCPPair(t, 1)
	c, s := p.dial(t)
	defer s.Close()
	bulk(t, c, s, 2<<20)
	c.Close()
	io.Copy(io.Discard, s)
	time.Sleep(200 * time.Millisecond)
	if st := state(c); st != tcp.StateFinWait2 {
		t.Fatalf("setup: closer in %v, want FIN-WAIT2", st)
	}
	if connOf(c).returnable() {
		t.Fatal("slot returnable in FIN_WAIT_2")
	}
}

// 転送を終えた Q 本が開いたまま枠を持つ。直後の新しい転送は floor のまま(保有者に需要が残る)。
// tcpIdleReclaim の後は、各側で 1 本を floor に戻して枠を受け取る。戻された保有者は、需要が戻ると
// 枠を求め直す。
func TestTCPIdleReclaim(t *testing.T) {
	p := newTCPPair(t, tcpBoostSlots)
	var conns [][2]net.Conn
	for i := 0; i < tcpBoostSlots; i++ {
		c, s := p.dial(t)
		bulk(t, c, s, 1<<20)
		conns = append(conns, [2]net.Conn{c, s})
	}
	defer func() {
		for _, cc := range conns {
			cc[0].Close()
			cc[1].Close()
		}
	}()
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	bulk(t, c, s, 2<<20)
	if boosted(c) || boosted(s) {
		t.Fatal("slot reclaimed from a holder with recent demand")
	}
	time.Sleep(tcpIdleReclaim + 200*time.Millisecond)
	bulk(t, c, s, 4<<20)
	if !boosted(c) || !boosted(s) {
		t.Fatalf("new flow boosted a=%v b=%v after the holders went idle, want both", boosted(c), boosted(s))
	}
	var hc, hs net.Conn
	demA, demB := 0, 0
	for _, cc := range conns {
		if !boosted(cc[0]) {
			demA++
			hc, hs = cc[0], cc[1]
		}
		if !boosted(cc[1]) {
			demB++
		}
		for _, x := range cc {
			if snd, rcv := bufSizes(x); !boosted(x) && (snd != tcpSendFloor || rcv != tcpRecvFloor) {
				t.Fatalf("demoted holder at snd=%d rcv=%d, want the floor", snd, rcv)
			}
			if r := len(connOf(x).hist.ring); !boosted(x) && r > floorHist {
				t.Fatalf("demoted holder keeps a write history of %d, want <= %d", r, floorHist)
			}
		}
	}
	if demA != 1 || demB != 1 {
		t.Fatalf("demoted A=%d B=%d, want exactly one per side", demA, demB)
	}
	if p.a.pool.inUse() > tcpBoostSlots || p.b.pool.inUse() > tcpBoostSlots {
		t.Fatal("slot cap exceeded")
	}
	// 戻された保有者の需要が戻る。他の保有者は idle なので、そこから回収して枠を得る
	bulk(t, hc, hs, 4<<20)
	if snd, _ := bufSizes(hc); !boosted(hc) || snd != tcpBoostSize {
		t.Fatalf("demoted holder after new demand: boosted=%v snd=%d", boosted(hc), snd)
	}
}

// 転送を続けている保有者からは回収しない。
func TestTCPNoReclaimBusy(t *testing.T) {
	p := newTCPPair(t, 1)
	hc, hs := p.dial(t)
	defer hc.Close()
	defer hs.Close()
	stop := make(chan struct{})
	done := make(chan struct{})
	go io.Copy(io.Discard, hs)
	go func() {
		defer close(done)
		buf := make([]byte, 32<<10)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := hc.Write(buf); err != nil {
				return
			}
		}
	}()
	time.Sleep(tcpIdleReclaim + 500*time.Millisecond)
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	bulk(t, c, s, 4<<20)
	close(stop)
	<-done
	if !boosted(hc) || boosted(c) {
		t.Fatalf("busy holder boosted=%v, second flow boosted=%v", boosted(hc), boosted(c))
	}
}

// 需要は無いが、送信のキューが floor を超える保有者(相手が読まない)と、受信のキューにデータが
// 残る保有者は floor に戻さない。
func TestTCPNoReclaimQueued(t *testing.T) {
	p := newTCPPair(t, 1)
	hc, hs := p.dial(t)
	defer hc.Close()
	defer hs.Close()
	bulk(t, hc, hs, 2<<20)
	fillNonReader(hc)
	time.Sleep(tcpIdleReclaim + 200*time.Millisecond)
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	bulk(t, c, s, 4<<20)
	as, ar := bufSizes(hc)
	_, br := bufSizes(hs)
	if !boosted(hc) || as != tcpBoostSize || ar != tcpBoostSize || boosted(c) {
		t.Fatalf("sender with a queue over the floor: boosted=%v snd=%d rcv=%d; new flow boosted=%v", boosted(hc), as, ar, boosted(c))
	}
	if !boosted(hs) || br != tcpBoostSize || boosted(s) || recvQueue(hs) == 0 {
		t.Fatalf("receiver with queued data: boosted=%v rcv=%d queue=%d; new flow boosted=%v", boosted(hs), br, recvQueue(hs), boosted(s))
	}
}

// 書き込みの途中にいる保有者は、需要が無くても floor に戻さない。途中で戻すと、boost を前提に
// 進む書き込みが、boost を返した接続に boost の大きさの送信のバッファを残す。保有者の書き込みを
// hook で止めた間に、別の接続が同じ枠の集まりに枠を求める。
func TestTCPDemoteSkipsWriteInProgress(t *testing.T) {
	var holder atomic.Pointer[tcpConn]
	entered := make(chan struct{})
	release := make(chan struct{})
	p := newTCPPairOpts(t, 1, func(c *tcpConn) {
		if holder.CompareAndSwap(c, nil) {
			close(entered)
			<-release
		}
	}, nil)
	hc, hs := p.dial(t)
	defer hc.Close()
	defer hs.Close()
	bulk(t, hc, hs, 2<<20)
	if !boosted(hc) {
		t.Fatal("setup: holder not boosted")
	}
	time.Sleep(tcpIdleReclaim + 200*time.Millisecond)
	holder.Store(connOf(hc))
	wdone := make(chan error, 1)
	go func() {
		_, err := hc.Write([]byte("x"))
		wdone <- err
	}()
	<-entered
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	bulk(t, c, s, 2<<20)
	holderBoosted, newBoosted := boosted(hc), boosted(c)
	close(release)
	if err := <-wdone; err != nil {
		t.Fatal(err)
	}
	if !holderBoosted || newBoosted {
		t.Fatalf("holder boosted=%v, new flow boosted=%v while the holder's write was in progress", holderBoosted, newBoosted)
	}
	if snd, _ := bufSizes(hc); !boosted(hc) && snd > tcpSendFloor {
		t.Fatalf("holder without boost has snd=%d", snd)
	}
}

// 小さい書き込みの数の上限。読まない相手へ 1 byte の書き込みを繰り返すと、送信の側に残る
// 書き込みは floor では 256 回、boost では 4096 回以内に止まる。boost を回収された保有者は
// floor の 256 回に戻る。
func TestTCPSmallWriteFlood(t *testing.T) {
	check := func(t *testing.T, w, peer net.Conn, want int) {
		t.Helper()
		acc := floodOneByte(w)
		held := acc - recvQueue(peer)
		t.Logf("accepted=%d peer queue=%d held=%d boosted=%v", acc, recvQueue(peer), held, boosted(w))
		if held > want || held <= 0 {
			t.Fatalf("sender holds %d 1-byte writes, want 1..%d", held, want)
		}
	}
	t.Run("floor", func(t *testing.T) {
		p := newTCPPair(t, 1)
		c, s := p.dial(t)
		defer c.Close()
		defer s.Close()
		check(t, s, c, tcpSendFloor/tcpWriteUnit)
	})
	t.Run("boost", func(t *testing.T) {
		p := newTCPPair(t, 1)
		c, s := p.dial(t)
		defer c.Close()
		defer s.Close()
		bulk(t, s, c, 2<<20)
		if !boosted(s) {
			t.Fatal("setup: not boosted")
		}
		check(t, s, c, tcpBoostSize/tcpWriteUnit)
	})
	t.Run("after reclaim", func(t *testing.T) {
		p := newTCPPair(t, 1)
		hc, hs := p.dial(t)
		defer hc.Close()
		defer hs.Close()
		bulk(t, hs, hc, 2<<20)
		time.Sleep(tcpIdleReclaim + 200*time.Millisecond)
		c, s := p.dial(t)
		defer c.Close()
		defer s.Close()
		bulk(t, s, c, 4<<20)
		if boosted(hs) || !boosted(s) {
			t.Fatalf("setup: holder boosted=%v, new flow boosted=%v", boosted(hs), boosted(s))
		}
		check(t, hs, hc, tcpSendFloor/tcpWriteUnit)
	})
}

// 小さいやり取りだけの多数の接続は枠を持たない。
func TestTCPManyIdleNoBoost(t *testing.T) {
	p := newTCPPair(t, tcpBoostSlots)
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < 200; i++ {
		c, s := p.dial(t)
		conns = append(conns, c, s)
		c.Write([]byte("hello"))
		io.ReadFull(s, make([]byte, 5))
	}
	if p.a.pool.inUse() != 0 || p.b.pool.inUse() != 0 {
		t.Fatalf("idle conns hold slots A=%d B=%d", p.a.pool.inUse(), p.b.pool.inUse())
	}
}

// 遅い読み手の接続は、送信と受信のバッファを超えて保持しない。隣の接続は転送を終える。
func TestTCPSlowReader(t *testing.T) {
	p := newTCPPair(t, tcpBoostSlots)
	sc, ss := p.dial(t)
	defer sc.Close()
	defer ss.Close()
	var written atomic.Int64
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := sc.Write(buf)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := io.ReadFull(ss, buf); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	time.Sleep(1500 * time.Millisecond)
	snd, _ := bufSizes(sc)
	_, rcv := bufSizes(ss)
	held := written.Load() - int64(recvQueue(ss))
	t.Logf("slow reader: written=%d sender held~%d (snd=%d) receiver queue=%d (rcv=%d)", written.Load(), held, snd, recvQueue(ss), rcv)
	// 送信の側の保持は、送信のバッファに相手の窓の中の送信中の分を加えた量まで
	if held > snd+rcv || int64(recvQueue(ss)) > rcv {
		t.Fatal("slow reader holds more than its buffers")
	}
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	bulk(t, c, s, 8<<20)
}

// 期限を過ぎた書き込みと、Close で解かれた書き込みは誤りを返す。
func TestTCPWriteDeadlineAndClose(t *testing.T) {
	p := newTCPPair(t, 1)
	c, s := p.dial(t)
	defer s.Close()
	fillNonReader(c)
	c.SetWriteDeadline(time.Now().Add(-time.Second))
	_, err := c.Write([]byte("x"))
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write past the deadline: %v, want a timeout", err)
	}
	c.SetWriteDeadline(time.Time{})
	werr := make(chan error, 1)
	go func() {
		// 相手は読まないので、どこかの書き込みが待ちに入る
		for {
			if _, err := c.Write(make([]byte, 64<<10)); err != nil {
				werr <- err
				return
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	c.Close()
	select {
	case <-werr:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked write not released by Close")
	}
}

// 待ち受けの無いポートへの dial は connect の誤りを返す。
func TestTCPDialRefused(t *testing.T) {
	p := newTCPPair(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := p.a.DialTCP(ctx, netip.AddrPortFrom(p.b.local, 9001))
	var oe *net.OpError
	if !errors.As(err, &oe) || oe.Op != "connect" || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("dial to a closed port: %v, want a refused connect error", err)
	}
}

// boost を持つ間も需要を記録し続ける。記録しないと、転送を続ける保有者が需要の無い保有者に見える。
func TestTCPDemandTrackedWhileBoosted(t *testing.T) {
	p := newTCPPair(t, 1)
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	bulk(t, c, s, 2<<20)
	if !boosted(c) || !boosted(s) {
		t.Fatal("setup: not boosted")
	}
	time.Sleep(tcpDemandWindow + 50*time.Millisecond)
	before := [2]int64{connOf(c).lastDemand.Load(), connOf(s).lastDemand.Load()}
	bulk(t, c, s, 2<<20)
	after := [2]int64{connOf(c).lastDemand.Load(), connOf(s).lastDemand.Load()}
	if after[0] <= before[0] || after[1] <= before[1] {
		t.Fatalf("demand while boosted not recorded: before %v after %v", before, after)
	}
}

// writeHistory の和を、長さの列そのものから数えた値と比べる。ring を広げた直後の覚えていない長さは
// 0 と数えるので、boost の和は本当の和以下で、広げてから boostHist 回を書いた後は一致する。
func TestWriteHistorySums(t *testing.T) {
	var h writeHistory
	var all []int
	trueSum := func(k int) int64 {
		var s int64
		for i := max(0, len(all)-k); i < len(all); i++ {
			s += int64(all[i])
		}
		return s
	}
	rng := rand.New(rand.NewPCG(1, 2))
	knownSince := 0 // これより前の長さは boost の ring に無い
	step := func(n int) {
		for i := 0; i < n; i++ {
			v := 1 + rng.IntN(5000)
			h.add(v)
			all = append(all, v)
			if f, _ := h.sum(tcpSendFloor); f != trueSum(floorHist) {
				t.Fatalf("after %d writes: floor sum %d, want %d", len(all), f, trueSum(floorHist))
			}
			if len(h.ring) == boostHist {
				b, _ := h.sum(tcpBoostSize)
				known := min(boostHist, len(all)-knownSince)
				var want int64
				for j := len(all) - known; j < len(all); j++ {
					want += int64(all[j])
				}
				if b != want || b > trueSum(boostHist) {
					t.Fatalf("after %d writes: boost sum %d, want %d (true %d)", len(all), b, want, trueSum(boostHist))
				}
			}
		}
	}
	step(300)
	h.resize(boostHist)
	knownSince = len(all) - floorHist
	step(5000)
	h.resize(floorHist)
	step(100)
	h.resize(boostHist)
	knownSince = len(all) - floorHist
	step(4200)
	if _, full := h.sum(tcpBoostSize); !full {
		t.Fatal("boost history not full")
	}
}
