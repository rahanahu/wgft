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
	"runtime"
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

// newTCPPairOpts は、a の書き込みの hook と、2 つの Device の間を渡る packet を捨てるかを決める drop を付ける。
func newTCPPairOpts(t *testing.T, q int, hookA func(*tcpConn), drop func([]byte) bool) *tcpPair {
	return newTCPPairMTU(t, q, 1420, hookA, drop)
}

// tcpPairAddr は n 番目の組のアドレス。1 つの試験のプロセスで 255 組を超えても正しい IPv4 になる。
func tcpPairAddr(n int32, host byte) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(100 + n/256), byte(n % 256), host})
}

func newTCPPairMTU(t *testing.T, q, mtu int, hookA func(*tcpConn), drop func([]byte) bool) *tcpPair {
	t.Helper()
	n := tcpPairN.Add(1)
	if n >= 150*256 {
		t.Fatal("too many pairs in one test process")
	}
	a, err := Create(tcpPairAddr(n, 1), mtu)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Create(tcpPairAddr(n, 2), mtu)
	if err != nil {
		t.Fatal(err)
	}
	a.pool, b.pool = newBoostPool(q), newBoostPool(q)
	a.pool.writeHook = hookA
	var wg sync.WaitGroup
	fwd := func(from, to *Device, drop func([]byte) bool) {
		defer wg.Done()
		buf := make([]byte, mtu+100)
		sizes := []int{0}
		for {
			n, err := from.Read([][]byte{buf}, sizes, 0)
			if err != nil || n != 1 {
				return
			}
			if drop != nil && drop(buf[:sizes[0]]) {
				continue
			}
			to.Write([][]byte{buf[:sizes[0]]}, 0)
		}
	}
	wg.Add(2)
	go fwd(a, b, drop)
	go fwd(b, a, drop)
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

// bulkBudget は bulk の 1 回の転送に許す時間の上限で、転送の始めから測る。読み書きが進んでも延ばさない。
// 上限を過ぎた転送は止まったとみなして試験を落とす。この上限は、止まった転送が CI の runner を
// 占有し続けないための打ち切りである。止まった転送がこの時間の内に回復することは保証しない。
// Device の送信のキューが溢れて窓の大半を失った転送は、SACK による回復が最小の再送の待ちごとに
// 少しずつしか進まず、boost の窓では見積もりでこの上限に近い時間か、それを超える時間がかかる。
// 見積もりは未確認である。
const bulkBudget = 2 * time.Minute

func bulkErr(w, r net.Conn, n int) error { return bulkWithin(w, r, n, bulkBudget) }

// bulkError は bulk の転送の失敗と、それまでに動いた byte 数。
type bulkError struct {
	n, written      int
	read            int64
	elapsed, budget time.Duration
	werr, rerr      error
	// readerReleased は、書き込みが失敗した後に読み手の期限を今にして待ちを解いたか
	readerReleased bool
}

func (e *bulkError) Error() string {
	var b strings.Builder
	if e.elapsed >= e.budget {
		fmt.Fprintf(&b, "bulk transfer did not finish within its budget of %v", e.budget)
	} else {
		b.WriteString("bulk transfer failed")
	}
	fmt.Fprintf(&b, ": %d of %d bytes written, %d read, after %v", e.written, e.n, e.read, e.elapsed.Round(time.Millisecond))
	if e.werr != nil {
		fmt.Fprintf(&b, "; write: %v", e.werr)
	}
	if e.rerr != nil {
		if e.readerReleased && e.elapsed < e.budget {
			fmt.Fprintf(&b, "; read released after the write failed: %v", e.rerr)
		} else {
			fmt.Fprintf(&b, "; read: %v", e.rerr)
		}
	}
	return b.String()
}

func (e *bulkError) Unwrap() []error {
	var errs []error
	for _, err := range []error{e.werr, e.rerr} {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// bulkRead は r から n byte を読み捨て、読んだ数を read に足し、終わりを done に送る。1 回の読み込みは
// 8 KiB で、残りが少なければ残りの分である。以前の io.CopyN(io.Discard, r, n) は io.Discard の
// ReadFrom の 8 KiB の buffer で読んでおり、受け手の読み方を変えないためにこれと同じ大きさにする。
// countingDiscard は ReadFrom を持たないので、buffer を渡さないと io.Copy は 32 KiB で読む。
// 足りないまま EOF で終わったときは、io.CopyN と同じく io.EOF を返す。
func bulkRead(r net.Conn, n int, read *atomic.Int64, done chan<- error) {
	got, err := io.CopyBuffer(countingDiscard{read}, io.LimitReader(r, int64(n)), make([]byte, 8<<10))
	if got < int64(n) && err == nil {
		err = io.EOF
	}
	done <- err
}

type countingDiscard struct{ n *atomic.Int64 }

func (c countingDiscard) Write(b []byte) (int, error) {
	c.n.Add(int64(len(b)))
	return len(b), nil
}

// bulkWithin は w から r へ n byte を送り、r が読み切るまで待つ。期限は転送の始めから budget 後の
// 固定の時刻で、読み書きを始める前に両端の接続へ置く。期限は既に待っている読み書きも解く。
// 書き込みが途中で失敗したら、読み手の期限を今にして待ちを解く。読み手の goroutine が終わってから
// 戻り、戻る前に両端の期限を外す。
func bulkWithin(w, r net.Conn, n int, budget time.Duration) error {
	start := time.Now()
	dl := start.Add(budget)
	w.SetDeadline(dl)
	r.SetDeadline(dl)
	defer func() {
		w.SetDeadline(time.Time{})
		r.SetDeadline(time.Time{})
	}()
	var read atomic.Int64
	done := make(chan error, 1)
	go bulkRead(r, n, &read, done)
	buf := make([]byte, 32<<10)
	e := &bulkError{n: n, budget: budget}
	for e.written < n {
		m, err := w.Write(buf)
		e.written += m
		if err != nil {
			e.werr = err
			break
		}
	}
	if e.werr != nil {
		r.SetReadDeadline(time.Now())
		e.readerReleased = true
	}
	e.rerr = <-done
	e.read, e.elapsed = read.Load(), time.Since(start)
	if e.werr == nil && e.rerr == nil {
		return nil
	}
	return e
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
	p := newTCPPairOpts(t, 1, nil, func(pkt []byte) bool {
		ip := header.IPv4(pkt)
		if !ip.IsValid(len(pkt)) || ip.TransportProtocol() != header.TCPProtocolNumber {
			return false
		}
		th := header.TCP(ip.Payload())
		if f := th.Flags(); f.Contains(header.TCPFlagSyn) {
			isAck := f.Contains(header.TCPFlagAck)
			mu.Lock()
			scales[isAck] = header.ParseSynOptions(th.Options(), isAck).WS
			mu.Unlock()
		}
		return false
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

// countBoosted は、pool の枠の排他を持ったまま、conns の side の端のうち boost の印が立つ数を返す。
// boost の印は枠の排他の外で変わるので、走査の間に印が変わると、ある時点の値より多く数えることはある
// (demote が下ろした古い保有者の印を先に読み、枠を得た新しい保有者の印を後で読む場合)。それでも
// Q を超えない。枠の排他を持つ間は枠の保有者の集まりが固定で、接続を閉じない限り印は保有者にしか
// 立たないので、数は保有者の数以下で、Q 以下である。
func countBoosted(pool *boostPool, conns [][2]net.Conn, side int) int {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	n := 0
	for _, cc := range conns {
		if boosted(cc[side]) {
			n++
		}
	}
	return n
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
			for _, cc := range conns {
				for _, x := range cc {
					// 書き込みは、確かめの間だけ送信のバッファを floor より小さい値にする。書き込みの
					// 外にいる接続の送信のバッファだけを見る
					snd, rcv := int64(tcpSendFloor), int64(0)
					if xc := connOf(x); xc.wmu.TryLock() {
						snd, rcv = bufSizes(x)
						xc.wmu.Unlock()
					} else {
						_, rcv = bufSizes(x)
					}
					if snd < tcpSendFloor || rcv < tcpRecvFloor {
						belowFloor++
					}
				}
			}
			// 枠は戻してから渡す(demote が boost の印を下ろした後に、枠の排他の中で新しい保有者へ
			// 渡り、新しい保有者が印を立てる)ので、印を接続ごとに時間をかけて読むと、ある接続の
			// 古い印と別の接続の新しい印を両方数えて Q + 1 になりうる。枠の排他を持ったまま数える。
			nA := countBoosted(p.a.pool, conns, 0)
			nB := countBoosted(p.b.pool, conns, 1)
			maxBoosted = max(maxBoosted, nA, nB)
		}
	}()
	// 転送は bulkBudget で打ち切られ、止まった転送は試験を落とす。wg.Wait は打ち切りの後に戻る
	var wg sync.WaitGroup
	for i, cc := range conns {
		wg.Add(1)
		go func(i int, cc [2]net.Conn) {
			defer wg.Done()
			if err := bulkErr(cc[0], cc[1], 4<<20); err != nil {
				t.Errorf("flow %d of %d, %v to %v: %v", i, flows, cc[0].LocalAddr(), cc[1].LocalAddr(), err)
			}
		}(i, cc)
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

// bulk の転送は、止まっても期限で試験を落として戻る。2 つの Device の間を渡る packet をすべて捨てて
// 転送を止める。書き手と読み手がともに待つとき、書き終えた後に読み手だけが待つとき、書き込みが
// 途中で失敗したときのどれでも、期限か失敗の後に戻り、読み手の goroutine を残さない。
func TestBulkStopsWhenStalled(t *testing.T) {
	const budget = time.Second
	stalled := func(t *testing.T) (net.Conn, net.Conn) {
		var hole atomic.Bool
		p := newTCPPairOpts(t, 1, nil, func([]byte) bool { return hole.Load() })
		c, s := p.dial(t)
		t.Cleanup(func() {
			c.Close()
			s.Close()
		})
		hole.Store(true)
		return c, s
	}
	run := func(t *testing.T, w, r net.Conn, n int, budget, guard time.Duration) *bulkError {
		t.Helper()
		ch := make(chan error, 1)
		go func() { ch <- bulkWithin(w, r, n, budget) }()
		var err error
		select {
		case err = <-ch:
		case <-time.After(guard):
			t.Fatalf("bulk did not return within %v", guard)
		}
		var be *bulkError
		if !errors.As(err, &be) {
			t.Fatalf("bulk on a stalled pair: %v, want a bulkError", err)
		}
		t.Log(be)
		// 読み手は結果を送った直後にまだ終わりきっていないことがあるので、少し待つ
		waitFor(t, 2*time.Second, "the reader goroutine ends after bulk returned", func() bool {
			buf := make([]byte, 1<<20)
			return !strings.Contains(string(buf[:runtime.Stack(buf, true)]), "nettun.bulkRead(")
		})
		return be
	}
	t.Run("writer and reader", func(t *testing.T) {
		c, s := stalled(t)
		e := run(t, c, s, 8<<20, budget, budget+10*time.Second)
		if e.elapsed < budget || e.werr == nil || e.written >= e.n {
			t.Fatalf("elapsed=%v written=%d write error=%v, want a write stopped by the budget", e.elapsed, e.written, e.werr)
		}
	})
	t.Run("reader after the writes fit", func(t *testing.T) {
		c, s := stalled(t)
		e := run(t, c, s, 64<<10, budget, budget+10*time.Second)
		if e.elapsed < budget || e.werr != nil || e.written != e.n || e.rerr == nil || e.read != 0 {
			t.Fatalf("elapsed=%v written=%d read=%d errors %v and %v, want every write accepted and the read stopped by the budget", e.elapsed, e.written, e.read, e.werr, e.rerr)
		}
	})
	// 期限は転送の後に外す。残すと、同じ接続を後で使う試験の読み書きが期限で失敗する
	t.Run("deadlines cleared after a transfer", func(t *testing.T) {
		p := newTCPPair(t, 1)
		c, s := p.dial(t)
		defer c.Close()
		defer s.Close()
		// この転送は止めないので、遅い runner でも期限の内に終わる長さにする。確かめるのは期限が
		// 過ぎた後の読み書きである
		const transferBudget = 5 * time.Second
		start := time.Now()
		if err := bulkWithin(c, s, 1<<20, transferBudget); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Until(start.Add(transferBudget + 200*time.Millisecond)))
		for _, x := range [][2]net.Conn{{c, s}, {s, c}} {
			if _, err := x[0].Write([]byte("ping")); err != nil {
				t.Fatalf("write after the budget passed: %v", err)
			}
			if _, err := io.ReadFull(x[1], make([]byte, 4)); err != nil {
				t.Fatalf("read after the budget passed: %v", err)
			}
		}
	})
	t.Run("write fails midway", func(t *testing.T) {
		c, s := stalled(t)
		// 書き手を閉じて書き込みを失敗させる。閉じるのが書き始めより先でも書き込みは失敗する。
		// 期限は試験の待ちより長いので、読み手の待ちは期限では解けない
		go func() {
			time.Sleep(300 * time.Millisecond)
			c.Close()
		}()
		e := run(t, c, s, 8<<20, time.Minute, 10*time.Second)
		if e.werr == nil || e.elapsed >= e.budget || !e.readerReleased || e.rerr == nil {
			t.Fatalf("write error=%v elapsed=%v reader released=%v read error=%v, want the failed write to release the reader", e.werr, e.elapsed, e.readerReleased, e.rerr)
		}
	})
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

// 送信の向きを閉じた保有者は floor に戻さない。gVisor は送信を閉じた endpoint を、キューに
// データが残っていても書き込める状態と答える。戻すと、boost の大きさのデータを持つ接続が
// floor の扱いになる。netpipe は EOF を CloseWrite で伝えるので、相手が読むのを止めた転送で起こる。
func TestTCPNoDemoteAfterCloseWrite(t *testing.T) {
	p := newTCPPair(t, 1)
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	bulk(t, c, s, 2<<20)
	if !boosted(c) {
		t.Fatal("setup: not boosted")
	}
	written := fillNonReader(c)
	if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(tcpIdleReclaim + 300*time.Millisecond)
	c2, s2 := p.dial(t)
	defer c2.Close()
	defer s2.Close()
	bulk(t, c2, s2, 4<<20)
	held := written - recvQueue(s)
	snd, _ := bufSizes(c)
	t.Logf("written=%d peer queue=%d held=%d holder boosted=%v snd=%d state=%v new flow boosted=%v", written, recvQueue(s), held, boosted(c), snd, state(c), boosted(c2))
	if held <= tcpSendFloor {
		t.Fatalf("setup: holder holds only %d unacknowledged bytes", held)
	}
	if !boosted(c) || snd != tcpBoostSize || boosted(c2) {
		t.Fatalf("half-closed holder with %d unacknowledged bytes demoted: boosted=%v snd=%d, new flow boosted=%v", held, boosted(c), snd, boosted(c2))
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

// OnBoost は登録の時点の状態で 1 回呼び、枠を得たときに真を、需要の無い保有者として floor に戻った
// ときに偽を知らせる。中継はこれで組にしたカーネルのソケットの受信のバッファを合わせる(設計文書 7 節)。
func TestTCPOnBoostReportsSlot(t *testing.T) {
	p := newTCPPair(t, 1)
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	var mu sync.Mutex
	var got []bool
	c.(*TCPConn).OnBoost(func(b bool) bool {
		mu.Lock()
		got = append(got, b)
		mu.Unlock()
		return true
	})
	events := func() []bool {
		mu.Lock()
		defer mu.Unlock()
		return append([]bool(nil), got...)
	}
	if e := events(); len(e) != 1 || e[0] {
		t.Fatalf("events after registering = %v, want [false]", e)
	}
	bulk(t, c, s, 4<<20)
	if e := events(); !boosted(c) || len(e) != 2 || !e[1] {
		t.Fatalf("events after a bulk transfer = %v (boosted=%v), want [false true]", e, boosted(c))
	}
	// 保有者が 1 秒需要を持たない間に、別の接続が枠を求めて回収する
	time.Sleep(tcpIdleReclaim + 200*time.Millisecond)
	c2, s2 := p.dial(t)
	defer c2.Close()
	defer s2.Close()
	bulk(t, c2, s2, 4<<20)
	if !boosted(c2) || boosted(c) {
		t.Fatalf("after reclaim: new flow boosted=%v, old holder boosted=%v", boosted(c2), boosted(c))
	}
	if e := events(); len(e) != 3 || e[2] {
		t.Fatalf("events after the slot was reclaimed = %v, want [false true false]", e)
	}
}

// 枠が満ちていて得られない接続は、需要があっても真を知らせない。大きいバッファを持つ中継のカーネルの
// ソケットは、これで枠の数までに収まる(設計文書 7 節)。
func TestTCPOnBoostSilentWithoutSlot(t *testing.T) {
	p := newTCPPair(t, 1)
	hc, hs := p.dial(t)
	defer hc.Close()
	defer hs.Close()
	// 保有者は転送を続けるので、枠は回収されない
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
	defer func() {
		close(stop)
		<-done
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !boosted(hc) || !boosted(hs) {
		if time.Now().After(deadline) {
			t.Fatalf("holder never took the slots: boosted c=%v s=%v", boosted(hc), boosted(hs))
		}
		time.Sleep(10 * time.Millisecond)
	}

	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	var mu sync.Mutex
	got := map[string][]bool{}
	for name, x := range map[string]net.Conn{"dialer": c, "acceptor": s} {
		x.(*TCPConn).OnBoost(func(b bool) bool {
			mu.Lock()
			got[name] = append(got[name], b)
			mu.Unlock()
			return true
		})
	}
	bulk(t, c, s, 4<<20)
	bulk(t, s, c, 4<<20)
	if !boosted(hc) || !boosted(hs) || boosted(c) || boosted(s) {
		t.Fatalf("holder boosted c=%v s=%v, new flow boosted c=%v s=%v; want only the holder", boosted(hc), boosted(hs), boosted(c), boosted(s))
	}
	mu.Lock()
	defer mu.Unlock()
	for _, name := range []string{"dialer", "acceptor"} {
		if e := got[name]; len(e) != 1 || e[0] {
			t.Fatalf("%s events without a slot = %v, want [false]", name, e)
		}
	}
}

// 組にしたカーネルのソケットが floor への戻りを断る保有者からは回収しない。保有者は boost のまま枠を
// 持つ。断りが止めば、次に別の接続が枠を求めたときに改めて試され、回収される(設計文書 7 節)。
func TestTCPReclaimWaitsForKernelSide(t *testing.T) {
	p := newTCPPair(t, 1)
	hc, hs := p.dial(t)
	defer hc.Close()
	defer hs.Close()
	var refuse atomic.Bool
	var refused atomic.Int32
	refuse.Store(true)
	hc.(*TCPConn).OnBoost(func(b bool) bool {
		if !b && boosted(hc) && refuse.Load() {
			refused.Add(1)
			return false
		}
		return true
	})
	bulk(t, hc, hs, 4<<20)
	if !boosted(hc) {
		t.Fatal("holder did not take the slot")
	}
	time.Sleep(tcpIdleReclaim + 200*time.Millisecond)
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	bulk(t, c, s, 4<<20)
	if refused.Load() == 0 {
		t.Fatal("the new flow never tried to reclaim the idle holder")
	}
	if !boosted(hc) || boosted(c) {
		t.Fatalf("after a refused return: holder boosted=%v, new flow boosted=%v", boosted(hc), boosted(c))
	}
	if snd, rcv := bufSizes(hc); snd != tcpBoostSize || rcv != tcpBoostSize {
		t.Fatalf("holder after a refused return: snd=%d rcv=%d, want the boost %d", snd, rcv, tcpBoostSize)
	}
	refuse.Store(false)
	// 需要の区間を新しくし、次の転送で枠を求め直させる
	time.Sleep(tcpDemandWindow + 50*time.Millisecond)
	bulk(t, c, s, 4<<20)
	waitFor(t, 2*time.Second, "the new flow takes the slot once the kernel side lets go", func() bool {
		return boosted(c) && !boosted(hc)
	})
}

// 組にしたカーネルのソケットに floor への戻りを聞くのは、gVisor の側の確かめがすべて通った後だけで
// ある。先に聞くと、gVisor の側が断ったときに、枠を持つ接続のカーネルのソケットだけが floor に残る。
func TestTCPKernelSideAskedLast(t *testing.T) {
	p := newTCPPair(t, 1)
	hc, hs := p.dial(t)
	defer hc.Close()
	defer hs.Close()
	var asked atomic.Int32
	for _, x := range []net.Conn{hc, hs} {
		x.(*TCPConn).OnBoost(func(b bool) bool {
			if !b && boosted(x) {
				asked.Add(1)
			}
			return true
		})
	}
	bulk(t, hc, hs, 2<<20)
	fillNonReader(hc)
	time.Sleep(tcpIdleReclaim + 200*time.Millisecond)
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	bulk(t, c, s, 4<<20)
	if !boosted(hc) || !boosted(hs) || boosted(c) || boosted(s) {
		t.Fatalf("setup: holders boosted c=%v s=%v, new flow boosted c=%v s=%v", boosted(hc), boosted(hs), boosted(c), boosted(s))
	}
	if n := asked.Load(); n != 0 {
		t.Fatalf("asked the kernel side %d times although gVisor's side refused", n)
	}
}
