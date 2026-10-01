package nettun

import (
	"fmt"
	"io"
	"math"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// 回収で受信のバッファを縮めるときの、gVisor の受信のメモリ(rcvMemUsed)に関する試験。穴を作って
// 順序外の segment を積み、縮め、穴を埋める再送を通して、接続が読み進めるかを見る。

// holeFilter は、有効な間、port から 9000 へ向かうデータの segment のうち、順序番号 holeSeq の byte を
// 含むもの(穴を作る segment とその再送)をすべて捨てる。frozen の間は、その向きのデータの segment を
// すべて捨て、受け手の順序外の積み方を固定する。
type holeFilter struct {
	on      atomic.Bool
	frozen  atomic.Bool
	port    atomic.Uint32
	holeSeq atomic.Uint32
}

func newHoleFilter() *holeFilter { return &holeFilter{} }

func (h *holeFilter) drop(pkt []byte) bool {
	if !h.on.Load() {
		return false
	}
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) || ip.TransportProtocol() != header.TCPProtocolNumber {
		return false
	}
	th := header.TCP(ip.Payload())
	pl := uint32(len(th.Payload()))
	if th.DestinationPort() != 9000 || uint32(th.SourcePort()) != h.port.Load() || pl == 0 {
		return false
	}
	if h.frozen.Load() {
		return true
	}
	// 順序番号の一周をまたいでも正しい差で比べる
	return h.holeSeq.Load()-th.SequenceNumber() < pl
}

// start は、c がまだ送っていない次の byte を穴にする。最初に見えたデータの segment を穴にすると、
// 遅い環境では、先に送ったデータの遅れた再送(tail loss probe など)が穴に選ばれ、新しいデータが
// 順序どおりに届いてしまう。
func (h *holeFilter) start(c net.Conn) {
	h.port.Store(uint32(c.LocalAddr().(*net.TCPAddr).Port))
	h.holeSeq.Store(sndNxtOf(c))
	h.on.Store(true)
}

// newHolePair は穴の試験の組を作る。送り手の stack の再送の回数の上限(gVisor の既定は 15 回)を
// 外す。穴を埋める segment の再送は、穴を開けている間すべて捨てる。遅い環境では、その間に
// 順序外の segment に応える ACK が長く続き、SACK と RACK による再送が上限を超え、送り手が接続を
// 中断する(ErrTimeout)。上限は、この試験が確かめる受け手の受け入れとは関係しない。
func newHolePair(t *testing.T, mtu int, h *holeFilter) *tcpPair {
	t.Helper()
	p := newTCPPairMTU(t, 1, mtu, nil, h.drop)
	opt := tcpip.TCPMaxRetriesOption(math.MaxUint32)
	if err := p.a.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		t.Fatalf("setup: TCP max retries: %v", err)
	}
	return p
}

// sndNxtOf は試験のためだけに、送り手の次に送る順序番号(SndNxt)を読む。gVisor は endpoint の錠を
// 持って書き換えるので、同じ錠を持って読む。
func sndNxtOf(c net.Conn) uint32 {
	return uint32(tcpStateOf(c, "snd", "SndNxt")[0])
}

// tcpStateOf は試験のためだけに、endpoint の snd か rcv の数のフィールドを、endpoint の錠を持って読む。
func tcpStateOf(c net.Conn, side string, names ...string) []uint64 {
	e := connOf(c).ep.(*tcp.Endpoint)
	e.LockUser()
	defer e.UnlockUser()
	v := reflect.ValueOf(e).Elem().FieldByName(side).Elem()
	out := make([]uint64, len(names))
	for i, name := range names {
		f := v.FieldByName(name)
		out[i] = reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Uint()
	}
	return out
}

// syncWindow は、受け手 s が今の受信の窓を送り手 c に知らせ、c がそれを受け取るまで待つ。gVisor の
// 受け手は、読み手が読んで窓が開いても、前に知らせた窓が閾値(1 segment と受信のバッファの半分の
// 小さい方)以上なら知らせ直さない。遅い環境では、bulk の終わりに知らせた窓が 64 KiB の segment
// 1 つか 2 つ分のまま残ることがある。そのまま穴を作ると、送り手は穴の segment だけを送り、残りの
// 窓に収まらない次の segment は送らずに待つ。穴の segment は捨て続けるので受け手から何も返らず、
// 順序外が積まれない。s から c へ 1 byte を送ると、その segment が今の窓を運ぶ。待つのは、送り手の
// 送ったものがすべて確認され、送り手の窓の右端が受け手の知らせた右端に等しいことである。
func syncWindow(t *testing.T, c, s net.Conn) {
	t.Helper()
	s.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := s.Write([]byte{0})
	s.SetWriteDeadline(time.Time{})
	if err != nil {
		t.Fatalf("setup: write the window update: %v", err)
	}
	if _, err := readAllErr(c, 1, 10*time.Second); err != nil {
		t.Fatalf("setup: read the window update: %v", err)
	}
	var snd, rcv []uint64
	waitFor(t, 10*time.Second, "setup: the sender learns the receiver's window", func() bool {
		snd, rcv = tcpStateOf(c, "snd", "SndUna", "SndNxt", "SndWnd"), tcpStateOf(s, "rcv", "RcvNxt", "RcvAcc")
		return snd[0] == snd[1] && snd[1] == rcv[0] && uint32(snd[0]+snd[2]) == uint32(rcv[1]) && recvQueue(s) == 0
	})
	t.Logf("sender window %d", snd[2])
}

// queueDrops は、受け手が受信のメモリの不足で受け入れなかった segment の数を返す。
func queueDrops(c net.Conn) uint64 {
	return connOf(c).ep.Stats().(*tcp.Stats).ReceiveErrors.SegmentQueueDropped.Value()
}

// holeDiag は、穴を埋めた後に読み進めなかったときの手がかりを返す。
func holeDiag(t *testing.T, p *tcpPair, c, s net.Conn) string {
	t.Helper()
	var ti tcpip.TCPInfoOption
	connOf(c).ep.GetSockOpt(&ti)
	st := p.a.stack.Stats().TCP
	pb, n := pendingOf(s)
	return fmt.Sprintf("sender %v error %v rto %v retransmits %d timeouts %d cwnd %d window %d; receiver %v pending %d in %d rcvMemUsed %d queue drops %d",
		state(c), connOf(c).ep.LastError(), ti.RTO, st.Retransmits.Value(), st.Timeouts.Value(), ti.SndCwnd, tcpStateOf(c, "snd", "SndWnd")[0],
		state(s), pb, n, recvMemOf(t, s), queueDrops(s))
}

// recvMemOf は試験のために gVisor の受信のメモリを読む。
func recvMemOf(t *testing.T, c net.Conn) int {
	t.Helper()
	m, ok := newBoostPool(0).receiveMemUsed(connOf(c).ep)
	if !ok {
		t.Fatal("rcvMemUsed is not readable")
	}
	return m
}

// pendingOf は試験のためだけに、順序外のキューの byte(PendingBufUsed)と segment の数を読む。
// gVisor はどちらも endpoint の錠(LockUser)を持って書き換えるので、同じ錠を持って読む。
func pendingOf(c net.Conn) (bytes, n int) {
	e := connOf(c).ep.(*tcp.Endpoint)
	e.LockUser()
	defer e.UnlockUser()
	v := reflect.ValueOf(e).Elem().FieldByName("rcv").Elem()
	pb := v.FieldByName("TCPReceiverState").FieldByName("PendingBufUsed")
	h := v.FieldByName("pendingRcvdSegments")
	return int(reflect.NewAt(pb.Type(), unsafe.Pointer(pb.UnsafeAddr())).Elem().Int()), h.Len()
}

// waitFor は cond が成り立つまで 20 ms ごとに調べ、d の間に成り立たなければ試験を止める。
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(d); !cond(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, d)
		}
	}
}

// settle は、sample の値が 300 ms 以上、かつ 15 回続けて変わらなくなるまで待つ。回数も求めるのは、
// プロセス全体が止められた後の最初の 1 回だけで、変わらないと判断しないためである。
func settle(t *testing.T, what string, sample func() [3]int) [3]int {
	t.Helper()
	last, since, same := sample(), time.Now(), 0
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
		v := sample()
		if v != last {
			last, since, same = v, time.Now(), 0
			continue
		}
		if same++; same >= 15 && time.Since(since) >= 300*time.Millisecond {
			return v
		}
	}
	t.Fatalf("%s did not settle: last %v", what, last)
	return last
}

// readAll は r から n byte を timeout の間に読めたかを返す。
func readAll(r net.Conn, n int, timeout time.Duration) (int, bool) {
	got, err := readAllErr(r, n, timeout)
	return got, err == nil
}

func readAllErr(r net.Conn, n int, timeout time.Duration) (int, error) {
	r.SetReadDeadline(time.Now().Add(timeout))
	defer r.SetReadDeadline(time.Time{})
	got, err := io.CopyN(io.Discard, r, int64(n))
	return int(got), err
}

// holeIdle は、穴を埋めた後に読み進めない状態を止まったとみなすまでの時間の下限。穴を開けていた間に
// 送り手の再送の間隔は延びるので、最初の再送までの待ちを含めて余裕を取る。
const holeIdle = 40 * time.Second

// stallBound は、穴を埋めた後に送り手 c から何も届かない状態を止まったとみなすまでの時間。
// 送り手の今の再送の間隔(RTO)に holeIdle の 4 分の 1 を足した値と、holeIdle の大きい方である。
// 穴の segment の再送は穴を開けている間すべて捨てるので、そのたびに RTO が倍に延びる。遅い環境で
// 穴を長く開けると、RTO は holeIdle を超え(gVisor の上限は 120 秒)、穴を埋めた後の最初の再送は、
// 今の RTO の分だけ後になりうる。その前に止まったとみなすと、受け入れる受け手を誤って落とす。
func stallBound(c net.Conn) time.Duration {
	var ti tcpip.TCPInfoOption
	connOf(c).ep.GetSockOpt(&ti)
	return max(holeIdle, ti.RTO+holeIdle/4)
}

// readProgress は r から n byte を読み、idle() の間 1 byte も読めなければ止まったとして誤りを返す。
// idle は読むたびに求め直す。全体の期限は置かない。遅い環境では、穴を埋めた後の転送が、送り手の
// queue の溢れと再送で遅くなるが、読み進めている限り、受け取れなくなった接続ではない。
func readProgress(r net.Conn, n int, idle func() time.Duration) (int, error) {
	defer r.SetReadDeadline(time.Time{})
	buf := make([]byte, 64<<10)
	got := 0
	for got < n {
		r.SetReadDeadline(time.Now().Add(idle()))
		k, err := r.Read(buf[:min(len(buf), n-got)])
		got += k
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// makeHole は、送り手 c から大きさ ooo のデータを 1 回で書き、先頭の segment を捨てて、受け手 s に
// 順序外として積ませる。積み終わったら、以後 c からのデータを穴を埋めるまですべて捨て、受け手が
// 受け取った segment をすべて処理し終えた後の受信のメモリを返す。時間だけで積み終わりを判断しない。
// 遅い環境では、送り手が送り始める前や送る途中で、受け手のメモリが一時的に変わらないことがある。
func makeHole(t *testing.T, p *tcpPair, h *holeFilter, c, s net.Conn, ooo int) int {
	t.Helper()
	syncWindow(t, c, s)
	h.start(c)
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(make([]byte, ooo)); err != nil {
		t.Fatalf("setup: write %d: %v; %s", ooo, err, holeDiag(t, p, c, s))
	}
	c.SetWriteDeadline(time.Time{})
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, n := pendingOf(s); n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("setup: no out-of-order data behind the hole within 10s: %s", holeDiag(t, p, c, s))
		}
	}
	// 送り手が送り終え、受け手が積み終えるまで待つ
	settle(t, "setup: the burst behind the hole", func() [3]int { return [3]int{recvMemOf(t, s), int(sndNxtOf(c)), 0} })
	h.frozen.Store(true)
	// 捨て始める前に渡った segment を受け手が処理し終えると、受信のメモリは順序外のキューの byte に
	// 等しく、受信のキューは空になる。以後は何も届かないので、この値は穴を埋めるまで変わらない
	v := settle(t, "setup: the receiver", func() [3]int { pb, _ := pendingOf(s); return [3]int{recvMemOf(t, s), pb, recvQueue(s)} })
	m := v[0]
	if pb, n := pendingOf(s); pb == 0 || n == 0 || recvQueue(s) != 0 || m != pb {
		t.Fatalf("setup: no out-of-order data behind the hole: pending=%d segments=%d queue=%d rcvMemUsed=%d", pb, n, recvQueue(s), m)
	}
	if st := state(c); st != tcp.StateEstablished {
		t.Fatalf("setup: sender %v with the hole open: %v", st, connOf(c).ep.LastError())
	}
	return m
}

// gVisor の rcvMemUsed の名前と型が、このビルドの前提と合う(go.mod の固定の版)。gVisor を更新して
// 合わなくなれば、回収は止まり、この試験が落ちる。
func TestGVisorRecvMemLayout(t *testing.T) {
	if !recvMem.ok {
		t.Fatal("tcp.Endpoint has no rcvMemUsed of type atomicbitops.Int32; the reclaim is disabled")
	}
	type noField struct{ other int32 }
	type wrongType struct{ rcvMemUsed int32 }
	type inner struct{ rcvMemUsed atomicbitops.Int32 }
	type embedded struct{ inner }
	for _, typ := range []reflect.Type{reflect.TypeFor[noField](), reflect.TypeFor[wrongType](), reflect.TypeFor[embedded]()} {
		if lookupRecvMem(typ).ok {
			t.Errorf("lookupRecvMem(%v) accepted a layout it must reject", typ)
		}
	}
	type good struct {
		pad        [3]int64
		rcvMemUsed atomicbitops.Int32
	}
	// 型は reflect でだけ使う。フィールドを一度書いて、使っていないという静的解析の指摘を避ける
	_ = []any{noField{other: 0}, wrongType{rcvMemUsed: 0}, embedded{inner{rcvMemUsed: atomicbitops.Int32{}}}, good{pad: [3]int64{}, rcvMemUsed: atomicbitops.Int32{}}}
	if l := lookupRecvMem(reflect.TypeFor[good]()); !l.ok || l.off != 24 {
		t.Fatalf("lookupRecvMem(good) = %+v", l)
	}
	// 読んだ値が gVisor の値と一致する。読まない受け手の受信のメモリは、受信のキューの byte 以上
	p := newTCPPair(t, 0)
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	if m := recvMemOf(t, s); m != 0 {
		t.Fatalf("fresh endpoint rcvMemUsed = %d", m)
	}
	c.Write(make([]byte, 100<<10))
	waitFor(t, 10*time.Second, "100 KiB queued at the receiver", func() bool { return recvQueue(s) == 100<<10 })
	if m, q := recvMemOf(t, s), recvQueue(s); m < q {
		t.Fatalf("rcvMemUsed = %d with %d bytes queued", m, q)
	}
	if got, ok := readAll(s, 100<<10, 5*time.Second); !ok {
		t.Fatalf("read %d of %d", got, 100<<10)
	}
	if m := settle(t, "receive memory after reading", func() [3]int { return [3]int{recvMemOf(t, s), 0, 0} }); m[0] != 0 {
		t.Fatalf("rcvMemUsed = %d after reading everything", m[0])
	}
}

// 受け手の受信のバッファを、順序外を積んだ後の受信のメモリ M に対して B に縮め、穴を埋める再送を
// 通す。gVisor の enqueue は受信のメモリが B 以下のときだけデータの segment を受け入れるので、
// B >= M なら読み進め、B < M なら何も受け入れず止まる。回収は B = floor で、M <= floor のときだけ縮める。
func TestGVisorShrinkBoundary(t *testing.T) {
	cases := []struct {
		name   string
		mtu    int
		ooo    int
		slack  func(m, seg int) int // B - M
		writer bool                 // 縮めた後も送り手が先を送り続ける
		stall  bool
	}{
		{name: "B equals M", mtu: 1420, ooo: 200 << 10, slack: func(m, seg int) int { return 0 }},
		{name: "B is one segment above M", mtu: 1420, ooo: 200 << 10, slack: func(m, seg int) int { return seg }},
		{name: "B equals M, the sender keeps sending", mtu: 1420, ooo: 200 << 10, slack: func(m, seg int) int { return 0 }, writer: true},
		{name: "B equals M, 64 KiB segments", mtu: 65535, ooo: 3 << 20, slack: func(m, seg int) int { return 0 }},
		{name: "B equals M, 64 KiB segments, the sender keeps sending", mtu: 65535, ooo: 3 << 20, slack: func(m, seg int) int { return 0 }, writer: true},
		{name: "B is one byte below M", mtu: 1420, ooo: 200 << 10, slack: func(m, seg int) int { return -1 }, stall: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHoleFilter()
			p := newHolePair(t, tc.mtu, h)
			c, s := p.dial(t)
			defer c.Close()
			defer s.Close()
			bulk(t, c, s, 4<<20) // 両端に boost を得させ、広い窓で順序外を多く積めるようにする
			if !boosted(c) || !boosted(s) {
				t.Fatal("setup: not boosted")
			}
			m := makeHole(t, p, h, c, s, tc.ooo)
			pb, n := pendingOf(s)
			seg := pb / n
			if tc.mtu > 1500 && seg < 60<<10 {
				t.Fatalf("setup: out-of-order segments of %d bytes, want about 64 KiB", seg)
			}
			b := m + tc.slack(m, seg)
			so := connOf(s).ep.SocketOptions()
			so.SetReceiveBufferSize(int64(b), true)
			if got := so.GetReceiveBufferSize(); got != int64(b) {
				t.Fatalf("receive buffer %d, want %d", got, b)
			}
			if got := recvMemOf(t, s); got != m {
				t.Fatalf("setup: rcvMemUsed moved from %d to %d while the hole was frozen", m, got)
			}
			var more atomic.Int64
			stop := make(chan struct{})
			done := make(chan struct{})
			if tc.writer {
				go func() {
					defer close(done)
					buf := make([]byte, 32<<10)
					for {
						select {
						case <-stop:
							return
						default:
						}
						c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
						k, _ := c.Write(buf)
						more.Add(int64(k))
					}
				}()
			} else {
				close(done)
			}
			drops := queueDrops(s)
			h.on.Store(false)
			var (
				got int
				err error
			)
			if tc.stall {
				// 止まるのが、再送が届かないからではなく、届いた再送を受け手が受け入れないからで
				// あることを確かめる。拒んだ数か受信のメモリが変わるまで待ち、その後も何も読めない
				// ことを見る
				for deadline := time.Now().Add(stallBound(c)); queueDrops(s) == drops && recvMemOf(t, s) == m; time.Sleep(20 * time.Millisecond) {
					if time.Now().After(deadline) {
						t.Fatalf("B below M: no retransmission reached the receiver: %s", holeDiag(t, p, c, s))
					}
				}
				got, err = readAllErr(s, tc.ooo, 8*time.Second)
			} else {
				got, err = readProgress(s, tc.ooo, func() time.Duration { return stallBound(c) })
			}
			ok := err == nil
			close(stop)
			<-done
			pbAfter, nAfter := pendingOf(s)
			t.Logf("M=%d pending=%d in %d segments (%d each) B=%d: read %d of %d ok=%v; pending after %d in %d; written after %d; queue drops %d",
				m, pb, n, seg, b, got, tc.ooo, ok, pbAfter, nAfter, more.Load(), queueDrops(s)-drops)
			if tc.stall {
				if got != 0 || recvMemOf(t, s) != m {
					t.Fatalf("B below M: read %d, rcvMemUsed %d; want a stall with nothing accepted", got, recvMemOf(t, s))
				}
				return
			}
			if !ok {
				t.Fatalf("B >= M: read only %d of %d after the hole was filled: %v; %s", got, tc.ooo, err, holeDiag(t, p, c, s))
			}
		})
	}
}

// 回収の場面: boost を得た受け手に穴を作り順序外を積み、需要が止まってから別の流れが枠を求める。
// 順序外が floor 以下なら floor に戻して枠を渡し、穴が埋まれば読み進める。floor を超えていれば
// 戻さず、枠を持ったまま読み進める。
func TestTCPReclaimWithHole(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ooo     int
		demoted bool
	}{
		{name: "within the floor", ooo: 128 << 10, demoted: true},
		{name: "over the floor", ooo: 3 << 20, demoted: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHoleFilter()
			p := newHolePair(t, 1420, h)
			c, s := p.dial(t)
			defer c.Close()
			defer s.Close()
			bulk(t, c, s, 4<<20)
			if !boosted(c) || !boosted(s) {
				t.Fatal("setup: not boosted")
			}
			m := makeHole(t, p, h, c, s, tc.ooo)
			if (m <= tcpRecvFloor) != tc.demoted {
				t.Fatalf("setup: rcvMemUsed %d is on the wrong side of the floor", m)
			}
			time.Sleep(tcpIdleReclaim + 200*time.Millisecond)
			c2, s2 := p.dial(t)
			defer c2.Close()
			defer s2.Close()
			bulk(t, c2, s2, 4<<20)
			_, rcv := bufSizes(s)
			t.Logf("rcvMemUsed=%d: holder boosted=%v rcv=%d, new flow boosted=%v", m, boosted(s), rcv, boosted(s2))
			if boosted(s) == tc.demoted || boosted(s2) != tc.demoted {
				t.Fatalf("rcvMemUsed %d: holder boosted=%v, new flow boosted=%v", m, boosted(s), boosted(s2))
			}
			if !tc.demoted && rcv != tcpBoostSize {
				t.Fatalf("holder kept at rcv=%d", rcv)
			}
			h.on.Store(false)
			if got, err := readProgress(s, tc.ooo, func() time.Duration { return stallBound(c) }); err != nil {
				t.Fatalf("read only %d of %d after the hole was filled: %v; %s", got, tc.ooo, err, holeDiag(t, p, c, s))
			}
		})
	}
}

// 回収の判定の境界。受信のメモリが floor ちょうどなら縮め、floor より 1 byte 多ければ縮めない。
// 読めなければ縮めない。
func TestTCPReclaimRecvMemBoundary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mem     int
		ok      bool
		demoted bool
	}{
		{"floor", tcpRecvFloor, true, true},
		{"one segment below the floor", tcpRecvFloor - 2048, true, true},
		{"one byte over the floor", tcpRecvFloor + 1, true, false},
		{"unreadable", 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newTCPPair(t, 1)
			p.b.pool.recvMemHook = func(tcpip.Endpoint) (int, bool) { return tc.mem, tc.ok }
			hc, hs := p.dial(t)
			defer hc.Close()
			defer hs.Close()
			bulk(t, hc, hs, 2<<20)
			if !boosted(hs) {
				t.Fatal("setup: holder not boosted")
			}
			time.Sleep(tcpIdleReclaim + 200*time.Millisecond)
			c, s := p.dial(t)
			defer c.Close()
			defer s.Close()
			bulk(t, c, s, 4<<20)
			_, rcv := bufSizes(hs)
			if boosted(hs) == tc.demoted || boosted(s) != tc.demoted {
				t.Fatalf("rcvMemUsed %d ok=%v: holder boosted=%v rcv=%d, new flow boosted=%v", tc.mem, tc.ok, boosted(hs), rcv, boosted(s))
			}
			if want := map[bool]int64{true: tcpRecvFloor, false: tcpBoostSize}[tc.demoted]; rcv != want {
				t.Fatalf("holder rcv=%d, want %d", rcv, want)
			}
		})
	}
}
