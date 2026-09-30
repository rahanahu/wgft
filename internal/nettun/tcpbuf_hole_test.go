package nettun

import (
	"io"
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

// holeFilter は、有効な間、port から 9000 へ向かう最初のデータの segment と、その再送をすべて捨てる。
type holeFilter struct {
	on      atomic.Bool
	port    atomic.Uint32
	holeSeq atomic.Int64
}

func newHoleFilter() *holeFilter {
	h := &holeFilter{}
	h.holeSeq.Store(-1)
	return h
}

func (h *holeFilter) drop(pkt []byte) bool {
	if !h.on.Load() {
		return false
	}
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) || ip.TransportProtocol() != header.TCPProtocolNumber {
		return false
	}
	th := header.TCP(ip.Payload())
	pl := int64(len(th.Payload()))
	if th.DestinationPort() != 9000 || uint32(th.SourcePort()) != h.port.Load() || pl == 0 {
		return false
	}
	seq := int64(th.SequenceNumber())
	h.holeSeq.CompareAndSwap(-1, seq)
	hs := h.holeSeq.Load()
	return seq <= hs && hs < seq+pl
}

func (h *holeFilter) start(c net.Conn) {
	h.port.Store(uint32(c.LocalAddr().(*net.TCPAddr).Port))
	h.on.Store(true)
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

// quiesce は、受信のメモリが 300 ms 変わらなくなるまで待ち、その値を返す。
func quiesce(t *testing.T, c net.Conn) int {
	t.Helper()
	last, since := -1, time.Now()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		m := recvMemOf(t, c)
		if m != last {
			last, since = m, time.Now()
		} else if time.Since(since) > 300*time.Millisecond {
			return m
		}
	}
	t.Fatal("receive memory did not settle")
	return 0
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

// makeHole は、送り手 c から大きさ ooo のデータを 1 回で書き、先頭の segment を捨てて、受け手 s に
// 順序外として積ませる。積み終わった受け手の受信のメモリを返す。
func makeHole(t *testing.T, h *holeFilter, c, s net.Conn, ooo int) int {
	t.Helper()
	h.start(c)
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(make([]byte, ooo)); err != nil {
		t.Fatalf("setup: write %d: %v", ooo, err)
	}
	c.SetWriteDeadline(time.Time{})
	m := quiesce(t, s)
	if pb, n := pendingOf(s); pb == 0 || n == 0 || recvQueue(s) != 0 {
		t.Fatalf("setup: no out-of-order data behind the hole: pending=%d segments=%d queue=%d", pb, n, recvQueue(s))
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
	m := quiesce(t, s)
	if q := recvQueue(s); q != 100<<10 || m < q {
		t.Fatalf("rcvMemUsed = %d with %d bytes queued", m, q)
	}
	readAll(s, 100<<10, 5*time.Second)
	if m := quiesce(t, s); m != 0 {
		t.Fatalf("rcvMemUsed = %d after reading everything", m)
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
			p := newTCPPairMTU(t, 1, tc.mtu, nil, h.drop)
			c, s := p.dial(t)
			defer c.Close()
			defer s.Close()
			bulk(t, c, s, 4<<20) // 両端に boost を得させ、広い窓で順序外を多く積めるようにする
			if !boosted(c) || !boosted(s) {
				t.Fatal("setup: not boosted")
			}
			m := makeHole(t, h, c, s, tc.ooo)
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
			h.on.Store(false)
			timeout := 40 * time.Second
			if tc.stall {
				timeout = 8 * time.Second
			}
			got, ok := readAll(s, tc.ooo, timeout)
			close(stop)
			<-done
			pbAfter, nAfter := pendingOf(s)
			t.Logf("M=%d pending=%d in %d segments (%d each) B=%d: read %d of %d ok=%v; pending after %d in %d; written after %d; queue drops %d",
				m, pb, n, seg, b, got, tc.ooo, ok, pbAfter, nAfter, more.Load(),
				connOf(s).ep.Stats().(*tcp.Stats).ReceiveErrors.SegmentQueueDropped.Value())
			if tc.stall {
				if got != 0 || recvMemOf(t, s) != m {
					t.Fatalf("B below M: read %d, rcvMemUsed %d; want a stall with nothing accepted", got, recvMemOf(t, s))
				}
				return
			}
			if !ok {
				t.Fatalf("B >= M: read only %d of %d after the hole was filled", got, tc.ooo)
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
			p := newTCPPairOpts(t, 1, nil, h.drop)
			c, s := p.dial(t)
			defer c.Close()
			defer s.Close()
			bulk(t, c, s, 4<<20)
			if !boosted(c) || !boosted(s) {
				t.Fatal("setup: not boosted")
			}
			m := makeHole(t, h, c, s, tc.ooo)
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
			if got, err := readAllErr(s, tc.ooo, 40*time.Second); err != nil {
				var ti tcpip.TCPInfoOption
				connOf(c).ep.GetSockOpt(&ti)
				pb, n := pendingOf(s)
				t.Fatalf("read only %d of %d after the hole was filled: %v; sender %v rto %v; receiver %v pending %d in %d rcvMemUsed %d",
					got, tc.ooo, err, state(c), ti.RTO, state(s), pb, n, recvMemOf(t, s))
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
