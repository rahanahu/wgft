package wgstack

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/bits"
	mrand "math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rahanahu/wgft/internal/ipv4frag"
)

var logf = log.Printf

// limits は表の大きさ。本番は defaultLimits で、package の中の試験だけが小さな値を渡す。
type limits struct {
	maxFlows int // K
	acceptQ  int // Q
	synRows  int // N_syn
	twRows   int // M
	ctlSlots int // Q_ctl
}

func defaultLimits(k int) limits {
	if k <= 0 {
		k = defaultMaxFlows
	}
	return limits{maxFlows: k, acceptQ: acceptQueueAll, synRows: synRowsAll, twRows: twRowsAll, ctlSlots: ctlSlots}
}

func (l limits) conns() int { return l.maxFlows + l.acceptQ } // N_c = K + Q

// stack は決定的な核。goroutine を作らず、時計と乱数を直接読まない。操作は「packet と時刻を受けて
// 状態を変え、出力を返す」(input と poll)、「時刻を受けてタイマーを進める」(advance)、アプリケーションの
// 操作(conn.go と listener.go)の 3 種類だけである。例外は boost の回収で、別の Device の接続の需要を
// 確かめるとき、その接続の Device の時計(clock)を読む。
//
// 錠は表の錠 tmu と接続ごとの錠 tcb.mu の 2 段で、ほかは末端の錠(output.mu、wheel.mu、chunkPool.mu、
// boostPool.mu、rngMu、chMu)である。順は tcb.mu -> tmu -> 末端で、tmu を持ったまま tcb.mu を取らない。
// 表の錠は 4 つ組の hash の表、空きの枠の list、握手の途中の表、TIME_WAIT の表、待ち受けの表と accept の
// 待ち行列を守る。ある接続の処理が別の接続に触れるとき(boost の回収)は、自分の錠を離してから相手の錠を
// TryLock で取る。
type stack struct {
	lim    limits
	mtu    int
	local  []netip.Prefix // 受け付ける宛先の集合
	addr   uint32         // 自分のアドレス(集合の最初のアドレス)
	clock  func() int64
	isnKey sipKey
	tsKey  sipKey

	tmu       sync.Mutex
	closed    bool
	conns     []tcb
	connIdx   index
	free      []int32 // 空きの枠
	syn       synTable
	tw        twTable
	listeners map[netip.AddrPort]*listener
	queued    int // accept の待ち行列の全体の数

	out output
	udp udpState

	frag          *ipv4frag.Table
	fragNextSweep atomic.Int64
	wheel         *wheel
	chunks        chunkPool
	pool          *boostPool

	rngMu sync.Mutex
	rng   *mrand.ChaCha8

	chMu    sync.Mutex
	chSec   int64
	chCount int

	icmpMu    sync.Mutex
	icmpSec   int64
	icmpCount int
	ping      pingTable

	ipID atomic.Uint32

	advMu sync.Mutex
	fired []int32

	// sleepUntil は Device のタイマーの goroutine が眠る期限(ns)。それより早い期限が入ったら kick を呼ぶ
	sleepUntil atomic.Int64
	kick       func()

	done chan struct{} // Device の Close で閉じる

	trace       func(TraceEvent) // Config.Trace
	boostPolicy BoostPolicy      // Config.TestBoost

	counters
}

// counters は種類ごとの拒否と事象の数。gates は 1 分に 1 回までのログの門である。
type counters struct {
	mssFloor       atomic.Uint64
	synFull        atomic.Uint64
	acceptOverflow atomic.Uint64
	twEvicted      atomic.Uint64
	ctlDropped     atomic.Uint64
	oooDropped     atomic.Uint64
	rcvTrimmed     atomic.Uint64
	challengeLimit atomic.Uint64
	icmpLimited    atomic.Uint64
	fragments      atomic.Uint64
	udpDropped     atomic.Uint64
	icmpDropped    atomic.Uint64
	malformed      atomic.Uint64
	badChecksum    atomic.Uint64
	notLocal       atomic.Uint64
	rtxAborted     atomic.Uint64
	probeAborted   atomic.Uint64
	boostGranted   atomic.Uint64
	boostReclaimed atomic.Uint64

	// 送り手の事象(wgstack-performance.md の「安く確かめる手順」)
	rtos, rtosBackedOff, rtosShortOfDupThresh atomic.Uint64
	fastRecoveries, partialAcks               atomic.Uint64
	retrans                                   [numRtxCauses]atomic.Uint64
	dupAcksIn, acksDelayed, acksImmediate     atomic.Uint64

	mssGate, synGate, acceptGate, twGate, ctlGate, oooGate gate
}

// gate は lograte.Gate と同じく 1 分に 1 回までの門だが、核の時刻で判定する。
type gate struct {
	mu   sync.Mutex
	next int64
	used bool
}

func (g *gate) allow(now int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.used && now < g.next {
		return false
	}
	g.used = true
	g.next = now + int64(time.Minute)
	return true
}

// newStack は核を作る。表と固定の配列はここで確保し、後から大きくしない。
func newStack(local []netip.Prefix, mtu int, lim limits, clock func() int64, random io.Reader, pool *boostPool) (*stack, error) {
	if len(local) == 0 {
		return nil, errors.New("no local address")
	}
	for _, p := range local {
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("local prefix %s is not IPv4", p)
		}
	}
	if mtu < 576 || mtu > 65535 {
		return nil, fmt.Errorf("MTU %d is out of range 576 to 65535", mtu)
	}
	if random == nil {
		random = rand.Reader
	}
	var seed [64]byte
	if _, err := io.ReadFull(random, seed[:]); err != nil {
		return nil, fmt.Errorf("reading the random seed: %w", err)
	}
	le := binary.LittleEndian
	s := &stack{
		lim:       lim,
		mtu:       mtu,
		local:     local,
		addr:      addrBits(local[0].Addr()),
		clock:     clock,
		isnKey:    sipKey{le.Uint64(seed[0:]), le.Uint64(seed[8:])},
		listeners: make(map[netip.AddrPort]*listener),
		pool:      pool,
		done:      make(chan struct{}),
		chSec:     -1,
		icmpSec:   -1,
	}
	tableKey := sipKey{le.Uint64(seed[16:]), le.Uint64(seed[24:])}
	var chachaSeed [32]byte
	copy(chachaSeed[:], seed[32:])
	s.rng = mrand.NewChaCha8(chachaSeed)
	s.tsKey = sipKey{s.rng.Uint64(), s.rng.Uint64()}
	s.ipID.Store(uint32(s.rng.Uint64()))

	n := lim.conns()
	s.conns = make([]tcb, n)
	s.free = make([]int32, n)
	for i := range s.conns {
		c := &s.conns[i]
		c.s = s
		c.id = int32(i)
		c.qprev, c.qnext = -1, -1
		c.snd.pool = &s.chunks
		c.rcv.r.pool = &s.chunks
		s.free[i] = int32(n - 1 - i) // 小さい番号から使う
	}
	s.connIdx = newIndex(n, tableKey)
	s.syn = newSynTable(lim.synRows, tableKey)
	s.tw = newTWTable(lim.twRows, tableKey)
	s.out = output{
		conns:  newDlist(n),
		rows:   newDlist(lim.synRows + lim.twRows),
		ctl:    newCtlRing(lim.ctlSlots, mtu),
		notify: make(chan struct{}, 1),
	}
	s.wheel = newWheel(n * numTimers)
	s.udp.init()
	frag, err := ipv4frag.New(fragLimits)
	if err != nil {
		return nil, err
	}
	s.frag = frag
	s.fired = make([]int32, 0, n*numTimers)
	return s, nil
}

// isLocal は a が受け付ける宛先の集合に入るかを返す。
func (s *stack) isLocal(a uint32) bool {
	addr := addrFrom(a)
	for _, p := range s.local {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *stack) randomN(n int) int {
	s.rngMu.Lock()
	defer s.rngMu.Unlock()
	hi, _ := bits.Mul64(s.rng.Uint64(), uint64(n))
	return int(hi)
}

func (s *stack) nextID() uint16 { return uint16(s.ipID.Add(1)) }

// isn は RFC 6528 の鍵付きの hash で ISN を作る。M は 4 µs ごとに進む時計である。reuse は TIME_WAIT の
// 4 つ組を新しい SYN が使い直すときの前の接続の SND.NXT で、Linux と同じく ISN をその 65537 先より
// 前に置かない。前の接続の古い segment が新しい接続の番号の空間に入らないためである(RFC 1122 4.2.2.13)。
func (s *stack) isn(t tuple, now int64, reuse reuseISS) uint32 {
	iss := uint32(now/4000) + uint32(s.isnKey.hashTuple(t))
	if reuse.ok {
		if floor := reuse.sndNxt + 65537; seqLT(iss, floor) {
			iss = floor
		}
	}
	return iss
}

// reuseISS は、TIME_WAIT の 4 つ組を使い直す SYN に渡す前の接続の SND.NXT。
type reuseISS struct {
	ok     bool
	sndNxt uint32
}

// tsOffset は timestamp の値に足す offset。Linux の secure_tcp_ts_off と同じくアドレスの組の鍵付きの hash
// から作るので、同じ相手との接続の TSval は接続を作り直しても増え続け、相手の PAWS が働く。
func (s *stack) tsOffset(t tuple) uint32 {
	return uint32(s.tsKey.sum(uint64(t.laddr)|uint64(t.raddr)<<32, 0))
}

// challengeAllowed は Device 全体の challenge ACK の token bucket から 1 つ取れたかを返す。Linux と
// 同じく、1 秒ごとに limit/2 から 3*limit/2 の間の乱数の数を補う。
func (s *stack) challengeAllowed(now int64) bool {
	sec := now / int64(time.Second)
	s.chMu.Lock()
	if sec != s.chSec || s.chCount < 0 {
		s.chSec = sec
		s.chCount = challengeAckLimit/2 + s.randomN(challengeAckLimit)
	}
	ok := s.chCount > 0
	if ok {
		s.chCount--
	}
	s.chMu.Unlock()
	if !ok {
		s.challengeLimit.Add(1)
	}
	return ok
}

// noteDeadline は、ns の期限が Device のタイマーの goroutine の眠りの期限より早ければ起こす。
func (s *stack) noteDeadline(ns int64) {
	if s.kick == nil {
		return
	}
	if u := s.sleepUntil.Load(); u == 0 || ns < u {
		s.kick()
	}
}

// input は 1 つの IPv4 の packet を処理する。packet は呼び出しの間だけ使い、保持しない。
func (s *stack) input(pkt []byte, now int64) {
	ip, drop := parseIPv4(pkt)
	switch drop {
	case ipv4Malformed:
		s.malformed.Add(1)
		return
	case ipv4BadChecksum:
		s.badChecksum.Add(1)
		return
	}
	if !s.isLocal(ip.dst) || ip.src == ip.dst {
		s.notLocal.Add(1)
		return
	}
	if ip.fragment {
		s.inputFragment(&ip, now)
		return
	}
	switch ip.proto {
	case protoTCP:
		seg, d := parseTCP(&ip)
		switch d {
		case tcpMalformed:
			s.malformed.Add(1)
			return
		case tcpBadChecksum:
			s.badChecksum.Add(1)
			return
		}
		s.inputTCP(&seg, now)
	case protoICMP:
		s.inputICMP(&ip, now)
	case protoUDP:
		s.inputUDP(&ip, now)
	default:
		s.malformed.Add(1)
	}
}

// dropMSS は MSS の下限で SYN を捨てたことを数え、1 分に 1 回までログに出す。
func (s *stack) dropMSS(seg *segment, now int64) {
	n := s.mssFloor.Add(1)
	if s.mssGate.allow(now) {
		logf("wgstack: dropped TCP handshakes that advertise an MSS below %d; %d dropped since the tunnel was built, the latest from %s; peers that advertise a smaller MSS cannot connect through this tunnel",
			minMSS, n, seg.tup.remote())
	}
}

func (s *stack) refused(c *atomic.Uint64, g *gate, now int64, what string) {
	n := c.Add(1)
	if g.allow(now) {
		logf("wgstack: %s; %d since the tunnel was built", what, n)
	}
}

// replyRST は、どの接続にも行にも当たらない segment に RST を返す(RFC 9293 3.10.7.1)。RST には返さない。
func (s *stack) replyRST(seg *segment) {
	if seg.has(flagRST) {
		return
	}

	h := tcpHeader{tup: seg.tup, flags: flagRST}
	if seg.has(flagACK) {
		h.seq = seg.ack
	} else {
		h.ack = seg.seq + seg.seqLen()
		h.flags |= flagACK
	}
	s.sendCtl(h)
}

// sendCtl は option の無い segment を制御の輪に積む。輪が満杯なら捨てて数える。
func (s *stack) sendCtl(h tcpHeader) {
	if s.mtu < ipHeaderLen+tcpHeaderLen {
		return
	}
	id := s.nextID()
	ok := s.out.pushCtl(func(b []byte) int {
		writeTCP(b, id, h, nil, 0)
		return finishTCP(b)
	})
	if !ok {
		s.refused(&s.ctlDropped, &s.ctlGate, s.clock(), "dropped control packets because the control output ring was full")
	}
}

// inputTCP は TCP の segment を、接続の枠、TIME_WAIT の行、握手の途中の行、待ち受けの順に渡す。
func (s *stack) inputTCP(seg *segment, now int64) {
	if seg.has(flagSYN) && seg.opt.hasMSS && seg.opt.mss != 0 && seg.opt.mss < minMSS {
		s.dropMSS(seg, now)
		return
	}
	var reuse reuseISS
	for range 3 {
		s.tmu.Lock()
		if s.closed {
			s.tmu.Unlock()
			return
		}
		if id, gen := s.connIdx.find(seg.tup); id >= 0 {
			s.tmu.Unlock()
			c := &s.conns[id]
			c.mu.Lock()
			if c.gen != gen || !c.inIndex {
				c.mu.Unlock()
				continue
			}
			again := c.input(seg, now, &reuse)
			c.mu.Unlock()
			if again {
				continue // TIME_WAIT の接続が新しい SYN を受けた(RFC 6191)
			}
			return
		}
		if r := s.tw.find(seg.tup); r >= 0 {
			if s.twInput(r, seg, now, &reuse) {
				s.tmu.Unlock()
				return
			}
			// 行を外した。SYN を待ち受けに渡す
		}
		if r := s.syn.find(seg.tup); r >= 0 {
			p, ok := s.synInput(r, seg, now)
			s.tmu.Unlock()
			if ok {
				s.promote(p, seg, now)
			}
			return
		}
		l := s.listeners[seg.tup.local()]
		if l != nil && seg.flags&(flagSYN|flagACK|flagRST) == flagSYN {
			s.newSynRow(l, seg, now, reuse)
			s.tmu.Unlock()
			return
		}
		s.tmu.Unlock()
		if l != nil && seg.has(flagSYN) && !seg.has(flagACK) {
			return // SYN と RST の両方を持つ segment は捨てる
		}
		s.replyRST(seg)
		return
	}
}

// advance は時刻を now まで進め、期限の来た接続のタイマーと行の期限を処理する。
func (s *stack) advance(now int64) {
	s.advMu.Lock()
	defer s.advMu.Unlock()
	fired := s.wheel.advance(now, s.fired[:0])
	for _, n := range fired {
		c := &s.conns[n/numTimers]
		kind := int(n % numTimers)
		c.mu.Lock()
		if c.state != stFree && c.tdl[kind] != 0 && c.tdl[kind] <= now {
			c.tdl[kind] = 0
			c.onTimer(kind, now)
		}
		c.mu.Unlock()
	}
	s.fired = fired[:0]
	s.tmu.Lock()
	closed := s.closed
	if !closed {
		s.expireSynRows(now)
		s.expireTWRows(now)
	}
	s.tmu.Unlock()
	if !closed {
		s.sweepFrag(now)
	}
}

// nextDeadline は次にタイマーか行の期限が来うる最も早い時刻(ns)を返す。無ければ 0 を返す。
func (s *stack) nextDeadline() int64 {
	next := int64(0)
	if t := s.wheel.nextTick(); t != noTick {
		next = t * tickNs
	}
	if _, entries, _ := s.frag.Usage(); entries > 0 {
		if d := s.fragNextSweep.Load(); next == 0 || d < next {
			next = d
		}
	}
	s.tmu.Lock()
	for _, d := range [2]int64{s.syn.nextDeadline(), s.tw.nextDeadline()} {
		if d != 0 && (next == 0 || d < next) {
			next = d
		}
	}
	s.tmu.Unlock()
	return next
}

// poll は次に送る packet を 1 つ b に作り、その長さを返す。送るものが無ければ 0 を返す。組は deficit
// round robin で選ぶ。呼び出し側は poll を直列にする(Device.readMu)。
func (s *stack) poll(b []byte, now int64) int {
	o := &s.out
	quantum := s.mtu
	// 取り出した項目が何も作らなければ次を見る。項目は取り出すと list から外れるので、この繰り返しは
	// 有限である
	for {
		o.mu.Lock()
		cls := -1
		for range numClasses {
			c := o.cur
			if o.classEmpty(c) {
				o.deficit[c] = 0
				o.cur = (c + 1) % numClasses
				continue
			}
			if o.deficit[c] <= 0 {
				o.deficit[c] += quantum
			}
			cls = c
			break
		}
		if cls < 0 {
			o.mu.Unlock()
			return 0
		}
		var n int
		switch cls {
		case classCtl:
			n = o.ctl.pop(b)
			o.mu.Unlock()
		case classConn:
			id := o.conns.popFront()
			o.mu.Unlock()
			n = s.conns[id].poll(b, now)
		case classRow:
			id := o.rows.popFront()
			o.mu.Unlock()
			n = s.pollRow(id, b, now)
		case classUDP:
			o.mu.Unlock()
			n = s.pollUDP(b)
		default:
			o.mu.Unlock()
		}
		if n == 0 {
			continue
		}
		o.mu.Lock()
		o.deficit[cls] -= n
		if o.deficit[cls] <= 0 || o.classEmpty(cls) {
			o.cur = (cls + 1) % numClasses
		}
		o.mu.Unlock()
		return n
	}
}
