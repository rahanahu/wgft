//go:build qbench

// Package qbench is a rough in-process TCP quality benchmark that compares wgstack with the
// gVisor netstack in internal/nettun over an impaired in-memory link. It is test-only (every
// file is a _test.go file behind the qbench build tag) and is run by hand. plan_test.go holds
// the measurement plan of docs/design/userspace/wgstack-performance.md, with a routine mode and a
// gate mode that adds the reference Linux; TestQBench is the older fixed-size transfer.
//
//	go test -tags qbench -run TestQBenchRoutine -v ./internal/tcpharness/qbench
//	go test -tags qbench -run 'TestQBench$' -timeout 90m -v ./internal/tcpharness/qbench
package qbench

import (
	"bufio"
	"container/heap"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// Impair describes the link. Everything is applied per direction, except the outage, which
// cuts both directions.
type Impair struct {
	Delay time.Duration // one-way delay
	// Loss is the random loss probability, each direction: per data segment and per block of
	// stream data, and per non-data packet, with LossContent; per packet with LossArrival.
	Loss      float64
	LossModel LossModel
	// LossBlock is LossContent's block in bytes; 0 takes the payload of a full segment from the
	// SYNs. The thin stream sets its message size.
	LossBlock   int
	Reorder     float64 // probability that a packet is held back by ReorderExtra
	ReorderGap  time.Duration
	RateBps     int64         // bits per second per direction; 0 means unlimited
	QueuePkts   int           // drop-tail queue length in packets at the rate limit
	OutageAfter int64         // payload bytes in the data direction before the outage starts; 0 disables
	OutageAt    time.Duration // time after the first payload byte in the data direction; 0 disables
	OutageLen   time.Duration
	DataDir     int // direction (0: A to B, 1: B to A) whose payload bytes trigger the outage
}

// LossModel is how the random loss picks the packets it drops.
type LossModel int

const (
	// LossContent, the default, keys each decision on what the packet carries, so every engine
	// loses the same data whatever its segment boundaries and timing. A data segment is dropped
	// when it covers the first byte of a block, counted from the ISN of its direction, whose
	// draw for this transmission of that byte fires: draw(seed, direction, block, n) for the
	// n-th transmission the loss stage sees, below Loss for a segment with one block start and
	// below 1-(1-Loss)^(1/k) for one with k, so every segment is lost with probability Loss.
	// The draws of each transmission are independent, so a block whose first transmission is
	// lost is not lost forever, and every engine meets the same sequence of fates for the same
	// block. A packet without data, such as a pure
	// ACK, is keyed on its flags, its acknowledgment relative to the peer's ISN and how many such
	// packets came before it, so engines that acknowledge the same byte meet the same fate. A
	// packet of another flow, or one that arrives before its direction's ISN is known, falls
	// back to the per-direction generator.
	LossContent LossModel = iota
	// LossArrival is the earlier model: one draw per packet in arrival order, per direction, so
	// the n-th packet is dropped on every engine whatever it carries. QBENCH_LOSS_MODEL=arrival
	// selects it, for comparison.
	LossArrival
)

func (m LossModel) String() string {
	if m == LossArrival {
		return "arrival"
	}
	return "content"
}

type timed struct {
	at  time.Time
	seq uint64
	pkt []byte
}

type timedHeap []timed

func (h timedHeap) Len() int { return len(h) }
func (h timedHeap) Less(i, j int) bool {
	if h[i].at.Equal(h[j].at) {
		return h[i].seq < h[j].seq
	}
	return h[i].at.Before(h[j].at)
}
func (h timedHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *timedHeap) Push(x any)   { *h = append(*h, x.(timed)) }
func (h *timedHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// dirStats counts what one direction carried.
type dirStats struct {
	Pkts, DataPkts  int
	Dropped, QDrops int // random loss and outage drops; rate-limit queue drops
	Retrans         int // data segments whose sequence range their flow already sent
	PayloadBytes    int64
	// maxEnd is the highest sequence end per flow, keyed by the two ports: a kernel engine's
	// socket of an earlier run can still send into a new rig, and its numbers are unrelated.
	maxEnd map[uint32]uint32
}

// Link joins two packet interfaces. deliver[d] hands a packet that crossed direction d to the
// receiving device.
type Link struct {
	imp  Impair
	t0   time.Time
	mu   sync.Mutex
	rng  [2]*rand.Rand
	free [2]time.Time // when the rate-limited line is next idle

	outStart, outEnd time.Time
	outCut           bool
	firstData        time.Time

	// flow is the rig's connection, from the client's SYN: the two ports as the client sends them.
	// Only its packets count and start the outage; a kernel socket of an earlier run that still
	// sends into the new rig passes uncounted.
	flow     uint32
	haveFlow bool

	trace *bufio.Writer // SetTrace's packet log; nil without one

	seed int64
	// LossContent's state, per direction: the ISN and the SYN's options, how many times the loss
	// stage saw the first byte of each block, and how many times it saw each non-data packet key.
	isn     [2]uint32
	haveISN [2]bool
	synMSS  [2]int
	synTS   [2]bool
	block   int
	txCount [2]map[int64]uint32
	hiEnd   [2]int64 // the highest stream end seen, which unwraps the next segment's offset
	ctlSeen [2]map[ctlKey]uint32

	st [2]dirStats

	deliver [2]func([]byte)
	q       [2]struct {
		mu   sync.Mutex
		h    timedHeap
		seq  uint64
		wake chan struct{}
	}
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func NewLink(imp Impair, seed int64, deliverAB, deliverBA func([]byte)) *Link {
	l := &Link{imp: imp, stop: make(chan struct{}), t0: time.Now(), seed: seed}
	l.rng[0] = rand.New(rand.NewSource(seed))
	l.rng[1] = rand.New(rand.NewSource(seed ^ 0x5bd1e995))
	l.deliver = [2]func([]byte){deliverAB, deliverBA}
	for d := 0; d < 2; d++ {
		l.q[d].wake = make(chan struct{}, 1)
		l.wg.Add(1)
		go l.run(d)
	}
	return l
}

// Halt stops the link's delivery and returns once nothing is delivered any more, within one
// write in flight. Packets sent afterwards are counted and traced but never delivered, so the
// trace's tail can list packets the link took after Halt. A rig halts its link before it closes
// the devices, so no packet reaches a closed device: a closed gVisor client that is handed a
// packet answers it into its closed queue and panics. Halt removes only the link as a source:
// the gVisor client stack's own goroutines and timers can still write while wireguard's
// tun/netstack closes its device, which only a change there could rule out.
func (l *Link) Halt() {
	l.stopOnce.Do(func() { close(l.stop) })
	l.wg.Wait()
}

// Close halts the link if it still runs and flushes its packet log.
func (l *Link) Close() {
	l.Halt()
	l.mu.Lock()
	if l.trace != nil {
		l.trace.Flush()
	}
	l.mu.Unlock()
}

// traceHeader names the columns of the packet log. Times are milliseconds from the link's start:
// in when the packet entered, out when the link delivers it or "-" when it dropped it. dir is
// "c>d" from the client and "d>c" from the DUT; fate is ok, loss, outage or queue.
const traceHeader = "in_ms\tout_ms\tdir\tfate\tflags\tseq\tack\tlen\twin\tsack\ttsval\ttsecr\n"

// SetTrace writes one line per TCP packet that enters the link to w, flushed when the link
// closes.
func (l *Link) SetTrace(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.trace = bufio.NewWriterSize(w, 1<<20)
	l.trace.WriteString(traceHeader)
}

// traceLocked writes the packet's line. l.mu is held.
func (l *Link) traceLocked(d int, in time.Time, out time.Time, fate string, pkt []byte) {
	if l.trace == nil {
		return
	}
	line, ok := tcpTraceFields(pkt)
	if !ok {
		return
	}
	o := "-"
	if !out.IsZero() {
		o = fmt.Sprintf("%.3f", float64(out.Sub(l.t0))/float64(time.Millisecond))
	}
	fmt.Fprintf(l.trace, "%.3f\t%s\t%s\t%s\t%s\n", float64(in.Sub(l.t0))/float64(time.Millisecond), o, [2]string{"c>d", "d>c"}[d], fate, line)
}

// tcpTraceFields is the flags, sequence, acknowledgment, payload length, raw window field, SACK
// blocks and timestamps of a TCP packet, tab-separated. A SYN's flags carry its MSS and window
// scale, so the window can be scaled.
func tcpTraceFields(p []byte) (string, bool) {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 6 {
		return "", false
	}
	ihl := int(p[0]&15) * 4
	tot := int(binary.BigEndian.Uint16(p[2:4]))
	if tot > len(p) || len(p) < ihl+20 {
		return "", false
	}
	t := p[ihl:tot]
	off := int(t[12]>>4) * 4
	if off < 20 || off > len(t) {
		return "", false
	}
	var flags []string
	for i, n := range []string{"F", "S", "R", "P", "A"} {
		if t[13]&(1<<i) != 0 {
			flags = append(flags, n)
		}
	}
	var sack []string
	tsval, tsecr := "-", "-"
	ws, mss := "", "" // on a SYN, appended to the flags
	o := t[20:off]
	for len(o) > 0 {
		if o[0] == 0 {
			break
		}
		if o[0] == 1 {
			o = o[1:]
			continue
		}
		if len(o) < 2 || int(o[1]) < 2 || int(o[1]) > len(o) {
			break
		}
		switch o[0] {
		case 5:
			for b := o[2:o[1]]; len(b) >= 8; b = b[8:] {
				sack = append(sack, fmt.Sprintf("%d-%d", binary.BigEndian.Uint32(b), binary.BigEndian.Uint32(b[4:])))
			}
		case 3:
			if o[1] == 3 {
				ws = fmt.Sprintf(" ws=%d", o[2])
			}
		case 2:
			if o[1] == 4 {
				mss = fmt.Sprintf(" mss=%d", binary.BigEndian.Uint16(o[2:]))
			}
		case 8:
			if o[1] == 10 {
				tsval = fmt.Sprint(binary.BigEndian.Uint32(o[2:]))
				tsecr = fmt.Sprint(binary.BigEndian.Uint32(o[6:]))
			}
		}
		o = o[o[1]:]
	}
	sk := "-"
	if len(sack) > 0 {
		sk = strings.Join(sack, ",")
	}
	return fmt.Sprintf("%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s", strings.Join(flags, "")+mss+ws, binary.BigEndian.Uint32(t[4:]), binary.BigEndian.Uint32(t[8:]),
		len(t)-off, binary.BigEndian.Uint16(t[14:]), sk, tsval, tsecr), true
}

// Outage returns the cut window; zero times mean it has not started.
func (l *Link) Outage() (start, end time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.outStart, l.outEnd
}

func (l *Link) Stats(d int) dirStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.st[d]
}

// tcpInfo is what the link reads from an IPv4/TCP packet.
type tcpInfo struct {
	ports    uint32 // source and destination port
	seq, ack uint32
	flags    byte
	n        int // payload length
	mss      int // the MSS option, 0 without one
	ts       bool
}

const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagACK = 0x10
)

// parseTCP parses an IPv4/TCP packet. ok is false for anything else.
func parseTCP(p []byte) (ti tcpInfo, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 6 {
		return ti, false
	}
	ihl := int(p[0]&15) * 4
	tot := int(binary.BigEndian.Uint16(p[2:4]))
	if tot > len(p) || len(p) < ihl+20 {
		return ti, false
	}
	t := p[ihl:tot]
	if len(t) < 20 {
		return ti, false
	}
	off := int(t[12]>>4) * 4
	if off < 20 || off > len(t) {
		return ti, false
	}
	ti = tcpInfo{ports: binary.BigEndian.Uint32(t), seq: binary.BigEndian.Uint32(t[4:]), ack: binary.BigEndian.Uint32(t[8:]), flags: t[13], n: len(t) - off}
	for o := t[20:off]; len(o) > 0 && o[0] != 0; {
		if o[0] == 1 {
			o = o[1:]
			continue
		}
		if len(o) < 2 || int(o[1]) < 2 || int(o[1]) > len(o) {
			break
		}
		switch {
		case o[0] == 2 && o[1] == 4:
			ti.mss = int(binary.BigEndian.Uint16(o[2:]))
		case o[0] == 8 && o[1] == 10:
			ti.ts = true
		}
		o = o[o[1]:]
	}
	return ti, true
}

// ctlKey is LossContent's key of a packet without data: its SYN, FIN, RST and ACK flags and its
// acknowledgment relative to the peer's ISN.
type ctlKey struct {
	flags byte
	ack   uint32
}

// draw is LossContent's uniform value in [0, 1) for a key: splitmix64 over the seed and the
// key's words, so a decision depends on nothing but the key.
func draw(seed int64, words ...uint64) float64 {
	h := uint64(seed)
	for _, w := range words {
		h ^= w
		h += 0x9e3779b97f4a7c15
		h = (h ^ h>>30) * 0xbf58476d1ce4e5b9
		h = (h ^ h>>27) * 0x94d049bb133111eb
		h ^= h >> 31
	}
	return float64(h>>11) / (1 << 53)
}

// learnLocked records the ISN and the options of the rig's SYN in direction d. l.mu is held.
func (l *Link) learnLocked(d int, ti tcpInfo) {
	if ti.flags&flagSYN == 0 || l.haveISN[d] {
		return
	}
	l.isn[d], l.haveISN[d] = ti.seq, true
	l.synMSS[d], l.synTS[d] = ti.mss, ti.ts
}

// blockLocked is LossContent's block: Impair.LossBlock, or the payload of a full segment, the
// smaller MSS of the two SYNs less the 12 bytes of the timestamp option when both SYNs carry it.
// The two SYNs are the same for every engine at the same MTU, so the blocks are too. l.mu is held.
func (l *Link) blockLocked() int {
	if l.block > 0 {
		return l.block
	}
	if l.imp.LossBlock > 0 {
		l.block = l.imp.LossBlock
		return l.block
	}
	mss := 0
	for _, m := range l.synMSS {
		if m > 0 && (mss == 0 || m < mss) {
			mss = m
		}
	}
	if mss == 0 {
		mss = 536
	}
	if l.synTS[0] && l.synTS[1] {
		mss -= 12
	}
	l.block = mss
	return l.block
}

// lostLocked decides the random loss of a packet that reached the loss stage in direction d.
// l.mu is held.
func (l *Link) lostLocked(d int, ti tcpInfo, ok, ours bool) bool {
	if l.imp.LossModel == LossArrival || !ok || !ours || !l.haveISN[d] {
		return l.rng[d].Float64() < l.imp.Loss
	}
	if ti.n == 0 || ti.flags&flagSYN != 0 {
		k := ctlKey{flags: ti.flags & (flagSYN | flagFIN | flagRST | flagACK)}
		if ti.flags&flagACK != 0 && l.haveISN[1-d] {
			k.ack = ti.ack - l.isn[1-d]
		}
		if l.ctlSeen[d] == nil {
			l.ctlSeen[d] = map[ctlKey]uint32{}
		}
		l.ctlSeen[d][k]++
		return draw(l.seed, uint64(d), 2, uint64(k.flags), uint64(k.ack), uint64(l.ctlSeen[d][k])) < l.imp.Loss
	}
	// the payload's stream offsets from the first data byte after the SYN, unwrapped against the
	// highest end seen so far, so a stream longer than the sequence space keeps counting
	b := int64(l.blockLocked())
	rel := ti.seq - l.isn[d] - 1
	s := l.hiEnd[d] + int64(int32(rel-uint32(l.hiEnd[d])))
	e := s + int64(ti.n)
	l.hiEnd[d] = max(l.hiEnd[d], e)
	first, last := ceilDiv(s, b), ceilDiv(e, b) // the block starts in [s, e) are first..last-1
	if first >= last {
		return false
	}
	if l.txCount[d] == nil {
		l.txCount[d] = map[int64]uint32{}
	}
	// A segment that carries k block starts is dropped when any of their draws is below
	// 1-(1-Loss)^(1/k), so the segment, and each block in it, is lost with probability Loss
	// however many messages an engine coalesces. For k = 1 the threshold is Loss.
	q := l.imp.Loss
	if k := last - first; k > 1 {
		q = 1 - math.Pow(1-l.imp.Loss, 1/float64(k))
	}
	lost := false
	// every block whose first byte the segment carries counts this transmission
	for i := first; i < last; i++ {
		l.txCount[d][i]++
		if draw(l.seed, uint64(d), 1, uint64(i), uint64(l.txCount[d][i])) < q {
			lost = true
		}
	}
	return lost
}

// ceilDiv is x/b rounded up, for any sign of x.
func ceilDiv(x, b int64) int64 {
	q := x / b
	if x%b > 0 {
		q++
	}
	return q
}

// Send puts a packet that entered on direction d into the link.
func (l *Link) Send(d int, pkt []byte) {
	now := time.Now()
	ti, ok := parseTCP(pkt)
	ports, seq, n := ti.ports, ti.seq, ti.n
	l.mu.Lock()
	if ok && d == 0 && !l.haveFlow && ti.flags&(flagSYN|flagACK) == flagSYN {
		l.flow, l.haveFlow = ports, true
	}
	ours := ok && l.haveFlow && (d == 0 && ports == l.flow || d == 1 && ports == l.flow<<16|l.flow>>16)
	if ours {
		l.learnLocked(d, ti)
	}
	s := &l.st[d]
	if ours {
		s.Pkts++
	}
	if ours && n > 0 {
		s.DataPkts++
		s.PayloadBytes += int64(n)
		end := seq + uint32(n)
		if s.maxEnd == nil {
			s.maxEnd = map[uint32]uint32{}
		}
		if m, seen := s.maxEnd[ports]; seen && int32(end-m) <= 0 {
			s.Retrans++
		} else {
			s.maxEnd[ports] = end
		}
		if l.imp.OutageAfter > 0 && !l.outCut && d == l.imp.DataDir && s.PayloadBytes >= l.imp.OutageAfter {
			l.outCut = true
			l.outStart, l.outEnd = now, now.Add(l.imp.OutageLen)
		}
		if l.imp.OutageAt > 0 && !l.outCut && d == l.imp.DataDir {
			if l.firstData.IsZero() {
				l.firstData = now
			}
			if now.Sub(l.firstData) >= l.imp.OutageAt {
				l.outCut = true
				l.outStart, l.outEnd = now, now.Add(l.imp.OutageLen)
			}
		}
	}
	if l.outCut && !now.Before(l.outStart) && now.Before(l.outEnd) {
		s.Dropped++
		l.traceLocked(d, now, time.Time{}, "outage", pkt)
		l.mu.Unlock()
		return
	}
	if l.imp.Loss > 0 && l.lostLocked(d, ti, ok, ours) {
		s.Dropped++
		l.traceLocked(d, now, time.Time{}, "loss", pkt)
		l.mu.Unlock()
		return
	}
	dep := now
	if l.imp.RateBps > 0 {
		start := l.free[d]
		if start.Before(now) {
			start = now
		}
		qpk := l.imp.QueuePkts
		if qpk == 0 {
			qpk = 200
		}
		perPkt := time.Duration(int64(1420) * 8 * int64(time.Second) / l.imp.RateBps)
		if start.Sub(now) > time.Duration(qpk)*perPkt {
			s.QDrops++
			l.traceLocked(d, now, time.Time{}, "queue", pkt)
			l.mu.Unlock()
			return
		}
		dep = start.Add(time.Duration(int64(len(pkt)) * 8 * int64(time.Second) / l.imp.RateBps))
		l.free[d] = dep
	}
	at := dep.Add(l.imp.Delay)
	if l.imp.Reorder > 0 && l.rng[d].Float64() < l.imp.Reorder {
		at = at.Add(l.imp.ReorderGap)
	}
	l.traceLocked(d, now, at, "ok", pkt)
	l.mu.Unlock()

	q := &l.q[d]
	q.mu.Lock()
	q.seq++
	heap.Push(&q.h, timed{at: at, seq: q.seq, pkt: pkt})
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (l *Link) run(d int) {
	defer l.wg.Done()
	q := &l.q[d]
	tm := time.NewTimer(time.Hour)
	defer tm.Stop()
	for {
		var due []timed
		var wait time.Duration = time.Hour
		q.mu.Lock()
		now := time.Now()
		for q.h.Len() > 0 && !q.h[0].at.After(now) {
			due = append(due, heap.Pop(&q.h).(timed))
		}
		if q.h.Len() > 0 {
			wait = q.h[0].at.Sub(now)
		}
		q.mu.Unlock()
		for _, it := range due {
			// a halted link delivers nothing more, so Halt returns within one write
			select {
			case <-l.stop:
				return
			default:
			}
			l.deliver[d](it.pkt)
		}
		if len(due) > 0 {
			continue
		}
		if !tm.Stop() {
			select {
			case <-tm.C:
			default:
			}
		}
		tm.Reset(wait)
		select {
		case <-tm.C:
		case <-q.wake:
		case <-l.stop:
			return
		}
	}
}
