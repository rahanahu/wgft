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
	"math/rand"
	"strings"
	"sync"
	"time"
)

// Impair describes the link. Everything is applied per direction, except the outage, which
// cuts both directions.
type Impair struct {
	Delay       time.Duration // one-way delay
	Loss        float64       // random loss probability per packet, each direction
	Reorder     float64       // probability that a packet is held back by ReorderExtra
	ReorderGap  time.Duration
	RateBps     int64         // bits per second per direction; 0 means unlimited
	QueuePkts   int           // drop-tail queue length in packets at the rate limit
	OutageAfter int64         // payload bytes in the data direction before the outage starts; 0 disables
	OutageAt    time.Duration // time after the first payload byte in the data direction; 0 disables
	OutageLen   time.Duration
	DataDir     int // direction (0: A to B, 1: B to A) whose payload bytes trigger the outage
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

	st [2]dirStats

	deliver [2]func([]byte)
	q       [2]struct {
		mu   sync.Mutex
		h    timedHeap
		seq  uint64
		wake chan struct{}
	}
	stop chan struct{}
	wg   sync.WaitGroup
}

func NewLink(imp Impair, seed int64, deliverAB, deliverBA func([]byte)) *Link {
	l := &Link{imp: imp, stop: make(chan struct{}), t0: time.Now()}
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

func (l *Link) Close() {
	close(l.stop)
	l.wg.Wait()
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

// payload parses an IPv4/TCP packet into its two ports, sequence number and payload length. ok
// is false for anything else.
func payload(p []byte) (ports, seq uint32, n int, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 6 {
		return 0, 0, 0, false
	}
	ihl := int(p[0]&15) * 4
	tot := int(binary.BigEndian.Uint16(p[2:4]))
	if tot > len(p) || len(p) < ihl+20 {
		return 0, 0, 0, false
	}
	off := int(p[ihl+12]>>4) * 4
	if ihl+off > tot {
		return 0, 0, 0, false
	}
	return binary.BigEndian.Uint32(p[ihl:]), binary.BigEndian.Uint32(p[ihl+4:]), tot - ihl - off, true
}

// Send puts a packet that entered on direction d into the link.
func (l *Link) Send(d int, pkt []byte) {
	now := time.Now()
	ports, seq, n, ok := payload(pkt)
	l.mu.Lock()
	if ok && d == 0 && !l.haveFlow && len(pkt) > 33 && pkt[int(pkt[0]&15)*4+13]&0x12 == 0x02 {
		l.flow, l.haveFlow = ports, true
	}
	ours := ok && l.haveFlow && (d == 0 && ports == l.flow || d == 1 && ports == l.flow<<16|l.flow>>16)
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
	if l.imp.Loss > 0 && l.rng[d].Float64() < l.imp.Loss {
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
