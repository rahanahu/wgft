//go:build qbench

// Package qbench is a rough in-process TCP quality benchmark that compares wgstack with the
// gVisor netstack in internal/nettun over an impaired in-memory link. It is test-only (every
// file is a _test.go file behind the qbench build tag) and is run by hand:
//
//	go test -tags qbench -run TestQBench -timeout 90m -v ./internal/tcpharness/qbench
package qbench

import (
	"container/heap"
	"encoding/binary"
	"math/rand"
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
	RateBps     int64 // bits per second per direction; 0 means unlimited
	QueuePkts   int   // drop-tail queue length in packets at the rate limit
	OutageAfter int64 // payload bytes in the data direction before the outage starts; 0 disables
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
	Retrans         int // data segments whose sequence range was already sent
	PayloadBytes    int64
	maxEnd          uint32
	haveEnd         bool
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

// payload parses an IPv4/TCP packet. ok is false for anything else.
func payload(p []byte) (seq uint32, n int, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 6 {
		return 0, 0, false
	}
	ihl := int(p[0]&15) * 4
	tot := int(binary.BigEndian.Uint16(p[2:4]))
	if tot > len(p) || len(p) < ihl+20 {
		return 0, 0, false
	}
	off := int(p[ihl+12]>>4) * 4
	if ihl+off > tot {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(p[ihl+4:]), tot - ihl - off, true
}

// Send puts a packet that entered on direction d into the link.
func (l *Link) Send(d int, pkt []byte) {
	now := time.Now()
	seq, n, ok := payload(pkt)
	l.mu.Lock()
	s := &l.st[d]
	s.Pkts++
	if ok && n > 0 {
		s.DataPkts++
		s.PayloadBytes += int64(n)
		end := seq + uint32(n)
		if s.haveEnd && int32(end-s.maxEnd) <= 0 {
			s.Retrans++
		} else {
			s.maxEnd, s.haveEnd = end, true
		}
		if l.imp.OutageAfter > 0 && !l.outCut && d == l.imp.DataDir && s.PayloadBytes >= l.imp.OutageAfter {
			l.outCut = true
			l.outStart, l.outEnd = now, now.Add(l.imp.OutageLen)
		}
	}
	if l.outCut && !now.Before(l.outStart) && now.Before(l.outEnd) {
		s.Dropped++
		l.mu.Unlock()
		return
	}
	if l.imp.Loss > 0 && l.rng[d].Float64() < l.imp.Loss {
		s.Dropped++
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
