package tcpharness

import (
	"sort"
	"time"
)

// receiver models the testbench's receive side for the loss-recovery scenarios: it keeps every
// byte that arrived, the cumulative point and the SACK blocks in RFC 2018's order, most recently
// changed first, and builds the ACKs a receiver would send.
type receiver struct {
	p      *Peer
	base   uint32            // the first data sequence number
	cum    uint32            // the next byte expected in order
	got    map[uint32][]byte // by sequence number, as received
	blocks []SACKBlock       // above cum, most recently changed first
}

func newReceiver(p *Peer) *receiver {
	return &receiver{p: p, base: p.RcvNxt, cum: p.RcvNxt, got: map[uint32][]byte{}}
}

func after(a, b uint32) bool { return int32(a-b) > 0 }

// take records a data segment as having arrived.
func (r *receiver) take(s Segment) {
	if len(s.Payload) == 0 {
		return
	}
	if old, ok := r.got[s.Seq]; !ok || len(old) < len(s.Payload) {
		r.got[s.Seq] = s.Payload
	}
	l, rt := s.Seq, s.Seq+uint32(len(s.Payload))
	if !after(rt, r.cum) {
		return
	}
	if !after(l, r.cum) {
		r.cum = rt
	} else {
		nb := SACKBlock{l, rt}
		var rest []SACKBlock
		for _, b := range r.blocks {
			if !after(b.Left, nb.Right) && !after(nb.Left, b.Right) { // overlap or touch
				nb = SACKBlock{min32(b.Left, nb.Left), max32(b.Right, nb.Right)}
				continue
			}
			rest = append(rest, b)
		}
		r.blocks = append([]SACKBlock{nb}, rest...)
	}
	// the cumulative point swallows blocks that now touch it
	for moved := true; moved; {
		moved = false
		var rest []SACKBlock
		for _, b := range r.blocks {
			switch {
			case !after(b.Left, r.cum) && after(b.Right, r.cum):
				r.cum = b.Right
				moved = true
			case !after(b.Right, r.cum):
			default:
				rest = append(rest, b)
			}
		}
		r.blocks = rest
	}
}

func min32(a, b uint32) uint32 {
	if after(a, b) {
		return b
	}
	return a
}

func max32(a, b uint32) uint32 {
	if after(a, b) {
		return a
	}
	return b
}

// ack builds the ACK the receiver would send now, echoing ecr in its timestamps.
func (r *receiver) ack(ecr uint32) Segment {
	r.p.RcvNxt = r.cum
	s := r.p.Segment(FlagACK, r.p.SndNxt, nil)
	if s.Opts.TS != nil {
		s.Opts.TS.Ecr = ecr
	}
	if r.p.SACK {
		n := min(len(r.blocks), 3)
		s.Opts.SACK = append([]SACKBlock(nil), r.blocks[:n]...)
	}
	return s
}

// stream returns the bytes received from base on, in order, up to n bytes.
func (r *receiver) stream(n int) []byte {
	var out []byte
	keys := make([]uint32, 0, len(r.got))
	for k := range r.got {
		keys = append(keys, k-r.base)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		b := r.got[k+r.base]
		if int(k) > len(out) {
			break
		}
		if end := int(k) + len(b); end > len(out) {
			out = append(out, b[len(out)-int(k):]...)
		}
		if len(out) >= n {
			return out[:n]
		}
	}
	return out
}

// loop runs scheduled testbench actions against the scenario's clock while handling the DUT's
// segments as they come, so a scenario can answer each segment after a path delay.
type loop struct {
	h  *H
	ev []event
}

type event struct {
	at time.Time
	fn func()
}

// after schedules fn d from now on the scenario's clock.
func (l *loop) after(d time.Duration, fn func()) {
	l.ev = append(l.ev, event{l.h.Now().Add(d), fn})
}

// run hands each segment of p's flow to on and fires the due events, until d has passed or done
// reports true.
func (l *loop) run(p *Peer, d time.Duration, on func(Segment), done func() bool) {
	end := l.h.Now().Add(d)
	for !done() {
		now := l.h.Now()
		if !now.Before(end) {
			return
		}
		wait := end.Sub(now)
		for _, e := range l.ev {
			if w := e.at.Sub(now); w < wait {
				wait = max(w, 0)
			}
		}
		if s, ok := p.Next(wait); ok {
			on(s)
		}
		now = l.h.Now()
		var rest []event
		var due []event
		for _, e := range l.ev {
			if !e.at.After(now) {
				due = append(due, e)
			} else {
				rest = append(rest, e)
			}
		}
		sort.SliceStable(due, func(i, j int) bool { return due[i].at.Before(due[j].at) })
		l.ev = rest
		for _, e := range due {
			e.fn()
		}
	}
}
