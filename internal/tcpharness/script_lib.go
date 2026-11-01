package tcpharness

import (
	"net/netip"
	"strconv"
)

// The functions of the scenario script language. The describers return the same text as the Go
// scenarios' helpers, which the expected-difference lists match.

func (in *interp) call(e *Expr, local map[string]any) any {
	n := len(e.Args)
	arg := func(i int) any { return in.eval(e.Args[i], local) }
	// okArg is the optional argument that overrides a capture's ok, as the Go describers take it.
	okArg := func(i int, s *segv) bool {
		if n > i {
			return in.truth(arg(i))
		}
		return s.ok
	}
	switch e.Name {
	// Lazy: only the chosen branch is evaluated.
	case "yes_no":
		if in.truth(arg(0)) {
			return arg(1)
		}
		return arg(2)
	case "clocked":
		if _, ok := in.h.DUT.(ClockedDUT); ok {
			return arg(0)
		}
		return arg(1)

	// Predicates on a segment.
	case "is_data":
		return isData(in.seg(arg(0)).seg)
	case "is_pure_ack":
		return isPureAck(in.seg(arg(0)).seg)
	case "is_fin":
		return isFIN(in.seg(arg(0)).seg)
	case "is_rst":
		return isRST(in.seg(arg(0)).seg)
	case "is_synack":
		return in.seg(arg(0)).seg.Has(FlagSYN | FlagACK)
	case "has":
		return in.seg(arg(0)).seg.Has(uint8(in.int(arg(1))))
	case "acks":
		return acks(uint32(in.seq(arg(1))))(in.seg(arg(0)).seg)

	// Lists.
	case "len":
		switch v := arg(0).(type) {
		case []byte:
			return int64(len(v))
		case []any:
			return int64(len(v))
		}
		in.failf("len takes bytes or a list")
	case "count":
		return int64(len(in.list(arg(0))))
	case "first", "filter", "any":
		l := in.list(arg(0))
		var out []any
		for _, x := range l {
			if in.truth(in.eval(e.Args[1], withS(local, x))) {
				switch e.Name {
				case "first":
					return x
				case "any":
					return true
				}
				out = append(out, x)
			}
		}
		switch e.Name {
		case "first":
			return &segv{}
		case "any":
			return false
		}
		return out
	case "max_of", "sum_of":
		var acc int64
		for i, x := range in.list(arg(0)) {
			v := in.int(in.eval(e.Args[1], withS(local, x)))
			switch {
			case e.Name == "sum_of":
				acc += v
			case i == 0 || v > acc:
				acc = v
			}
		}
		return acc

	// Values.
	case "pattern":
		return pattern(int(in.count(arg(0))), byte(in.int(arg(1))))
	case "seq":
		return seqv(uint32(in.int(arg(0))))
	case "int":
		return int64(in.seq(arg(0)))
	case "text":
		return []byte(in.text(arg(0)))
	case "ms":
		return in.dur(arg(0)).Milliseconds()
	case "block":
		return SACKBlock{uint32(in.seq(arg(0))), uint32(in.seq(arg(1)))}
	case "ts":
		return &tsv{uint32(in.seq(arg(0))), uint32(in.seq(arg(1)))}
	case "ts_val":
		return seqv(in.peer(arg(0)).p.TSVal())

	// Options and segments.
	case "opts_standard":
		return optsv{StandardSYN()}
	case "opts_nosack":
		return optsv{NoSACKSYN()}
	case "opts_none":
		return optsv{NoOptions()}
	case "segment":
		p := in.peer(arg(0)).p
		var b []byte
		if n == 4 {
			b = in.bytes(arg(3))
		}
		return &segv{seg: p.Segment(uint8(in.int(arg(1))), uint32(in.seq(arg(2))), b), ok: true}
	case "raw":
		p := in.peer(arg(0)).p
		return &segv{seg: Segment{Src: p.Local, Dst: p.Remote, Seq: uint32(in.seq(arg(2))), Flags: uint8(in.int(arg(1)))}, ok: true}
	case "syn":
		p := in.peer(arg(0)).p
		return &segv{seg: Segment{Src: p.Local, Dst: p.Remote, Seq: p.ISS, Flags: FlagSYN, Window: 65535, Opts: in.opts(arg(1))}, ok: true}
	case "with":
		return in.with(arg(0), e, local)

	// Describers.
	case "seg_desc":
		s := in.seg(arg(0))
		return []byte(segDesc(s.seg, okArg(1, s)))
	case "ack_desc", "sack_desc":
		s := in.seg(arg(0))
		base := uint32(in.seq(arg(1)))
		if e.Name == "ack_desc" {
			return []byte(ackDesc(s.seg, okArg(2, s), base))
		}
		return []byte(sackDesc(s.seg, okArg(2, s), base))
	case "synack_desc":
		s := in.seg(arg(1))
		return []byte(synackString(in.peer(arg(0)).p, s.seg, okArg(2, s)))
	case "err_kind":
		switch v := arg(0).(type) {
		case nil:
			return []byte(errKind(nil))
		case errv:
			return []byte(errKind(v.err))
		}
		in.failf("err_kind takes an error or none")
	case "err_string":
		switch v := arg(0).(type) {
		case nil:
			return []byte(errString(nil))
		case errv:
			return []byte(errString(v.err))
		}
		in.failf("err_string takes an error or none")
	case "quote":
		return []byte(strconv.Quote(string(in.bytes(arg(0)))))
	}
	in.failf("unknown function %s", e.Name)
	return nil
}

// with returns a copy of a segment or options value with the named fields replaced.
func (in *interp) with(x any, e *Expr, local map[string]any) any {
	switch v := x.(type) {
	case *segv:
		cp := *v
		cp.seg.Opts = copyOptions(v.seg.Opts)
		cp.seg.Payload = append([]byte(nil), v.seg.Payload...)
		for _, k := range sortedKeys(e.Named) {
			val := in.eval(e.Named[k], local)
			switch k {
			case "seq":
				cp.seg.Seq = uint32(in.seq(val))
			case "ack":
				cp.seg.Ack = uint32(in.seq(val))
			case "flags":
				cp.seg.Flags = uint8(in.int(val))
			case "window":
				cp.seg.Window = uint16(in.int(val))
			case "payload":
				cp.seg.Payload = in.bytes(val)
			case "opts":
				cp.seg.Opts = copyOptions(in.opts(val))
			case "ts_val":
				if cp.seg.Opts.TS == nil {
					in.failf("with ts_val= on a segment without timestamps")
				}
				cp.seg.Opts.TS.Val = uint32(in.seq(val))
			case "src", "dst":
				ap, ok := val.(netip.AddrPort)
				if !ok {
					in.failf("%s= takes an address and port", k)
				}
				if k == "src" {
					cp.seg.Src = ap
				} else {
					cp.seg.Dst = ap
				}
			default:
				in.failf("with does not set a segment's %s", k)
			}
		}
		return &cp
	case optsv:
		o := copyOptions(v.o)
		for _, k := range sortedKeys(e.Named) {
			val := in.eval(e.Named[k], local)
			switch k {
			case "mss":
				if val == nil {
					o.MSS = nil
				} else {
					m := uint16(in.int(val))
					o.MSS = &m
				}
			case "ws":
				o.WS = int(in.int(val))
			case "sack_permitted":
				o.SACKPermitted = in.truth(val)
			case "ts":
				if val == nil {
					o.TS = nil
				} else {
					t, ok := val.(*tsv)
					if !ok {
						in.failf("ts= takes ts(val, ecr) or none")
					}
					o.TS = &Timestamps{t.val, t.ecr}
				}
			default:
				in.failf("with does not set an option %s", k)
			}
		}
		return optsv{o}
	}
	in.failf("with takes a segment or options, not %s", typeName(x))
	return nil
}

// copyOptions copies o so a with() on the copy cannot change the original.
func copyOptions(o Options) Options {
	if o.MSS != nil {
		m := *o.MSS
		o.MSS = &m
	}
	if o.TS != nil {
		t := *o.TS
		o.TS = &t
	}
	o.SACK = append([]SACKBlock(nil), o.SACK...)
	if len(o.SACK) == 0 {
		o.SACK = nil
	}
	return o
}

func (in *interp) list(v any) []any {
	l, ok := v.([]any)
	if !ok {
		if v == nil {
			return nil
		}
		in.failf("a list is expected, not %s", typeName(v))
	}
	return l
}

func withS(local map[string]any, s any) map[string]any {
	out := make(map[string]any, len(local)+1)
	for k, v := range local {
		out[k] = v
	}
	out["s"] = s
	return out
}
