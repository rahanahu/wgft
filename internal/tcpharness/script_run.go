package tcpharness

import (
	"bytes"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// This file runs a parsed Script on an H: the Go runner of docs/design/v2/test-tooling.md. Each
// statement calls the H and Peer operation or the helper the Go scenarios call, so a script and
// the Go function it replaces drive a DUT the same way.

// Values. A script value is one of: int64, bool, []byte, time.Duration, time.Time, seqv,
// netip.Addr, netip.AddrPort, *segv, Options (optsv), *tsv, SACKBlock, []any, *peerv, *listenerv,
// Conn, error, *recordv, or nil for none.
type (
	seqv uint32
	tsv  struct{ val, ecr uint32 }
	// segv is a segment and, for a capture, whether it was seen and when.
	segv struct {
		seg Segment
		ok  bool
		at  time.Time
	}
	optsv struct{ o Options }
	peerv struct {
		p      *Peer
		synack *segv
		conn   Conn
	}
	listenerv struct {
		l      Listener
		closed bool
	}
	recordv struct {
		name   string
		fields map[string]any
	}
	errv struct{ err error } // a non-nil error; a nil error is none
)

// scriptFail ends the scenario on a script error, the way a panic in a Go scenario would.
type scriptFail struct{ msg string }

type interp struct {
	h    *H
	file string
	vars map[string]any
	line int
}

// runScript runs s on h.
func runScript(h *H, file string, s *Script) {
	h.T.Helper()
	in := &interp{h: h, file: file, vars: map[string]any{}}
	defer func() {
		if r := recover(); r != nil {
			f, ok := r.(scriptFail)
			if !ok {
				panic(r)
			}
			h.T.Fatalf("script %s:%d: %s", file, in.line, f.msg)
		}
	}()
	in.block(s.Body)
}

func (in *interp) failf(format string, args ...any) {
	panic(scriptFail{fmt.Sprintf(format, args...)})
}

func (in *interp) block(body []*Stmt) bool {
	for _, st := range body {
		in.line = st.Line
		if !in.stmt(st) {
			return false
		}
	}
	return true
}

// stmt runs one statement and reports whether the script goes on.
func (in *interp) stmt(st *Stmt) bool {
	h := in.h
	h.T.Helper()
	arg := func(i int) any {
		if i >= len(st.Args) {
			in.failf("%s needs at least %d arguments", st.Verb, i+1)
		}
		return in.eval(st.Args[i], nil)
	}
	named := func(k string) (any, bool) {
		e, ok := st.Named[k]
		if !ok {
			return nil, false
		}
		return in.eval(e, nil), true
	}
	bind := func(v any) {
		if st.Bind != "" {
			in.vars[st.Bind] = v
		}
	}
	first := func() string { return st.Args[0].Name }
	in.checkNamed(st)
	switch st.Verb {
	case "stop":
		return false
	case "if":
		if in.truth(arg(0)) {
			return in.block(st.Then)
		}
		return in.block(st.Else)
	case "let":
		in.vars[st.Bind] = arg(0)
	case "set":
		obj, field, _ := strings.Cut(st.Bind, ".")
		pv, ok := in.vars[obj].(*peerv)
		if !ok {
			in.failf("set works on a peer's fields; %s is %s", obj, typeName(in.vars[obj]))
		}
		in.setPeer(pv, field, arg(0))
	case "listen":
		port := in.port(arg(1))
		l, err := h.DUT.Listen(port)
		if st.Bind == "" && err != nil {
			h.T.Fatalf("listen on %d: %v", port, err)
		}
		if err != nil {
			in.vars[first()] = nil
			bind(errv{err})
			break
		}
		lv := &listenerv{l: l}
		h.T.Cleanup(func() {
			if !lv.closed {
				l.Close()
			}
		})
		in.vars[first()] = lv
		bind(nil)
	case "connect", "handshake":
		d := in.dial(st)
		var pv *peerv
		if st.Verb == "connect" {
			l := in.listener(arg(1))
			p, sa, c := h.ConnectWith(l.l, in.port(arg(2)), d)
			pv = &peerv{p: p, synack: &segv{seg: sa, ok: true, at: h.Now()}, conn: c}
		} else {
			p, sa := h.Handshake(in.port(arg(1)), d)
			pv = &peerv{p: p, synack: &segv{seg: sa, ok: true, at: h.Now()}}
		}
		in.vars[first()] = pv
	case "accept":
		in.vars[first()] = h.Accept(in.listener(arg(1)).l)
	case "peer":
		in.vars[first()] = &peerv{p: h.NewPeer(in.port(arg(1)))}
	case "reincarnate":
		old := in.peer(arg(1))
		iss, ok := named("iss")
		if !ok {
			in.failf("reincarnate needs iss=")
		}
		q := old.p.Reincarnate(uint32(in.seq(iss)))
		if v, ok := named("ts_base"); ok {
			q.tsBase = uint32(in.seq(v))
		}
		in.vars[first()] = &peerv{p: q}
	case "adopt":
		pv := in.peer(arg(0))
		pv.p.adopt(in.opts(arg(1)), in.seg(arg(2)).seg)
	case "send":
		in.peer(arg(0)).p.Send(in.seg(arg(1)).seg)
	case "send_data":
		in.peer(arg(0)).p.SendData(in.bytes(arg(1)))
	case "send_ack":
		in.peer(arg(0)).p.SendAck()
	case "send_fin":
		var b []byte
		if len(st.Args) > 1 {
			b = in.bytes(arg(1))
		}
		in.peer(arg(0)).p.SendFIN(b)
	case "send_fresh_ack":
		bind(seqv(in.peer(arg(0)).p.SendFreshAck()))
	case "await":
		p := in.peer(arg(0)).p
		d := in.dur(arg(1))
		var s Segment
		var ok bool
		if e, has := st.Named["match"]; has {
			pred := in.predicate(e)
			s, ok = p.Await(d, func(c Segment) bool { return pred(&segv{seg: c, ok: true}) })
		} else {
			s, ok = p.Next(d)
		}
		bind(&segv{seg: s, ok: ok, at: h.Now()})
	case "quiet":
		s, quiet := in.peer(arg(0)).p.Quiet(in.dur(arg(1)))
		bind(&recordv{name: "quiet", fields: map[string]any{"quiet": quiet, "seg": &segv{seg: s, ok: !quiet, at: h.Now()}}})
	case "quiet_since":
		p := in.peer(arg(0)).p
		f := in.seg(arg(3))
		s, quiet, stale, timedOut := p.QuietSince(in.dur(arg(1)), uint32(in.seq(arg(2))), f.seg, f.at, in.conn(arg(4)))
		desc := segDesc(s, !quiet)
		if timedOut {
			desc = fmt.Sprintf("no segment, and Delivered not reported within %v of the ACK", settleBudget)
		}
		bind(&recordv{name: "quiet_since", fields: map[string]any{"quiet": quiet, "stale": int64(stale), "timed_out": timedOut,
			"seg": &segv{seg: s, ok: !quiet, at: h.Now()}, "desc": []byte(desc)}})
	case "collect":
		var out []any
		for _, s := range h.Collect(in.dur(arg(0))) {
			out = append(out, &segv{seg: s, ok: true})
		}
		bind(out)
	case "write":
		c := in.conn(arg(0))
		n, err := c.Write(in.bytes(arg(1)))
		if st.Bind == "" && err != nil {
			h.T.Fatalf("write: %v", err)
		}
		bind(&recordv{name: "write", fields: map[string]any{"n": int64(n), "err": wrapErr(err)}})
	case "read":
		got, err := readFull(in.conn(arg(0)), int(in.int(arg(1))), in.dur(arg(2)))
		bind(&recordv{name: "read", fields: map[string]any{"data": got, "err": wrapErr(err)}})
	case "close":
		switch v := arg(0).(type) {
		case *listenerv:
			v.closed = true
			v.l.Close()
		case Conn:
			v.Close()
		default:
			in.failf("close takes a listener or a connection, not %s", typeName(v))
		}
	case "close_write":
		if err := in.conn(arg(0)).CloseWrite(); err != nil {
			h.T.Fatalf("CloseWrite: %v", err)
		}
	case "abort":
		in.conn(arg(0)).Abort()
	case "check", "require":
		ok := in.truth(arg(0))
		what, got := in.template(st.What), in.template(st.Got)
		if st.Verb == "check" {
			h.Check(st.ID, ok, what, got)
		} else {
			h.Require(st.ID, ok, what, got)
		}
	case "measure":
		h.Measure(st.ID, measureValue(arg(0)))
	case "log":
		h.T.Logf("%s", in.template(st.What))
	case "alive":
		pv := in.peer(arg(0))
		alive(h, st.ID, pv.p, in.conn(arg(1)))
	case "delivered":
		delivered(h, st.ID, in.conn(arg(0)))
	case "recv":
		got, dups, maxLen := receiveMax(in.peer(arg(0)).p, int(in.int(arg(1))), in.dur(arg(2)))
		bind(&recordv{name: "recv", fields: map[string]any{"data": got, "dups": int64(dups), "max_len": int64(maxLen)}})
	default:
		in.failf("statement %s is not implemented", st.Verb)
	}
	return true
}

// checkNamed rejects named arguments a statement does not take.
func (in *interp) checkNamed(st *Stmt) {
	allowed := map[string][]string{
		"connect": {"syn", "window", "syn_window", "ack_delay"}, "handshake": {"syn", "window", "syn_window", "ack_delay"},
		"reincarnate": {"iss", "ts_base"}, "await": {"match"},
	}
	for k := range st.Named {
		ok := false
		for _, a := range allowed[st.Verb] {
			ok = ok || a == k
		}
		if !ok {
			in.failf("%s does not take %s=", st.Verb, k)
		}
	}
}

func (in *interp) dial(st *Stmt) Dial {
	d := Dial{SYN: NoOptions()}
	for k, e := range st.Named {
		v := in.eval(e, nil)
		switch k {
		case "syn":
			d.SYN = in.opts(v)
		case "window":
			d.Window = uint16(in.int(v))
		case "syn_window":
			d.SynWindow = uint16(in.int(v))
		case "ack_delay":
			d.AckDelay = in.dur(v)
		}
	}
	return d
}

func (in *interp) setPeer(pv *peerv, field string, v any) {
	p := pv.p
	switch field {
	case "snd_nxt":
		p.SndNxt = uint32(in.seq(v))
	case "rcv_nxt":
		p.RcvNxt = uint32(in.seq(v))
	case "window":
		p.Window = uint16(in.int(v))
	case "ws":
		p.WS = int(in.int(v))
	default:
		in.failf("set does not write a peer's %s", field)
	}
}

// template renders a template's parts.
func (in *interp) template(t []TmplPart) string {
	var b strings.Builder
	for _, p := range t {
		if p.Expr == nil {
			b.WriteString(p.Text)
			continue
		}
		b.WriteString(in.text(in.eval(p.Expr, nil)))
	}
	return b.String()
}

// text formats a value inside a template.
func (in *interp) text(v any) string {
	switch x := v.(type) {
	case int64:
		return strconv.FormatInt(x, 10)
	case seqv:
		return strconv.FormatUint(uint64(x), 10)
	case bool:
		return strconv.FormatBool(x)
	case []byte:
		return string(x)
	}
	in.failf("a template cannot show %s", typeName(v))
	return ""
}

// measureValue gives Measure the value a Go scenario passes: bytes as a string.
func measureValue(v any) any {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case seqv:
		return uint32(x)
	case nil:
		return "none"
	}
	return v
}

func wrapErr(err error) any {
	if err == nil {
		return nil
	}
	return errv{err}
}

// predicate compiles a match= expression: s is the candidate. Outer names keep the values they
// had when the statement started.
func (in *interp) predicate(e *Expr) func(*segv) bool {
	frozen := make(map[string]any, len(in.vars))
	for k, v := range in.vars {
		frozen[k] = snapshot(v)
	}
	return func(s *segv) bool {
		saved := in.vars
		in.vars = frozen
		defer func() { in.vars = saved }()
		return in.truth(in.eval(e, map[string]any{"s": s}))
	}
}

// snapshot copies a peer's fields, so a predicate reads them as they were when it was made.
func snapshot(v any) any {
	if pv, ok := v.(*peerv); ok {
		cp := *pv.p
		return &peerv{p: &cp, synack: pv.synack, conn: pv.conn}
	}
	return v
}

// Evaluation.

func (in *interp) eval(e *Expr, local map[string]any) any {
	switch e.Kind {
	case "int":
		return e.Int
	case "dur":
		return time.Duration(e.Int)
	case "str":
		return append([]byte(nil), e.Str...)
	case "name":
		if v, ok := local[e.Name]; ok {
			return v
		}
		if v, ok := in.constant(e.Name); ok {
			return v
		}
		v, ok := in.vars[e.Name]
		if !ok {
			in.failf("%s is not bound", e.Name)
		}
		return v
	case "field":
		return in.field(in.eval(e.Args[0], local), e.Name)
	case "index":
		x, i := in.eval(e.Args[0], local), in.int(in.eval(e.Args[1], local))
		switch l := x.(type) {
		case []any:
			if i < 0 || int(i) >= len(l) {
				in.failf("index %d out of range of %d", i, len(l))
			}
			return l[i]
		case []byte:
			if i < 0 || int(i) >= len(l) {
				in.failf("index %d out of range of %d", i, len(l))
			}
			return int64(l[i])
		}
		in.failf("cannot index %s", typeName(x))
	case "slice":
		b := in.bytes(in.eval(e.Args[0], local))
		lo, hi := int64(0), int64(len(b))
		if e.Args[1] != nil {
			lo = in.int(in.eval(e.Args[1], local))
		}
		if e.Args[2] != nil {
			hi = in.int(in.eval(e.Args[2], local))
		}
		if lo < 0 || hi < lo || int(hi) > len(b) {
			in.failf("slice [%d:%d] out of range of %d", lo, hi, len(b))
		}
		return append([]byte(nil), b[lo:hi]...)
	case "un":
		x := in.eval(e.Args[0], local)
		if e.Name == "!" {
			return !in.truth(x)
		}
		switch v := x.(type) {
		case int64:
			return -v
		case time.Duration:
			return -v
		}
		in.failf("cannot negate %s", typeName(x))
	case "bin":
		return in.binary(e, local)
	case "call":
		return in.call(e, local)
	}
	in.failf("bad expression %s", e.Kind)
	return nil
}

func (in *interp) constant(name string) (any, bool) {
	switch name {
	case "SYN":
		return int64(FlagSYN), true
	case "FIN":
		return int64(FlagFIN), true
	case "RST":
		return int64(FlagRST), true
	case "PSH":
		return int64(FlagPSH), true
	case "ACK":
		return int64(FlagACK), true
	case "PEER_ADDR":
		return PeerAddr, true
	case "DUT_ADDR":
		return in.h.DUT.Addr(), true
	case "MTU":
		return int64(MTU), true
	case "now":
		return in.h.Now(), true
	case "prompt":
		return in.h.Prompt(), true
	case "none":
		return nil, true
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return nil, false
}

func (in *interp) binary(e *Expr, local map[string]any) any {
	switch e.Name {
	case "&&":
		return in.truth(in.eval(e.Args[0], local)) && in.truth(in.eval(e.Args[1], local))
	case "||":
		return in.truth(in.eval(e.Args[0], local)) || in.truth(in.eval(e.Args[1], local))
	}
	l, r := in.eval(e.Args[0], local), in.eval(e.Args[1], local)
	switch e.Name {
	case "==":
		return in.equal(l, r)
	case "!=":
		return !in.equal(l, r)
	case "<", "<=", ">", ">=":
		c := in.compare(l, r)
		switch e.Name {
		case "<":
			return c < 0
		case "<=":
			return c <= 0
		case ">":
			return c > 0
		}
		return c >= 0
	}
	switch a := l.(type) {
	case int64:
		switch b := r.(type) {
		case int64:
			switch e.Name {
			case "+":
				return a + b
			case "-":
				return a - b
			case "*":
				return a * b
			case "/", "%":
				if b == 0 {
					in.failf("division by zero")
				}
				if e.Name == "/" {
					return a / b
				}
				return a % b
			case "|":
				return a | b
			}
		case seqv:
			if e.Name == "+" {
				return b + seqv(uint32(a))
			}
		case time.Duration:
			if e.Name == "*" {
				return time.Duration(a) * b
			}
		}
	case seqv:
		switch b := r.(type) {
		case int64:
			switch e.Name {
			case "+":
				return a + seqv(uint32(b))
			case "-":
				return a - seqv(uint32(b))
			}
		case seqv:
			if e.Name == "-" {
				return int64(int32(a - b))
			}
		}
	case time.Duration:
		switch b := r.(type) {
		case time.Duration:
			switch e.Name {
			case "+":
				return a + b
			case "-":
				return a - b
			}
		case int64:
			switch e.Name {
			case "*":
				return a * time.Duration(b)
			case "/":
				if b == 0 {
					in.failf("division by zero")
				}
				return a / time.Duration(b)
			}
		}
	case time.Time:
		switch b := r.(type) {
		case time.Time:
			if e.Name == "-" {
				return a.Sub(b)
			}
		case time.Duration:
			if e.Name == "+" {
				return a.Add(b)
			}
		}
	case []byte:
		if b, ok := r.([]byte); ok && e.Name == "+" {
			return append(append([]byte(nil), a...), b...)
		}
	}
	in.failf("%s %s %s is not defined", typeName(l), e.Name, typeName(r))
	return nil
}

func (in *interp) equal(l, r any) bool {
	if l == nil || r == nil {
		return l == nil && r == nil
	}
	switch a := l.(type) {
	case []byte:
		b, ok := r.([]byte)
		if !ok {
			in.failf("bytes == %s is not defined", typeName(r))
		}
		return bytes.Equal(a, b)
	case int64, bool, seqv, netip.Addr, netip.AddrPort, time.Duration, SACKBlock:
		if typeName(l) != typeName(r) {
			in.failf("%s == %s is not defined", typeName(l), typeName(r))
		}
		return l == r
	case *tsv:
		b, ok := r.(*tsv)
		return ok && *a == *b
	case errv:
		return false // a non-nil error equals only none, which the nil case handles
	}
	in.failf("%s == %s is not defined", typeName(l), typeName(r))
	return false
}

func (in *interp) compare(l, r any) int {
	switch a := l.(type) {
	case int64:
		if b, ok := r.(int64); ok {
			return cmp3(a, b)
		}
	case seqv:
		if b, ok := r.(seqv); ok {
			return cmp3(int32(a-b), 0)
		}
	case time.Duration:
		if b, ok := r.(time.Duration); ok {
			return cmp3(a, b)
		}
	case time.Time:
		if b, ok := r.(time.Time); ok {
			return a.Compare(b)
		}
	}
	in.failf("%s and %s do not compare", typeName(l), typeName(r))
	return 0
}

func cmp3[T int64 | int32 | time.Duration](a, b T) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// field reads a field of a value.
func (in *interp) field(x any, name string) any {
	switch v := x.(type) {
	case *segv:
		return in.segField(v, name)
	case *peerv:
		return in.peerField(v, name)
	case *recordv:
		f, ok := v.fields[name]
		if !ok {
			in.failf("the %s result has no field %s", v.name, name)
		}
		return f
	case *tsv:
		switch name {
		case "val":
			return seqv(v.val)
		case "ecr":
			return seqv(v.ecr)
		}
	case SACKBlock:
		switch name {
		case "left":
			return seqv(v.Left)
		case "right":
			return seqv(v.Right)
		}
	case nil:
		in.failf("none has no field %s", name)
	}
	in.failf("%s has no field %s", typeName(x), name)
	return nil
}

func (in *interp) segField(v *segv, name string) any {
	s := v.seg
	switch name {
	case "ok":
		return v.ok
	case "at":
		return v.at
	case "src":
		return s.Src
	case "dst":
		return s.Dst
	case "seq":
		return seqv(s.Seq)
	case "ack":
		return seqv(s.Ack)
	case "flags":
		return int64(s.Flags)
	case "window":
		return int64(s.Window)
	case "len":
		return int64(len(s.Payload))
	case "seq_len":
		return int64(s.Len())
	case "payload":
		return append([]byte(nil), s.Payload...)
	case "mss":
		if s.Opts.MSS == nil {
			return nil
		}
		return int64(*s.Opts.MSS)
	case "ws":
		return int64(s.Opts.WS)
	case "sack_permitted":
		return s.Opts.SACKPermitted
	case "sack":
		out := []any{}
		for _, b := range s.Opts.SACK {
			out = append(out, b)
		}
		return out
	case "ts":
		if s.Opts.TS == nil {
			return nil
		}
		return &tsv{s.Opts.TS.Val, s.Opts.TS.Ecr}
	case "df":
		return s.DF
	case "ttl":
		return int64(s.TTL)
	case "id":
		return int64(s.ID)
	}
	in.failf("a segment has no field %s", name)
	return nil
}

func (in *interp) peerField(v *peerv, name string) any {
	p := v.p
	switch name {
	case "local":
		return p.Local
	case "remote":
		return p.Remote
	case "iss":
		return seqv(p.ISS)
	case "snd_nxt":
		return seqv(p.SndNxt)
	case "dut_iss":
		return seqv(p.DutISS)
	case "rcv_nxt":
		return seqv(p.RcvNxt)
	case "ws":
		return int64(p.WS)
	case "dut_ws":
		return int64(p.DutWS)
	case "window":
		return int64(p.Window)
	case "sack":
		return p.SACK
	case "ts":
		return p.TS
	case "ts_recent":
		return seqv(p.TSRecent)
	case "syn_ts_val":
		return seqv(p.SynTSVal)
	case "dut_ack":
		return seqv(p.DutAck)
	case "dut_window":
		return int64(p.DutWindow)
	case "synack":
		if v.synack == nil {
			in.failf("the peer has no SYN-ACK; connect and handshake record it")
		}
		return v.synack
	case "conn":
		if v.conn == nil {
			in.failf("the peer has no connection; connect records it")
		}
		return v.conn
	}
	in.failf("a peer has no field %s", name)
	return nil
}

// Conversions.

func (in *interp) truth(v any) bool {
	b, ok := v.(bool)
	if !ok {
		in.failf("a condition is bool, not %s", typeName(v))
	}
	return b
}

func (in *interp) int(v any) int64 {
	i, ok := v.(int64)
	if !ok {
		in.failf("an int is expected, not %s", typeName(v))
	}
	return i
}

func (in *interp) seq(v any) seqv {
	switch x := v.(type) {
	case seqv:
		return x
	}
	in.failf("a sequence number is expected, not %s", typeName(v))
	return 0
}

func (in *interp) dur(v any) time.Duration {
	d, ok := v.(time.Duration)
	if !ok {
		in.failf("a duration is expected, not %s", typeName(v))
	}
	return d
}

func (in *interp) bytes(v any) []byte {
	b, ok := v.([]byte)
	if !ok {
		in.failf("bytes are expected, not %s", typeName(v))
	}
	return b
}

func (in *interp) port(v any) uint16 {
	i := in.int(v)
	if i < 1 || i > 65535 {
		in.failf("port %d out of range", i)
	}
	return uint16(i)
}

func (in *interp) peer(v any) *peerv {
	p, ok := v.(*peerv)
	if !ok {
		in.failf("a peer is expected, not %s", typeName(v))
	}
	return p
}

func (in *interp) listener(v any) *listenerv {
	l, ok := v.(*listenerv)
	if !ok {
		in.failf("a listener is expected, not %s", typeName(v))
	}
	return l
}

func (in *interp) conn(v any) Conn {
	c, ok := v.(Conn)
	if !ok {
		in.failf("a connection is expected, not %s", typeName(v))
	}
	return c
}

func (in *interp) seg(v any) *segv {
	s, ok := v.(*segv)
	if !ok {
		in.failf("a segment is expected, not %s", typeName(v))
	}
	return s
}

func (in *interp) opts(v any) Options {
	o, ok := v.(optsv)
	if !ok {
		in.failf("options are expected, not %s", typeName(v))
	}
	return o.o
}

func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "none"
	case int64:
		return "int"
	case bool:
		return "bool"
	case []byte:
		return "bytes"
	case time.Duration:
		return "duration"
	case time.Time:
		return "time"
	case seqv:
		return "seq"
	case netip.Addr:
		return "addr"
	case netip.AddrPort:
		return "addrport"
	case *segv:
		return "segment"
	case optsv:
		return "options"
	case *tsv:
		return "timestamps"
	case SACKBlock:
		return "block"
	case []any:
		return "list"
	case *peerv:
		return "peer"
	case *listenerv:
		return "listener"
	case Conn:
		return "connection"
	case errv:
		return "error"
	case *recordv:
		return "result"
	}
	return fmt.Sprintf("%T", v)
}
