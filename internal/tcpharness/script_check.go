package tcpharness

import "fmt"

// The static check of a parsed script, after the syntax and before the bindings: each statement's
// argument count, named arguments and result, and each call's function, argument count and named
// arguments. The Rust parser makes the same checks with the same kinds.

// verbSig is a statement's shape: at least min and at most max positional arguments after its ID,
// the named arguments it takes, and whether it gives a result to bind with ->.
type verbSig struct {
	min, max int
	named    []string
	result   bool
}

var dialNamed = []string{"syn", "window", "syn_window", "ack_delay"}

// verbSigs lists every statement with arguments; let, set, if, else, end, stop, check, require,
// measure and log have their own syntax.
var verbSigs = map[string]verbSig{
	"listen":         {2, 2, nil, true},
	"connect":        {3, 3, dialNamed, false},
	"handshake":      {2, 2, dialNamed, false},
	"accept":         {2, 2, nil, false},
	"peer":           {2, 2, nil, false},
	"reincarnate":    {2, 2, []string{"iss", "ts_base"}, false},
	"adopt":          {3, 3, nil, false},
	"send":           {2, 2, nil, false},
	"send_data":      {2, 2, nil, false},
	"send_ack":       {1, 1, nil, false},
	"send_fin":       {1, 2, nil, false},
	"send_fresh_ack": {1, 1, nil, true},
	"await":          {2, 2, []string{"match"}, true},
	"quiet":          {2, 2, nil, true},
	"quiet_since":    {5, 5, nil, true},
	"collect":        {1, 1, nil, true},
	"write":          {2, 2, nil, true},
	"read":           {3, 3, nil, true},
	"close":          {1, 1, nil, false},
	"close_write":    {1, 1, nil, false},
	"abort":          {1, 1, nil, false},
	"alive":          {2, 2, nil, false},
	"delivered":      {1, 1, nil, false},
	"recv":           {3, 3, nil, true},

	"collect_flow":      {2, 2, []string{"until"}, true},
	"flight":            {4, 4, nil, true},
	"burst":             {1, 1, nil, true},
	"at_once":           {1, 1, nil, true},
	"listen_udp":        {2, 2, nil, false},
	"udp_read":          {2, 2, nil, true},
	"udp_write":         {2, 2, []string{"to"}, true},
	"inject_ip":         {1, 1, nil, false},
	"inject_icmp_error": {1, 1, nil, false},
	"await_ip":          {1, 1, []string{"match"}, true},
	"await_datagram":    {1, 1, []string{"match"}, true},
	"echo":              {4, 4, []string{"cuts"}, true},
}

// funcSig is a function's argument count; only with takes named arguments.
type funcSig struct{ min, max int }

var funcSigs = map[string]funcSig{
	"yes_no": {3, 3}, "clocked": {2, 2},
	"is_data": {1, 1}, "is_pure_ack": {1, 1}, "is_fin": {1, 1}, "is_rst": {1, 1}, "is_synack": {1, 1},
	"has": {2, 2}, "acks": {2, 2},
	"len": {1, 1}, "count": {1, 1}, "first": {2, 2}, "filter": {2, 2}, "any": {2, 2}, "max_of": {2, 2}, "sum_of": {2, 2},
	"pattern": {2, 2}, "seq": {1, 1}, "int": {1, 1}, "text": {1, 1}, "ms": {1, 1}, "block": {2, 2}, "ts": {2, 2}, "ts_val": {1, 1},
	"opts_standard": {0, 0}, "opts_nosack": {0, 0}, "opts_none": {0, 0},
	"segment": {3, 4}, "raw": {3, 3}, "syn": {2, 2}, "with": {1, 1},
	"seg_desc": {1, 2}, "ack_desc": {2, 3}, "sack_desc": {2, 3}, "synack_desc": {2, 3},
	"err_kind": {1, 1}, "err_string": {1, 1}, "quote": {1, 1},

	"list": {0, 1 << 16}, "max": {2, 2}, "zeros": {1, 1}, "addr": {1, 1}, "addrport": {2, 2}, "with_port": {2, 2},
	"seg_size": {1, 1}, "wire": {1, 1}, "wire_len": {1, 1},
	"udp": {4, 4}, "icmp": {7, 7}, "fragments": {1, 1 << 16}, "fragments_every": {2, 2}, "frag": {3, 3},
	"frag_needed": {3, 3}, "corrupt": {3, 3}, "set_bytes": {3, 3},
	"to_peer": {1, 1}, "icmp_type": {1, 1}, "parse_udp": {1, 1}, "parse_icmp": {1, 1}, "parse_quote": {1, 1},
	"reply_desc": {3, 3}, "pmtu_desc": {1, 1}, "seg_descs": {1, 1}, "seconds_text": {2, 2},
}

// requiredNamed are the named arguments a statement cannot do without.
var requiredNamed = map[string]string{
	"reincarnate": "iss", "udp_write": "to", "await_ip": "match", "await_datagram": "match",
}

func checkStatic(file string, body []*Stmt) error {
	for _, st := range body {
		errf := func(kind, format string, args ...any) error {
			return &ScriptError{File: file, Line: st.Line, Kind: kind, Msg: fmt.Sprintf(format, args...)}
		}
		if sig, ok := verbSigs[st.Verb]; ok {
			if n := len(st.Args); n < sig.min || n > sig.max {
				if sig.min == sig.max {
					return errf(KindArity, "%s takes %d arguments; got %d", st.Verb, sig.min, n)
				}
				return errf(KindArity, "%s takes %d to %d arguments; got %d", st.Verb, sig.min, sig.max, n)
			}
			for _, k := range sortedKeys(st.Named) {
				if !contains(sig.named, k) {
					return errf(KindNamedArgument, "%s does not take %s=", st.Verb, k)
				}
			}
			if st.Bind != "" && !sig.result {
				return errf(KindBind, "%s gives no result to bind with ->", st.Verb)
			}
		}
		for verb, need := range requiredNamed {
			if st.Verb == verb && st.Named[need] == nil {
				return errf(KindNamedArgument, "%s needs %s=", verb, need)
			}
		}
		exprs := append([]*Expr{}, st.Args...)
		for _, k := range sortedKeys(st.Named) {
			exprs = append(exprs, st.Named[k])
		}
		for _, part := range append(append([]TmplPart{}, st.What...), st.Got...) {
			if part.Expr != nil {
				exprs = append(exprs, part.Expr)
			}
		}
		for _, e := range exprs {
			if kind, msg := checkCalls(e); kind != "" {
				return errf(kind, "%s", msg)
			}
		}
		if err := checkStatic(file, st.Then); err != nil {
			return err
		}
		if err := checkStatic(file, st.Else); err != nil {
			return err
		}
	}
	return nil
}

// checkCalls checks every call in e and returns the kind and message of the first error.
func checkCalls(e *Expr) (string, string) {
	if e == nil {
		return "", ""
	}
	if e.Kind == "call" {
		sig, ok := funcSigs[e.Name]
		if !ok {
			return KindUnknownFunction, fmt.Sprintf("unknown function %s", e.Name)
		}
		if n := len(e.Args); n < sig.min || n > sig.max {
			return KindArity, fmt.Sprintf("%s takes %s arguments; got %d", e.Name, argRange(sig), n)
		}
		if len(e.Named) > 0 && e.Name != "with" {
			return KindNamedArgument, fmt.Sprintf("%s takes no named arguments", e.Name)
		}
	}
	for _, a := range e.Args {
		if k, m := checkCalls(a); k != "" {
			return k, m
		}
	}
	for _, k := range sortedKeys(e.Named) {
		if k2, m := checkCalls(e.Named[k]); k2 != "" {
			return k2, m
		}
	}
	return "", ""
}

func argRange(s funcSig) string {
	if s.min == s.max {
		return fmt.Sprint(s.min)
	}
	return fmt.Sprintf("%d to %d", s.min, s.max)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
