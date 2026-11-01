package tcpharness

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// This file parses the scenario script language of docs/design/v2/test-tooling.md, section 1:
// one statement per line, a header, if/else/end, and a small expression language. The Rust
// runner parses the same files; both parsers must produce the same canonical AST (ScriptAST),
// which the fixtures under scripts/testdata pin.

// Script is one parsed scenario script.
type Script struct {
	Name  string
	Refs  string
	Linux [][2]string
	Body  []*Stmt
}

// Stmt is one statement. Verb is its first word; ID is the check ID of the verbs that take one;
// Args and Named are its arguments; Bind is the name after "->". If holds the condition of an
// if statement, with Then and Else its bodies. What and Got are a check's templates.
type Stmt struct {
	Line  int
	Verb  string
	ID    string
	Args  []*Expr
	Named map[string]*Expr
	Bind  string
	Then  []*Stmt
	Else  []*Stmt
	What  []TmplPart
	Got   []TmplPart
}

// TmplPart is a literal piece of a template, or an interpolated expression.
type TmplPart struct {
	Text string
	Expr *Expr
}

// Expr is one expression node. Kind is one of int, dur, str, name, call, bin, un, field, index.
type Expr struct {
	Kind  string
	Int   int64
	Str   []byte
	Name  string // name, call, field, bin and un operators
	Args  []*Expr
	Named map[string]*Expr // call arguments given as name=expr
}

// The verbs whose first argument is a raw check ID, and those whose rest of line is one
// expression after it.
var (
	idVerbs   = map[string]bool{"check": true, "require": true, "measure": true, "alive": true, "delivered": true}
	exprVerbs = map[string]bool{"check": true, "require": true, "measure": true, "if": true}
	// bindFirst lists the verbs that bind their first argument, which must be a bare name.
	bindFirst = map[string]bool{"listen": true, "connect": true, "handshake": true, "peer": true, "accept": true, "reincarnate": true}
	tmplVerbs = map[string]bool{"check": true, "require": true}
)

// scriptVerbs is every statement verb the language has.
var scriptVerbs = map[string]bool{
	"let": true, "set": true, "if": true, "else": true, "end": true, "stop": true,
	"listen": true, "connect": true, "handshake": true, "accept": true, "peer": true, "reincarnate": true, "adopt": true,
	"send": true, "send_data": true, "send_ack": true, "send_fin": true, "send_fresh_ack": true,
	"await": true, "quiet": true, "quiet_since": true, "collect": true,
	"write": true, "read": true, "close": true, "close_write": true, "abort": true,
	"check": true, "require": true, "measure": true, "log": true,
	"alive": true, "delivered": true, "recv": true,
}

// scriptConsts are the names every script may read without binding them.
var scriptConsts = map[string]bool{
	"SYN": true, "FIN": true, "RST": true, "PSH": true, "ACK": true,
	"PEER_ADDR": true, "DUT_ADDR": true, "MTU": true,
	"now": true, "prompt": true, "none": true, "true": true, "false": true,
}

// predicateArg names, per function, the argument evaluated once per element with s bound.
var predicateArg = map[string]int{"first": 1, "filter": 1, "any": 1, "max_of": 1, "sum_of": 1}

// ScriptError is a parse or binding error with its line.
type ScriptError struct {
	File string
	Line int
	Msg  string
}

func (e *ScriptError) Error() string { return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg) }

// ParseScript parses and checks one script. file names it in errors.
func ParseScript(file, src string) (*Script, error) {
	p := &parser{file: file}
	if err := p.lines(src); err != nil {
		return nil, err
	}
	s, err := p.script()
	if err != nil {
		return nil, err
	}
	if err := checkBindings(file, s.Body); err != nil {
		return nil, err
	}
	return s, nil
}

type srcLine struct {
	n      int
	indent int
	text   string // without the indentation and the comment
}

type parser struct {
	file string
	ls   []srcLine
	i    int
}

func (p *parser) errf(line int, format string, args ...any) error {
	return &ScriptError{File: p.file, Line: line, Msg: fmt.Sprintf(format, args...)}
}

// lines splits src into non-empty lines without comments. A # outside a string literal starts
// a comment.
func (p *parser) lines(src string) error {
	for i, raw := range strings.Split(src, "\n") {
		raw = strings.TrimRight(raw, " \t\r")
		if strings.ContainsRune(raw, '\t') {
			return p.errf(i+1, "tab character; indent with spaces")
		}
		text := stripComment(raw)
		trimmed := strings.TrimLeft(text, " ")
		if strings.TrimSpace(trimmed) == "" {
			continue
		}
		p.ls = append(p.ls, srcLine{n: i + 1, indent: len(text) - len(trimmed), text: strings.TrimRight(trimmed, " ")})
	}
	return nil
}

func stripComment(s string) string {
	in := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && in:
			i++
		case c == '"':
			in = !in
		case c == '#' && !in:
			return s[:i]
		}
	}
	return s
}

func (p *parser) script() (*Script, error) {
	s := &Script{}
	if p.i >= len(p.ls) {
		return nil, p.errf(1, "empty script")
	}
	l := p.ls[p.i]
	name, ok := strings.CutPrefix(l.text, "scenario ")
	if !ok || strings.TrimSpace(name) == "" || strings.ContainsRune(strings.TrimSpace(name), ' ') {
		return nil, p.errf(l.n, "the script starts with: scenario NAME")
	}
	s.Name = strings.TrimSpace(name)
	p.i++
	if p.i >= len(p.ls) {
		return nil, p.errf(l.n, "a refs: line follows the scenario line")
	}
	l = p.ls[p.i]
	refs, ok := strings.CutPrefix(l.text, "refs:")
	if !ok {
		return nil, p.errf(l.n, "a refs: line follows the scenario line")
	}
	s.Refs = strings.TrimSpace(refs)
	p.i++
	for p.i < len(p.ls) {
		l = p.ls[p.i]
		kv, ok := strings.CutPrefix(l.text, "linux:")
		if !ok {
			break
		}
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok || k == "" || v == "" {
			return nil, p.errf(l.n, "a linux: line is linux: PATH=VALUE")
		}
		s.Linux = append(s.Linux, [2]string{k, v})
		p.i++
	}
	body, end, err := p.block()
	if err != nil {
		return nil, err
	}
	if end != "" {
		return nil, p.errf(p.ls[p.i-1].n, "%s without if", end)
	}
	s.Body = body
	return s, nil
}

// block parses statements up to the end of the input or an else or end line, which it consumes
// and names in its second result.
func (p *parser) block() ([]*Stmt, string, error) {
	var out []*Stmt
	for p.i < len(p.ls) {
		l := p.ls[p.i]
		verb, rest, _ := strings.Cut(l.text, " ")
		if verb == "else" || verb == "end" {
			if strings.TrimSpace(rest) != "" {
				return nil, "", p.errf(l.n, "%s takes nothing after it", verb)
			}
			p.i++
			return out, verb, nil
		}
		if strings.HasPrefix(l.text, "what:") || strings.HasPrefix(l.text, "got:") {
			return nil, "", p.errf(l.n, "a what: or got: line belongs right after check or require")
		}
		st, err := p.stmt(l)
		if err != nil {
			return nil, "", err
		}
		p.i++
		if tmplVerbs[st.Verb] {
			if err := p.templates(st, l); err != nil {
				return nil, "", err
			}
		}
		if st.Verb == "if" {
			then, end, err := p.block()
			if err != nil {
				return nil, "", err
			}
			st.Then = then
			if end == "else" {
				els, end2, err := p.block()
				if err != nil {
					return nil, "", err
				}
				if end2 != "end" {
					return nil, "", p.errf(l.n, "if without end")
				}
				st.Else = els
			} else if end != "end" {
				return nil, "", p.errf(l.n, "if without end")
			}
		}
		out = append(out, st)
	}
	return out, "", nil
}

func (p *parser) templates(st *Stmt, at srcLine) error {
	for _, key := range []string{"what:", "got:"} {
		if p.i >= len(p.ls) {
			return p.errf(at.n, "%s needs a %s line", st.Verb, key)
		}
		l := p.ls[p.i]
		text, ok := strings.CutPrefix(l.text, key)
		if !ok || l.indent == 0 {
			return p.errf(l.n, "%s needs an indented %s line", st.Verb, key)
		}
		t, err := parseTemplate(strings.TrimPrefix(text, " "))
		if err != nil {
			return p.errf(l.n, "%v", err)
		}
		if key == "what:" {
			st.What = t
		} else {
			st.Got = t
		}
		p.i++
	}
	return nil
}

func (p *parser) stmt(l srcLine) (*Stmt, error) {
	verb, rest, _ := strings.Cut(l.text, " ")
	rest = strings.TrimLeft(rest, " ")
	st := &Stmt{Line: l.n, Verb: verb}
	if !scriptVerbs[verb] {
		return nil, p.errf(l.n, "unknown statement %q", verb)
	}
	if idVerbs[verb] {
		id, r, _ := strings.Cut(rest, " ")
		if id == "" {
			return nil, p.errf(l.n, "%s needs an ID", verb)
		}
		st.ID, rest = id, strings.TrimLeft(r, " ")
	}
	switch verb {
	case "stop":
		if rest != "" {
			return nil, p.errf(l.n, "stop takes nothing after it")
		}
		return st, nil
	case "log":
		t, err := parseTemplate(rest)
		if err != nil {
			return nil, p.errf(l.n, "%v", err)
		}
		st.What = t
		return st, nil
	}
	toks, err := lex(rest)
	if err != nil {
		return nil, p.errf(l.n, "%v", err)
	}
	ep := &exprParser{toks: toks}
	switch {
	case verb == "let" || verb == "set":
		target, err := ep.target(verb == "set")
		if err != nil {
			return nil, p.errf(l.n, "%v", err)
		}
		if !ep.accept("=") {
			return nil, p.errf(l.n, "%s %s needs = and an expression", verb, target)
		}
		e, err := ep.full()
		if err != nil {
			return nil, p.errf(l.n, "%v", err)
		}
		st.Bind, st.Args = target, []*Expr{e}
		return st, nil
	case exprVerbs[verb]:
		e, err := ep.full()
		if err != nil {
			return nil, p.errf(l.n, "%v", err)
		}
		st.Args = []*Expr{e}
		return st, nil
	}
	for !ep.done() && !ep.peek("->") {
		if ep.namedAhead() {
			name := ep.next().text
			ep.next() // =
			e, err := ep.atom()
			if err != nil {
				return nil, p.errf(l.n, "%v", err)
			}
			if st.Named == nil {
				st.Named = map[string]*Expr{}
			}
			if st.Named[name] != nil {
				return nil, p.errf(l.n, "%s= given twice", name)
			}
			st.Named[name] = e
			continue
		}
		if len(st.Named) > 0 {
			return nil, p.errf(l.n, "a positional argument after a named one")
		}
		e, err := ep.atom()
		if err != nil {
			return nil, p.errf(l.n, "%v", err)
		}
		st.Args = append(st.Args, e)
	}
	if ep.accept("->") {
		t := ep.next()
		if t.kind != tIdent || !ep.done() {
			return nil, p.errf(l.n, "-> is followed by one name")
		}
		st.Bind = t.text
	}
	if bindFirst[verb] && (len(st.Args) == 0 || st.Args[0].Kind != "name") {
		return nil, p.errf(l.n, "%s binds its first argument, which is a name", verb)
	}
	return st, nil
}

// parseTemplate splits text into literal parts and {expr} parts. {{ and }} are literal braces.
func parseTemplate(text string) ([]TmplPart, error) {
	var out []TmplPart
	var lit strings.Builder
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '{' && i+1 < len(text) && text[i+1] == '{', c == '}' && i+1 < len(text) && text[i+1] == '}':
			lit.WriteByte(c)
			i++
		case c == '}':
			return nil, fmt.Errorf("a } without {")
		case c == '{':
			end := matchingBrace(text, i)
			if end < 0 {
				return nil, fmt.Errorf("a { without }")
			}
			toks, err := lex(text[i+1 : end])
			if err != nil {
				return nil, err
			}
			ep := &exprParser{toks: toks}
			e, err := ep.full()
			if err != nil {
				return nil, err
			}
			if lit.Len() > 0 {
				out = append(out, TmplPart{Text: lit.String()})
				lit.Reset()
			}
			out = append(out, TmplPart{Expr: e})
			i = end
		default:
			lit.WriteByte(c)
		}
	}
	if lit.Len() > 0 {
		out = append(out, TmplPart{Text: lit.String()})
	}
	return out, nil
}

// matchingBrace returns the index of the } that closes the { at i, skipping string literals.
func matchingBrace(s string, i int) int {
	in := false
	for j := i + 1; j < len(s); j++ {
		switch {
		case in && s[j] == '\\':
			j++
		case s[j] == '"':
			in = !in
		case !in && s[j] == '}':
			return j
		}
	}
	return -1
}

// Tokens.

const (
	tInt = iota
	tDur
	tStr
	tIdent
	tOp
)

type token struct {
	kind  int
	text  string
	val   int64
	str   []byte
	space bool // whitespace before the token
}

var ops = []string{"||", "&&", "==", "!=", "<=", ">=", "->", "<", ">", "!", "|", "+", "-", "*", "/", "%", "(", ")", "[", "]", ",", ".", "=", ":"}

var durUnits = []struct {
	name string
	ns   int64
}{{"ns", 1}, {"us", 1e3}, {"ms", 1e6}, {"s", 1e9}}

func lex(s string) ([]token, error) {
	var out []token
	space := false
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ':
			space = true
			i++
			continue
		case c >= '0' && c <= '9':
			j := i
			base := 10
			if strings.HasPrefix(s[i:], "0x") {
				j += 2
				base = 16
			}
			for j < len(s) && isDigit(s[j], base) {
				j++
			}
			digits := s[i:j]
			if base == 16 {
				digits = s[i+2 : j]
			}
			v, err := strconv.ParseInt(digits, base, 64)
			if err != nil {
				return nil, fmt.Errorf("bad number %q", s[i:j])
			}
			t := token{kind: tInt, text: s[i:j], val: v, space: space}
			for _, u := range durUnits {
				if strings.HasPrefix(s[j:], u.name) && (j+len(u.name) == len(s) || !isIdentByte(s[j+len(u.name)])) {
					t.kind, t.val = tDur, v*u.ns
					j += len(u.name)
					break
				}
			}
			if j < len(s) && isIdentByte(s[j]) {
				return nil, fmt.Errorf("bad number %q", s[i:j+1])
			}
			t.text = s[i:j]
			out = append(out, t)
			i = j
		case c == '"':
			b, n, err := lexString(s[i:])
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: tStr, text: s[i : i+n], str: b, space: space})
			i += n
		case isIdentByte(c):
			j := i
			for j < len(s) && (isIdentByte(s[j]) || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			out = append(out, token{kind: tIdent, text: s[i:j], space: space})
			i = j
		default:
			matched := false
			for _, op := range ops {
				if strings.HasPrefix(s[i:], op) {
					out = append(out, token{kind: tOp, text: op, space: space})
					i += len(op)
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("unexpected character %q", c)
			}
		}
		space = false
	}
	return out, nil
}

func isDigit(c byte, base int) bool {
	if base == 16 {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
	}
	return c >= '0' && c <= '9'
}

func isIdentByte(c byte) bool { return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// lexString reads a string literal at the start of s and returns its bytes and length.
func lexString(s string) ([]byte, int, error) {
	var b []byte
	for i := 1; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			return b, i + 1, nil
		case '\\':
			if i+1 >= len(s) {
				return nil, 0, fmt.Errorf("unterminated string")
			}
			i++
			switch s[i] {
			case '\\', '"':
				b = append(b, s[i])
			case 'n':
				b = append(b, '\n')
			case 't':
				b = append(b, '\t')
			case 'x':
				if i+2 >= len(s) {
					return nil, 0, fmt.Errorf("bad \\x escape")
				}
				v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
				if err != nil {
					return nil, 0, fmt.Errorf("bad \\x escape")
				}
				b = append(b, byte(v))
				i += 2
			default:
				return nil, 0, fmt.Errorf("unknown escape \\%c", s[i])
			}
		default:
			b = append(b, c)
		}
	}
	return nil, 0, fmt.Errorf("unterminated string")
}

// Expressions.

type exprParser struct {
	toks  []token
	i     int
	depth int // bracket depth, for atom
}

func (p *exprParser) done() bool { return p.i >= len(p.toks) }
func (p *exprParser) next() token {
	t := p.toks[p.i]
	p.i++
	return t
}
func (p *exprParser) peek(op string) bool {
	return !p.done() && p.toks[p.i].kind == tOp && p.toks[p.i].text == op
}
func (p *exprParser) accept(op string) bool {
	if p.peek(op) {
		p.i++
		return true
	}
	return false
}

// namedAhead reports whether the next tokens are NAME= with no space, the start of a named
// argument.
func (p *exprParser) namedAhead() bool {
	return p.i+1 < len(p.toks) && p.toks[p.i].kind == tIdent && p.toks[p.i+1].kind == tOp &&
		p.toks[p.i+1].text == "=" && !p.toks[p.i+1].space
}

// target parses the left side of let (a name) or set (name.field).
func (p *exprParser) target(field bool) (string, error) {
	if p.done() || p.toks[p.i].kind != tIdent {
		return "", fmt.Errorf("a name is expected")
	}
	name := p.next().text
	if !field {
		return name, nil
	}
	if !p.accept(".") || p.done() || p.toks[p.i].kind != tIdent {
		return "", fmt.Errorf("set takes NAME.FIELD")
	}
	return name + "." + p.next().text, nil
}

// full parses one expression that takes the rest of the tokens.
func (p *exprParser) full() (*Expr, error) {
	e, err := p.or()
	if err != nil {
		return nil, err
	}
	if !p.done() {
		return nil, fmt.Errorf("unexpected %q after the expression", p.toks[p.i].text)
	}
	return e, nil
}

// atom parses one argument: an expression with no whitespace outside brackets.
func (p *exprParser) atom() (*Expr, error) {
	start := p.i
	end := p.i
	depth := 0
	for end < len(p.toks) {
		t := p.toks[end]
		if end > start && t.space && depth == 0 {
			break
		}
		if t.kind == tOp {
			switch t.text {
			case "(", "[":
				depth++
			case ")", "]":
				depth--
			case "->":
				if depth == 0 {
					goto out
				}
			}
		}
		end++
	}
out:
	sub := &exprParser{toks: p.toks[start:end]}
	e, err := sub.full()
	if err != nil {
		return nil, err
	}
	p.i = end
	return e, nil
}

func bin(op string, l, r *Expr) *Expr { return &Expr{Kind: "bin", Name: op, Args: []*Expr{l, r}} }

func (p *exprParser) or() (*Expr, error) {
	l, err := p.and()
	for err == nil && p.accept("||") {
		var r *Expr
		r, err = p.and()
		l = bin("||", l, r)
	}
	return l, err
}

func (p *exprParser) and() (*Expr, error) {
	l, err := p.not()
	for err == nil && p.accept("&&") {
		var r *Expr
		r, err = p.not()
		l = bin("&&", l, r)
	}
	return l, err
}

func (p *exprParser) not() (*Expr, error) {
	if p.accept("!") {
		x, err := p.not()
		return &Expr{Kind: "un", Name: "!", Args: []*Expr{x}}, err
	}
	return p.cmp()
}

func (p *exprParser) cmp() (*Expr, error) {
	l, err := p.bitor()
	if err != nil {
		return nil, err
	}
	for _, op := range []string{"==", "!=", "<=", ">=", "<", ">"} {
		if p.accept(op) {
			r, err := p.bitor()
			if err != nil {
				return nil, err
			}
			for _, op2 := range []string{"==", "!=", "<=", ">=", "<", ">"} {
				if p.peek(op2) {
					return nil, fmt.Errorf("comparisons do not chain; use &&")
				}
			}
			return bin(op, l, r), nil
		}
	}
	return l, nil
}

func (p *exprParser) bitor() (*Expr, error) {
	l, err := p.add()
	for err == nil && !p.peek("||") && p.accept("|") {
		var r *Expr
		r, err = p.add()
		l = bin("|", l, r)
	}
	return l, err
}

func (p *exprParser) add() (*Expr, error) {
	l, err := p.mul()
	for err == nil {
		op := ""
		switch {
		case p.peek("+"):
			op = "+"
		case p.peek("-") && !p.peek("->"):
			op = "-"
		}
		if op == "" {
			break
		}
		p.i++
		var r *Expr
		r, err = p.mul()
		l = bin(op, l, r)
	}
	return l, err
}

func (p *exprParser) mul() (*Expr, error) {
	l, err := p.unary()
	for err == nil {
		op := ""
		for _, o := range []string{"*", "/", "%"} {
			if p.peek(o) {
				op = o
			}
		}
		if op == "" {
			break
		}
		p.i++
		var r *Expr
		r, err = p.unary()
		l = bin(op, l, r)
	}
	return l, err
}

func (p *exprParser) unary() (*Expr, error) {
	if p.accept("-") {
		x, err := p.unary()
		return &Expr{Kind: "un", Name: "-", Args: []*Expr{x}}, err
	}
	return p.postfix()
}

func (p *exprParser) postfix() (*Expr, error) {
	x, err := p.primary()
	for err == nil {
		switch {
		case p.accept("."):
			if p.done() || p.toks[p.i].kind != tIdent {
				return nil, fmt.Errorf("a field name follows .")
			}
			x = &Expr{Kind: "field", Name: p.next().text, Args: []*Expr{x}}
		case p.accept("["):
			var lo, hi *Expr
			if !p.peek(":") {
				if lo, err = p.or(); err != nil {
					return nil, err
				}
			}
			if p.accept(":") {
				if !p.peek("]") {
					if hi, err = p.or(); err != nil {
						return nil, err
					}
				}
				if !p.accept("]") {
					return nil, fmt.Errorf("] expected")
				}
				x = &Expr{Kind: "slice", Args: []*Expr{x, lo, hi}}
				continue
			}
			if !p.accept("]") || lo == nil {
				return nil, fmt.Errorf("] expected")
			}
			x = &Expr{Kind: "index", Args: []*Expr{x, lo}}
		default:
			return x, nil
		}
	}
	return x, err
}

func (p *exprParser) primary() (*Expr, error) {
	if p.done() {
		return nil, fmt.Errorf("an expression is expected")
	}
	t := p.next()
	switch t.kind {
	case tInt:
		return &Expr{Kind: "int", Int: t.val}, nil
	case tDur:
		return &Expr{Kind: "dur", Int: t.val}, nil
	case tStr:
		return &Expr{Kind: "str", Str: t.str}, nil
	case tIdent:
		if !p.accept("(") {
			return &Expr{Kind: "name", Name: t.text}, nil
		}
		call := &Expr{Kind: "call", Name: t.text}
		for !p.accept(")") {
			if len(call.Args)+len(call.Named) > 0 && !p.accept(",") {
				return nil, fmt.Errorf(", or ) expected in the call of %s", t.text)
			}
			if p.namedAhead() {
				name := p.next().text
				p.next()
				e, err := p.or()
				if err != nil {
					return nil, err
				}
				if call.Named == nil {
					call.Named = map[string]*Expr{}
				}
				call.Named[name] = e
				continue
			}
			if len(call.Named) > 0 {
				return nil, fmt.Errorf("a positional argument after a named one in the call of %s", t.text)
			}
			e, err := p.or()
			if err != nil {
				return nil, err
			}
			call.Args = append(call.Args, e)
		}
		return call, nil
	case tOp:
		if t.text == "(" {
			e, err := p.or()
			if err != nil {
				return nil, err
			}
			if !p.accept(")") {
				return nil, fmt.Errorf(") expected")
			}
			return e, nil
		}
	}
	return nil, fmt.Errorf("unexpected %q", t.text)
}

// checkBindings is the static definite-binding check: every name a statement reads is bound on
// every path that reaches it. s is bound inside match= and the predicate argument of the list
// functions, where it shadows an outer s.
func checkBindings(file string, body []*Stmt) error {
	_, err := bindBlock(file, body, map[string]bool{})
	return err
}

// bindBlock returns the names bound after body, or nil when body always stops.
func bindBlock(file string, body []*Stmt, bound map[string]bool) (map[string]bool, error) {
	cur := copySet(bound)
	for _, st := range body {
		if cur == nil {
			return nil, &ScriptError{File: file, Line: st.Line, Msg: "statement after stop is never reached"}
		}
		readErr := func(e *Expr, extra map[string]bool) error {
			if name := unboundName(e, cur, extra); name != "" {
				return &ScriptError{File: file, Line: st.Line, Msg: fmt.Sprintf("%s is not bound on every path to here", name)}
			}
			return nil
		}
		args := st.Args
		if bindFirst[st.Verb] {
			args = args[1:]
		}
		if st.Verb == "set" {
			obj, _, _ := strings.Cut(st.Bind, ".")
			if !cur[obj] {
				return nil, &ScriptError{File: file, Line: st.Line, Msg: fmt.Sprintf("%s is not bound on every path to here", obj)}
			}
		}
		for _, a := range args {
			if err := readErr(a, nil); err != nil {
				return nil, err
			}
		}
		for _, k := range sortedKeys(st.Named) {
			var extra map[string]bool
			if k == "match" {
				extra = map[string]bool{"s": true}
			}
			if err := readErr(st.Named[k], extra); err != nil {
				return nil, err
			}
		}
		for _, part := range append(append([]TmplPart{}, st.What...), st.Got...) {
			if part.Expr != nil {
				if err := readErr(part.Expr, nil); err != nil {
					return nil, err
				}
			}
		}
		switch st.Verb {
		case "if":
			a, err := bindBlock(file, st.Then, cur)
			if err != nil {
				return nil, err
			}
			b, err := bindBlock(file, st.Else, cur)
			if err != nil {
				return nil, err
			}
			cur = intersect(a, b)
			continue
		case "stop":
			cur = nil
			continue
		case "let":
			cur[st.Bind] = true
			continue
		}
		if bindFirst[st.Verb] {
			cur[st.Args[0].Name] = true
		}
		if st.Bind != "" && st.Verb != "set" {
			cur[st.Bind] = true
		}
	}
	return cur, nil
}

// unboundName returns the first name e reads that is neither bound, extra, a constant nor a
// called function's name.
func unboundName(e *Expr, bound, extra map[string]bool) string {
	if e == nil {
		return ""
	}
	switch e.Kind {
	case "name":
		if bound[e.Name] || extra[e.Name] || scriptConsts[e.Name] {
			return ""
		}
		return e.Name
	case "call":
		for i, a := range e.Args {
			x := extra
			if pi, ok := predicateArg[e.Name]; ok && pi == i {
				x = copySet(extra)
				if x == nil {
					x = map[string]bool{}
				}
				x["s"] = true
			}
			if n := unboundName(a, bound, x); n != "" {
				return n
			}
		}
		for _, k := range sortedKeys(e.Named) {
			if n := unboundName(e.Named[k], bound, extra); n != "" {
				return n
			}
		}
		return ""
	}
	for _, a := range e.Args {
		if n := unboundName(a, bound, extra); n != "" {
			return n
		}
	}
	return ""
}

func copySet(m map[string]bool) map[string]bool {
	if m == nil {
		return nil
	}
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func intersect(a, b map[string]bool) map[string]bool {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	out := map[string]bool{}
	for k := range a {
		if b[k] {
			out[k] = true
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ScriptAST is the canonical form of a script that both parsers produce, as a value that
// encoding/json writes with sorted keys.
func ScriptAST(s *Script) map[string]any {
	linux := []any{}
	for _, kv := range s.Linux {
		linux = append(linux, []any{kv[0], kv[1]})
	}
	return map[string]any{"scenario": s.Name, "refs": s.Refs, "linux": linux, "body": stmtsAST(s.Body)}
}

func stmtsAST(body []*Stmt) []any {
	out := []any{}
	for _, st := range body {
		m := map[string]any{"line": st.Line, "verb": st.Verb}
		if st.ID != "" {
			m["id"] = st.ID
		}
		if len(st.Args) > 0 {
			m["args"] = exprsAST(st.Args)
		}
		if len(st.Named) > 0 {
			m["named"] = namedAST(st.Named)
		}
		if st.Bind != "" {
			m["bind"] = st.Bind
		}
		if st.Verb == "if" {
			m["then"] = stmtsAST(st.Then)
			if st.Else != nil {
				m["else"] = stmtsAST(st.Else)
			}
		}
		if st.What != nil {
			m["what"] = tmplAST(st.What)
		}
		if st.Got != nil {
			m["got"] = tmplAST(st.Got)
		}
		out = append(out, m)
	}
	return out
}

func tmplAST(t []TmplPart) []any {
	out := []any{}
	for _, p := range t {
		if p.Expr != nil {
			out = append(out, map[string]any{"expr": exprAST(p.Expr)})
		} else {
			out = append(out, map[string]any{"text": p.Text})
		}
	}
	return out
}

func exprsAST(es []*Expr) []any {
	out := []any{}
	for _, e := range es {
		out = append(out, exprAST(e))
	}
	return out
}

func namedAST(m map[string]*Expr) map[string]any {
	out := map[string]any{}
	for k, e := range m {
		out[k] = exprAST(e)
	}
	return out
}

// exprAST writes integers as decimal strings, so a reader that parses JSON numbers as floats
// keeps every 64-bit value; a string literal that is not valid UTF-8 is written in hex.
func exprAST(e *Expr) any {
	if e == nil {
		return nil
	}
	switch e.Kind {
	case "int", "dur":
		return map[string]any{e.Kind: strconv.FormatInt(e.Int, 10)}
	case "str":
		if utf8.Valid(e.Str) {
			return map[string]any{"str": string(e.Str)}
		}
		return map[string]any{"hex": hex.EncodeToString(e.Str)}
	case "name":
		return map[string]any{"name": e.Name}
	case "call":
		m := map[string]any{"call": e.Name, "args": exprsAST(e.Args)}
		if len(e.Named) > 0 {
			m["named"] = namedAST(e.Named)
		}
		return m
	case "field":
		return map[string]any{"field": e.Name, "of": exprAST(e.Args[0])}
	case "index":
		return map[string]any{"index": exprAST(e.Args[1]), "of": exprAST(e.Args[0])}
	case "slice":
		return map[string]any{"slice": []any{exprAST(e.Args[1]), exprAST(e.Args[2])}, "of": exprAST(e.Args[0])}
	case "bin":
		return map[string]any{"op": e.Name, "l": exprAST(e.Args[0]), "r": exprAST(e.Args[1])}
	case "un":
		return map[string]any{"op": e.Name, "x": exprAST(e.Args[0])}
	}
	return map[string]any{"bad": e.Kind}
}
