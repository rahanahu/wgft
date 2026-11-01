package wgstack

// testNet の記録 (docs/design/v2/test-tooling.md の 4 節)。記録を求めた試験の testNet は、Device に対する
// 操作 (packet の入力、出力の引き取り、時計、アプリケーションの操作) を、dutserve が同じ操作に返す要求と
// 応答の frame の列として書く。製品のコードは変えない。

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rahanahu/wgft/internal/dutproto"
)

// recordEnv は記録の先の directory。TestWriteRecordings だけが読む。
const recordEnv = "WGFT_WGSTACK_RECORD"

// recordCommitEnv は記録の meta に書く Go の wgstack の commit。作る手順 (scripts/wgstack-record.sh) が与える。
const recordCommitEnv = "WGFT_WGSTACK_RECORD_COMMIT"

// pollAll は、引き取りを空になるまで続けた POLL の最大の数。
const pollAll = 1 << 20

// recSpec は 1 つの記録の名前と、記録のために変える試験の選択。source が空なら記録しない。
type recSpec struct {
	dir     string
	source  string
	name    string
	test    string
	seed    uint64
	variant string
	cc      *CongestionControl
	boost   *BoostPolicy
}

// netRecorder は testNet の操作を frame の列に書く。
type netRecorder struct {
	n       *testNet
	spec    recSpec
	frames  []byte
	hello   bool
	stopped string
	handles map[any]dutproto.Handle
	next    dutproto.Handle

	// 続けて呼んだ Poll は 1 つの POLL にまとめる。最後が空なら引き取りを空になるまで続けたので pollAll
	polled []dutproto.Bytes
	pollN  int
	empty  bool

	// 状態を変える要求が間に無い同じ問い合わせは書かない (rustdut の送り直さない規則と同じ)
	asked map[string]bool
}

// record は spec の記録を始める。記録は試験が通った時だけ、試験の終わりに spec.dir に書く。
func (n *testNet) record(spec recSpec) {
	if spec.source == "" {
		return
	}
	if spec.cc != nil {
		n.d.s.ccPolicy = *spec.cc
	}
	if spec.boost != nil {
		n.d.s.boostPolicy = *spec.boost
	}
	r := &netRecorder{n: n, spec: spec, handles: map[any]dutproto.Handle{}, asked: map[string]bool{}}
	n.rec = r
	n.t.Cleanup(func() {
		if n.t.Failed() {
			return
		}
		if err := r.write(); err != nil {
			n.t.Errorf("writing the recording %s/%s: %v", spec.source, spec.name, err)
		}
	})
}

// limitNames は HELLO の上限の組の名前と、limits の欄。
var limitNames = []struct {
	name string
	f    func(*limits) *int
}{
	{"maxFlows", func(l *limits) *int { return &l.maxFlows }},
	{"acceptQ", func(l *limits) *int { return &l.acceptQ }},
	{"synRows", func(l *limits) *int { return &l.synRows }},
	{"twRows", func(l *limits) *int { return &l.twRows }},
	{"ctlSlots", func(l *limits) *int { return &l.ctlSlots }},
	{"udpRxDgrams", func(l *limits) *int { return &l.udpRxDgrams }},
	{"udpTxDgrams", func(l *limits) *int { return &l.udpTxDgrams }},
	{"fragEntries", func(l *limits) *int { return &l.fragEntries }},
	{"fragPieces", func(l *limits) *int { return &l.fragPieces }},
}

// helloLimits は lim を HELLO の上限の組にする。すべての名前を順に並べる。
func helloLimits(lim limits) []dutproto.Limit {
	out := make([]dutproto.Limit, 0, len(limitNames))
	for _, ln := range limitNames {
		out = append(out, dutproto.Limit{Name: ln.name, Value: uint64(*ln.f(&lim))})
	}
	return out
}

// limitsFromHello は HELLO の上限の組を limits にする。空なら既定。名前の無い欄は 0 (本番の値) で、表の
// 大きさの 5 つは必ず要る。
func limitsFromHello(ls []dutproto.Limit) (limits, error) {
	if len(ls) == 0 {
		return defaultLimits(0), nil
	}
	var lim limits
	seen := map[string]bool{}
	for _, l := range ls {
		found := false
		for _, ln := range limitNames {
			if ln.name == l.Name {
				if l.Value > 1<<30 {
					return lim, fmt.Errorf("limit %s=%d is out of range", l.Name, l.Value)
				}
				*ln.f(&lim) = int(l.Value)
				found, seen[l.Name] = true, true
			}
		}
		if !found {
			return lim, fmt.Errorf("unknown limit %q", l.Name)
		}
	}
	for _, ln := range limitNames[:5] {
		if !seen[ln.name] {
			return lim, fmt.Errorf("limit %s is missing", ln.name)
		}
	}
	return lim, nil
}

func (r *netRecorder) put(m dutproto.Msg) { r.frames = dutproto.AppendFrame(r.frames, m) }

// ensureHello は最初の操作の前に HELLO を書く。試験は Device を作った後に輻輳の制御や boost の与え方を
// 変えるので、その値を最初の操作の時に読む。
func (r *netRecorder) ensureHello() {
	if r.hello {
		return
	}
	r.hello = true
	s := r.n.d.s
	r.put(&dutproto.Hello{Version: dutproto.Version, Clock: dutproto.ClockFake, Addr: dutAddr, MTU: testMTU,
		Seed: bytes.Repeat([]byte{7}, dutproto.SeedLen), Limits: helloLimits(s.lim),
		Boost: dutproto.Boost(s.boostPolicy), Congestion: dutproto.Congestion(s.ccPolicy)})
	r.put(&dutproto.HelloOK{Engine: dutserveEngine, Version: dutproto.Version})
}

// flushPoll はまとめた Poll を 1 つの POLL にして書く。
func (r *netRecorder) flushPoll() {
	if r.pollN == 0 {
		return
	}
	max := uint32(len(r.polled))
	if r.empty {
		max = pollAll
	}
	r.ensureHello()
	r.put(&dutproto.Poll{Max: max})
	r.put(&dutproto.Packets{Packets: r.polled})
	r.polled, r.pollN, r.empty = nil, 0, false
	clear(r.asked)
}

// emit は要求と応答を書く。query なら、状態を変える要求が間に無い同じ要求を書かない。
func (r *netRecorder) emit(req, resp dutproto.Msg, query bool) {
	if r.stopped != "" {
		return
	}
	r.flushPoll()
	r.ensureHello()
	if query {
		key := string(dutproto.AppendFrame(nil, req))
		if r.asked[key] {
			return
		}
		r.asked[key] = true
	} else {
		clear(r.asked)
	}
	r.put(req)
	r.put(resp)
}

// stop は記録をここで終える。frame に無い操作 (Device の内部を直接動かす試験の操作) の前に呼ぶ。
func (r *netRecorder) stop(reason string) {
	if r.stopped != "" {
		return
	}
	r.flushPoll()
	r.ensureHello()
	r.stopped = reason
}

func (r *netRecorder) poll(pkt []byte) {
	if r.stopped != "" {
		return
	}
	if r.empty {
		r.flushPoll()
	}
	r.pollN++
	if len(pkt) == 0 {
		r.empty = true
		r.flushPoll()
		return
	}
	r.polled = append(r.polled, append(dutproto.Bytes{}, pkt...))
}

func (r *netRecorder) add(o any) dutproto.Handle {
	r.next++
	r.handles[o] = r.next
	return r.next
}

// handle は記録が知る物の handle を返す。知らなければ記録を止めて 0 を返す。
func (r *netRecorder) handle(o any) dutproto.Handle {
	h, ok := r.handles[o]
	if !ok {
		r.stop(fmt.Sprintf("an operation on a %T the recording did not see made", o))
	}
	return h
}

func (r *netRecorder) write() error {
	r.flushPoll()
	r.ensureHello()
	fr, err := dutproto.SplitFrames(r.frames)
	if err != nil {
		return err
	}
	meta := dutproto.RecMeta{Source: r.spec.source, Name: r.spec.name, Test: r.spec.test, Seed: r.spec.seed,
		Variant: r.spec.variant, GoCommit: os.Getenv(recordCommitEnv), GoVersion: runtime.Version(),
		GOARCH: runtime.GOARCH, GOAMD64: goamd64(), Tags: dutproto.Tags(fr), Truncated: r.stopped}
	var b bytes.Buffer
	if err := dutproto.WriteRecord(&b, meta, r.frames); err != nil {
		return err
	}
	path := filepath.Join(r.spec.dir, r.spec.source, r.spec.name+".rec.gz")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}

// 以下は testNet の操作の記録つきの形。記録を求めない試験では、そのまま Device を呼ぶ。

// poll は Device の出力を 1 つ引き取る。
func (n *testNet) poll(buf []byte) int {
	k := n.d.Poll(buf)
	if n.rec != nil {
		n.rec.poll(buf[:k])
	}
	return k
}

// writePkts は packet の列を 1 回の Write で入れる。
func (n *testNet) writePkts(pkts ...[]byte) (int, error) {
	k, err := n.d.Write(pkts, 0)
	if n.rec != nil {
		req := &dutproto.Inject{}
		for _, p := range pkts {
			req.Packets = append(req.Packets, append(dutproto.Bytes{}, p...))
		}
		n.rec.emit(req, okOrErr(err), false)
	}
	return k, err
}

// listenTCP は ap のポートで待ち受ける。
func (n *testNet) listenTCP(port uint16) (*TCPListener, error) {
	l, err := n.d.ListenTCP(netipAP(port))
	if n.rec != nil {
		var resp dutproto.Msg = errOrNil(err)
		if err == nil {
			resp = &dutproto.HandleResp{H: n.rec.add(l)}
		}
		n.rec.emit(&dutproto.TCPListen{Port: port}, resp, false)
	}
	return l, err
}

// accept は待ち受けから 1 つ受け取る。待たずに受け取れる時だけ呼ぶ。
func (n *testNet) accept(l *TCPListener) *Conn {
	n.t.Helper()
	c := acceptOne(n.t, l)
	if n.rec != nil {
		h := n.rec.handle(l)
		n.rec.emit(&dutproto.Accept{H: h}, &dutproto.Accepted{H: n.rec.add(c), Remote: c.tup.remote()}, false)
	}
	return c
}

// read は Read を呼ぶ。待たずに戻る時 (readable) だけ呼ぶ。
func (n *testNet) read(c *Conn, b []byte) (int, error) {
	k, err := c.Read(b)
	if n.rec != nil {
		var resp dutproto.Msg = &dutproto.Data{Data: append(dutproto.Bytes{}, b[:k]...)}
		if err != nil {
			resp = errResp(err)
		}
		n.rec.emit(&dutproto.Read{H: n.rec.handle(c), Max: uint32(len(b))}, resp, k == 0 && err == nil)
	}
	return k, err
}

// writeConn は Write を呼ぶ。待たずに書ける量 (room) までだけを渡す。
func (n *testNet) writeConn(c *Conn, b []byte) (int, error) {
	k, err := c.Write(b)
	if n.rec != nil {
		var resp dutproto.Msg = &dutproto.Wrote{N: uint32(k)}
		if err != nil {
			resp = errResp(err)
		}
		n.rec.emit(&dutproto.Write{H: n.rec.handle(c), Data: append(dutproto.Bytes{}, b...)}, resp, k == 0 && err == nil)
	}
	return k, err
}

func (n *testNet) closeConn(c *Conn) error {
	err := c.Close()
	if n.rec != nil {
		n.rec.emit(&dutproto.Close{H: n.rec.handle(c)}, okOrErr(err), false)
	}
	return err
}

func (n *testNet) closeWrite(c *Conn) error {
	err := c.CloseWrite()
	if n.rec != nil {
		n.rec.emit(&dutproto.CloseWrite{H: n.rec.handle(c)}, okOrErr(err), false)
	}
	return err
}

func (n *testNet) abort(c *Conn) {
	c.Abort()
	if n.rec != nil {
		n.rec.emit(&dutproto.Abort{H: n.rec.handle(c)}, &dutproto.OK{}, false)
	}
}

func (n *testNet) delivered(c *Conn) bool {
	v := c.Delivered()
	if n.rec != nil {
		n.rec.emit(&dutproto.Delivered{H: n.rec.handle(c)}, &dutproto.Bool{V: v}, true)
	}
	return v
}

// internal は frame に無い操作の前に呼ぶ。記録はそこで終わる。
func (n *testNet) internal(what string) {
	if n.rec != nil {
		n.rec.stop(what)
	}
}

func errOrNil(err error) dutproto.Msg {
	if err == nil {
		return &dutproto.OK{}
	}
	return errResp(err)
}

// recordDir は記録の先の directory。無ければ試験を SKIP にする。
func recordDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv(recordEnv)
	if dir == "" {
		t.Skipf("set %s to a directory to write the Go wgstack's recordings", recordEnv)
	}
	return dir
}
