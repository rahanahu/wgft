package wgstack

// dutserve は凍結した Go の wgstack を DUT の口 (internal/dutproto、docs/design/v2/test-tooling.md の 3 節)
// で出す試験のバイナリの形である。`go test -c -o wgstack-dutserve.test ./internal/wgstack` で作り、環境変数
// WGFT_WGSTACK_DUTSERVE=1 を与えて起こすと、TestMain が試験を流さずに標準入力の要求に標準出力で答える。
// 製品のコードは変えない。待たずに戻る操作は package の中の確かめ (dutready_test.go) で作るので、壁時計で
// 待たず、受け入れの goroutine も持たず、応答の列は要求の列だけで決まる。

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/dutproto"
)

// dutserveEnv を 1 にすると試験のバイナリは dutserve として動く。
const dutserveEnv = "WGFT_WGSTACK_DUTSERVE"

func TestMain(m *testing.M) {
	if os.Getenv(dutserveEnv) == "1" {
		os.Exit(dutserveMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// dutserveEngine は HELLO_OK で返す engine の名前。tcpharness の wgstackdut と同じ名前にする。
const dutserveEngine = "wgstack"

// 終了コード:0 は標準入力が frame の境目で閉じた時、2 は口の誤り。
const (
	dutserveExitOK       = 0
	dutserveExitProtocol = 2
)

// dutserveMain は引数 (--clock fake だけを受ける) を読み、in の要求に out で答える。
func dutserveMain(args []string, in io.Reader, out io.Writer, logw io.Writer) int {
	clock := ""
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--clock" && i+1 < len(args):
			clock = args[i+1]
			i++
		case strings.HasPrefix(a, "--clock="):
			clock = strings.TrimPrefix(a, "--clock=")
		default:
			fmt.Fprintf(logw, "dutserve: unknown argument %q; the only argument is --clock fake\n", a)
			return dutserveExitProtocol
		}
	}
	if clock != "fake" {
		fmt.Fprintf(logw, "dutserve: needs --clock fake; got %q: the Go wgstack's DUT runs only on the fake clock\n", clock)
		return dutserveExitProtocol
	}
	return serveDUT(dutproto.NewConn(in, out), logw)
}

// dutServer は 1 つの Device と、その上で作った物の handle の表。
type dutServer struct {
	dev    *Device
	clk    *ManualClock
	addr   netip.Addr
	objs   []any // handle - 1 で引く。*TCPListener、*Conn、*UDPConn、*PingConn
	events []dutproto.BoostEvent
	buf    []byte
}

// protoError は口の誤り。応答を書いた後にプロセスを終える。
type protoError struct{ msg string }

func (e *protoError) Error() string { return e.msg }

func protoErrorf(format string, args ...any) *protoError {
	return &protoError{msg: fmt.Sprintf(format, args...)}
}

// serveDUT は要求を 1 つずつ読み、応答を 1 つずつ書く。最初の要求は HELLO であること。
func serveDUT(c *dutproto.Conn, logw io.Writer) int {
	var srv *dutServer
	defer func() {
		if srv != nil {
			srv.dev.Close()
		}
	}()
	for {
		m, err := c.Recv()
		if err == io.EOF {
			return dutserveExitOK
		}
		var resp dutproto.Msg
		var perr *protoError
		switch {
		case err != nil:
			perr = protoErrorf("reading a request: %v", err)
		case srv == nil:
			h, ok := m.(*dutproto.Hello)
			if !ok {
				perr = protoErrorf("the first request is %s; it must be HELLO", m.Kind())
				break
			}
			srv, perr = newDUTServer(h)
			if perr == nil {
				resp = &dutproto.HelloOK{Engine: dutserveEngine, Version: dutproto.Version}
			}
		default:
			resp, perr = srv.handle(m)
		}
		if perr != nil {
			fmt.Fprintf(logw, "dutserve: %s\n", perr.msg)
			c.Send(&dutproto.Error{Err: dutproto.ErrOther, Msg: perr.msg})
			return dutserveExitProtocol
		}
		if err := c.Send(resp); err != nil {
			fmt.Fprintf(logw, "dutserve: writing a response: %v\n", err)
			return dutserveExitProtocol
		}
	}
}

// newDUTServer は HELLO の Device を公開の New で作る。既定でない上限の組は断る。小さな上限の記録は package
// の中の testNet が作る (test-tooling.md の 4 節)。
func newDUTServer(h *dutproto.Hello) (*dutServer, *protoError) {
	switch {
	case h.Version != dutproto.Version:
		return nil, protoErrorf("HELLO asks for protocol version %d; dutserve speaks %d", h.Version, dutproto.Version)
	case h.Clock != dutproto.ClockFake:
		return nil, protoErrorf("HELLO asks for clock %d; dutserve runs only the fake clock", h.Clock)
	case len(h.Limits) > 0:
		return nil, protoErrorf("HELLO asks for %d non-default limits; dutserve builds the Device with the public New and takes only the default limits", len(h.Limits))
	case len(h.Seed) != dutproto.SeedLen:
		return nil, protoErrorf("HELLO carries a seed of %d bytes; want %d", len(h.Seed), dutproto.SeedLen)
	case h.Boost > dutproto.BoostNever:
		return nil, protoErrorf("HELLO asks for boost policy %d, which wgstack does not have", h.Boost)
	case h.Congestion > dutproto.CongestionNewReno:
		return nil, protoErrorf("HELLO asks for congestion control %d, which wgstack does not have", h.Congestion)
	}
	clk := NewManualClock()
	// 種の 64 byte の後は読めない Reader を渡す。Go の wgstack が作成の後に Config.Rand を読めば、ここで分かる
	dev, err := New(Config{Addr: h.Addr, MTU: int(h.MTU), Clock: clk, Rand: bytes.NewReader(h.Seed),
		TestBoost: BoostPolicy(h.Boost), TestCongestion: CongestionControl(h.Congestion)})
	if err != nil {
		return nil, protoErrorf("wgstack.New: %v", err)
	}
	return &dutServer{dev: dev, clk: clk, addr: h.Addr, buf: make([]byte, 65536)}, nil
}

// maxRead は READ、UDP_RECV、PING_RECV の最大の byte 数の上限。応答が 1 つの frame に収まる値にする。
const maxRead = dutproto.MaxFrame - 64

func checkMax(m dutproto.Msg, n uint32) *protoError {
	if n > maxRead {
		return protoErrorf("%s asks for %d bytes; at most %d fit in a frame", m.Kind(), n, maxRead)
	}
	return nil
}

func (s *dutServer) add(o any) dutproto.Handle {
	s.objs = append(s.objs, o)
	return dutproto.Handle(len(s.objs))
}

// obj は handle の物を型 T で返す。知らない handle と違う型は口の誤り。
func obj[T any](s *dutServer, h dutproto.Handle, what string) (T, *protoError) {
	var zero T
	if h == 0 || int(h) > len(s.objs) {
		return zero, protoErrorf("unknown handle %d", h)
	}
	o, ok := s.objs[h-1].(T)
	if !ok {
		return zero, protoErrorf("handle %d is a %T, not a %s", h, s.objs[h-1], what)
	}
	return o, nil
}

// errResp は wgstack の誤りを ERROR の応答にする。文は誤りの Error() のままで、rustdut が同じ文の誤りに戻す。
func errResp(err error) *dutproto.Error {
	k := dutproto.ErrOther
	var ne interface{ Timeout() bool }
	switch {
	case errors.Is(err, io.EOF):
		k = dutproto.ErrEOF
	case errors.As(err, &ne) && ne.Timeout():
		k = dutproto.ErrTimeout
	case errors.Is(err, net.ErrClosed):
		k = dutproto.ErrClosed
	case errors.Is(err, syscall.ECONNRESET) || strings.Contains(err.Error(), "connection reset"):
		k = dutproto.ErrReset
	case errors.Is(err, syscall.EPIPE):
		k = dutproto.ErrBrokenPipe
	}
	return &dutproto.Error{Err: k, Msg: err.Error()}
}

func okOrErr(err error) dutproto.Msg {
	if err != nil {
		return errResp(err)
	}
	return &dutproto.OK{}
}

// handle は HELLO の後の要求に答える。待つ操作は、dutready_test.go の確かめが待たずに戻ると言う時だけ公開の
// 操作を呼び、待つ場合は呼ばずに WOULD_BLOCK (WRITE では WROTE 0) を返す。
func (s *dutServer) handle(m dutproto.Msg) (dutproto.Msg, *protoError) {
	switch m := m.(type) {
	case *dutproto.Hello:
		return nil, protoErrorf("a second HELLO")
	case *dutproto.Inject:
		bufs := make([][]byte, len(m.Packets))
		for i, p := range m.Packets {
			bufs[i] = p
		}
		_, err := s.dev.Write(bufs, 0)
		return okOrErr(err), nil
	case *dutproto.Poll:
		out := &dutproto.Packets{Packets: []dutproto.Bytes{}}
		for range m.Max {
			n := s.dev.Poll(s.buf)
			if n == 0 {
				break
			}
			out.Packets = append(out.Packets, append(dutproto.Bytes{}, s.buf[:n]...))
		}
		return out, nil
	case *dutproto.Advance:
		// 復号が 2^63-1 ns を超える時間を断るので、m.D は負にならない
		s.clk.Advance(m.D)
		s.dev.Tick()
		return &dutproto.Time{Now: s.clk.Now()}, nil
	case *dutproto.Now:
		return &dutproto.Time{Now: s.clk.Now()}, nil
	case *dutproto.TCPListen:
		l, err := s.dev.ListenTCP(netip.AddrPortFrom(s.addr, m.Port))
		if err != nil {
			return errResp(err), nil
		}
		return &dutproto.HandleResp{H: s.add(l)}, nil
	case *dutproto.UDPListen:
		pc, err := s.dev.ListenUDP(netip.AddrPortFrom(s.addr, m.Port))
		if err != nil {
			return errResp(err), nil
		}
		return &dutproto.HandleResp{H: s.add(pc.(*UDPConn))}, nil
	case *dutproto.Accept:
		l, perr := obj[*TCPListener](s, m.H, "listener")
		if perr != nil {
			return nil, perr
		}
		if !acceptReady(l) {
			return &dutproto.WouldBlock{}, nil
		}
		c, err := l.Accept()
		if err != nil {
			return errResp(err), nil
		}
		wc := c.(*Conn)
		return &dutproto.Accepted{H: s.add(wc), Remote: wc.tup.remote()}, nil
	case *dutproto.Read:
		c, perr := obj[*Conn](s, m.H, "connection")
		if perr == nil {
			perr = checkMax(m, m.Max)
		}
		if perr != nil {
			return nil, perr
		}
		if m.Max > 0 && !readReady(c) {
			return &dutproto.WouldBlock{}, nil
		}
		b := make([]byte, m.Max)
		n, err := c.Read(b)
		if err != nil {
			return errResp(err), nil
		}
		return &dutproto.Data{Data: b[:n]}, nil
	case *dutproto.Write:
		c, perr := obj[*Conn](s, m.H, "connection")
		if perr != nil {
			return nil, perr
		}
		room, writable := writeRoom(c)
		data := m.Data
		switch {
		case len(data) == 0 || !writable:
			// 書けない接続の Write と長さ 0 の Write は待たずに戻る
		case room == 0:
			return &dutproto.Wrote{N: 0}, nil
		default:
			data = data[:min(uint64(len(data)), room)]
		}
		n, err := c.Write(data)
		if err != nil {
			return errResp(err), nil
		}
		return &dutproto.Wrote{N: uint32(n)}, nil
	case *dutproto.Close:
		if m.H == 0 || int(m.H) > len(s.objs) {
			return nil, protoErrorf("unknown handle %d", m.H)
		}
		switch o := s.objs[m.H-1].(type) {
		case *TCPListener:
			return okOrErr(o.Close()), nil
		case *Conn:
			return okOrErr(o.Close()), nil
		case *UDPConn:
			return okOrErr(o.Close()), nil
		default:
			return nil, protoErrorf("CLOSE of handle %d, a %T; an echo endpoint closes with PING_CLOSE", m.H, o)
		}
	case *dutproto.CloseWrite:
		c, perr := obj[*Conn](s, m.H, "connection")
		if perr != nil {
			return nil, perr
		}
		return okOrErr(c.CloseWrite()), nil
	case *dutproto.Abort:
		c, perr := obj[*Conn](s, m.H, "connection")
		if perr != nil {
			return nil, perr
		}
		c.Abort()
		return &dutproto.OK{}, nil
	case *dutproto.CloseForDelivery:
		c, perr := obj[*Conn](s, m.H, "connection")
		if perr != nil {
			return nil, perr
		}
		return okOrErr(c.CloseForDelivery()), nil
	case *dutproto.Delivered:
		c, perr := obj[*Conn](s, m.H, "connection")
		if perr != nil {
			return nil, perr
		}
		return &dutproto.Bool{V: c.Delivered()}, nil
	case *dutproto.BoostPolicy:
		c, perr := obj[*Conn](s, m.H, "connection")
		if perr != nil {
			return nil, perr
		}
		h, floor := m.H, m.Floor
		first, now := true, false
		c.OnBoost(func(boosted bool) bool {
			if first {
				first, now = false, boosted
			} else {
				s.events = append(s.events, dutproto.BoostEvent{H: h, Boosted: boosted})
			}
			return boosted || floor
		})
		return &dutproto.Bool{V: now}, nil
	case *dutproto.Events:
		ev := &dutproto.EventList{Events: s.events}
		if ev.Events == nil {
			ev.Events = []dutproto.BoostEvent{}
		}
		s.events = nil
		return ev, nil
	case *dutproto.UDPRecv:
		u, perr := obj[*UDPConn](s, m.H, "UDP socket")
		if perr == nil {
			perr = checkMax(m, m.Max)
		}
		if perr != nil {
			return nil, perr
		}
		if !udpRecvReady(u) {
			return &dutproto.WouldBlock{}, nil
		}
		b := make([]byte, m.Max)
		n, from, err := u.ReadFrom(b)
		if err != nil {
			return errResp(err), nil
		}
		return &dutproto.Datagram{From: from.(*net.UDPAddr).AddrPort(), Data: b[:n]}, nil
	case *dutproto.UDPSend:
		u, perr := obj[*UDPConn](s, m.H, "UDP socket")
		if perr != nil {
			return nil, perr
		}
		to := net.UDPAddrFromAddrPort(m.To)
		if !udpSendReady(u, m.Data, to) {
			return &dutproto.WouldBlock{}, nil
		}
		_, err := u.WriteTo(m.Data, to)
		return okOrErr(err), nil
	case *dutproto.PingOpen:
		pc, err := s.dev.DialPing(s.addr, m.To)
		if err != nil {
			return errResp(err), nil
		}
		return &dutproto.HandleResp{H: s.add(pc.(*PingConn))}, nil
	case *dutproto.PingSend:
		p, perr := obj[*PingConn](s, m.H, "echo endpoint")
		if perr != nil {
			return nil, perr
		}
		_, err := p.Write(m.Data)
		return okOrErr(err), nil
	case *dutproto.PingRecv:
		p, perr := obj[*PingConn](s, m.H, "echo endpoint")
		if perr == nil {
			perr = checkMax(m, m.Max)
		}
		if perr != nil {
			return nil, perr
		}
		if !pingRecvReady(p) {
			return &dutproto.WouldBlock{}, nil
		}
		b := make([]byte, m.Max)
		n, err := p.Read(b)
		if err != nil {
			return errResp(err), nil
		}
		return &dutproto.Data{Data: b[:n]}, nil
	case *dutproto.PingClose:
		p, perr := obj[*PingConn](s, m.H, "echo endpoint")
		if perr != nil {
			return nil, perr
		}
		return okOrErr(p.Close()), nil
	case *dutproto.Stats:
		return &dutproto.Text{S: keyValues(s.dev.Stats(), nil)}, nil
	case *dutproto.Bound:
		return &dutproto.Text{S: keyValues(s.dev.Bound(), nil)}, nil
	case *dutproto.Held:
		return &dutproto.Text{S: keyValues(s.dev.Stats(), heldFields)}, nil
	case *dutproto.RTOAt, *dutproto.ConnSocket:
		return &dutproto.Error{Err: dutproto.ErrOther, Msg: m.Kind().String() + " needs --clock real; dutserve runs only the fake clock"}, nil
	}
	return nil, protoErrorf("%s is not a request", m.Kind())
}

// heldFields は Stats のうち今の保持の量の欄。HELD はこれだけを返す。
var heldFields = map[string]bool{
	"Conns": true, "SynRows": true, "TWRows": true, "AcceptQueued": true, "CtlQueued": true,
	"ChunkBytes": true, "RecordBytes": true, "IntervalBytes": true, "Boosted": true, "Reserved": true,
	"UDPRxBytes": true, "UDPRxDatagrams": true, "UDPTxBytes": true, "UDPTxDatagrams": true,
	"FragBytes": true, "PingEndpoints": true, "HeldChunksInPool": true,
}

// keyValues は構造体の欄を宣言の順に key=value で並べる。only が nil でなければ、その欄だけを並べる。
func keyValues(v any, only map[string]bool) string {
	rv := reflect.ValueOf(v)
	var parts []string
	for i := range rv.NumField() {
		name := rv.Type().Field(i).Name
		if only != nil && !only[name] {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%v", name, rv.Field(i).Interface()))
	}
	return strings.Join(parts, " ")
}

// dutClient は同じプロセスの dutserve と pipe で話す。
type dutClient struct {
	t    *testing.T
	c    *dutproto.Conn
	in   *io.PipeWriter
	code chan int
	logw *bytes.Buffer
}

func startDutserve(t *testing.T, args ...string) *dutClient {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	d := &dutClient{t: t, c: dutproto.NewConn(outR, inW), in: inW, code: make(chan int, 1), logw: &bytes.Buffer{}}
	go func() {
		code := dutserveMain(args, inR, outW, d.logw)
		outW.Close()
		inR.Close()
		d.code <- code
	}()
	return d
}

// do は要求を送り、応答の種類が want であることを確かめて応答を返す。
func (d *dutClient) do(req dutproto.Msg, want dutproto.Kind) dutproto.Msg {
	d.t.Helper()
	if err := d.c.Send(req); err != nil {
		d.t.Fatalf("%s: %v", req.Kind(), err)
	}
	resp, err := d.c.Recv()
	if err != nil {
		d.t.Fatalf("%s: %v", req.Kind(), err)
	}
	if resp.Kind() != want {
		d.t.Fatalf("%s answered %s, want %s", dutproto.Format(req), dutproto.Format(resp), want)
	}
	return resp
}

// end は標準入力を閉じ、終了コードを返す。
func (d *dutClient) end() int {
	d.in.Close()
	code := <-d.code
	if d.logw.Len() > 0 {
		d.t.Logf("dutserve's standard error: %s", d.logw.String())
	}
	return code
}

func testHello() *dutproto.Hello {
	return &dutproto.Hello{Version: dutproto.Version, Clock: dutproto.ClockFake, Addr: dutAddr, MTU: testMTU,
		Seed: make(dutproto.Bytes, dutproto.SeedLen), Limits: []dutproto.Limit{}}
}

// TestDutserveSession は 1 つの接続を dutserve で動かす。握手、待つ必要のある Accept と Read、データ、Write、
// 時計、問い合わせ、閉じる順を確かめ、標準入力を閉じると終了コード 0 で終わることを確かめる。
func TestDutserveSession(t *testing.T) {
	d := startDutserve(t, "--clock", "fake")
	if r := d.do(testHello(), dutproto.KindHelloOK).(*dutproto.HelloOK); r.Engine != dutserveEngine || r.Version != dutproto.Version {
		t.Fatalf("HELLO_OK %s", dutproto.Format(r))
	}
	l := d.do(&dutproto.TCPListen{Port: 80}, dutproto.KindHandle).(*dutproto.HandleResp).H
	d.do(&dutproto.Accept{H: dutproto.Handle(l)}, dutproto.KindWouldBlock)
	syn := buildPeer(tseg{sport: 40000, dport: 80, seq: 1000, flags: flagSYN, wnd: 65535, mss: 1380, ws: -1})
	d.do(&dutproto.Inject{Packets: []dutproto.Bytes{syn}}, dutproto.KindOK)
	pk := d.do(&dutproto.Poll{Max: 4}, dutproto.KindPackets).(*dutproto.Packets)
	if len(pk.Packets) != 1 {
		t.Fatalf("POLL after the SYN: %s", dutproto.Format(pk))
	}
	ip, _ := parseIPv4(pk.Packets[0])
	sa, _ := parseTCP(&ip)
	if sa.flags != flagSYN|flagACK {
		t.Fatalf("not a SYN-ACK: %s", dutproto.PacketString(pk.Packets[0]))
	}
	p := &peerConn{sport: 40000, dport: 80, snd: 1001, rcv: sa.seq + 1, wnd: 65535}
	ack := buildPeer(p.seg(flagACK, nil))
	data := buildPeer(p.seg(flagACK|flagPSH, []byte("hello")))
	d.do(&dutproto.Inject{Packets: []dutproto.Bytes{ack}}, dutproto.KindOK)
	acc := d.do(&dutproto.Accept{H: l}, dutproto.KindAccepted).(*dutproto.Accepted)
	if acc.Remote != netip.AddrPortFrom(peerAddr, 40000) {
		t.Errorf("ACCEPTED from %v", acc.Remote)
	}
	c := acc.H
	d.do(&dutproto.Read{H: c, Max: 100}, dutproto.KindWouldBlock)
	if r := d.do(&dutproto.Read{H: c, Max: 0}, dutproto.KindData).(*dutproto.Data); len(r.Data) != 0 {
		t.Errorf("READ of 0 bytes returned %d", len(r.Data))
	}
	d.do(&dutproto.Inject{Packets: []dutproto.Bytes{data}}, dutproto.KindOK)
	if r := d.do(&dutproto.Read{H: c, Max: 100}, dutproto.KindData).(*dutproto.Data); string(r.Data) != "hello" {
		t.Errorf("READ returned %q", r.Data)
	}
	if r := d.do(&dutproto.Write{H: c, Data: dutproto.Bytes("world")}, dutproto.KindWrote).(*dutproto.Wrote); r.N != 5 {
		t.Errorf("WROTE %d", r.N)
	}
	if r := d.do(&dutproto.Advance{D: 50 * time.Millisecond}, dutproto.KindTime).(*dutproto.Time); r.Now != 50*time.Millisecond {
		t.Errorf("ADVANCE answered %v", r.Now)
	}
	if r := d.do(&dutproto.Now{}, dutproto.KindTime).(*dutproto.Time); r.Now != 50*time.Millisecond {
		t.Errorf("NOW answered %v", r.Now)
	}
	if r := d.do(&dutproto.Held{}, dutproto.KindText).(*dutproto.Text); !strings.HasPrefix(r.S, "Conns=1 ") {
		t.Errorf("HELD answered %q", r.S)
	}
	d.do(&dutproto.Stats{}, dutproto.KindText)
	d.do(&dutproto.Bound{}, dutproto.KindText)
	if r := d.do(&dutproto.BoostPolicy{H: c, Floor: true}, dutproto.KindBool).(*dutproto.Bool); r.V {
		t.Errorf("a new connection has its boost")
	}
	d.do(&dutproto.Events{}, dutproto.KindEventList)
	d.do(&dutproto.RTOAt{H: c}, dutproto.KindError)
	d.do(&dutproto.Delivered{H: c}, dutproto.KindBool)
	d.do(&dutproto.CloseWrite{H: c}, dutproto.KindOK)
	if r := d.do(&dutproto.Write{H: c, Data: dutproto.Bytes("x")}, dutproto.KindError).(*dutproto.Error); r.Err != dutproto.ErrBrokenPipe {
		t.Errorf("WRITE after CLOSE_WRITE: %s", dutproto.Format(r))
	}
	d.do(&dutproto.Abort{H: c}, dutproto.KindOK)
	if r := d.do(&dutproto.Read{H: c, Max: 10}, dutproto.KindError).(*dutproto.Error); r.Err != dutproto.ErrClosed {
		t.Errorf("READ after ABORT: %s", dutproto.Format(r))
	}
	u := d.do(&dutproto.UDPListen{Port: 53}, dutproto.KindHandle).(*dutproto.HandleResp).H
	d.do(&dutproto.UDPRecv{H: u, Max: 100}, dutproto.KindWouldBlock)
	d.do(&dutproto.Inject{Packets: []dutproto.Bytes{buildUDP(netip.AddrPortFrom(peerAddr, 7000), 53, []byte("query"))}}, dutproto.KindOK)
	if r := d.do(&dutproto.UDPRecv{H: u, Max: 3}, dutproto.KindDatagram).(*dutproto.Datagram); string(r.Data) != "que" || r.From != netip.AddrPortFrom(peerAddr, 7000) {
		t.Errorf("UDP_RECV %s", dutproto.Format(r))
	}
	d.do(&dutproto.UDPSend{H: u, To: netip.AddrPortFrom(peerAddr, 7000), Data: dutproto.Bytes("answer")}, dutproto.KindOK)
	pg := d.do(&dutproto.PingOpen{To: peerAddr}, dutproto.KindHandle).(*dutproto.HandleResp).H
	d.do(&dutproto.PingRecv{H: pg, Max: 100}, dutproto.KindWouldBlock)
	d.do(&dutproto.PingClose{H: pg}, dutproto.KindOK)
	d.do(&dutproto.Close{H: l}, dutproto.KindOK)
	if code := d.end(); code != dutserveExitOK {
		t.Errorf("exit status %d after the standard input closed, want %d", code, dutserveExitOK)
	}
}

// TestDutserveRefuses checks that dutserve answers a protocol error with ERROR and exit status 2:
// a request before HELLO, non-default limits, a second HELLO, an unknown handle, a handle of the
// wrong kind, a broken frame, and arguments other than --clock fake.
func TestDutserveRefuses(t *testing.T) {
	limits := testHello()
	limits.Limits = []dutproto.Limit{{Name: "maxFlows", Value: 8}}
	cases := []struct {
		name string
		reqs []dutproto.Msg
		raw  []byte
	}{
		{"no HELLO", []dutproto.Msg{&dutproto.Now{}}, nil},
		{"limits", []dutproto.Msg{limits}, nil},
		{"second HELLO", []dutproto.Msg{testHello(), testHello()}, nil},
		{"unknown handle", []dutproto.Msg{testHello(), &dutproto.Read{H: 9, Max: 1}}, nil},
		{"wrong kind", []dutproto.Msg{testHello(), &dutproto.UDPListen{Port: 53}, &dutproto.Accept{H: 1}}, nil},
		{"broken frame", []dutproto.Msg{testHello()}, []byte{3, 0, 0, 0, byte(dutproto.KindRead), 1, 2}},
	}
	for _, c := range cases {
		var in, out, logw bytes.Buffer
		for _, m := range c.reqs {
			in.Write(dutproto.AppendFrame(nil, m))
		}
		in.Write(c.raw)
		code := dutserveMain([]string{"--clock=fake"}, &in, &out, &logw)
		if code != dutserveExitProtocol {
			t.Errorf("%s: exit status %d, want %d", c.name, code, dutserveExitProtocol)
		}
		var last dutproto.Msg
		for {
			m, err := dutproto.ReadMsg(&out)
			if err != nil {
				break
			}
			last = m
		}
		if _, ok := last.(*dutproto.Error); !ok {
			t.Errorf("%s: the last response is %v, want ERROR", c.name, last)
		}
	}
	for _, args := range [][]string{nil, {"--clock", "real"}, {"--verbose"}} {
		if code := dutserveMain(args, &bytes.Buffer{}, &bytes.Buffer{}, io.Discard); code != dutserveExitProtocol {
			t.Errorf("arguments %q: exit status %d, want %d", args, code, dutserveExitProtocol)
		}
	}
}
