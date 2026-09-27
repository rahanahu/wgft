package wgbind

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

// fakeEndpoint は 1 件の datagram の送信元を id で区別する conn.Endpoint。
type fakeEndpoint struct{ id int }

func (fakeEndpoint) ClearSrc()             {}
func (fakeEndpoint) SrcToString() string   { return "" }
func (e fakeEndpoint) DstToString() string { return fmt.Sprintf("fake-%d", e.id) }
func (e fakeEndpoint) DstToBytes() []byte  { return []byte{byte(e.id)} }
func (fakeEndpoint) DstIP() netip.Addr     { return netip.Addr{} }
func (fakeEndpoint) SrcIP() netip.Addr     { return netip.Addr{} }

// fakeResult は内側の受信の関数の 1 回分の結果。err があれば datagram は無視する。
type fakeResult struct {
	datagrams []string
	err       error
}

// fakeBind は台本どおりに受信の結果を返す内側のバインド。受信の関数は 1 つだけ返す。
type fakeBind struct {
	batch   int
	script  []fakeResult
	calls   []int // 呼び出しごとの len(bufs)
	minBuf  int   // 渡されたバッファの最小の長さ
	sent    [][]byte
	sentTo  conn.Endpoint
	closed  int
	opened  int
	sendErr error
}

func (f *fakeBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	f.opened++
	f.minBuf = -1
	return []conn.ReceiveFunc{f.receive}, port, nil
}

func (f *fakeBind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	f.calls = append(f.calls, len(bufs))
	for _, b := range bufs {
		if f.minBuf < 0 || len(b) < f.minBuf {
			f.minBuf = len(b)
		}
	}
	if len(f.script) == 0 {
		return 0, net.ErrClosed
	}
	res := f.script[0]
	f.script = f.script[1:]
	if res.err != nil {
		return 0, res.err
	}
	if len(res.datagrams) > len(bufs) {
		panic("fakeBind: script returns more datagrams than the batch")
	}
	for i, d := range res.datagrams {
		sizes[i] = copy(bufs[i], d)
		eps[i] = fakeEndpoint{id: i + 1}
	}
	return len(res.datagrams), nil
}

func (f *fakeBind) Close() error                                { f.closed++; return nil }
func (f *fakeBind) SetMark(uint32) error                        { return nil }
func (f *fakeBind) BatchSize() int                              { return f.batch }
func (f *fakeBind) ParseEndpoint(string) (conn.Endpoint, error) { return fakeEndpoint{}, nil }
func (f *fakeBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	f.sent = bufs
	f.sentTo = ep
	return f.sendErr
}

// permanentError は wireguard-go が回復不能と読む非一時的な net.Error。
type permanentError struct{}

func (permanentError) Error() string   { return "permanent receive error" }
func (permanentError) Timeout() bool   { return false }
func (permanentError) Temporary() bool { return false }

func open(t *testing.T, inner *fakeBind) (conn.Bind, conn.ReceiveFunc) {
	t.Helper()
	b := BatchOne(inner)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(fns) != 1 {
		t.Fatalf("Open returned %d receive functions, want 1", len(fns))
	}
	return b, fns[0]
}

// one は包みの受信を 1 回呼び、wireguard-go と同じく長さ 1 の bufs、sizes、eps を渡す。
func one(t *testing.T, fn conn.ReceiveFunc) (string, conn.Endpoint, error) {
	t.Helper()
	buf := make([]byte, maxDatagram)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := fn([][]byte{buf}, sizes, eps)
	if err != nil {
		if n != 0 {
			t.Fatalf("receive returned n=%d with error %v, want 0", n, err)
		}
		return "", nil, err
	}
	if n != 1 {
		t.Fatalf("receive returned n=%d, want 1", n)
	}
	return string(buf[:sizes[0]]), eps[0], nil
}

func TestBatchOneReportsBatchSizeOne(t *testing.T) {
	b := BatchOne(&fakeBind{batch: 4})
	if got := b.BatchSize(); got != 1 {
		t.Fatalf("BatchSize() = %d, want 1", got)
	}
}

func TestBatchOneLeavesABatchSizeOneBindAlone(t *testing.T) {
	inner := &fakeBind{batch: 1}
	if got := BatchOne(inner); got != conn.Bind(inner) {
		t.Fatalf("BatchOne(inner with BatchSize 1) = %T, want the inner bind itself", got)
	}
}

func TestBatchOneHandsOutOneDatagramPerCallInOrder(t *testing.T) {
	inner := &fakeBind{batch: 4, script: []fakeResult{
		{datagrams: []string{"a", "bb", ""}}, // 空の 1 件は wireguard-go が捨てるので、そのまま渡す
		{datagrams: []string{"cccc"}},
	}}
	_, fn := open(t, inner)
	want := []struct {
		data string
		id   int
	}{{"a", 1}, {"bb", 2}, {"", 3}, {"cccc", 1}}
	for i, w := range want {
		got, ep, err := one(t, fn)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if got != w.data || ep.(fakeEndpoint).id != w.id {
			t.Fatalf("call %d: got %q from %v, want %q from fake-%d", i, got, ep.DstToString(), w.data, w.id)
		}
	}
	// 内側は手持ちが尽きたときだけ呼ばれ、毎回 BatchSize 個ちょうどのバッファを受ける。
	if len(inner.calls) != 2 || inner.calls[0] != 4 || inner.calls[1] != 4 {
		t.Fatalf("inner receive calls = %v, want [4 4]", inner.calls)
	}
	if inner.minBuf < maxDatagram {
		t.Fatalf("smallest buffer handed to the inner bind is %d bytes, want at least %d", inner.minBuf, maxDatagram)
	}
}

func TestBatchOneReturnsTheInnerErrorUnwrappedAfterHandingOutWhatItHolds(t *testing.T) {
	sentinel := permanentError{}
	inner := &fakeBind{batch: 3, script: []fakeResult{
		{datagrams: []string{"a", "b"}},
		{err: sentinel},
	}}
	_, fn := open(t, inner)
	for _, want := range []string{"a", "b"} {
		got, _, err := one(t, fn)
		if err != nil || got != want {
			t.Fatalf("got %q, %v; want %q, nil", got, err, want)
		}
	}
	_, _, err := one(t, fn)
	// 同じ値であること。wireguard-go は net.Error への直接の型の判定で Temporary を見るので、
	// 包んだ誤りは一時的と誤って読まれる。
	if err != error(sentinel) {
		t.Fatalf("receive returned %#v, want the inner bind's error value %#v unchanged", err, sentinel)
	}
	if _, ok := err.(net.Error); !ok {
		t.Fatalf("returned error does not type-assert to net.Error the way wireguard-go reads it: %#v", err)
	}
}

func TestBatchOneReturnsErrClosedAfterCloseEvenWithDatagramsHeld(t *testing.T) {
	inner := &fakeBind{batch: 4, script: []fakeResult{
		{datagrams: []string{"a", "b", "c"}},
		{datagrams: []string{"never"}},
	}}
	b, fn := open(t, inner)
	if got, _, err := one(t, fn); err != nil || got != "a" {
		t.Fatalf("first call: %q, %v", got, err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if inner.closed != 1 {
		t.Fatalf("inner Close called %d times, want 1", inner.closed)
	}
	calls := len(inner.calls)
	for i := 0; i < 2; i++ {
		_, _, err := one(t, fn)
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("receive after Close returned %v, want net.ErrClosed", err)
		}
	}
	if len(inner.calls) != calls {
		t.Fatalf("inner receive was called after Close (%d calls, had %d)", len(inner.calls), calls)
	}
}

func TestBatchOneOpensAgainAfterClose(t *testing.T) {
	inner := &fakeBind{batch: 2, script: []fakeResult{
		{datagrams: []string{"old"}},
		{datagrams: []string{"new"}},
	}}
	b, fn := open(t, inner)
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, _, err := one(t, fn); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old receive function after Close returned %v, want net.ErrClosed", err)
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	got, _, err := one(t, fns[0])
	if err != nil || got != "old" {
		t.Fatalf("receive after the second Open: %q, %v; want the next scripted datagram", got, err)
	}
	if _, _, err := one(t, fn); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old receive function after the second Open returned %v, want net.ErrClosed still", err)
	}
}

func TestBatchOneSendPassesThrough(t *testing.T) {
	sendErr := errors.New("send failed")
	inner := &fakeBind{batch: 4, sendErr: sendErr}
	b := BatchOne(inner)
	bufs := [][]byte{[]byte("payload")}
	ep := fakeEndpoint{id: 7}
	if err := b.Send(bufs, ep); err != sendErr {
		t.Fatalf("Send returned %v, want the inner bind's error %v unchanged", err, sendErr)
	}
	if len(inner.sent) != 1 || &inner.sent[0][0] != &bufs[0][0] || inner.sentTo != conn.Endpoint(ep) {
		t.Fatalf("inner Send got %q to %v, want the same buffers to %v", inner.sent, inner.sentTo, ep)
	}
}

// Close は受信とは別の goroutine から来る。-race で走らせるための試験。
func TestBatchOneCloseRacesWithReceive(t *testing.T) {
	script := make([]fakeResult, 64)
	for i := range script {
		script[i] = fakeResult{datagrams: []string{"x", "y"}}
	}
	inner := &fakeBind{batch: 2, script: script}
	b, fn := open(t, inner)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			if _, _, err := one(t, fn); err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("receive returned %v, want net.ErrClosed", err)
				}
				return
			}
		}
	}()
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()
}

// 実際の標準のバインドを包み、loopback の UDP で 1 件ずつ届くことを確かめる。標準のバインドの
// BatchSize が 1 の OS では包まれないので、そのことだけを確かめる。
func TestBatchOneWithTheStandardBind(t *testing.T) {
	inner := conn.NewStdNetBind()
	b := BatchOne(inner)
	if inner.BatchSize() == 1 {
		if b != inner {
			t.Fatalf("BatchOne wrapped a bind whose BatchSize is already 1")
		}
		return
	}
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()
	var recv4 conn.ReceiveFunc
	for _, fn := range fns {
		if fn.PrettyName() == "v4" {
			recv4 = fn
		}
	}
	if recv4 == nil {
		t.Skip("no IPv4 receive function")
	}
	sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sender.Close()
	const count = 5
	for i := 0; i < count; i++ {
		if _, err := sender.Write([]byte(fmt.Sprintf("datagram-%d", i))); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	for i := 0; i < count; i++ {
		got, ep, err := one(t, recv4)
		if err != nil {
			t.Fatalf("receive %d: %v", i, err)
		}
		if want := fmt.Sprintf("datagram-%d", i); got != want {
			t.Fatalf("receive %d: got %q, want %q", i, got, want)
		}
		if ep.DstIP() != netip.MustParseAddr("127.0.0.1") {
			t.Fatalf("receive %d: endpoint %s, want 127.0.0.1", i, ep.DstToString())
		}
	}
}
