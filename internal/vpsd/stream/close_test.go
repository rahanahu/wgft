package stream

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/net/netutil"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/proto"
)

type observedCloseConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *observedCloseConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

type observedCloseListener struct {
	net.Listener
	accepted chan *observedCloseConn
}

func (l *observedCloseListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	o := &observedCloseConn{Conn: c}
	l.accepted <- o
	return o, nil
}

type initialStateFailure struct {
	*fakeBackend
	entered chan struct{}
	release chan struct{}
}

func (b *initialStateFailure) StateFor(agent string, sel proto.Negotiated) (*proto.State, error) {
	if agent == "first" {
		close(b.entered)
		<-b.release
		return nil, errBackendFailure
	}
	return b.fakeBackend.StateFor(agent, sel)
}

func closeTestReceive[T any](t *testing.T, ch <-chan T, label string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
		var zero T
		return zero
	}
}

// The strong server-side references and disabled GC exclude finalizer cleanup.
// Neither failed client is read or closed until the waiting upgrade succeeds.
func TestAcceptedStreamReturnsTransportSlot(t *testing.T) {
	previous := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previous)
	for _, stateFailure := range []bool{false, true} {
		name := "malformed-json"
		if stateFailure {
			name = "initial-state-error"
		}
		t.Run(name, func(t *testing.T) {
			serverKey, _ := wgtypes.GeneratePrivateKey()
			base := &fakeBackend{server: serverKey, keys: map[string]wgtypes.Key{}, gen: 1}
			var backend Backend = base
			var failure *initialStateFailure
			var unblock func()
			if stateFailure {
				failure = &initialStateFailure{fakeBackend: base, entered: make(chan struct{}), release: make(chan struct{})}
				backend = failure
				var once sync.Once
				unblock = func() { once.Do(func() { close(failure.release) }) }
				defer unblock()
			}
			h := New(backend)
			retained := make(chan *websocket.Conn, 2)
			h.OnStreamConnect = func(agent, _ string) {
				h.mu.Lock()
				retained <- h.conns[agent].ws
				h.mu.Unlock()
			}
			returned := make(chan struct{}, 2)
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h.ServeHTTP(w, r)
				returned <- struct{}{}
			}))
			observed := &observedCloseListener{Listener: srv.Listener, accepted: make(chan *observedCloseConn, 2)}
			srv.Listener = netutil.LimitListener(observed, 1)
			srv.Start()
			t.Cleanup(srv.Close)
			url := "ws" + strings.TrimPrefix(srv.URL, "http")
			first, _, err := dial(t, url, "tok-first")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { first.CloseNow() })
			transport := closeTestReceive(t, observed.accepted, "first transport")
			key, _ := wgtypes.GeneratePrivateKey()
			sendJSON(t, first, proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String()})
			strong := closeTestReceive(t, retained, "server connection")
			t.Cleanup(func() { strong.CloseNow() })
			if stateFailure {
				closeTestReceive(t, failure.entered, "StateFor entry")
			} else if m, err := readMsg(t, first); err != nil || m.State == nil {
				t.Fatalf("initial state: %v %v", m, err)
			}

			// Establish the second TCP connection in the listen backlog before
			// ending the first handler. The sole permit is still occupied.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			tcpReady := make(chan struct{})
			httpTransport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, network, address)
				if err == nil {
					close(tcpReady)
				}
				return c, err
			}}
			defer httpTransport.CloseIdleConnections()
			type dialResult struct {
				ws  *websocket.Conn
				err error
			}
			waiting := make(chan dialResult, 1)
			go func() {
				ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
					HTTPClient: &http.Client{Transport: httpTransport},
					HTTPHeader: http.Header{"Authorization": {"Bearer tok-next"}},
				})
				waiting <- dialResult{ws, err}
			}()
			closeTestReceive(t, tcpReady, "waiting TCP connection")
			if transport.closes.Load() != 0 {
				t.Fatal("first transport closed before the trigger")
			}
			if stateFailure {
				unblock()
			} else if err := first.Write(ctx, websocket.MessageText, []byte("{")); err != nil {
				t.Fatal(err)
			}
			closeTestReceive(t, returned, "failed handler exit")
			if got := transport.closes.Load(); got != 1 {
				t.Fatalf("server transport Close calls = %d, want 1", got)
			}
			next := closeTestReceive(t, waiting, "waiting upgrade")
			if next.err != nil {
				t.Fatal(next.err)
			}
			t.Cleanup(func() { next.ws.CloseNow() })
			nextTransport := closeTestReceive(t, observed.accepted, "replacement transport")
			nextKey, _ := wgtypes.GeneratePrivateKey()
			sendJSON(t, next.ws, proto.Message{Type: proto.MsgPublicKey, PublicKey: nextKey.PublicKey().String()})
			if m, err := readMsg(t, next.ws); err != nil || m.State == nil {
				t.Fatalf("replacement state: %v %v", m, err)
			}
			strong.CloseNow()
			strong.CloseNow()
			if transport.closes.Load() != 1 || nextTransport.closes.Load() != 0 || !h.Status("next").Connected {
				t.Fatal("duplicate old cleanup affected the replacement")
			}
			if h.Status("first").Connected {
				t.Fatal("failed stream still connected")
			}
			if err := next.ws.Close(websocket.StatusNormalClosure, "done"); err != nil {
				t.Fatal(err)
			}
			closeTestReceive(t, returned, "replacement handler exit")
			if nextTransport.closes.Load() != 1 {
				t.Fatal("normal peer close did not release the replacement")
			}
			runtime.KeepAlive(strong)
		})
	}
}

func TestAcceptedStreamConcurrentCloseAfterSupersede(t *testing.T) {
	serverKey, _ := wgtypes.GeneratePrivateKey()
	h := New(&fakeBackend{server: serverKey, keys: map[string]wgtypes.Key{}, gen: 1})
	retained := make(chan *websocket.Conn, 2)
	h.OnStreamConnect = func(agent, _ string) {
		h.mu.Lock()
		retained <- h.conns[agent].ws
		h.mu.Unlock()
	}
	returned := make(chan struct{}, 2)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		returned <- struct{}{}
	}))
	observed := &observedCloseListener{Listener: srv.Listener, accepted: make(chan *observedCloseConn, 2)}
	srv.Listener = netutil.LimitListener(observed, 2)
	srv.Start()
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	old, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { old.CloseNow() })
	transport := closeTestReceive(t, observed.accepted, "old transport")
	key, _ := wgtypes.GeneratePrivateKey()
	sendJSON(t, old, proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String()})
	strong := closeTestReceive(t, retained, "old server connection")
	t.Cleanup(func() { strong.CloseNow() })
	if _, err := readMsg(t, old); err != nil {
		t.Fatal(err)
	}
	next, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { next.CloseNow() })
	nextTransport := closeTestReceive(t, observed.accepted, "new transport")
	sendJSON(t, next, proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String()})
	newStrong := closeTestReceive(t, retained, "new server connection")
	t.Cleanup(func() { newStrong.CloseNow() })
	if _, err := readMsg(t, next); err != nil {
		t.Fatal(err)
	}
	// Supersede already owns an asynchronous graceful close. Explicit close,
	// immediate close, peer close, and the handler fallback may all overlap.
	start := make(chan struct{})
	finished := make(chan struct{}, 3)
	for _, closeConn := range []func(){
		func() { strong.Close(websocket.StatusNormalClosure, "done") },
		func() { strong.CloseNow() },
		func() { old.CloseNow() },
	} {
		go func() {
			<-start
			closeConn()
			finished <- struct{}{}
		}()
	}
	close(start)
	for range 3 {
		closeTestReceive(t, finished, "concurrent close")
	}
	closeTestReceive(t, returned, "superseded handler exit")
	if transport.closes.Load() != 1 || nextTransport.closes.Load() != 0 || !h.Status("home").Connected {
		t.Fatal("old close changed the live replacement or closed its transport")
	}
	h.Push("home")
	if m, err := readMsg(t, next); err != nil || m.State == nil {
		t.Fatalf("replacement no longer usable: %v %v", m, err)
	}
	if err := next.Close(websocket.StatusNormalClosure, "done"); err != nil {
		t.Fatal(err)
	}
	closeTestReceive(t, returned, "normal peer-close handler exit")
	if nextTransport.closes.Load() != 1 || h.Status("home").Connected {
		t.Fatal("normal close did not release the replacement")
	}
	runtime.KeepAlive(strong)
	runtime.KeepAlive(newStrong)
}
