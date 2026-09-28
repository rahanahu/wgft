package stream

import (
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/proto"
)

type publicationBackend struct {
	*fakeBackend
	mu      sync.Mutex
	state   proto.State
	revoked bool
	calls   int
	before  func(int)
	after   func(int)
}

func (b *publicationBackend) StateFor(_, _ string, _ wgtypes.Key, _ proto.Negotiated) (*proto.State, error) {
	b.mu.Lock()
	b.calls++
	call, before := b.calls, b.before
	b.mu.Unlock()
	if before != nil {
		before(call)
	}
	b.mu.Lock()
	if b.revoked {
		b.mu.Unlock()
		return nil, errors.New("registration revoked")
	}
	st := b.state
	st.Rules = append([]proto.AgentRule(nil), st.Rules...)
	after := b.after
	b.mu.Unlock()
	if after != nil {
		after(call)
	}
	return &st, nil
}

func publicationFixture(t *testing.T, before func(int)) (*Hub, *publicationBackend, string, wgtypes.Key) {
	t.Helper()
	server, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	b := &publicationBackend{fakeBackend: &fakeBackend{server: server, keys: map[string]wgtypes.Key{}}, before: before,
		state: proto.State{Generation: 1,
			WG:    proto.WGConfig{ServerPubkey: server.PublicKey().String(), Endpoint: "server.example:51820", Address: "10.200.0.2/24", MTU: 1280, Keepalive: 25, UDPTimeout: 7, UDPTimeoutStream: 19},
			Rules: []proto.AgentRule{{ID: "r", ListenPort: proto.PortRange{Lo: 25565, Hi: 25565}, Target: "192.0.2.10:25565", Enabled: true}}}}
	h := New(b)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return h, b, "ws" + strings.TrimPrefix(srv.URL, "http"), key
}

func openPublicationStream(t *testing.T, url string, key wgtypes.Key) *websocket.Conn {
	t.Helper()
	c, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.CloseNow() })
	sendJSON(t, c, proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String()})
	return c
}

func requirePublicationState(t *testing.T, c *websocket.Conn, generation uint64, disabled bool) {
	t.Helper()
	m, err := readMsg(t, c)
	if err != nil || m.Type != proto.MsgState || m.State == nil {
		t.Fatalf("State read: %+v, %v", m, err)
	}
	s := m.State
	if s.Generation != generation || s.AgentDisabled != disabled || len(s.Rules) != 1 || s.Rules[0].Enabled == disabled ||
		s.Rules[0].Target != "192.0.2.10:25565" || s.WG.Endpoint != "server.example:51820" || s.WG.MTU != 1280 ||
		s.WG.UDPTimeout != 7 || s.WG.UDPTimeoutStream != 19 {
		t.Fatalf("wrong selected wire State: %+v", s)
	}
}

func currentConn(t *testing.T, h *Hub) *conn {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.conns["home"]
	if c == nil {
		t.Fatal("no current connection")
	}
	return c
}

func waitWorkerDone(t *testing.T, c *conn) {
	t.Helper()
	select {
	case <-c.pushDone:
	case <-time.After(5 * time.Second):
		t.Fatal("push worker did not join")
	}
}

func TestInitialAndPushSelectLatestStateAtSend(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	h, b, url, key := publicationFixture(t, func(call int) {
		if call == 2 {
			close(entered)
			<-release
		}
	})
	c := openPublicationStream(t, url, key)
	<-entered
	b.mu.Lock()
	b.state.Generation = 2
	b.state.AgentDisabled = true
	b.state.Rules[0].Enabled = false
	b.mu.Unlock()
	close(release)
	requirePublicationState(t, c, 2, true)

	// A later saved edit that failed publication has not changed this backend's
	// authorized State. The queued push selects the same State on the wire.
	writer := currentConn(t, h)
	writer.sendMu.Lock()
	h.Push("home")
	if cap(writer.pushCh) != 1 || len(writer.pushCh) > 1 {
		t.Fatal("push queue is not bounded to one request")
	}
	writer.sendMu.Unlock()
	requirePublicationState(t, c, 2, true)
}

func TestQueuedPushAfterRevokeDoesNotSendState(t *testing.T) {
	h, b, url, key := publicationFixture(t, nil)
	c := openPublicationStream(t, url, key)
	requirePublicationState(t, c, 1, false)
	old := currentConn(t, h)
	old.sendMu.Lock()
	for i := 0; i < 1000; i++ {
		h.Push("home")
	}
	b.mu.Lock()
	b.revoked = true
	b.mu.Unlock()
	h.Disconnect("home", proto.CloseRevoked, "revoked")
	old.sendMu.Unlock()
	if _, err := readMsg(t, c); websocket.CloseStatus(err) != websocket.StatusCode(proto.CloseRevoked) {
		t.Fatalf("revoke close: %v", err)
	}
	waitWorkerDone(t, old)
	b.mu.Lock()
	calls := b.calls
	b.mu.Unlock()
	if calls != 2 {
		t.Fatalf("queued push selected revoked State %d times", calls-2)
	}
}

func TestReplacementSkipsOldQueuedPushAndSendsNewInitialState(t *testing.T) {
	h, b, url, key := publicationFixture(t, nil)
	c1 := openPublicationStream(t, url, key)
	requirePublicationState(t, c1, 1, false)
	old := currentConn(t, h)
	old.sendMu.Lock()
	h.Push("home")
	b.mu.Lock()
	b.state.Generation = 2
	b.mu.Unlock()
	c2 := openPublicationStream(t, url, key)
	requirePublicationState(t, c2, 2, false)
	old.sendMu.Unlock()
	if _, err := readMsg(t, c1); websocket.CloseStatus(err) != websocket.StatusCode(proto.CloseSuperseded) {
		t.Fatalf("old connection close: %v", err)
	}
	waitWorkerDone(t, old)
	b.mu.Lock()
	calls := b.calls
	b.mu.Unlock()
	if calls != 4 {
		t.Fatalf("old queued push selected State after replacement: %d calls", calls)
	}
}

func TestInFlightSelectionMayFinishAfterReplacement(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	h, _, url, key := publicationFixture(t, func(call int) {
		if call == 3 {
			close(entered)
			<-release
		}
	})
	c1 := openPublicationStream(t, url, key)
	requirePublicationState(t, c1, 1, false)
	old := currentConn(t, h)
	h.Push("home")
	<-entered // The old send passed the current-connection check.
	c2 := openPublicationStream(t, url, key)
	requirePublicationState(t, c2, 1, false)
	c1.CloseNow()
	close(release)
	waitWorkerDone(t, old)
	// The old Write may finish or fail after replacement. Either outcome is
	// allowed for an already-started send; the new connection got its own State.
}

func TestAlreadySelectedStateMayFinishAfterDisable(t *testing.T) {
	h, b, url, key := publicationFixture(t, nil)
	c := openPublicationStream(t, url, key)
	requirePublicationState(t, c, 1, false)
	selected, release := make(chan struct{}), make(chan struct{})
	b.mu.Lock()
	b.after = func(call int) {
		if call == 3 {
			close(selected)
			<-release
		}
	}
	b.mu.Unlock()
	h.Push("home")
	<-selected
	b.mu.Lock()
	b.state.Generation = 2
	b.state.AgentDisabled = true
	b.state.Rules[0].Enabled = false
	b.mu.Unlock()
	close(release)
	requirePublicationState(t, c, 1, false) // selected before the disable commit
	h.Push("home")
	requirePublicationState(t, c, 2, true) // selected after the commit
}

func TestRetiredKeyCancelsQueuedPushWorker(t *testing.T) {
	h, b, url, key := publicationFixture(t, nil)
	c := openPublicationStream(t, url, key)
	requirePublicationState(t, c, 1, false)
	old := currentConn(t, h)
	old.sendMu.Lock()
	for i := 0; i < 1000; i++ {
		h.Push("home")
	}
	h.RetireIfDifferent("home", "tok-home", "new published key")
	old.sendMu.Unlock()
	if msg, err := readMsg(t, c); err == nil || msg.Type == proto.MsgState {
		t.Fatalf("retired key received queued State: %+v, %v", msg, err)
	}
	waitWorkerDone(t, old)
	if h.Status("home").Connected {
		t.Fatal("retired key remained connected")
	}
	b.mu.Lock()
	calls := b.calls
	b.mu.Unlock()
	if calls != 2 { // admission and initial send only
		t.Fatalf("retired key selected State after publication: %d calls", calls)
	}
}
