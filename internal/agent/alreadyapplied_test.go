package agent

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/proto"
)

func testState(gen uint64, target string) *proto.State {
	return &proto.State{
		Generation: gen,
		WG:         proto.WGConfig{Address: "10.200.0.2/24", MTU: 1420, Keepalive: 25, UDPTimeout: 30},
		Rules:      []proto.AgentRule{{ID: "r1", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 25565, Hi: 25565}, Target: target, Enabled: true}},
	}
}

// alreadyApplied is true only for a State equal in generation and content to the last one applied,
// while the tunnel is up and nothing waits for a retry or shows a refused wg config (design.md
// 5.2 節).
func TestAlreadyAppliedNeedsTheSameAppliedStateAndNothingPending(t *testing.T) {
	dp := &fakeDataplane{}
	rt := newFakeDataplaneRuntime(t, dp)
	if rt.alreadyApplied(testState(0, "192.168.1.30:25565")) {
		t.Fatal("true before anything was applied")
	}
	applied := testState(3, "192.168.1.30:25565")
	if err := rt.apply(applied); err != nil {
		t.Fatal(err)
	}
	if !rt.alreadyApplied(testState(3, "192.168.1.30:25565")) {
		t.Fatal("false for an equal copy of the applied State")
	}
	if rt.alreadyApplied(testState(4, "192.168.1.30:25565")) {
		t.Error("true for a newer generation")
	}
	if rt.alreadyApplied(testState(3, "192.168.1.31:25565")) {
		t.Error("true for a different rule in the same generation")
	}
	timeouts := testState(3, "192.168.1.30:25565")
	timeouts.WG.UDPTimeout = 60
	if rt.alreadyApplied(timeouts) {
		t.Error("true for new UDP timeouts in the same generation")
	}
	rt.mu.Lock()
	rt.pendingSt = testState(4, "192.168.1.30:25565")
	rt.mu.Unlock()
	if rt.alreadyApplied(testState(3, "192.168.1.30:25565")) {
		t.Error("true while a State waits for a retry")
	}
	rt.mu.Lock()
	rt.pendingSt = nil
	rt.refused = &refusedState{gen: 4}
	rt.mu.Unlock()
	if rt.alreadyApplied(testState(3, "192.168.1.30:25565")) {
		t.Error("true while a refused wg config is shown")
	}
	rt.mu.Lock()
	rt.refused = nil
	dp.up = false
	rt.mu.Unlock()
	if rt.alreadyApplied(testState(3, "192.168.1.30:25565")) {
		t.Error("true while the tunnel is down")
	}
}

// Over a stream: the first State of a connection is applied, a later repeat of the applied State is
// not, a State of the same generation with other content is, and so is a newer generation. The
// first State of a new connection is applied even when it repeats the applied one.
func TestStreamDoesNotReapplyTheSameState(t *testing.T) {
	srv, pin, stateCh, hbCh, _ := newTestStreamServer(t)
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	dp := &fakeDataplane{}
	rt := &runtime{
		dp: dp,
		f: &credentials.Credentials{
			Endpoint:       strings.TrimPrefix(srv.URL, "https://"),
			CertSHA256:     hex.EncodeToString(pin[:]),
			PermanentToken: "tok",
		},
		priv:              priv,
		heartbeatInterval: time.Hour,
		opts:              Options{CredentialsPath: t.TempDir() + "/agent.json"},
	}
	applies := func() int {
		rt.mu.Lock()
		defer rt.mu.Unlock()
		return len(dp.applied)
	}
	connect := func() (context.CancelFunc, chan error) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- rt.streamOnce(ctx) }()
		return cancel, done
	}
	waitHeartbeat := func(gen uint64) {
		t.Helper()
		for {
			select {
			case hb := <-hbCh:
				if hb.Generation == gen {
					return
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("no heartbeat for generation %d", gen)
			}
		}
	}
	// A heartbeat reports a generation only after applying it, and States are handled in order, so a
	// heartbeat of the last, newer generation shows every State before it was handled.
	cancel, done := connect()
	stateCh <- testState(1, "192.168.1.30:25565")
	waitHeartbeat(1)
	stateCh <- testState(1, "192.168.1.30:25565") // a repeat: skipped
	changed := testState(1, "192.168.1.30:25565")
	changed.WG.UDPTimeout = 60
	stateCh <- changed                            // same generation, other content: applied
	stateCh <- testState(2, "192.168.1.30:25565") // newer: applied
	waitHeartbeat(2)
	if got := applies(); got != 3 {
		t.Fatalf("applies = %d, want 3: the repeat skipped, the same-generation change applied", got)
	}
	stateCh <- testState(2, "192.168.1.30:25565") // a repeat: skipped
	stateCh <- testState(2, "192.168.1.31:25565") // same generation, another target: applied
	stateCh <- testState(2, "192.168.1.31:25565") // a repeat of that one: skipped
	stateCh <- testState(3, "192.168.1.31:25565")
	waitHeartbeat(3)
	if got := applies(); got != 5 {
		t.Fatalf("applies = %d, want 5", got)
	}
	cancel()
	<-done

	// A fresh server, so the old connection's handler cannot take the States meant for the new one.
	srv2, pin2, stateCh2, hbCh2, _ := newTestStreamServer(t)
	rt.mu.Lock()
	rt.f.Endpoint, rt.f.CertSHA256 = strings.TrimPrefix(srv2.URL, "https://"), hex.EncodeToString(pin2[:])
	rt.mu.Unlock()
	stateCh, hbCh = stateCh2, hbCh2
	cancel, done = connect()
	defer func() {
		cancel()
		<-done
	}()
	stateCh <- testState(3, "192.168.1.31:25565") // the first State of a new connection: applied
	stateCh <- testState(4, "192.168.1.31:25565")
	waitHeartbeat(4)
	if got := applies(); got != 7 {
		t.Fatalf("applies after a reconnect = %d, want 7: the first State of a connection is applied even when it repeats", got)
	}
}
