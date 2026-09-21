//go:build linux

package vpsd

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/vpsd/stream"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは Daemon.AgentRuleStatuses(design.md 5.2、7a.11 節)を、Daemon.hub が具体型
// *stream.Hub である(interface で差し替えられない)ため、本物の Hub と WebSocket 接続で確かめる。
// 実際の不具合(2026-09-21 のレビュー指摘)は、rule_id をキーに「そのルール ID を最後に報告した
// どの agent か」を拾ってしまい、切断した agent の古いハートビートが今の持ち主を上書きしうる形に
// あった。直した形は、rules(呼び出し元がこの応答用に読んだ今のルール集合)を歩き、各ルールの
// 今の持ち主(proto.Rule.Agent)のハートビートだけを見る。

// fakeStreamBackend is a minimal stream.Backend (internal/vpsd/stream) that accepts any
// "tok-<agent>" token and otherwise does nothing, just enough to drive a real *stream.Hub over a
// real WebSocket connection in these tests.
type fakeStreamBackend struct {
	server wgtypes.Key
}

func (b *fakeStreamBackend) Authenticate(tok string) (string, error) {
	return strings.TrimPrefix(tok, "tok-"), nil
}
func (b *fakeStreamBackend) ServerPublicKey() wgtypes.Key { return b.server.PublicKey() }
func (b *fakeStreamBackend) OtherAgentHasKey(string, wgtypes.Key) (bool, error) {
	return false, nil
}
func (b *fakeStreamBackend) SetPublicKey(string, wgtypes.Key) error { return nil }
func (b *fakeStreamBackend) StateFor(agent string, sel proto.Negotiated) (*proto.State, error) {
	return &proto.State{Generation: 1, WG: proto.WGConfig{Address: "10.200.0.2/24"}}, nil
}

// newTestHub starts a real *stream.Hub behind an httptest.Server and returns it with the ws:// URL
// to dial.
func newTestHub(t *testing.T) (*stream.Hub, string) {
	t.Helper()
	server, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	h := stream.New(&fakeStreamBackend{server: server})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return h, "ws" + strings.TrimPrefix(srv.URL, "http")
}

// connectAgent dials url as agent (the required pubkey handshake first, draining the initial full
// state), sends one heartbeat, and waits for h.Status(agent) to reflect it before returning the open
// connection. The caller closes it to simulate that agent going offline; per design.md 5.2 節, h
// then keeps the last heartbeat's content and only flips Connected to false (stream.Hub.drop).
func connectAgent(t *testing.T, h *stream.Hub, url, agent string, hb proto.Heartbeat) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: map[string][]string{"Authorization": {"Bearer tok-" + agent}}})
	if err != nil {
		t.Fatalf("%s: dial: %v", agent, err)
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	writeMsg(t, c, proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String()})
	if _, err := readMsg(t, c); err != nil {
		t.Fatalf("%s: initial state: %v", agent, err)
	}
	writeMsg(t, c, proto.Message{Type: proto.MsgHeartbeat, Heartbeat: &hb})
	waitUntil(t, func() bool { return h.Status(agent).Heartbeat != nil }, agent+": heartbeat not recorded")
	return c
}

// disconnectAgent closes c and waits for h to mark agent as no longer connected, keeping its last
// heartbeat (design.md 5.2 節: this is exactly the "stale agent state" behaviour under test).
func disconnectAgent(t *testing.T, h *stream.Hub, agent string, c *websocket.Conn) {
	t.Helper()
	c.Close(websocket.StatusNormalClosure, "")
	waitUntil(t, func() bool { return !h.Status(agent).Connected }, agent+": did not disconnect")
}

func writeMsg(t *testing.T, c *websocket.Conn, m proto.Message) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Write(context.Background(), websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}

func readMsg(t *testing.T, c *websocket.Conn) (proto.Message, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, b, err := c.Read(ctx)
	if err != nil {
		return proto.Message{}, err
	}
	var m proto.Message
	return m, json.Unmarshal(b, &m)
}

func waitUntil(t *testing.T, done func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !done() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !done() {
		t.Fatal(msg)
	}
}

// TestAgentRuleStatusesUsesRuleOwnCurrentAgent is the regression test for the review finding
// (2026-09-21): a rule id ("r_x") is listed in TWO agents' cached heartbeats - the stale one of an
// agent that is now disconnected, and the live one of the rule's actual, current owner - but the
// rule belongs only to the current owner. The old implementation walked every registered agent's
// last heartbeat (in d.st.Agents()'s "ORDER BY name" order) and wrote out[ruleID] for whichever
// agent it visited last, so a disconnected agent's stale report could silently overwrite the rule's
// real, live status if its name happened to sort after the live owner's - exactly the case named
// here ("z_stale" sorts after "b_live"). The fix looks a rule's status up only under its own agent
// (proto.Rule.Agent), which has no notion of "last one wins" at all, so the connection/report order
// cannot matter either; this is confirmed by running both orders.
func TestAgentRuleStatusesUsesRuleOwnCurrentAgent(t *testing.T) {
	const live, stale = "b_live", "z_stale" // stale sorts after live: the old bug's failure case
	for _, order := range []string{"live connects then stale", "stale connects then live"} {
		t.Run(order, func(t *testing.T) {
			h, url := newTestHub(t)
			liveHB := proto.Heartbeat{Generation: 1, Tunnel: proto.TunnelStatus{State: proto.StatusOK},
				Rules: []proto.RuleStatus{{ID: "r_x", State: proto.StatusError, Reason: "target 192.168.1.20:2456 is not in WGFT_AGENT_ALLOW_TARGETS"}}}
			staleHB := proto.Heartbeat{Generation: 1, Tunnel: proto.TunnelStatus{State: proto.StatusOK},
				Rules: []proto.RuleStatus{{ID: "r_x", State: proto.StatusOK}}}

			var liveConn, staleConn *websocket.Conn
			if order == "live connects then stale" {
				liveConn = connectAgent(t, h, url, live, liveHB)
				staleConn = connectAgent(t, h, url, stale, staleHB)
			} else {
				staleConn = connectAgent(t, h, url, stale, staleHB)
				liveConn = connectAgent(t, h, url, live, liveHB)
			}
			defer liveConn.Close(websocket.StatusNormalClosure, "")
			// The stale agent goes offline; design.md 5.2 節 keeps its last heartbeat (still
			// listing r_x) around.
			disconnectAgent(t, h, stale, staleConn)

			d := &Daemon{hub: h}
			// r_x belongs to live; stale's cached heartbeat happens to still mention the same ID.
			rules := []proto.Rule{{ID: "r_x", Agent: live}}
			got := d.AgentRuleStatuses(rules)

			st, ok := got["r_x"]
			if !ok {
				t.Fatal("r_x missing from AgentRuleStatuses()")
			}
			if st.Agent != live {
				t.Errorf("Agent = %q, want %q (r_x's current agent), not %q (its stale ex-reporter)", st.Agent, live, stale)
			}
			if !st.Connected {
				t.Errorf("Connected = false, want true: %q is live, this must not be %q's stale disconnected report", live, stale)
			}
			if st.State != proto.StatusError || !strings.Contains(st.Reason, "WGFT_AGENT_ALLOW_TARGETS") {
				t.Errorf("state/reason = %q/%q, want %q's error and reason, not %q's ok", st.State, st.Reason, live, stale)
			}
		})
	}
}

// TestAgentRuleStatusesOmitsDeletedRuleID confirms that a rule ID a disconnected agent's stale
// heartbeat still lists, but which no longer exists in the current rule set (deleted while that
// agent was offline), never appears in the result: the old implementation collected every ID any
// agent's heartbeat ever mentioned, so a deleted rule's id stayed in the map forever as a phantom
// entry. The fix only ever looks up IDs drawn from rules, so an ID absent from rules is never
// visited.
func TestAgentRuleStatusesOmitsDeletedRuleID(t *testing.T) {
	h, url := newTestHub(t)
	hb := proto.Heartbeat{Generation: 1, Tunnel: proto.TunnelStatus{State: proto.StatusOK},
		Rules: []proto.RuleStatus{
			{ID: "r_a", State: proto.StatusOK},
			{ID: "r_deleted", State: proto.StatusError, Reason: "tcp/8081: dial tcp 192.168.1.30:8081: connect: connection refused"},
		}}
	c := connectAgent(t, h, url, "home", hb)
	disconnectAgent(t, h, "home", c) // offline; r_deleted was removed from the rule set while it was down

	d := &Daemon{hub: h}
	rules := []proto.Rule{{ID: "r_a", Agent: "home"}} // r_deleted no longer exists
	got := d.AgentRuleStatuses(rules)

	if _, ok := got["r_deleted"]; ok {
		t.Errorf("r_deleted must not appear (it is no longer in rules), got %+v", got)
	}
	if st, ok := got["r_a"]; !ok || st.State != proto.StatusOK || st.Connected {
		t.Errorf("r_a = %+v, want present, ok, connected false (home is offline)", st)
	}
	if len(got) != 1 {
		t.Errorf("AgentRuleStatuses() = %+v, want exactly r_a", got)
	}
}

// TestAgentRuleStatusesNeverConnected confirms a rule whose agent has never connected at all (hub.Status
// returns the zero Status: Connected false, Heartbeat nil) still gets an entry - Agent and Connected
// present, State/Reason/At absent - rather than being left out of the map (2026-09-21, owner's
// decision; design.md 7a.11 節). An absent map entry would be indistinguishable from a Backend that
// does not implement AgentRuleStatusBackend at all. This same code path also covers a revoked
// agent's name (stream.Hub.Disconnect deletes its status entirely, design.md 5.1、5.2 節) or any
// other name the hub has simply never seen: Hub.Status returns the same zero value for all of them.
func TestAgentRuleStatusesNeverConnected(t *testing.T) {
	d := &Daemon{hub: stream.New(nil)}
	rules := []proto.Rule{{ID: "r_a", Agent: "home"}}
	got := d.AgentRuleStatuses(rules)
	st, ok := got["r_a"]
	if !ok {
		t.Fatal("r_a missing from AgentRuleStatuses(): every current rule must get an entry")
	}
	if st.Agent != "home" || st.Connected {
		t.Errorf("r_a = %+v, want Agent home, Connected false", st)
	}
	if st.State != "" || st.Reason != "" || st.At != "" {
		t.Errorf("r_a = %+v, want State/Reason/At all empty (never reported)", st)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"r_a":{"agent":"home","connected":false}}`; string(b) != want {
		t.Errorf("JSON = %s\nwant  %s", b, want)
	}
}

// TestAgentRuleStatusesConnectedButNotYetReported confirms a rule whose agent IS connected, but whose
// latest heartbeat simply does not list this particular rule yet (e.g. it was just added and the
// agent has not applied/reported on it yet), gets an entry with Connected true and State/Reason/At
// all absent - not mistaken for an error, and not left out of the map (2026-09-21, owner's decision;
// design.md 7a.11 節).
func TestAgentRuleStatusesConnectedButNotYetReported(t *testing.T) {
	h, url := newTestHub(t)
	hb := proto.Heartbeat{Generation: 1, Tunnel: proto.TunnelStatus{State: proto.StatusOK},
		Rules: []proto.RuleStatus{{ID: "r_a", State: proto.StatusOK}}} // r_new is not in here
	c := connectAgent(t, h, url, "home", hb)
	defer c.Close(websocket.StatusNormalClosure, "")

	d := &Daemon{hub: h}
	rules := []proto.Rule{{ID: "r_a", Agent: "home"}, {ID: "r_new", Agent: "home"}}
	got := d.AgentRuleStatuses(rules)

	st, ok := got["r_new"]
	if !ok {
		t.Fatal("r_new missing from AgentRuleStatuses(): every current rule must get an entry")
	}
	if st.Agent != "home" || !st.Connected {
		t.Errorf("r_new = %+v, want Agent home, Connected true (the agent is online)", st)
	}
	if st.State != "" || st.Reason != "" || st.At != "" {
		t.Errorf("r_new = %+v, want State/Reason/At all empty (this agent has not reported it yet)", st)
	}
	// The control: r_a, which the same heartbeat does list, still reports normally.
	if ra := got["r_a"]; ra.State != proto.StatusOK || !ra.Connected {
		t.Errorf("r_a = %+v, want state ok, connected true", ra)
	}
}
