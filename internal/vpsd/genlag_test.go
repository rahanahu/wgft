//go:build linux

package vpsd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/internal/vpsd/stream"
	"github.com/rahanahu/wgft/proto"
)

// TestGenLag は、ルール集合の世代の遅れの始まりの記録(genlag.go、設計文書 10.2a 節)を、
// 観測の列を与えて確かめる。時刻は呼び出しに渡すので、時計を差し替えたのと同じである。
func TestGenLag(t *testing.T) {
	t0 := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	sec := func(n int) time.Time { return t0.Add(time.Duration(n) * time.Second) }
	type step struct {
		server   uint64 // 0 以外なら serverAt
		agentGen uint64 // report が真なら reported
		report   bool
		at       int
	}
	cases := []struct {
		name      string
		steps     []step
		wantSince int // -1 なら遅れていない
	}{
		{
			name:      "agent that holds the current generation is not behind",
			steps:     []step{{server: 5, at: 0}, {agentGen: 5, report: true, at: 1}},
			wantSince: -1,
		},
		{
			name:      "lag starts when the server generation advances past the agent",
			steps:     []step{{server: 5, at: 0}, {agentGen: 5, report: true, at: 1}, {server: 6, at: 10}},
			wantSince: 10,
		},
		{
			name:      "lag starts at the first heartbeat seen behind, for example after a restart",
			steps:     []step{{server: 6, at: 0}, {agentGen: 5, report: true, at: 7}},
			wantSince: 7,
		},
		{
			name: "server advancing further during the lag does not reset the start",
			steps: []step{
				{server: 5, at: 0}, {agentGen: 5, report: true, at: 1},
				{server: 6, at: 10}, {agentGen: 5, report: true, at: 20},
				{server: 7, at: 30}, {agentGen: 6, report: true, at: 40}, {server: 8, at: 50},
			},
			wantSince: 10,
		},
		{
			name: "catching up clears the start",
			steps: []step{
				{server: 5, at: 0}, {agentGen: 5, report: true, at: 1},
				{server: 6, at: 10}, {agentGen: 6, report: true, at: 11},
			},
			wantSince: -1,
		},
		{
			name: "a new lag after catching up starts afresh",
			steps: []step{
				{server: 5, at: 0}, {agentGen: 5, report: true, at: 1},
				{server: 6, at: 10}, {agentGen: 6, report: true, at: 11},
				{server: 7, at: 100},
			},
			wantSince: 100,
		},
		{
			name: "a stale lower server generation read afterwards is ignored",
			steps: []step{
				{server: 6, at: 0}, {agentGen: 6, report: true, at: 1}, {server: 5, at: 2},
			},
			wantSince: -1,
		},
		{
			name: "a heartbeat ahead of the last server read clears the start",
			steps: []step{
				{server: 5, at: 0}, {agentGen: 4, report: true, at: 1}, {agentGen: 6, report: true, at: 2}, {server: 6, at: 3},
			},
			wantSince: -1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var g genLag
			for _, s := range tc.steps {
				if s.server != 0 {
					g.serverAt(s.server, sec(s.at))
				}
				if s.report {
					g.reported("home", s.agentGen, sec(s.at))
				}
			}
			since, ok := g.behindSince("home")
			if tc.wantSince < 0 {
				if ok {
					t.Fatalf("behindSince = %s, want not behind", since)
				}
				return
			}
			if !ok || !since.Equal(sec(tc.wantSince)) {
				t.Fatalf("behindSince = %s (ok %v), want %s", since, ok, sec(tc.wantSince))
			}
		})
	}
}

// TestGenLagForget は、恒久トークンを無効化したエージェントの記録が残らないことを確かめる。
func TestGenLagForget(t *testing.T) {
	var g genLag
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	g.serverAt(6, now)
	g.reported("home", 5, now)
	g.forget("home")
	if _, ok := g.behindSince("home"); ok {
		t.Fatal("a forgotten agent must not be reported behind")
	}
}

// TestAgentsGenerationBehindSince は、管理用 API のエージェント一覧が generation_behind_since を、
// エージェントが遅れている間だけ RFC3339 で返し、追いついたら省くことを確かめる(7a.11 節の加算)。
func TestAgentsGenerationBehindSince(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tok, err := st.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Register(tok, "home", "203.0.113.2", netip.MustParsePrefix("10.200.0.0/24")); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{st: st, dp: stubDataplane{}, hub: stream.New(nil)}
	start := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

	field := func() (string, bool) {
		t.Helper()
		infos, err := d.Agents()
		if err != nil || len(infos) != 1 {
			t.Fatalf("Agents() = %+v, %v", infos, err)
		}
		b, err := json.Marshal(infos[0])
		if err != nil {
			t.Fatal(err)
		}
		return infos[0].GenerationBehindSince, strings.Contains(string(b), `"generation_behind_since"`)
	}

	if v, inJSON := field(); v != "" || inJSON {
		t.Fatalf("an agent that has never been seen behind: generation_behind_since = %q (in JSON %v), want omitted", v, inJSON)
	}
	d.lag.serverAt(3, start)
	d.lag.reported("home", 2, start.Add(time.Second))
	want := start.Add(time.Second).Format(time.RFC3339)
	if v, inJSON := field(); v != want || !inJSON {
		t.Fatalf("a lagging agent: generation_behind_since = %q (in JSON %v), want %q", v, inJSON, want)
	}
	d.lag.reported("home", 3, start.Add(2*time.Second))
	if v, inJSON := field(); v != "" || inJSON {
		t.Fatalf("an agent that caught up: generation_behind_since = %q (in JSON %v), want omitted", v, inJSON)
	}
}

// registerHome は、エージェント home を登録した store と、それを使う Daemon を返す。
// dataplane は適用に成功する偽物で、hub はまだ持たない。
func registerHome(t *testing.T) (*store.Store, *Daemon) {
	t.Helper()
	st := openTestStore(t)
	tok, err := st.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Register(tok, "home", "203.0.113.2", netip.MustParsePrefix("10.200.0.0/24")); err != nil {
		t.Fatal(err)
	}
	return st, newHoldDaemon(t, st, newHoldParticipant(nil), "", "")
}

// TestBatchStartsTheLag は、Daemon.Batch が世代を進めた時点で、まだ追いついていないエージェントの
// 遅れの始まりを記録することを確かめる。ハートビートや管理用 API の読み取りを待たずに記録する。
func TestBatchStartsTheLag(t *testing.T) {
	st, d := registerHome(t)
	d.hub = stream.New(nil)
	gen, err := st.Generation()
	if err != nil {
		t.Fatal(err)
	}
	d.lag.reported("home", gen, time.Now()) // home は今の世代を持っている
	before := time.Now().Truncate(time.Second)
	res, err := d.Batch(admin.BatchRequest{Op: "api", Upsert: []proto.Rule{{ID: "r_web", Agent: "home", Proto: proto.TCP,
		ListenPort: proto.PortRange{Lo: 40443, Hi: 40443}, Target: "192.168.1.30:443",
		VPSMode: proto.ModeKernel, Enabled: false}}})
	if err != nil {
		t.Fatalf("Batch: %v", err)
	}
	if res.Generation <= gen {
		t.Fatalf("the batch did not advance the generation: %d -> %d", gen, res.Generation)
	}
	since, ok := d.lag.behindSince("home")
	if !ok {
		t.Fatal("after a batch that advanced the generation, an agent still on the old one must be behind")
	}
	if since.Before(before) {
		t.Errorf("behindSince = %s, want the time of the batch (not before %s)", since, before)
	}
}

// TestHubHeartbeatClearsTheLag は、serve が作る hub のハートビートが Daemon の遅れの記録につながって
// いることを確かめる。今の世代を報告したハートビートが hub を通ると、遅れの始まりが消える。
func TestHubHeartbeatClearsTheLag(t *testing.T) {
	st, d := registerHome(t)
	addRule(t, st, "r_web")
	gen, err := st.Generation()
	if err != nil || gen == 0 {
		t.Fatalf("generation = %d, %v; want one advanced by the rule", gen, err)
	}
	d.lag.serverAt(gen, time.Now())
	d.lag.reported("home", gen-1, time.Now())
	if _, ok := d.lag.behindSince("home"); !ok {
		t.Fatal("setup: home must start behind")
	}

	server, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	d.hub = d.newHub(&fakeStreamBackend{server: server})
	srv := serveHub(t, d.hub)
	c := connectAgent(t, d.hub, "ws"+strings.TrimPrefix(srv.URL, "http"), "home",
		proto.Heartbeat{Generation: gen, Tunnel: proto.TunnelStatus{State: proto.StatusOK}})
	defer c.CloseNow()
	waitUntil(t, func() bool { _, behind := d.lag.behindSince("home"); return !behind },
		"a heartbeat at the current generation through the hub must clear the lag start")
}

// TestRevokeForgetsTheLag は、恒久トークンを無効化したエージェントの遅れの記録を Revoke が消すことを
// 確かめる。
func TestRevokeForgetsTheLag(t *testing.T) {
	_, d := registerHome(t)
	d.hub = stream.New(nil)
	now := time.Now()
	d.lag.serverAt(5, now)
	d.lag.reported("home", 4, now)
	if err := d.Revoke("home"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, ok := d.lag.behindSince("home"); ok {
		t.Error("a revoked agent must not keep a lag start")
	}
}

// TestAgentsReadsHeartbeatAndLagTogether は、管理用 API のエージェント一覧が、ハートビートの状態と
// 遅れの始まりを 1 つの時点の組として返すことを確かめる。hub はハートビートの状態を更新してから
// OnHeartbeat で遅れの始まりを記録するので、その間に別々に読むと、古い世代なのに始まりが無い形を
// 返す。doctor はこの形を始まりを返さない旧い server とみなし、直ちに FAILED にする(設計文書
// 10.2a 節)。server の再起動の後、最初のハートビートが古い世代を報告する場合がこれに当たる。
func TestAgentsReadsHeartbeatAndLagTogether(t *testing.T) {
	st, d := registerHome(t)
	addRule(t, st, "r_a")
	addRule(t, st, "r_bb")
	gen, err := st.Generation()
	if err != nil || gen < 2 {
		t.Fatalf("generation = %d, %v; want at least 2", gen, err)
	}

	server, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	d.hub = d.newHub(&fakeStreamBackend{server: server})
	// hub の状態の更新の後、遅れの記録の前で止める
	record := d.hub.OnHeartbeat
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	d.hub.OnHeartbeat = func(agent string, generation uint64) {
		entered <- struct{}{}
		<-release
		record(agent, generation)
	}
	srv := serveHub(t, d.hub)
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()

	c, _, err := websocketDial(t, "ws"+strings.TrimPrefix(srv.URL, "http"), "home")
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	writeMsg(t, c, proto.Message{Type: proto.MsgHeartbeat,
		Heartbeat: &proto.Heartbeat{Generation: gen - 1, Tunnel: proto.TunnelStatus{State: proto.StatusOK}}})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("OnHeartbeat was not called")
	}

	type result struct {
		infos []admin.AgentInfo
		err   error
	}
	got := make(chan result, 1)
	go func() {
		infos, err := d.Agents()
		got <- result{infos, err}
	}()
	// 途中で返ってきた場合も、解放の後に返ってきた場合も、返った組を同じ条件で調べる
	var r result
	select {
	case r = <-got:
	case <-time.After(100 * time.Millisecond):
		close(release)
		released = true
		select {
		case r = <-got:
		case <-time.After(2 * time.Second):
			t.Fatal("Agents did not return after the heartbeat hook finished")
		}
	}
	if r.err != nil || len(r.infos) != 1 {
		t.Fatalf("Agents() = %+v, %v", r.infos, r.err)
	}
	a := r.infos[0]
	if a.Connected && a.LastHeartbeat != "" && a.Generation != gen && a.GenerationBehindSince == "" {
		t.Fatalf("Agents() returned generation %d of %d with a heartbeat but no generation_behind_since; "+
			"doctor reads that as an older server and fails the rule at once", a.Generation, gen)
	}
}

// websocketDial は agent として hub に接続し、公開鍵を送って最初の全体状態を読み捨てる。
func websocketDial(t *testing.T, url, agent string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: map[string][]string{"Authorization": {"Bearer tok-" + agent}}})
	if err != nil {
		return nil, resp, err
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	writeMsg(t, c, proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String()})
	if _, err := readMsg(t, c); err != nil {
		t.Fatalf("%s: initial state: %v", agent, err)
	}
	return c, resp, nil
}
