package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/tunnel"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// 制御ソケットの doctor の応答(設計文書 10.2c 節)。試験は制御ソケットを直接叩き、稼働中の
// プロセスしか持たない証拠が 1 行の JSON で返ることを確かめる。応答を読んで表示する側は別の
// コマンドが持つので、ここでは扱わない。
//
// readTunnelStatus と doctorSnapshot を差し替える試験があるので、この file の試験は並行させない。

// controlAsk は制御ソケットに 1 行の指示を送り、応答の 1 行を返す。
type controlAsk func(t *testing.T, req string) string

// serveTestControl は runtime の制御ソケットを開き、指示を送る関数を返す。
func serveTestControl(t *testing.T, rt *runtime) controlAsk {
	t.Helper()
	dir := t.TempDir()
	rt.opts.CredentialsPath = filepath.Join(dir, "agent.json")
	path := ControlPath(rt.opts.CredentialsPath)
	if len(path) > ControlPathLimit {
		t.Skipf("temp dir %q makes the control socket path too long for a Unix socket", dir)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go rt.serveControl(ctx)

	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.Dial("unix", path)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("control socket %s did not open: %v", path, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return func(t *testing.T, req string) string {
		t.Helper()
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatalf("dial the control socket: %v", err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := fmt.Fprintln(c, req); err != nil {
			t.Fatalf("send %q: %v", req, err)
		}
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			t.Fatalf("read the answer to %q: %v", req, err)
		}
		return line
	}
}

// parseDoctor は応答の 1 行を読む。行が 1 つであることも確かめる。
func parseDoctor(t *testing.T, line string) DoctorResponse {
	t.Helper()
	if !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 {
		t.Fatalf("the doctor answer is not one line: %q", line)
	}
	var res DoctorResponse
	if err := json.Unmarshal([]byte(line), &res); err != nil {
		t.Fatalf("the doctor answer is not JSON: %v; answer %q", err, line)
	}
	return res
}

// askDoctor は doctor を送り、応答を読む。
func askDoctor(t *testing.T, ask controlAsk) DoctorResponse {
	t.Helper()
	return parseDoctor(t, ask(t, DoctorCommand))
}

// fakeTunnelStatus は readTunnelStatus を差し替え、読みの回数を返す。トンネルを本当に立てずに
// トンネルのある runtime を組むために使う。
func fakeTunnelStatus(t *testing.T, next func(n int64) tunnel.Status) *atomic.Int64 {
	t.Helper()
	var reads atomic.Int64
	real := readTunnelStatus
	readTunnelStatus = func(*tunnel.Tunnel) tunnel.Status { return next(reads.Add(1)) }
	t.Cleanup(func() { readTunnelStatus = real })
	return &reads
}

// TestDoctorReportsWhyThereIsNoTunnel は、トンネルが無い 4 つの理由が、ハートビートと同じ文言で
// 応答に載ることを確かめる(設計文書 10.2c 節の tunnel.local)。doctor は 2 つ目の判定を持たない。
func TestDoctorReportsWhyThereIsNoTunnel(t *testing.T) {
	now := time.Now()
	st := &proto.State{Generation: 7}
	cases := []struct {
		name    string
		setup   func(rt *runtime)
		reason  string
		retryAt bool
	}{
		{
			name:   "no full state yet",
			setup:  func(rt *runtime) { rt.f = &credentials.Credentials{} },
			reason: "no tunnel; full state not received",
		},
		{
			name:   "closed by rotate-key",
			setup:  func(rt *runtime) { rt.f = &credentials.Credentials{LastState: st} },
			reason: "no tunnel",
		},
		{
			name: "build failed and will be retried",
			setup: func(rt *runtime) {
				rt.f = &credentials.Credentials{LastState: st}
				rt.retrySt = st
				rt.rebuild.retryAt = now.Add(5 * time.Minute)
			},
			reason:  "no tunnel; building it failed and will be retried",
			retryAt: true,
		},
		{
			name: "build failed on a bad wg config",
			setup: func(rt *runtime) {
				rt.f = &credentials.Credentials{LastState: st}
				rt.retrySt = st
			},
			reason: "no tunnel; building it failed",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rt := &runtime{dp: newTestUserspace(), gen: 7, rebuild: rebuildState{after: defaultRebuildAfter, backoffMax: defaultRebuildBackoffMax}}
			c.setup(rt)
			ask := serveTestControl(t, rt)
			res := askDoctor(t, ask)
			if res.Error != "" {
				t.Fatalf("doctor returned an error: %s", res.Error)
			}
			if res.RuntimeState == nil {
				t.Fatalf("doctor returned no runtime state; timeout %s", res.RuntimeStateTimeout)
			}
			tun := res.RuntimeState.Tunnel
			if tun.Present {
				t.Errorf("tunnel present = true, want false")
			}
			if tun.State != proto.StatusError || tun.Reason != c.reason {
				t.Errorf("tunnel state/reason = %q/%q, want %q/%q", tun.State, tun.Reason, proto.StatusError, c.reason)
			}
			if got, want := res.RuntimeState.Generation, uint64(7); got != want {
				t.Errorf("generation = %d, want %d", got, want)
			}
			if got := heartbeatOf(rt).Tunnel; got.State != tun.State || got.Reason != tun.Reason {
				t.Errorf("doctor and the heartbeat disagree: %+v vs %q/%q", got, tun.State, tun.Reason)
			}
			if c.retryAt && tun.Watchdog.RetryAt.IsZero() {
				t.Error("watchdog retry_at is zero while a retry is scheduled")
			}
			if !c.retryAt && !tun.Watchdog.RetryAt.IsZero() {
				t.Errorf("watchdog retry_at = %s while no retry is scheduled", tun.Watchdog.RetryAt)
			}
			if got, want := tun.Watchdog.RebuildInterval, defaultRebuildAfter; got != want {
				t.Errorf("watchdog rebuild interval = %s, want %s", got, want)
			}
			if !tun.StartedAt.IsZero() {
				t.Errorf("started_at = %s while there is no tunnel", tun.StartedAt)
			}
		})
	}
}

// heartbeatOf はハートビートを組む(試験の読みやすさのため)。
func heartbeatOf(rt *runtime) proto.Heartbeat { return rt.heartbeat() }

// TestDoctorReportsHandshakePending は、トンネルがありハンドシェイクがまだ成立していない実行で、
// 応答がハートビートと同じ理由と、ハートビートに載らない送受信バイト数を持つことを確かめる。
func TestDoctorReportsHandshakePending(t *testing.T) {
	ep := netip.MustParseAddrPort("203.0.113.10:51820")
	fakeTunnelStatus(t, func(int64) tunnel.Status {
		return tunnel.Status{Endpoint: ep, RxBytes: 111, TxBytes: 222}
	})
	built := time.Now().Add(-time.Minute)
	rt := &runtime{
		dp:       &userspaceDataplane{tun: &tunnel.Tunnel{}},
		tunStart: built,
		rebuild:  rebuildState{after: defaultRebuildAfter, backoffMax: defaultRebuildBackoffMax, wait: 10 * time.Minute},
	}
	ask := serveTestControl(t, rt)
	res := askDoctor(t, ask)
	if res.RuntimeState == nil {
		t.Fatalf("doctor returned no runtime state; timeout %s", res.RuntimeStateTimeout)
	}
	tun := res.RuntimeState.Tunnel
	if !tun.Present {
		t.Fatal("tunnel present = false, want true")
	}
	if tun.State != proto.StatusError || tun.Reason != ReasonHandshakePending {
		t.Errorf("tunnel state/reason = %q/%q, want %q/%q", tun.State, tun.Reason, proto.StatusError, ReasonHandshakePending)
	}
	if !tun.LastHandshake.IsZero() {
		t.Errorf("last handshake = %s, want the zero time", tun.LastHandshake)
	}
	if tun.Endpoint != ep.String() {
		t.Errorf("endpoint = %q, want %q", tun.Endpoint, ep)
	}
	if tun.RxBytes != 111 || tun.TxBytes != 222 {
		t.Errorf("transfer = %d/%d bytes, want 111/222", tun.RxBytes, tun.TxBytes)
	}
	if !tun.StartedAt.Equal(built.Round(0)) {
		t.Errorf("started_at = %s, want %s", tun.StartedAt, built)
	}
	// 実効値は保持している値と閾値の大きい方で、判定に使う値と同じである
	if got, want := tun.Watchdog.RebuildInterval, 10*time.Minute; got != want {
		t.Errorf("watchdog rebuild interval = %s, want %s", got, want)
	}
}

// TestDoctorReadsTheTunnelStatusOnce は、1 つの応答がトンネルの状態を 1 回しか読まないことと、
// その 1 回の値だけを載せることを確かめる(設計文書 10.2c 節)。読み直す形にすると、同じ応答の中に
// 異なる時点の最終ハンドシェイクと送受信バイト数が混ざる。
func TestDoctorReadsTheTunnelStatusOnce(t *testing.T) {
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	reads := fakeTunnelStatus(t, func(n int64) tunnel.Status {
		// 読むたびに別の時点の値を返す。混ざればどれかが食い違う
		return tunnel.Status{LastHandshake: base.Add(time.Duration(n) * time.Second), RxBytes: n, TxBytes: n}
	})
	rt := &runtime{dp: &userspaceDataplane{tun: &tunnel.Tunnel{}}, tunStart: time.Now()}
	ask := serveTestControl(t, rt)
	res := askDoctor(t, ask)
	if got := reads.Load(); got != 1 {
		t.Fatalf("one doctor answer read the tunnel status %d times, want 1", got)
	}
	tun := res.RuntimeState.Tunnel
	if !tun.LastHandshake.Equal(base.Add(time.Second)) || tun.RxBytes != 1 || tun.TxBytes != 1 {
		t.Errorf("the answer mixes reads: handshake %s rx %d tx %d, want %s 1 1",
			tun.LastHandshake, tun.RxBytes, tun.TxBytes, base.Add(time.Second))
	}
}

// TestDoctorShowsOnlyTheCurrentDeviceHandshake は、watchdog が控えている最終ハンドシェイクが
// 応答に混ざらないことを確かめる(設計文書 10.2c 節)。closeLocked は控えを消さないので、
// トンネルを立て直した直後は前のトンネルの値が残る。
func TestDoctorShowsOnlyTheCurrentDeviceHandshake(t *testing.T) {
	stale := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	current := time.Date(2026, 9, 23, 9, 0, 0, 0, time.UTC)
	fakeTunnelStatus(t, func(int64) tunnel.Status { return tunnel.Status{LastHandshake: current} })
	rt := &runtime{
		dp:       &userspaceDataplane{tun: &tunnel.Tunnel{}},
		tunStart: time.Now(),
		rebuild:  rebuildState{after: defaultRebuildAfter, backoffMax: defaultRebuildBackoffMax, lastHandshake: stale, observedAt: stale},
	}
	ask := serveTestControl(t, rt)
	line := ask(t, DoctorCommand)
	res := parseDoctor(t, line)
	if !res.RuntimeState.Tunnel.LastHandshake.Equal(current) {
		t.Errorf("last handshake = %s, want the value of the current device, %s", res.RuntimeState.Tunnel.LastHandshake, current)
	}
	if strings.Contains(line, stale.Format("2006-01-02")) {
		t.Errorf("the answer carries the watchdog's remembered handshake %s: %s", stale, line)
	}
}

// TestDoctorGroupsListenersByRule は、リスナーの一覧がルール単位にまとまることを確かめる
// (設計文書 10.2c 節)。ポート範囲の幅に上限が無いので、リスナー 1 つずつを並べると
// listen_port=1-65535 のルール 1 本で 1 行が数 MB になる。
func TestDoctorGroupsListenersByRule(t *testing.T) {
	const ports = 500
	rules := []proto.AgentRule{udpRule(t, "r1", 10000, 10000+ports-1, "192.0.2.5:10000")}
	fakeTunnelStatus(t, func(int64) tunnel.Status { return tunnel.Status{LastHandshake: time.Now()} })
	rt := &runtime{dp: &userspaceDataplane{tun: &tunnel.Tunnel{}, rl: relay.New(&fakeRelayNetwork{}, relay.Options{})}, tunStart: time.Now()}
	t.Cleanup(rt.us().rl.Close)
	rt.us().rl.Apply(relay.DesiredFromRules(rules))

	ask := serveTestControl(t, rt)
	line := ask(t, DoctorCommand)
	res := parseDoctor(t, line)
	if n := len(res.RuntimeState.Rules); n != 1 {
		t.Fatalf("the answer holds %d entries for 1 rule with %d listeners, want 1", n, ports)
	}
	r := res.RuntimeState.Rules[0]
	if r.ID != "r1" || r.Listeners != ports || r.Listening != ports {
		t.Errorf("rule entry = %+v, want id r1 with %d listeners, all listening", r, ports)
	}
	if r.Proto != proto.UDP {
		t.Errorf("rule proto = %q, want %q", r.Proto, proto.UDP)
	}
	// 1 行に収める約束は、ルール単位にまとめて初めて成り立つ。リスナー単位に戻すと、この
	// 500 ポートのルール 1 本だけで数万バイトになる
	if len(line) > 4096 {
		t.Errorf("the answer is %d bytes for 1 rule with %d listeners; it lists listeners one by one", len(line), ports)
	}
}

// TestDoctorReportsListenerBindFailure は、待ち受けを開けなかったルールの状態と、開けなかった
// 理由が載ることを確かめる。bind の失敗はポートの衝突を、宛先の失敗は宛先の機器を指すので、
// 2 つを分けて数える(設計文書 10.2c 節)。
func TestDoctorReportsListenerBindFailure(t *testing.T) {
	rules := []proto.AgentRule{udpRule(t, "r1", 20000, 20002, "192.0.2.5:20000")}
	fakeNet := &fakeRelayNetwork{failPorts: map[uint16]bool{20001: true}}
	fakeTunnelStatus(t, func(int64) tunnel.Status { return tunnel.Status{LastHandshake: time.Now()} })
	rt := &runtime{dp: &userspaceDataplane{tun: &tunnel.Tunnel{}, rl: relay.New(fakeNet, relay.Options{})}, tunStart: time.Now()}
	t.Cleanup(rt.us().rl.Close)
	rt.us().rl.Apply(relay.DesiredFromRules(rules))

	ask := serveTestControl(t, rt)
	res := askDoctor(t, ask)
	if n := len(res.RuntimeState.Rules); n != 1 {
		t.Fatalf("the answer holds %d rule entries, want 1", n)
	}
	r := res.RuntimeState.Rules[0]
	if r.State != proto.StatusError {
		t.Errorf("rule state = %q, want %q", r.State, proto.StatusError)
	}
	if r.Listeners != 3 || r.Listening != 2 || r.BindErrors != 1 {
		t.Errorf("rule entry = %+v, want 3 listeners, 2 listening, 1 bind error", r)
	}
	if !strings.Contains(r.BindError, "udp/20001") {
		t.Errorf("bind error = %q, want the port that could not be opened", r.BindError)
	}
	if r.TargetErrors != 0 {
		t.Errorf("target errors = %d, want 0; a bind failure is not a target failure", r.TargetErrors)
	}
	// ルールごとの状態はハートビートが組み立てる値そのものである
	want := heartbeatOf(rt).Rules
	if len(want) != 1 || want[0].State != r.State || want[0].Reason != r.Reason {
		t.Errorf("doctor and the heartbeat disagree: %+v vs %q/%q", want, r.State, r.Reason)
	}
}

// TestDoctorReportsFlowBudget は、フロー予算の使用量と上限、拒否の累計、その起点が載ることを
// 確かめる(設計文書 10.2c 節の relay.sessions と relay.refusals)。
func TestDoctorReportsFlowBudget(t *testing.T) {
	rules := []proto.AgentRule{udpRule(t, "r1", 30000, 30000, "192.0.2.5:30000")}
	fakeTunnelStatus(t, func(int64) tunnel.Status { return tunnel.Status{LastHandshake: time.Now()} })
	rt := &runtime{
		dp: &userspaceDataplane{
			tun: &tunnel.Tunnel{},
			rl:  relay.New(&fakeRelayNetwork{}, relay.Options{Limits: resource.Limits{UDPTotal: 16, TCPTotal: 16}}),
		},
		tunStart: time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC),
	}
	t.Cleanup(rt.us().rl.Close)
	rt.us().rl.Apply(relay.DesiredFromRules(rules))
	// 予算を使い切らせて、拒否を 1 件作る
	pool := rt.us().rl.UDPPool()
	l := pool.Listener("r1")
	for i := 0; i < 16; i++ {
		if _, ok := l.Acquire(); !ok {
			t.Fatalf("flow %d was refused while the budget still had room", i)
		}
	}
	if _, ok := l.Acquire(); ok {
		t.Fatal("the 17th flow was admitted into a budget of 16")
	}

	ask := serveTestControl(t, rt)
	res := askDoctor(t, ask)
	if !res.RuntimeState.RefusalsSince.Equal(rt.tunStart) {
		t.Errorf("refusals_since = %s, want the time the tunnel was built, %s", res.RuntimeState.RefusalsSince, rt.tunStart)
	}
	var udp *DoctorBudget
	for i := range res.RuntimeState.Budgets {
		if res.RuntimeState.Budgets[i].Proto == proto.UDP {
			udp = &res.RuntimeState.Budgets[i]
		}
	}
	if udp == nil {
		t.Fatalf("the answer holds no UDP budget: %+v", res.RuntimeState.Budgets)
	}
	if udp.Total != 16 || udp.InUse != 16 {
		t.Errorf("udp budget = %d of %d in use, want 16 of 16", udp.InUse, udp.Total)
	}
	if len(udp.Refusals) != 1 || udp.Refusals[0].RuleID != "r1" || udp.Refusals[0].Reason != resource.ReasonBudget || udp.Refusals[0].Count != 1 {
		t.Errorf("udp refusals = %+v, want 1 budget refusal for r1", udp.Refusals)
	}
}

// TestDoctorReportsTheRuntimeLockTimeout は、実行時の状態を守る排他を期限内に取れない実行で、
// doctor が黙って待たずにその事実を返すことを確かめる(設計文書 10.2c 節)。30 秒ごとの定期処理は
// この排他を取ったまま宛先への試し接続を一巡させるので、待ち切る形にすると、繰り返し使いたい
// トラブルの最中にこそ応答しなくなる。
func TestDoctorReportsTheRuntimeLockTimeout(t *testing.T) {
	const wait = 100 * time.Millisecond
	list, err := allowtargets.Parse("192.0.2.0/24:1-1024")
	if err != nil {
		t.Fatal(err)
	}
	rt := &runtime{dp: newTestUserspace(), doctorLockWait: wait, opts: Options{AllowTargets: list}}
	ask := serveTestControl(t, rt)

	rt.mu.Lock()
	start := time.Now()
	line := ask(t, DoctorCommand)
	elapsed := time.Since(start)
	rt.mu.Unlock()

	res := parseDoctor(t, line)
	if res.RuntimeState != nil {
		t.Errorf("the answer carries runtime state although the lock was held: %+v", res.RuntimeState)
	}
	if res.RuntimeStateTimeout != wait {
		t.Errorf("runtime_state_timeout = %s, want %s", res.RuntimeStateTimeout, wait)
	}
	if elapsed < wait {
		t.Errorf("the answer came after %s, before the %s deadline", elapsed, wait)
	}
	if elapsed > 5*time.Second {
		t.Errorf("the answer came after %s; doctor waited far past its %s deadline", elapsed, wait)
	}
	// 静的でない証拠のうち、実行時の排他を要らないものは通常どおり返る
	if res.Stream == nil {
		t.Error("the answer carries no stream observation; it does not need the runtime lock")
	}
	if res.AllowTargets == nil || !res.AllowTargets.Set || res.AllowTargets.List != "192.0.2.0/24:1-1024" {
		t.Errorf("allow targets = %+v, want the list the agent holds", res.AllowTargets)
	}
}

// TestDoctorTakesTheRuntimeLockWhenItIsFree は、排他が空いている実行では期限を待たずに
// 実行時の状態が返ることを確かめる。
func TestDoctorTakesTheRuntimeLockWhenItIsFree(t *testing.T) {
	rt := &runtime{dp: newTestUserspace(), doctorLockWait: 5 * time.Second, f: &credentials.Credentials{}}
	ask := serveTestControl(t, rt)
	start := time.Now()
	res := askDoctor(t, ask)
	if res.RuntimeState == nil {
		t.Fatalf("doctor returned no runtime state; timeout %s", res.RuntimeStateTimeout)
	}
	if res.RuntimeStateTimeout != 0 {
		t.Errorf("runtime_state_timeout = %s, want 0 when the lock was taken", res.RuntimeStateTimeout)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("taking a free lock needed %s", d)
	}
}

// TestDoctorSurvivesAPanic は、応答を組む処理が panic しても常駐プロセスが生き続け、
// 運用者に何が起きたかが分かる応答が返ることを確かめる(設計文書 10.2c 節)。
func TestDoctorSurvivesAPanic(t *testing.T) {
	rt := &runtime{dp: newTestUserspace(), f: &credentials.Credentials{}}
	ask := serveTestControl(t, rt)

	real := doctorSnapshot
	doctorSnapshot = func(*runtime) DoctorResponse { panic("simulated failure while collecting the agent state") }
	line := ask(t, DoctorCommand)
	doctorSnapshot = real

	res := parseDoctor(t, line)
	if res.Error == "" {
		t.Fatalf("the answer to a panicking doctor carries no error: %q", line)
	}
	if !strings.Contains(res.Error, "panicked") || !strings.Contains(res.Error, "simulated failure") {
		t.Errorf("error = %q, want it to name the panic", res.Error)
	}
	if res.RuntimeState != nil || res.Stream != nil || res.AllowTargets != nil {
		t.Errorf("the answer to a panic carries state: %+v", res)
	}
	// 常駐プロセスは生きている。同じソケットが次の指示に答える
	if got := ask(t, DoctorCommand); parseDoctor(t, got).RuntimeState == nil {
		t.Errorf("the next doctor answer has no runtime state: %q", got)
	}
	if got, want := ask(t, "no-such-command"), "error: unknown command\n"; got != want {
		t.Errorf("unknown command answer = %q, want %q", got, want)
	}
}

// TestControlAnswersUnknownCommand は、doctor を知らない古い常駐プロセスが返すのと同じ応答を、
// 知らない指示に対して返し続けることを確かめる(設計文書 10.2c 節)。
func TestControlAnswersUnknownCommand(t *testing.T) {
	rt := &runtime{dp: newTestUserspace()}
	ask := serveTestControl(t, rt)
	if got, want := ask(t, "rotate-keys"), "error: unknown command\n"; got != want {
		t.Errorf("answer = %q, want %q", got, want)
	}
}

// TestDoctorReportsTheStreamObservation は、制御ストリームの観測が応答に載ることを確かめる
// (設計文書 10.2c 節の stream.connection、stream.backoff、stream.liveness)。
func TestDoctorReportsTheStreamObservation(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	rt := &runtime{dp: newTestUserspace(), f: &credentials.Credentials{}}
	rt.noteStreamDisconnected(now, errors.New("connection reset by peer"))
	rt.noteStreamWaiting(now, 4*time.Second)
	ask := serveTestControl(t, rt)
	res := askDoctor(t, ask)
	if res.Stream == nil {
		t.Fatal("the answer carries no stream observation")
	}
	if res.Stream.Connected {
		t.Error("connected = true, want false")
	}
	if res.Stream.DisconnectReason != "connection reset by peer" {
		t.Errorf("disconnect reason = %q", res.Stream.DisconnectReason)
	}
	if res.Stream.Backoff != 4*time.Second || !res.Stream.RetryAt.Equal(now.Add(4*time.Second)) {
		t.Errorf("backoff = %s retry at = %s, want 4s and %s", res.Stream.Backoff, res.Stream.RetryAt, now.Add(4*time.Second))
	}
}

// TestDoctorReportsNoAllowTargets は、宛先の許可一覧を持たない実行がその事実を返すことを確かめる。
// 一覧の内容はエージェントの手元にしか無い(設計文書 10.2c 節)。
func TestDoctorReportsNoAllowTargets(t *testing.T) {
	rt := &runtime{dp: newTestUserspace(), f: &credentials.Credentials{}}
	ask := serveTestControl(t, rt)
	res := askDoctor(t, ask)
	if res.AllowTargets == nil || res.AllowTargets.Set {
		t.Errorf("allow targets = %+v, want an unset list", res.AllowTargets)
	}
	if res.AllowTargets.Env != allowtargets.Env {
		t.Errorf("env = %q, want %q", res.AllowTargets.Env, allowtargets.Env)
	}
}

// TestControlDoesNotRecoverARotateKeyPanic は、rotate-key の枝の panic を受け止めないことを
// 確かめる。rotateKey は rt.mu を defer ではなく手で放すので、受け止めると常駐プロセスは排他を
// 誰も放さないまま生き続け、ハートビートも全体状態の適用も次の doctor も永久に止まる。落ちれば
// agent.service の Restart=on-failure が立て直す。
//
// 認証情報が nil の runtime は、rotateKey が排他を取った後で必ず panic する。
func TestControlDoesNotRecoverARotateKeyPanic(t *testing.T) {
	rt := &runtime{dp: newTestUserspace()}
	got := func() (r any) {
		defer func() { r = recover() }()
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		go fmt.Fprintln(client, "rotate-key") //nolint:errcheck // 読み手が panic すれば書き手も終わる
		rt.serveControlConn(server)
		return nil
	}()
	if got == nil {
		t.Fatal("a panic inside rotate-key was recovered; the daemon would survive holding the runtime lock forever")
	}
	// 受け止めていないので、排他は取られたままである。プロセスが落ちるので害は無い
	if rt.mu.TryLock() {
		rt.mu.Unlock()
		t.Error("rotate-key released the runtime lock before panicking; this test no longer covers the wedge")
	}
}

// TestControlRecoversADoctorPanic は、doctor の枝だけが panic を受け止め、その後も排他が
// 空いていることを確かめる。doctor の経路が取る排他はすべて defer で放される。
func TestControlRecoversADoctorPanic(t *testing.T) {
	rt := &runtime{dp: newTestUserspace(), f: &credentials.Credentials{}}
	real := doctorSnapshot
	doctorSnapshot = func(*runtime) DoctorResponse { panic("simulated failure while collecting the agent state") }
	t.Cleanup(func() { doctorSnapshot = real })

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go fmt.Fprintln(client, DoctorCommand) //nolint:errcheck // 応答を読む側が続けて閉じる
	done := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(client).ReadString('\n')
		done <- line
	}()
	rt.serveControlConn(server)
	select {
	case line := <-done:
		if res := parseDoctor(t, line); res.Error == "" {
			t.Errorf("the answer to a panicking doctor carries no error: %q", line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no answer to a panicking doctor")
	}
	if !rt.mu.TryLock() {
		t.Fatal("the runtime lock is still held after the panic in doctor")
	}
	rt.mu.Unlock()
}

// TestLockRuntimeReleasesTheLockItAbandons は、期限を過ぎて諦めた取得が、後で取れたときに
// すぐ排他を放すことを確かめる。放さなければ、待っていた取得がそのまま排他を握り続け、
// 常駐プロセスは永久に固まる。
func TestLockRuntimeReleasesTheLockItAbandons(t *testing.T) {
	rt := &runtime{dp: newTestUserspace()}
	rt.mu.Lock()
	if rt.lockRuntime(50 * time.Millisecond) {
		rt.mu.Unlock()
		t.Fatal("lockRuntime took a lock that was already held")
	}
	// 放すと、待っている取得が必ずこの排他を取る。他に待ち手はいない。この猶予の間に、
	// 取ってすぐ放す実装は取得と解放を終え、放さない実装は握ったまま残る。猶予を置かずに
	// 測ると、試験の側の取得が先に通ってしまい、握られたことを見られない
	rt.mu.Unlock()
	time.Sleep(200 * time.Millisecond)

	deadline := time.Now().Add(10 * time.Second)
	for {
		if rt.mu.TryLock() {
			rt.mu.Unlock()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the lock taken after doctor gave up was never released; the agent is wedged")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestDoctorRulesMapSessionsAndFlowsSeparately は、中継が数える接続の数と、フロー予算の上限の
// 対象になる数を、別々の項目として運ぶことを確かめる(設計文書 10.2c 節の relay.sessions)。
// TCP は公開側と宛先側の両方を接続として数えるので、2 つは一致しない。
func TestDoctorRulesMapSessionsAndFlowsSeparately(t *testing.T) {
	sts := []relay.Status{
		{Key: relay.Key{Proto: proto.TCP, Port: 2456}, RuleID: "r1", Listening: true, Sessions: 6, Flows: 3},
		{Key: relay.Key{Proto: proto.TCP, Port: 2457}, RuleID: "r1", Listening: true, Sessions: 2, Flows: 1},
	}
	rules := doctorRules(ruleStatuses(sts), sts)
	if len(rules) != 1 {
		t.Fatalf("doctorRules returned %d entries for 1 rule, want 1", len(rules))
	}
	if rules[0].Sessions != 8 {
		t.Errorf("sessions = %d, want 8, the sum of what the relay holds", rules[0].Sessions)
	}
	if rules[0].Flows != 4 {
		t.Errorf("flows = %d, want 4, the sum of what the flow budget caps", rules[0].Flows)
	}
}

// TestDoctorClipsLongText は、代表として出す誤りの文字列に上限があることを確かめる。
// 制御ソケットの応答には大きさの上限が無いので、1 つの長い誤りで行が膨らまないようにする。
func TestDoctorClipsLongText(t *testing.T) {
	long := strings.Repeat("x", 100000)
	fakeNet := &fakeRelayNetwork{failPorts: map[uint16]bool{40000: true}, failReason: long}
	fakeTunnelStatus(t, func(int64) tunnel.Status { return tunnel.Status{LastHandshake: time.Now()} })
	rt := &runtime{dp: &userspaceDataplane{tun: &tunnel.Tunnel{}, rl: relay.New(fakeNet, relay.Options{})}, tunStart: time.Now()}
	t.Cleanup(rt.us().rl.Close)
	rt.us().rl.Apply(relay.DesiredFromRules([]proto.AgentRule{udpRule(t, "r1", 40000, 40000, "192.0.2.5:40000")}))

	ask := serveTestControl(t, rt)
	line := ask(t, DoctorCommand)
	if len(line) > 4096 {
		t.Errorf("the answer is %d bytes although the only listener error was clipped", len(line))
	}
	r := parseDoctor(t, line).RuntimeState.Rules[0]
	for name, got := range map[string]string{"bind_error": r.BindError, "reason": r.Reason} {
		if len(got) > maxDoctorText+len("... truncated") {
			t.Errorf("%s is %d bytes, want at most %d", name, len(got), maxDoctorText+len("... truncated"))
		}
		if !strings.HasSuffix(got, "... truncated") {
			t.Errorf("%s does not say it was clipped: %q", name, got)
		}
	}
}

// TestDoctorLeavesOutEmptyLists は、中継が無い実行で空の一覧が null として出ないことと、
// 時刻の項目が消えずにゼロ値として出ることを確かめる。encoding/json の omitempty は struct に
// 効かないので、読み手は時刻を IsZero で判定する。
func TestDoctorLeavesOutEmptyLists(t *testing.T) {
	rt := &runtime{dp: newTestUserspace(), f: &credentials.Credentials{}}
	ask := serveTestControl(t, rt)
	line := ask(t, DoctorCommand)
	if strings.Contains(line, "null") {
		t.Errorf("the answer carries a null: %s", line)
	}
	for _, key := range []string{`"rules"`, `"budgets"`} {
		if strings.Contains(line, key) {
			t.Errorf("%s is present although the agent has no relay: %s", key, line)
		}
	}
	for _, key := range []string{`"refusals_since"`, `"last_handshake"`, `"started_at"`, `"retry_at"`, `"agent_disabled"`} {
		if !strings.Contains(line, key) {
			t.Errorf("%s is missing; a time field never disappears from the answer, and agent_disabled has no omitempty either, so a false value still shows the key: %s", key, line)
		}
	}
	res := parseDoctor(t, line)
	if !res.RuntimeState.RefusalsSince.IsZero() || !res.RuntimeState.Tunnel.StartedAt.IsZero() {
		t.Errorf("a time with no value did not survive as the zero time: %+v", res.RuntimeState)
	}
	if res.RuntimeState.AgentDisabled {
		t.Errorf("AgentDisabled = true, want false: this runtime never applied a disabled state")
	}
}

// TestDoctorReportsAgentDisabled は、DoctorRuntimeState.AgentDisabled が、最後に適用した全体状態の
// proto.State.AgentDisabled をそのまま写すことを確かめる(仕様 5.1 節、設計文書 10.2c 節)。守りには
// 使わない診断専用のフィールドである。中継の有無に関わらず読めることも確かめる。relay.listeners の
// SKIPPED の判定は cmd/wgft の側の試験が持つ。
func TestDoctorReportsAgentDisabled(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    *credentials.Credentials
		want bool
	}{
		{"disabled by the server", &credentials.Credentials{LastState: &proto.State{AgentDisabled: true}}, true},
		{"enabled", &credentials.Credentials{LastState: &proto.State{AgentDisabled: false}}, false},
		{"an old server that never sends the field", &credentials.Credentials{LastState: oldServerState(t)}, false},
		{"no full state applied yet", &credentials.Credentials{}, false},
		{"no credentials file loaded", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &runtime{dp: newTestUserspace(), f: tc.f}
			ask := serveTestControl(t, rt)
			res := askDoctor(t, ask)
			if res.RuntimeState == nil {
				t.Fatal("the answer holds no runtime state")
			}
			if res.RuntimeState.AgentDisabled != tc.want {
				t.Errorf("AgentDisabled = %v, want %v", res.RuntimeState.AgentDisabled, tc.want)
			}
		})
	}
}

// TestDoctorClearsAgentDisabledOnReEnable は、無効から有効に戻った後の全体状態を適用すると、
// 次の doctor の応答が無効を持ち越さないことを確かめる。apply は proto.State をまるごと
// LastState に置き換えるので、消え残る経路が無いことを固定する(仕様 5.1 節)。本物のトンネルを
// 立てずに済むよう fakeDataplane を使う。
func TestDoctorClearsAgentDisabledOnReEnable(t *testing.T) {
	rt := newFakeDataplaneRuntime(t, &fakeDataplane{})
	if err := rt.apply(&proto.State{Generation: 1, AgentDisabled: true}); err != nil {
		t.Fatalf("apply the disabled state: %v", err)
	}
	if !rt.collectDoctor().RuntimeState.AgentDisabled {
		t.Fatal("the doctor answer does not show the agent as disabled after the disabled state was applied")
	}
	if !rt.f.LastState.AgentDisabled {
		t.Fatal("agent.json's LastState does not carry the disabled flag after the disabled state was applied")
	}
	if err := rt.apply(&proto.State{Generation: 2, AgentDisabled: false}); err != nil {
		t.Fatalf("apply the re-enabled state: %v", err)
	}
	if rt.collectDoctor().RuntimeState.AgentDisabled {
		t.Error("the doctor answer still shows the agent as disabled after it was re-enabled")
	}
	if rt.f.LastState.AgentDisabled {
		t.Error("agent.json's LastState still carries the disabled flag after it was re-enabled")
	}
}

// oldServerState は、agent_disabled を持たない旧い版の server が送った全体状態を模す。JSON を
// 経由して組み立てるのは、Go の構造体リテラルではなく、旧い server が実際に送るバイト列を試験の
// 入力にするためである。
func oldServerState(t *testing.T) *proto.State {
	t.Helper()
	var st proto.State
	old := `{"generation":1,"wg":{"server_pubkey":"","endpoint":"","address":"","mtu":0,"keepalive":0,"udp_timeout":0,"udp_timeout_stream":0},"rules":[]}`
	if err := json.Unmarshal([]byte(old), &st); err != nil {
		t.Fatal(err)
	}
	return &st
}

// udpRule は試験用の UDP ルールを 1 本作る。
func udpRule(t *testing.T, id string, lo, hi uint16, target string) proto.AgentRule {
	t.Helper()
	return proto.AgentRule{
		ID: id, Proto: proto.UDP, Enabled: true,
		ListenPort: proto.PortRange{Lo: lo, Hi: hi},
		Target:     target,
	}
}

// fakeRelayNetwork はリスナーを開く先の差し替えである。ホストのポートを 1 つも使わずに数百の
// 待ち受けを作れるので、ポート範囲の広いルールを試験に持ち込める。failPorts のポートは
// bind に失敗させる。
type fakeRelayNetwork struct {
	failPorts map[uint16]bool
	// failReason は bind の失敗の理由に足す文字列。誤りが長い場合の扱いを試すために使う
	failReason string
}

func (n *fakeRelayNetwork) bindErr(p proto.Proto, port uint16) error {
	if n.failReason != "" {
		return fmt.Errorf("simulated bind failure on %s port %d: %s", p, port, n.failReason)
	}
	return fmt.Errorf("simulated bind failure on %s port %d", p, port)
}

func (n *fakeRelayNetwork) ListenUDP(port uint16) (net.PacketConn, error) {
	if n.failPorts[port] {
		return nil, n.bindErr(proto.UDP, port)
	}
	return newIdleConn(), nil
}

func (n *fakeRelayNetwork) ListenTCP(port uint16) (net.Listener, error) {
	if n.failPorts[port] {
		return nil, n.bindErr(proto.TCP, port)
	}
	return newIdleConn(), nil
}

// idleConn は何も受け取らない待ち受けである。閉じるまで待ち、閉じたら誤りを返す。
// net.PacketConn と net.Listener の両方を満たすので、UDP と TCP のどちらにも使える。
type idleConn struct {
	closed chan struct{}
	once   sync.Once
}

func newIdleConn() *idleConn { return &idleConn{closed: make(chan struct{})} }

func (c *idleConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *idleConn) Addr() net.Addr      { return idleAddr{} }
func (c *idleConn) LocalAddr() net.Addr { return idleAddr{} }
func (c *idleConn) Accept() (net.Conn, error) {
	<-c.closed
	return nil, net.ErrClosed
}
func (c *idleConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}
func (c *idleConn) WriteTo([]byte, net.Addr) (int, error) { return 0, net.ErrClosed }
func (c *idleConn) SetDeadline(time.Time) error           { return nil }
func (c *idleConn) SetReadDeadline(time.Time) error       { return nil }
func (c *idleConn) SetWriteDeadline(time.Time) error      { return nil }

type idleAddr struct{}

func (idleAddr) Network() string { return "udp" }
func (idleAddr) String() string  { return "0.0.0.0:0" }
