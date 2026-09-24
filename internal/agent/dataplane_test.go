package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// us は runtime の dataplane をユーザー空間モードの実装として返す。トンネルと中継を直接確かめる
// 試験のための口である。
func (rt *runtime) us() *userspaceDataplane { return rt.dp.(*userspaceDataplane) }

// newTestUserspace は、宛先の許可一覧も予算の指定も持たないユーザー空間モードの dataplane を作る。
func newTestUserspace() *userspaceDataplane { return newUserspaceDataplane(nil, resource.Limits{}) }

// fakeDataplane は runtime の境目の試験に使う記録器である。トンネルを本当に立てずに、runtime が
// 境目をどう呼ぶかを確かめる。
type fakeDataplane struct {
	up       bool
	applyErr error
	applied  [][]proto.AgentRule
	reading  dataplaneReading
	reads    int
	// builtWith は build が受け取った wg 設定の並びである
	builtWith []proto.WGConfig
	// prepareHook は prepareApply の中で呼ばれる。名前を引いている間に他の経路が動く場合を模す
	prepareHook func()
}

func (d *fakeDataplane) build(_ wgtypes.Key, wg proto.WGConfig) (bool, error) {
	d.up = true
	d.builtWith = append(d.builtWith, wg)
	return true, nil
}

// prepareApply は、runtime が rt.mu の外で準備を呼ぶことを確かめるための口である。
func (d *fakeDataplane) prepareApply(*proto.State) any {
	if d.prepareHook != nil {
		d.prepareHook()
	}
	return nil
}
func (d *fakeDataplane) built() bool { return d.up }
func (d *fakeDataplane) applyRules(_ uint64, rules []proto.AgentRule, _ any) (string, error) {
	if d.applyErr != nil {
		return "", d.applyErr
	}
	d.applied = append(d.applied, rules)
	return "fake", nil
}
func (d *fakeDataplane) refresh()                 {}
func (d *fakeDataplane) close()                   { d.up = false }
func (d *fakeDataplane) lastHandshake() time.Time { return d.reading.tunnel.lastHandshake }
func (d *fakeDataplane) read() dataplaneReading {
	d.reads++
	return d.reading
}

func newFakeDataplaneRuntime(t *testing.T, dp *fakeDataplane) *runtime {
	t.Helper()
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &runtime{
		opts: Options{CredentialsPath: filepath.Join(t.TempDir(), "agent.json")},
		f:    &credentials.Credentials{},
		priv: priv,
		dp:   dp,
	}
}

// dataplane が宣言をまとめて公開できなかったときは、処理済み世代も認証情報ファイルの last_state も
// 進めない(設計文書 7a.3 節の backend 全体の失敗)。トンネルが既にある場合と、立てた直後の場合の
// 両方を確かめ、失敗が消えた後に同じ全体状態を適用し直せば世代が進むことも確かめる。
func TestApplyKeepsTheGenerationWhenTheDataplaneFails(t *testing.T) {
	t.Run("with a tunnel already up", func(t *testing.T) {
		dp := &fakeDataplane{}
		rt := newFakeDataplaneRuntime(t, dp)
		first := &proto.State{Generation: 1, Rules: []proto.AgentRule{{ID: "r1"}}}
		if err := rt.apply(first); err != nil {
			t.Fatal(err)
		}
		if rt.gen != 1 || rt.f.LastState != first {
			t.Fatalf("after a good apply: gen=%d last_state=%v, want 1 and the applied state", rt.gen, rt.f.LastState)
		}
		saved, err := os.ReadFile(rt.opts.CredentialsPath)
		if err != nil {
			t.Fatal(err)
		}

		dp.applyErr = errors.New("table rejected")
		second := &proto.State{Generation: 2, Rules: []proto.AgentRule{{ID: "r2"}}}
		if err := rt.apply(second); err == nil {
			t.Fatal("apply returned no error when the dataplane failed")
		}
		if rt.gen != 1 || rt.f.LastState != first {
			t.Errorf("after a failed apply: gen=%d, last_state is the new state: %v; want generation 1 and the previous state", rt.gen, rt.f.LastState == second)
		}
		after, err := os.ReadFile(rt.opts.CredentialsPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, saved) {
			t.Error("the credentials file was rewritten after a failed apply")
		}

		dp.applyErr = nil
		if err := rt.apply(second); err != nil {
			t.Fatal(err)
		}
		if rt.gen != 2 || rt.f.LastState != second {
			t.Errorf("after applying the same state again: gen=%d, want 2 and the state recorded", rt.gen)
		}
	})

	t.Run("right after building the tunnel", func(t *testing.T) {
		dp := &fakeDataplane{applyErr: errors.New("table rejected")}
		rt := newFakeDataplaneRuntime(t, dp)
		first := &proto.State{Generation: 1, Rules: []proto.AgentRule{{ID: "r1"}}}
		err := rt.apply(first)
		if err == nil {
			t.Fatal("apply returned no error when the dataplane failed")
		}
		// トンネルは立っているので、WireGuard の失敗には見せない
		if strings.HasPrefix(err.Error(), "wireguard:") {
			t.Errorf("error = %q; a dataplane failure after a successful build must not read as a wireguard failure", err)
		}
		if rt.gen != 0 || rt.f.LastState != nil {
			t.Errorf("after a failed apply: gen=%d last_state set=%v, want generation 0 and none", rt.gen, rt.f.LastState != nil)
		}
		if _, err := os.Stat(rt.opts.CredentialsPath); !os.IsNotExist(err) {
			t.Errorf("the credentials file was written after a failed apply: %v", err)
		}

		dp.applyErr = nil
		if err := rt.apply(first); err != nil {
			t.Fatal(err)
		}
		if rt.gen != 1 || rt.f.LastState != first {
			t.Errorf("after applying the same state again: gen=%d, want 1 and the state recorded", rt.gen)
		}
	})
}

// 閾値を持たない rebuildState でも、checkTunnel は同じハンドシェイクを 1 度しか新しいと数えない。
// 数え直すと、stream の再接続の待ちを 30 秒ごとに打ち切ってしまう(仕様 5.2 節)。
func TestCheckTunnelWakesOncePerHandshakeWithoutAThreshold(t *testing.T) {
	hs := time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC)
	dp := &fakeDataplane{up: true, reading: dataplaneReading{tunnel: tunnelReading{present: true, lastHandshake: hs}}}
	rt := newFakeDataplaneRuntime(t, dp)
	rt.f.LastState = &proto.State{Generation: 1}
	rt.handshakeWake = make(chan struct{}, 1)
	wakes := 0
	now := time.Now()
	for i := 0; i < 5; i++ {
		rt.checkTunnel(now.Add(time.Duration(i) * 30 * time.Second))
		select {
		case <-rt.handshakeWake:
			wakes++
		default:
		}
	}
	if wakes != 1 {
		t.Errorf("wakes = %d over 5 checks of one handshake, want 1", wakes)
	}
	// 新しいハンドシェイクは、閾値が無くても再び数える
	dp.reading.tunnel.lastHandshake = hs.Add(2 * time.Minute)
	rt.checkTunnel(now.Add(5 * 30 * time.Second))
	select {
	case <-rt.handshakeWake:
	default:
		t.Error("a new handshake did not wake the stream")
	}
	if !dp.up {
		t.Error("the watchdog closed the tunnel without a threshold")
	}
}

// Run が組む runtime は、宛先の許可一覧とフロー数の予算を dataplane に渡す。doctor が示す一覧も
// 同じ opts.AllowTargets なので、中継が守る一覧と食い違わない(設計文書 10.2c 節)。
func TestNewRuntimePassesTheAllowlistToTheDataplane(t *testing.T) {
	list, err := allowtargets.Parse("192.168.1.20:25565")
	if err != nil {
		t.Fatal(err)
	}
	limits := resource.Limits{UDPTotal: 16, TCPTotal: 8}
	rt := newRuntime(Options{AllowTargets: list, Limits: limits}, &credentials.Credentials{}, wgtypes.Key{})
	us, ok := rt.dp.(*userspaceDataplane)
	if !ok {
		t.Fatalf("dataplane is %T, want *userspaceDataplane", rt.dp)
	}
	if us.allow != list || us.allow != rt.opts.AllowTargets {
		t.Errorf("dataplane allowlist = %v, want the same list as opts.AllowTargets (%v)", us.allow, list)
	}
	if us.limits != limits {
		t.Errorf("dataplane limits = %+v, want %+v", us.limits, limits)
	}
}

// ハートビートは dataplane を 1 回だけ読み、トンネルの状態とルールごとの状態をその読みから組む
// (設計文書 10.2c 節)。中継を持たない dataplane(カーネルモード)の doctor の応答は、ルールごとの
// 状態を同じ読みから載せ、フロー予算と拒否の累計の起点を載せない。
func TestHeartbeatAndDoctorReadTheDataplaneOnce(t *testing.T) {
	hs := time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC)
	dp := &fakeDataplane{up: true, reading: dataplaneReading{
		tunnel: tunnelReading{present: true, lastHandshake: hs, rxBytes: 5, txBytes: 7},
		rules:  []proto.RuleStatus{{ID: "r1", State: proto.StatusError, Reason: "target refused"}},
	}}
	rt := newFakeDataplaneRuntime(t, dp)
	rt.gen = 4
	// 中継が無ければ拒否の累計の起点は無い。起点に使う時刻が立っていても載せないことを確かめる
	rt.tunStart = time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)

	hb := rt.heartbeat()
	if dp.reads != 1 {
		t.Errorf("heartbeat read the dataplane %d times, want 1", dp.reads)
	}
	if hb.Generation != 4 || hb.Tunnel.State != proto.StatusOK || !hb.Tunnel.LastHandshake.Equal(hs) {
		t.Errorf("heartbeat = %+v, want generation 4 and an ok tunnel with the handshake", hb)
	}
	if len(hb.Rules) != 1 || hb.Rules[0].ID != "r1" || hb.Rules[0].State != proto.StatusError {
		t.Errorf("heartbeat rules = %+v, want the dataplane's rule state", hb.Rules)
	}

	dp.reads = 0
	st := rt.collectDoctor().RuntimeState
	if dp.reads != 1 {
		t.Errorf("doctor read the dataplane %d times, want 1", dp.reads)
	}
	if st == nil || st.Tunnel.RxBytes != 5 || st.Tunnel.TxBytes != 7 {
		t.Fatalf("doctor runtime state = %+v, want the transfer counters from the same read", st)
	}
	if len(st.Rules) != 1 || st.Rules[0].ID != "r1" || st.Rules[0].State != proto.StatusError {
		t.Errorf("a dataplane without a relay: rules=%v, want the rule state from the same read", st.Rules)
	}
	if st.Budgets != nil || !st.RefusalsSince.IsZero() {
		t.Errorf("a dataplane without a relay: budgets=%v refusals_since=%v, want none", st.Budgets, st.RefusalsSince)
	}
}

// 公開できなかった全体状態は控えておき、30 秒ごとの試し直しが公開できた時点で世代を進める。
// 試し直しの間に新しい全体状態が届けば、そちらを試す(設計文書 7a.3 節、7b.3 節の 3 つ目の種類)。
func TestPendingStateIsRetried(t *testing.T) {
	dp := &fakeDataplane{}
	rt := newFakeDataplaneRuntime(t, dp)
	if err := rt.apply(&proto.State{Generation: 1}); err != nil {
		t.Fatal(err)
	}
	dp.applyErr = errors.New("batch refused")
	two := &proto.State{Generation: 2, Rules: []proto.AgentRule{{ID: "r2"}}}
	if err := rt.apply(two); err == nil {
		t.Fatal("apply succeeded although the dataplane failed")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.pendingSt != two || rt.gen != 1 || rt.f.LastState.Generation != 1 {
		t.Fatalf("pending %v gen %d last %d; want generation 2 pending and 1 processed", rt.pendingSt, rt.gen, rt.f.LastState.Generation)
	}
	if err := rt.retryPendingLocked(nil); err != nil || rt.gen != 1 {
		t.Fatalf("a failing retry: err %v gen %d", err, rt.gen)
	}
	three := &proto.State{Generation: 3}
	rt.mu.Unlock()
	if err := rt.apply(three); err == nil {
		t.Fatal("apply of generation 3 succeeded although the dataplane failed")
	}
	rt.mu.Lock()
	if rt.pendingSt != three {
		t.Fatalf("pending is generation %d, want the newer 3", rt.pendingSt.Generation)
	}
	dp.applyErr = nil
	if err := rt.retryPendingLocked(nil); err != nil {
		t.Fatal(err)
	}
	if rt.pendingSt != nil || rt.gen != 3 || rt.f.LastState != three {
		t.Errorf("after a good retry: pending %v gen %d; want nothing pending and generation 3", rt.pendingSt, rt.gen)
	}
}

// プロセスを終える誤りは試し直しの控えにせず、試し直しから返す。stream の側の適用で起きた場合は
// Run へ伝える(設計文書 11b 節)。
func TestFatalApplyErrorIsNotRetried(t *testing.T) {
	dp := &fakeDataplane{}
	rt := newFakeDataplaneRuntime(t, dp)
	rt.fatal = make(chan error, 1)
	dp.applyErr = &fatalError{err: errors.New("wgft0 is not ours")}
	err := rt.apply(&proto.State{Generation: 1})
	if !isFatal(err) {
		t.Fatalf("err = %v, want fatal", err)
	}
	if rt.pendingSt != nil {
		t.Error("a fatal failure was kept for a retry")
	}
	rt.reportFatal(err)
	rt.reportFatal(err) // 2 つ目は捨てられ、止まらない
	select {
	case got := <-rt.fatal:
		if !isFatal(got) {
			t.Errorf("Run received %v", got)
		}
	default:
		t.Fatal("the fatal error did not reach Run")
	}
	rt.mu.Lock()
	rt.pendingSt = &proto.State{Generation: 1}
	err = rt.retryPendingLocked(nil)
	rt.mu.Unlock()
	if !isFatal(err) {
		t.Errorf("retry: err = %v, want fatal", err)
	}
}

// カーネルモードのルールごとの状態は、中継が無くても doctor に届く。リスナーと予算は無い(設計文書
// 10.2c 節)。モードも応答に載る。
func TestDoctorShowsKernelRuleStates(t *testing.T) {
	dp := &fakeDataplane{up: true, reading: dataplaneReading{
		tunnel: tunnelReading{present: true, lastHandshake: time.Now()},
		rules:  []proto.RuleStatus{{ID: "r1", State: proto.StatusError, Reason: "target 192.168.1.20:80: connection refused"}},
	}}
	rt := newFakeDataplaneRuntime(t, dp)
	rt.opts.Mode = "kernel"
	rt.mu.Lock()
	st := rt.runtimeStateLocked()
	rt.mu.Unlock()
	if st.Mode != "kernel" {
		t.Errorf("mode = %q, want kernel", st.Mode)
	}
	if len(st.Rules) != 1 || st.Rules[0].ID != "r1" || st.Rules[0].State != proto.StatusError || st.Rules[0].Listeners != 0 {
		t.Errorf("rules = %+v, want r1 in error with no listeners", st.Rules)
	}
	if st.Budgets != nil {
		t.Errorf("budgets = %+v, want none in kernel mode", st.Budgets)
	}

	rt.opts.Mode = ""
	rt.mu.Lock()
	st = rt.runtimeStateLocked()
	rt.mu.Unlock()
	if st.Mode != "" {
		t.Errorf("userspace mode = %q, want the field left out", st.Mode)
	}
}

// stream の側の適用がプロセスを終える誤りに当たったら、Run の本体のループがその誤りで終わる
// (設計文書 11b 節)。stream の適用から Run の終わりまでを通して確かめる。
func TestFatalApplyFromTheStreamEndsRun(t *testing.T) {
	dp := &fakeDataplane{applyErr: &fatalError{err: errors.New("wgft0 is not ours")}}
	rt := newFakeDataplaneRuntime(t, dp)
	rt.fatal = make(chan error, 1)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- rt.serve(ctx, make(chan error), make(chan time.Time)) }()
	rt.applyFromStream(&proto.State{Generation: 1})
	select {
	case err := <-done:
		if !isFatal(err) {
			t.Errorf("Run ended with %v, want the fatal error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not end on a fatal error from the stream")
	}
}

// 控えは、失敗した全体状態が控えより古ければ置き換えない。rotate-key が last_state を適用し直して
// 失敗しても、控えていた新しい世代を失わない。
func TestPendingStateIsNotReplacedByAnOlderOne(t *testing.T) {
	dp := &fakeDataplane{}
	rt := newFakeDataplaneRuntime(t, dp)
	if err := rt.apply(&proto.State{Generation: 1}); err != nil {
		t.Fatal(err)
	}
	dp.applyErr = errors.New("batch refused")
	three := &proto.State{Generation: 3}
	_ = rt.apply(three)
	_ = rt.apply(rt.f.LastState) // rotate-key の適用し直しと同じく、処理済みの世代 1 を適用する
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.pendingSt != three {
		t.Errorf("pending is generation %d, want 3", rt.pendingSt.Generation)
	}
}

// 控えの試し直しが公開できたら、次の 30 秒を待たずにハートビートを送らせる。
func TestSuccessfulRetryAsksForAHeartbeat(t *testing.T) {
	dp := &fakeDataplane{}
	rt := newFakeDataplaneRuntime(t, dp)
	rt.stateNotify = make(chan struct{}, 1)
	if err := rt.apply(&proto.State{Generation: 1}); err != nil {
		t.Fatal(err)
	}
	dp.applyErr = errors.New("batch refused")
	_ = rt.apply(&proto.State{Generation: 2})
	if err := rt.retryPending(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-rt.stateNotify:
		t.Fatal("a failing retry asked for a heartbeat")
	default:
	}
	dp.applyErr = nil
	if err := rt.retryPending(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-rt.stateNotify:
	default:
		t.Fatal("a successful retry did not ask for a heartbeat")
	}
	if rt.generation() != 2 {
		t.Errorf("generation %d after the retry, want 2", rt.generation())
	}
}

// 試し直しの準備の間に控えが別の全体状態に替われば、準備を捨てて何も適用しない。次の試し直しが
// 新しい控えを扱う。
func TestRetryDiscardsAPreparationForAReplacedPendingState(t *testing.T) {
	dp := &fakeDataplane{}
	rt := newFakeDataplaneRuntime(t, dp)
	if err := rt.apply(&proto.State{Generation: 1}); err != nil {
		t.Fatal(err)
	}
	dp.applyErr = errors.New("batch refused")
	_ = rt.apply(&proto.State{Generation: 2})
	three := &proto.State{Generation: 3}
	dp.applyErr = nil
	calls := len(dp.applied)
	dp.prepareHook = func() {
		// 名前を引いている間に、stream の新しい全体状態の適用が失敗して控えを替える
		rt.mu.Lock()
		rt.pendingSt = three
		rt.mu.Unlock()
	}
	if err := rt.retryPending(); err != nil {
		t.Fatal(err)
	}
	if len(dp.applied) != calls {
		t.Fatalf("the retry applied a state after its pending state was replaced")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.pendingSt != three || rt.gen != 1 {
		t.Errorf("pending %d gen %d; want generation 3 still pending and 1 processed", rt.pendingSt.Generation, rt.gen)
	}
}

// 控えの試し直しは、控えた全体状態の wg 設定が今のものと違えば、apply と同じく立て直してから適用する。
// rotate-key が 1 つ前の全体状態の wg 設定で立て直した後がこの場合に当たる。
func TestRetryRebuildsForThePendingStatesWGConfig(t *testing.T) {
	dp := &fakeDataplane{}
	rt := newFakeDataplaneRuntime(t, dp)
	one := &proto.State{Generation: 1, WG: proto.WGConfig{MTU: 1420}}
	if err := rt.apply(one); err != nil {
		t.Fatal(err)
	}
	dp.applyErr = errors.New("batch refused")
	two := &proto.State{Generation: 2, WG: proto.WGConfig{MTU: 1380}}
	_ = rt.apply(two)
	// rotate-key は last_state(世代 1)で立て直す
	rt.mu.Lock()
	rt.closeLocked()
	rt.mu.Unlock()
	_ = rt.apply(one)
	dp.applyErr = nil
	if err := rt.retryPending(); err != nil {
		t.Fatal(err)
	}
	if got := dp.builtWith[len(dp.builtWith)-1]; got.MTU != 1380 {
		t.Errorf("the retry applied generation 2 on a tunnel built with MTU %d, want its own 1380", got.MTU)
	}
	if rt.generation() != 2 {
		t.Errorf("generation %d, want 2", rt.generation())
	}
}
