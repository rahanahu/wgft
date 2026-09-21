package agent

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/tunnel"
	"github.com/rahanahu/wgft/proto"
)

// tunnelIntercept は tunnel.New の呼び出しを記録し、指示された回数だけ失敗させる差し替え口
// (newTunnel。bindForDevice と同じ流儀の、この package の中だけの口)。
type tunnelIntercept struct {
	mu    sync.Mutex
	cfgs  []tunnel.Config
	fails int
}

// interceptTunnel は差し替えを始め、テストの後に元へ戻す。
func interceptTunnel(t *testing.T) *tunnelIntercept {
	t.Helper()
	real := newTunnel
	in := &tunnelIntercept{}
	newTunnel = func(cfg tunnel.Config) (*tunnel.Tunnel, error) {
		in.mu.Lock()
		in.cfgs = append(in.cfgs, cfg)
		fail := in.fails > 0
		if fail {
			in.fails--
		}
		in.mu.Unlock()
		if fail {
			return nil, errors.New("simulated failure to create the tunnel")
		}
		return real(cfg)
	}
	t.Cleanup(func() { newTunnel = real })
	return in
}

// failNext は次の n 回の作成を失敗させる。
func (in *tunnelIntercept) failNext(n int) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.fails = n
}

// calls は今までの呼び出しの回数を返す。
func (in *tunnelIntercept) calls() int {
	in.mu.Lock()
	defer in.mu.Unlock()
	return len(in.cfgs)
}

// last は最後に渡された宣言を返す。
func (in *tunnelIntercept) last(t *testing.T) tunnel.Config {
	t.Helper()
	in.mu.Lock()
	defer in.mu.Unlock()
	if len(in.cfgs) == 0 {
		t.Fatal("tunnel.New was never called")
	}
	return in.cfgs[len(in.cfgs)-1]
}

// 全体状態の適用がトンネルの作成に失敗したら、次の世代を待たずに試し直し、しかも失敗した全体状態から
// 立て直すことを確かめる(仕様 7 節)。認証情報ファイルの last_state は 1 つ前の全体状態を指したままな
// ので、そちらから立てるとサーバが想定していない設定とルールのトンネルになる。
func TestApplyBuildFailureIsRetriedWithTheFailedState(t *testing.T) {
	srvKey := newKey(t)
	echo := startUDPEcho(t)
	first := []proto.AgentRule{{
		ID: "r1", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2456},
		Target: echo, Enabled: true,
	}}
	rt := newRebuildTestRuntime(t, closedUDPPort(t), srvKey.PublicKey(), newKey(t), first)
	rt.rebuild = rebuildState{after: time.Second, backoffMax: 2 * time.Second}

	// 2 つ目の全体状態は wg 設定もルールも違う。作成を 1 回だけ失敗させる
	next := &proto.State{
		Generation: 2,
		WG: proto.WGConfig{
			ServerPubkey: srvKey.PublicKey().String(), Endpoint: closedUDPPort(t),
			Address: "10.200.0.2/24", MTU: 1380, Keepalive: 1, UDPTimeoutStream: 120,
		},
		Rules: []proto.AgentRule{{
			ID: "r2", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2457, Hi: 2457},
			Target: echo, Enabled: true,
		}},
	}
	in := interceptTunnel(t)
	in.failNext(1)
	if err := rt.apply(next); err == nil {
		t.Fatal("apply with a failing tunnel creation returned no error")
	}

	// 1. 世代も認証情報ファイルも進めない。試し直しは失敗した全体状態を控える
	if rt.tun != nil {
		t.Fatal("the failing build left a tunnel behind")
	}
	if rt.gen != 1 {
		t.Errorf("generation = %d after a failed apply, want 1", rt.gen)
	}
	if rt.f.LastState == nil || rt.f.LastState.Generation != 1 {
		t.Errorf("last state = %v after a failed apply, want generation 1", rt.f.LastState)
	}
	if rt.retrySt != next {
		t.Fatal("the state whose build failed was not kept for the retry")
	}
	if rt.rebuild.retryAt.IsZero() {
		t.Fatal("no retry was scheduled after apply failed to build")
	}
	if got, want := rt.heartbeat().Tunnel.Reason, "no tunnel; building it failed and will be retried"; got != want {
		t.Errorf("heartbeat reason = %q, want %q", got, want)
	}

	// 2. 次の判定で、失敗した全体状態の wg 設定とルールで立て直す
	rt.checkTunnel(time.Now())
	if rt.tun == nil {
		t.Fatal("the retry did not build a tunnel")
	}
	if got := in.last(t).MTU; got != 1380 {
		t.Errorf("the retry built with MTU %d, want 1380 (the state whose build failed)", got)
	}
	if rt.wgCfg.MTU != 1380 {
		t.Errorf("applied wg config MTU = %d, want 1380", rt.wgCfg.MTU)
	}
	st := rt.rl.Status()
	if len(st) != 1 || st[0].Key.Port != 2457 || st[0].RuleID != "r2" {
		t.Fatalf("listeners after the retry = %+v, want one for rule r2 on port 2457", st)
	}

	// 3. 適用の残りも終える。世代が進み、認証情報ファイルにも保存される
	if rt.gen != 2 {
		t.Errorf("generation = %d after the retry, want 2", rt.gen)
	}
	saved, err := credentials.Load(rt.opts.CredentialsPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.LastState == nil || saved.LastState.Generation != 2 {
		t.Errorf("saved last state = %v after the retry, want generation 2", saved.LastState)
	}
	if !rt.rebuild.retryAt.IsZero() || rt.retrySt != nil {
		t.Errorf("the retry was not cleared after a successful build: retryAt=%v retrySt=%v", rt.rebuild.retryAt, rt.retrySt != nil)
	}
}

// wg 設定そのものが誤っている全体状態は、何度立て直しても同じ結果になるので試し直さないことを
// 確かめる(仕様 7 節)。直った全体状態が届けば、そちらで立つ。
func TestApplyConfigErrorIsNotRetried(t *testing.T) {
	srvKey := newKey(t)
	rt := newRebuildTestRuntime(t, closedUDPPort(t), srvKey.PublicKey(), newKey(t), nil)
	rt.rebuild = rebuildState{after: time.Millisecond, backoffMax: 2 * time.Millisecond}

	broken := &proto.State{
		Generation: 2,
		WG: proto.WGConfig{
			ServerPubkey: "not-a-valid-key", Endpoint: closedUDPPort(t),
			Address: "10.200.0.2/24", MTU: 1420, Keepalive: 1,
		},
	}
	in := interceptTunnel(t)
	if err := rt.apply(broken); err == nil {
		t.Fatal("apply with a malformed server public key returned no error")
	}
	if rt.tun != nil {
		t.Fatal("the failed apply left a tunnel behind")
	}
	if !rt.rebuild.retryAt.IsZero() {
		t.Fatal("a wg config error must not schedule a retry; retrying cannot fix it")
	}
	if got, want := rt.heartbeat().Tunnel.Reason, "no tunnel; building it failed"; got != want {
		t.Errorf("heartbeat reason = %q, want %q", got, want)
	}

	// 判定を何度通しても作成を試さない
	for i := 0; i < 5; i++ {
		rt.checkTunnel(time.Now())
		time.Sleep(2 * time.Millisecond)
	}
	if n := in.calls(); n != 0 {
		t.Fatalf("tunnel.New was called %d times after a wg config error, want 0", n)
	}

	// 直った全体状態が届けば立つ
	fixed := &proto.State{
		Generation: 3,
		WG: proto.WGConfig{
			ServerPubkey: srvKey.PublicKey().String(), Endpoint: closedUDPPort(t),
			Address: "10.200.0.2/24", MTU: 1420, Keepalive: 1,
		},
	}
	if err := rt.apply(fixed); err != nil {
		t.Fatalf("apply a corrected state: %v", err)
	}
	if rt.tun == nil || rt.gen != 3 {
		t.Fatalf("a corrected state did not bring the tunnel back: tun=%v gen=%d", rt.tun != nil, rt.gen)
	}
}

// rotate-key の適用が作成に失敗したときは、新しい鍵で試し直すことを確かめる(仕様 7 節)。
// rotateKey は closeLocked でトンネルを閉じてから適用し直す。閉じた時点で試し直しの控えは消えるが、
// その後の作成の失敗が控え直すので、意図して閉じたトンネルは立て直さないまま、鍵の作り直しだけは
// 最後まで進む。
func TestRotateKeyBuildFailureIsRetriedWithTheNewKey(t *testing.T) {
	srvKey := newKey(t)
	oldKey := newKey(t)
	rt := newRebuildTestRuntime(t, closedUDPPort(t), srvKey.PublicKey(), oldKey, nil)
	rt.rebuild = rebuildState{after: time.Second, backoffMax: 2 * time.Second}

	in := interceptTunnel(t)
	in.failNext(1)
	pub, err := rt.rotateKey()
	if err != nil {
		t.Fatalf("rotate-key: %v", err)
	}
	if rt.tun != nil {
		t.Fatal("the failing build left a tunnel behind")
	}
	if rt.rebuild.retryAt.IsZero() {
		t.Fatal("no retry was scheduled after rotate-key failed to build")
	}

	rt.checkTunnel(time.Now())
	if rt.tun == nil {
		t.Fatal("the retry did not build a tunnel after rotate-key")
	}
	if got := in.last(t).PrivateKey.PublicKey(); got != pub {
		t.Errorf("the retry built with public key %s, want the rotated key %s", got, pub)
	}
	if got := in.last(t).PrivateKey.PublicKey(); got == oldKey.PublicKey() {
		t.Error("the retry built with the key that rotate-key replaced")
	}
}

// 試し直しを待っている間に停止したら、何も立てないことを確かめる(仕様 7 節)。
func TestShutdownDuringAPendingRetryBuildsNothing(t *testing.T) {
	srvKey := newKey(t)
	rt := newRebuildTestRuntime(t, closedUDPPort(t), srvKey.PublicKey(), newKey(t), nil)
	rt.rebuild = rebuildState{after: time.Millisecond, backoffMax: 2 * time.Millisecond}

	next := &proto.State{
		Generation: 2,
		WG: proto.WGConfig{
			ServerPubkey: srvKey.PublicKey().String(), Endpoint: closedUDPPort(t),
			Address: "10.200.0.2/24", MTU: 1380, Keepalive: 1,
		},
	}
	in := interceptTunnel(t)
	in.failNext(1)
	if err := rt.apply(next); err == nil {
		t.Fatal("apply with a failing tunnel creation returned no error")
	}
	if rt.rebuild.retryAt.IsZero() {
		t.Fatal("no retry was scheduled after apply failed to build")
	}

	rt.close() // 停止(Run の defer と同じ経路)
	if !rt.rebuild.retryAt.IsZero() || rt.retrySt != nil {
		t.Error("shutting down left the watchdog's retry scheduled")
	}
	before := in.calls()
	for i := 0; i < 5; i++ {
		rt.checkTunnel(time.Now())
		if rt.tun != nil {
			t.Fatal("the watchdog built a tunnel after shutdown")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if n := in.calls(); n != before {
		t.Fatalf("tunnel.New was called %d more times after shutdown, want 0", n-before)
	}
}
