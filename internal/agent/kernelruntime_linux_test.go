//go:build linux

package agent

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/agent/controlapi"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/proto"
)

// runtime の見直しは、名前を引く間に処理済みの全体状態が変われば、その解決の結果を捨てる。古い宣言の
// 解決の結果で新しい公開を上書きしないためである。試し直しを待つ間も見直しを行わない。
func TestObserveDiscardsAStaleResolution(t *testing.T) {
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {netip.MustParseAddr("192.168.1.3")}}}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, nil)
	k.link = ours(t, d)
	rt := &runtime{opts: Options{CredentialsPath: t.TempDir() + "/agent.json", Mode: "kernel"}, f: f, dp: d, wgCfg: d.WG}
	rt.setPrivKey(d.Priv)
	old := &proto.State{Generation: 1, WG: d.WG, Rules: []proto.AgentRule{tcpRule("r1", "game.lan:80", 80, 80)}}
	rt.mu.Lock()
	if err := rt.finishApplyLocked(old, nil); err != nil {
		t.Fatal(err)
	}
	rt.mu.Unlock()
	published := len(k.published)

	newer := &proto.State{Generation: 2, WG: d.WG, Rules: []proto.AgentRule{tcpRule("r1", "192.168.1.50:80", 80, 80)}}
	d.Ops.Lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		// 名前を引いている間に、stream が新しい全体状態を適用し終える
		rt.mu.Lock()
		if err := rt.finishApplyLocked(newer, nil); err != nil {
			t.Error(err)
		}
		rt.mu.Unlock()
		return []netip.Addr{netip.MustParseAddr("192.168.1.99")}, nil
	}
	rt.observe()
	if len(k.published) != published+1 {
		t.Fatalf("published %d tables during the check, want only the new state's 1", len(k.published)-published)
	}
	if got := d.Pub.Rules[0].Ranges[0].Dest.Addr(); got != netip.MustParseAddr("192.168.1.50") {
		t.Errorf("the check overwrote the new state with the old one's resolution: DNAT to %s", got)
	}

	rt.mu.Lock()
	rt.pendingSt = &proto.State{Generation: 3}
	rt.mu.Unlock()
	k.tableGone = true
	before := len(k.published)
	rt.observe()
	if len(k.published) != before {
		t.Error("the check published while a pending state waits for its retry")
	}
	rt.mu.Lock()
	rt.pendingSt = nil
	rt.mu.Unlock()
	rt.stateNotify = make(chan struct{}, 1)
	rt.observe()
	if len(k.published) != before+1 {
		t.Error("the check did not repair the missing table once nothing was pending")
	}
	// 見直しが公開し直したら、次の 30 秒を待たずにハートビートを送らせる
	select {
	case <-rt.stateNotify:
	default:
		t.Error("the repair did not ask for a heartbeat")
	}
}

// runtime の見直しは、名前を引く間に公開できなかった全体状態の控えが現れたら、解決の結果を捨てる。
// 控えの試し直しが公開を担うためである。
func TestObserveDiscardsAResolutionWhenAPendingStateAppears(t *testing.T) {
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {netip.MustParseAddr("192.168.1.3")}}}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, nil)
	k.link = ours(t, d)
	rt := &runtime{opts: Options{CredentialsPath: t.TempDir() + "/agent.json", Mode: "kernel"}, f: f, dp: d, wgCfg: d.WG}
	rt.setPrivKey(d.Priv)
	st := &proto.State{Generation: 1, WG: d.WG, Rules: []proto.AgentRule{tcpRule("r1", "game.lan:80", 80, 80)}}
	rt.mu.Lock()
	if err := rt.finishApplyLocked(st, nil); err != nil {
		t.Fatal(err)
	}
	rt.mu.Unlock()
	k.tableGone = true
	d.Ops.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		rt.mu.Lock()
		rt.pendingSt = &proto.State{Generation: 2}
		rt.mu.Unlock()
		return []netip.Addr{netip.MustParseAddr("192.168.1.3")}, nil
	}
	published := len(k.published)
	rt.observe()
	if len(k.published) != published {
		t.Error("the check published although a pending state appeared while it resolved names")
	}
}

// runtime は、見直しが誤りを返しても記録が変わっていれば認証情報ファイルを保存し、ハートビートを送らせる。
// 引き直したエンドポイントの収束に失敗した見直しも、表を公開し直していることがあるためである。
func TestObserveSavesARepairThatAlsoReturnsAnError(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	k := &fakeKernel{dns: map[string][]netip.Addr{"vps.example": {netip.MustParseAddr("203.0.113.1")}}}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, nil)
	d.Ops.Now = func() time.Time { return now }
	w := testWG(t)
	w.Endpoint = "vps.example:51820"
	if _, err := d.Build(d.Priv, w); err != nil {
		t.Fatal(err)
	}
	k.link = ours(t, d)
	path := t.TempDir() + "/agent.json"
	rt := &runtime{opts: Options{CredentialsPath: path, Mode: "kernel"}, f: f, dp: d, wgCfg: d.WG}
	rt.setPrivKey(d.Priv)
	st := &proto.State{Generation: 1, WG: w}
	rt.mu.Lock()
	if err := rt.finishApplyLocked(st, nil); err != nil {
		t.Fatal(err)
	}
	rt.mu.Unlock()
	k.link = ours(t, d)
	rt.observe()
	now = now.Add(200 * time.Second)
	rt.observe() // 印を付ける
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	k.ensureErr = errors.New("netlink: operation not permitted")
	k.tableGone = true
	rt.stateNotify = make(chan struct{}, 1)
	rt.observe()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the repair was not saved: %v", err)
	}
	select {
	case <-rt.stateNotify:
	default:
		t.Error("the repair did not ask for a heartbeat")
	}
}

// カーネルモードの dataplane が読む最終ハンドシェイクも、ユーザー空間モードと同じ判定で、再接続の
// 待ちの上限を決める証拠になる(仕様 5.2 節)。カーネルモードの runtime は作り直しの閾値を持たない。
func TestKernelHandshakeIsTheSameEvidenceForTheReconnectCap(t *testing.T) {
	k := &fakeKernel{}
	d := newTestKernel(t, k, nil, nil)
	rt := newFakeDataplaneRuntime(t, nil)
	rt.dp = d
	rt.f.LastState = &proto.State{Generation: 1}
	rt.rebuild = rebuildState{}
	link := ours(t, d)
	k.link = link

	now := time.Now()
	rt.checkTunnel(now)
	if rt.handshakeSeen.Load().fresh(now) {
		t.Fatal("wgft0 without a handshake counts as fresh")
	}
	link.Peers[0].LastHandshake = now.Add(-10 * time.Second)
	k.link = link
	rt.checkTunnel(now)
	if !rt.handshakeSeen.Load().fresh(now) {
		t.Fatal("a handshake 10 s old on wgft0 does not count as fresh")
	}
	if rt.handshakeSeen.Load().fresh(now.Add(170 * time.Second)) {
		t.Error("a handshake 180 s old on wgft0 still counts as fresh")
	}
	// 停止の間も残っていた wgft0 の古いハンドシェイクは、初めて読んでも新しくない
	rt2 := newFakeDataplaneRuntime(t, nil)
	rt2.dp = d
	rt2.f.LastState = &proto.State{Generation: 1}
	link.Peers[0].LastHandshake = now.Add(-time.Hour)
	k.link = link
	rt2.checkTunnel(now)
	if rt2.handshakeSeen.Load().fresh(now) {
		t.Error("an hour-old handshake left on wgft0 counts as fresh when first read")
	}
}

// runtime の通知の後の見直しは、処理済みの全体状態が無い間と、公開できなかった全体状態の試し直しを待つ
// 間は何もしない。直したら認証情報ファイルを保存し、次の 30 秒を待たずにハートビートを送らせる。
func TestRuntimeObserveNotified(t *testing.T) {
	k := &fakeKernel{}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, nil)
	k.link = ours(t, d)
	path := t.TempDir() + "/agent.json"
	rt := &runtime{opts: Options{CredentialsPath: path, Mode: "kernel"}, f: f, dp: d, wgCfg: d.WG,
		stateNotify: make(chan struct{}, 1)}
	rt.setPrivKey(d.Priv)
	k.tableGone = true
	rt.observeNotified()
	if len(k.published) != 0 {
		t.Fatal("the notified check published before any full state was applied")
	}
	st := &proto.State{Generation: 1, WG: d.WG, Rules: []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}}
	rt.mu.Lock()
	if err := rt.finishApplyLocked(st, nil); err != nil {
		t.Fatal(err)
	}
	rt.pendingSt = &proto.State{Generation: 2}
	rt.mu.Unlock()
	published := len(k.published)
	k.tableGone = true
	rt.observeNotified()
	if len(k.published) != published || len(rt.stateNotify) != 0 {
		t.Error("the notified check published while a pending state waits for its retry")
	}
	rt.mu.Lock()
	rt.pendingSt = nil
	rt.mu.Unlock()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	rt.observeNotified()
	if len(k.published) != published+1 {
		t.Fatal("the notified check did not repair the missing table once nothing was pending")
	}
	select {
	case <-rt.stateNotify:
	default:
		t.Error("the repair did not ask for a heartbeat")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the repair did not save the credentials file: %v", err)
	}
}

// fakeSensor は、購読が始まったら 1 回 wake を呼び、ctx が終わるまで待つ。
type fakeSensor struct{ started chan struct{} }

func (s fakeSensor) Watch(ctx context.Context, wake func()) error {
	close(s.started)
	wake()
	<-ctx.Done()
	return nil
}

// Run の手順どおり watchKernel と serve を動かすと、カーネルの変更の通知が通知の後の見直しに届き、
// 消えたテーブルを 30 秒を待たずに公開し直す。
func TestKernelNotificationsReachTheCheck(t *testing.T) {
	k := &fakeKernel{}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, nil)
	k.link = ours(t, d)
	sensor := fakeSensor{started: make(chan struct{})}
	d.Ops.Notify = sensor
	rt := &runtime{opts: Options{CredentialsPath: t.TempDir() + "/agent.json", Mode: "kernel"}, f: f, dp: d, wgCfg: d.WG,
		stateNotify: make(chan struct{}, 1), kernelWake: make(chan struct{}, 1), notifyDebounce: 10 * time.Millisecond}
	rt.setPrivKey(d.Priv)
	st := &proto.State{Generation: 1, WG: d.WG, Rules: []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}}
	rt.mu.Lock()
	if err := rt.finishApplyLocked(st, nil); err != nil {
		t.Fatal(err)
	}
	published := len(k.published)
	k.tableGone = true
	rt.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.serve(ctx, make(chan error), make(chan time.Time)) }()
	defer func() { cancel(); <-done }()
	rt.watchKernel(ctx)
	select {
	case <-sensor.started:
	case <-time.After(5 * time.Second):
		t.Fatal("watchKernel did not subscribe")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		rt.mu.Lock()
		n := len(k.published)
		rt.mu.Unlock()
		if n > published {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a notification did not lead to the table published again")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// 稼働中のカーネルモードのエージェントは、doctor の応答に、停止中と同じ読み方の結果、公開できずに試し直して
// いる全体状態の誤り、直前の見直しの誤り、ルールごとのポートの数を載せる(設計文書 10.2c 節)。
func TestDoctorCarriesTheKernelReading(t *testing.T) {
	fk := &fakeKernel{forwardOn: true}
	f := &credentials.Credentials{Mode: credentials.ModeKernel}
	d := newTestKernel(t, fk, f, nil)
	f.WGPrivateKey = d.Priv.String()
	rules := []proto.AgentRule{tcpRule("r1", "192.168.1.20:25565", 25565, 25567)}
	if _, err := d.ApplyRules(3, rules, nil); err != nil {
		t.Fatal(err)
	}
	f.LastState = &proto.State{Generation: 3, WG: d.WG, Rules: rules}
	d.ObserveErr = "read table inet wgft_agent: boom"
	k := healthyKernel(t, f)
	withKernelDoctor(t, k)
	rt := &runtime{opts: Options{CredentialsPath: t.TempDir() + "/agent.json", Mode: credentials.ModeKernel}, f: f, dp: d, wgCfg: d.WG,
		pendingErr: "publish table inet wgft_agent: refused"}
	rt.setPrivKey(d.Priv)
	res := rt.collectDoctor()
	st := res.RuntimeState
	if st == nil || st.Kernel == nil {
		t.Fatalf("runtime state = %+v, want the kernel reading", st)
	}
	if st.Kernel.Table.Source != controlapi.KernelTableFromRecord || st.Kernel.Table.Generation != 3 || st.Kernel.Interface.Name != "wgft0" {
		t.Errorf("kernel = %+v", st.Kernel)
	}
	if st.PublishError == "" || st.CheckError != "read table inet wgft_agent: boom" {
		t.Errorf("publish error %q, check error %q", st.PublishError, st.CheckError)
	}
	if len(st.Rules) != 1 || st.Rules[0].Ports != 3 || st.Rules[0].DNATPorts != 3 {
		t.Errorf("rules = %+v, want the ports of the record", st.Rules)
	}
	if res.Process == nil || res.Process.UID != os.Getuid() {
		t.Errorf("process = %+v, want this process's uid", res.Process)
	}
}

// ユーザー空間モードの応答はカーネルの読みを持たない。
func TestDoctorLeavesTheKernelOutInUserspaceMode(t *testing.T) {
	dp := &fakeDataplane{up: true, reading: agentdp.Reading{Tunnel: agentdp.TunnelReading{Present: true}}}
	rt := newFakeDataplaneRuntime(t, dp)
	res := rt.collectDoctor()
	if res.RuntimeState.Kernel != nil || res.RuntimeState.PublishError != "" {
		t.Errorf("runtime state = %+v, want no kernel reading", res.RuntimeState)
	}
	if res.Process == nil {
		t.Error("the process identity is missing; it is mode-independent")
	}
}
