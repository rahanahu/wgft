//go:build linux

package agent

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/proto"
)

// notified は、変更の通知の後の見直しを 1 回行い、誤りなら試験を落とす。
func notified(t *testing.T, d *kernelDataplane, gen uint64, rules []proto.AgentRule) bool {
	t.Helper()
	saved, err := d.observeNotified(gen, rules)
	if err != nil {
		t.Fatalf("notified check: %v", err)
	}
	return saved
}

// 通知の後の見直しは、自分の公開と wgft0 の収束が生んだ通知では何も公開し直さない。公開の直後に指紋を
// 読み直して基準にしているためである(7b.4 節の変更の通知)。外からの変更は、テーブルでも wgft0 でも直す。
func TestKernelNotifiedCheckRepairsOnlyOutsideChanges(t *testing.T) {
	k := &fakeKernel{}
	d := newTestKernel(t, k, nil, nil)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if notified(t, d, 1, rules) || len(k.published) != 1 || len(k.ensured) != 1 {
			t.Fatalf("the notifications of the agent's own publication led to published %d, ensured %d; want 1 and 1",
				len(k.published), len(k.ensured))
		}
	}
	k.tableGone = true // nft delete table inet wgft_agent
	if !notified(t, d, 1, rules) || len(k.published) != 2 || k.tableGone {
		t.Fatalf("a deleted table: published %d; want it published again", len(k.published))
	}
	if notified(t, d, 1, rules) || len(k.published) != 2 {
		t.Fatal("the notification of the repair itself published again")
	}
	link := ours(t, d)
	link.Exists = false // ip link del wgft0
	k.link = link
	k.onEnsure = func() { k.link = ours(t, d) }
	if !notified(t, d, 1, rules) || len(k.ensured) != 2 || len(k.published) != 3 {
		t.Fatalf("a deleted wgft0: ensured %d, published %d; want wgft0 converged and the table published", len(k.ensured), len(k.published))
	}
	if notified(t, d, 1, rules) || len(k.ensured) != 2 || len(k.published) != 3 {
		t.Fatal("the notifications of the repaired wgft0 led to another repair")
	}
}

// 通知の後の見直しは名前を引かず、試し接続もせず、直前の公開をそのまま公開し直す。名前の解決し直しは
// 30 秒ごとの見直しに残す(7b.4 節の変更の通知)。
func TestKernelNotifiedCheckDoesNotResolveNames(t *testing.T) {
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {netip.MustParseAddr("192.168.1.3")}}}
	d := newTestKernel(t, k, nil, nil)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("r1", "game.lan:80", 80, 80)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	lookups, probes := len(k.lookups), len(k.probed)
	k.dns["game.lan"] = []netip.Addr{netip.MustParseAddr("192.168.1.9")}
	k.tableGone = true
	if !notified(t, d, 1, rules) || len(k.published) != 2 {
		t.Fatalf("a deleted table: published %d; want it published again", len(k.published))
	}
	if len(k.lookups) != lookups || len(k.probed) != probes {
		t.Errorf("the notified check looked up %d names and probed %d targets, want none", len(k.lookups)-lookups, len(k.probed)-probes)
	}
	if got := k.published[1].Rules[0].Ranges[0].Dest.Addr(); got != netip.MustParseAddr("192.168.1.3") {
		t.Errorf("republished to %s, want the last publication's 192.168.1.3", got)
	}
}

// 公開し直しが失敗した後は、通知による公開し直しを、1 秒から倍になる間隔が過ぎるまで行わない。失敗した
// 公開もテーブルを差し替えて通知を生むことがあり、そのたびに公開し直すと失敗を繰り返すためである。
// 新しく見つかった食い違いは待たずに直し、30 秒ごとの見直しは間隔を待たない(7b.4 節の変更の通知、
// 7a.3 節の再試行)。
func TestKernelNotifiedCheckSpacesRetriesAfterAFailure(t *testing.T) {
	k := &fakeKernel{}
	d := newTestKernel(t, k, nil, nil)
	k.link = ours(t, d)
	now := time.Unix(1_000_000, 0)
	d.gate.Now = func() time.Time { return now }
	rules := []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	publish := d.ops.publish
	d.ops.publish = func(p nft.AgentPublication, c nft.AgentConfig) error {
		attempts++
		if k.publishErr != nil {
			// 応答の受信に失敗した公開のように、テーブルは差し替わってから誤りが返る
			k.tableGone = false
			k.tableEdit++
		}
		return publish(p, c)
	}
	k.publishErr = errors.New("netlink receive: no buffer space available")
	k.tableGone = true
	if _, err := d.observeNotified(1, rules); err == nil || attempts != 1 {
		t.Fatalf("a deleted table: %d attempts, err %v; want 1 failed attempt", attempts, err)
	}
	// 失敗した公開の差し替えが通知を生む。その食い違いはまだ新しいので、1 回だけ待たずに試す
	_, _ = d.observeNotified(1, rules)
	if attempts != 2 {
		t.Fatalf("the failed publication's own replacement led to %d attempts in all, want 2", attempts)
	}
	for i := 0; i < 5; i++ {
		k.tableEdit++ // 失敗した公開がまた差し替え、その通知が届く
		// 門が閉じた見直しは何も試さないので、誤りを返さず、前の誤りを残す
		if _, err := d.observeNotified(1, rules); err != nil || d.checkError() == "" {
			t.Fatalf("a check the gate held back returned %v with check error %q; want nil and the last failure kept", err, d.checkError())
		}
	}
	if attempts != 2 {
		t.Fatalf("notifications right after a failure led to %d attempts in all, want 2 until the delay passes", attempts)
	}
	now = now.Add(2 * time.Second)
	_, _ = d.observeNotified(1, rules)
	if attempts != 3 {
		t.Fatalf("after the delay passed: %d attempts in all, want 3", attempts)
	}
	_, _ = d.observeNotified(1, rules)
	if attempts != 3 {
		t.Fatalf("right after the third failure: %d attempts in all, want still 3", attempts)
	}
	// 新しい食い違い(wgft0 の MTU)は間隔を待たない
	link := ours(t, d)
	link.MTU = 1280
	k.link = link
	_, _ = d.observeNotified(1, rules)
	if attempts != 4 {
		t.Fatalf("a new drift waited for the delay: %d attempts in all, want 4", attempts)
	}
	// 30 秒ごとの見直しは間隔を待たない
	_, _ = d.observeCommit(1, rules, d.observePrepare(rules))
	if attempts != 5 {
		t.Fatalf("the 30-second check waited for the delay: %d attempts in all, want 5", attempts)
	}
	// 30 秒ごとの見直しの公開が成功すると間隔は 1 秒に戻り、同じ食い違いが続いても通知ですぐに直る
	k.publishErr = nil
	k.link = ours(t, d)
	if saved, err := d.observeCommit(1, rules, d.observePrepare(rules)); err != nil || !saved || attempts != 6 {
		t.Fatalf("the 30-second check: %d attempts in all, err %v; want the 6th to succeed", attempts, err)
	}
	k.tableEdit++ // ログに出した食い違いと同じなので、新しい食い違いではない
	if !notified(t, d, 1, rules) || attempts != 7 {
		t.Fatalf("after a success: %d attempts in all, want the same drift repaired at once", attempts)
	}
}

// 他のプロセスが同じ変更を繰り返すと、通知の後の見直しはそのたびに直すが、ログは 30 秒ごとの見直しが
// 食い違いを見つけない回を挟むまで 1 行だけにする。通知の後の見直しが食い違いを見つけない回は、
// 区切りに数えない(7b.4 節)。
func TestKernelNotifiedCheckLogsARecurringDriftOnce(t *testing.T) {
	k := &fakeKernel{}
	d := newTestKernel(t, k, nil, nil)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	for i := 0; i < 3; i++ {
		k.tableEdit++
		notified(t, d, 1, rules)
		notified(t, d, 1, rules) // 自分の公開の通知の後の、食い違いの無い見直し
	}
	if n := strings.Count(buf.String(), "changed outside wgft"); n != 1 {
		t.Errorf("logged the recurring drift %d times, want 1:\n%s", n, buf.String())
	}
	if len(k.published) != 4 {
		t.Errorf("published %d tables, want a repair on every notification", len(k.published))
	}
	observeOnce(t, d, 1, rules) // 30 秒ごとの見直しが食い違いを見つけない
	k.tableEdit++
	notified(t, d, 1, rules)
	if n := strings.Count(buf.String(), "changed outside wgft"); n != 2 {
		t.Errorf("a drift after a clean 30-second check logged %d lines in all, want 2", n)
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
	rt := &runtime{opts: Options{CredentialsPath: path, Mode: "kernel"}, f: f, priv: d.priv, dp: d, wgCfg: d.wg,
		stateNotify: make(chan struct{}, 1)}
	k.tableGone = true
	rt.observeNotified()
	if len(k.published) != 0 {
		t.Fatal("the notified check published before any full state was applied")
	}
	st := &proto.State{Generation: 1, WG: d.wg, Rules: []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}}
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
	d.ops.notify = sensor
	rt := &runtime{opts: Options{CredentialsPath: t.TempDir() + "/agent.json", Mode: "kernel"}, f: f, priv: d.priv, dp: d, wgCfg: d.wg,
		stateNotify: make(chan struct{}, 1), kernelWake: make(chan struct{}, 1), notifyDebounce: 10 * time.Millisecond}
	st := &proto.State{Generation: 1, WG: d.wg, Rules: []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}}
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

// wgft0 の収束の失敗も、通知による直し直しの間隔を空ける。稼働中に現れたアドレス帯の重なりのように
// 収束の失敗が続く間、リンクの通知のたびに試し直さない(7b.4 節の変更の通知)。
func TestKernelNotifiedCheckSpacesRetriesAfterALinkFailure(t *testing.T) {
	k := &fakeKernel{}
	d := newTestKernel(t, k, nil, nil)
	k.link = ours(t, d)
	now := time.Unix(1_000_000, 0)
	d.gate.Now = func() time.Time { return now }
	rules := []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	link := ours(t, d)
	link.Exists = false
	k.link = link
	k.ensureErr = errors.New("10.200.0.1 is covered by a route on eth0")
	if _, err := d.observeNotified(1, rules); err == nil || len(k.ensured) != 2 {
		t.Fatalf("a deleted wgft0: ensured %d times in all, err %v; want 1 failed attempt after the apply", len(k.ensured), err)
	}
	for i := 0; i < 5; i++ {
		// リンクの通知が続く。門が閉じた見直しは前の誤りを残す
		if _, err := d.observeNotified(1, rules); err != nil || !strings.Contains(d.checkError(), "covered by a route") {
			t.Fatalf("a check the gate held back returned %v with check error %q; want nil and the last failure kept", err, d.checkError())
		}
	}
	if len(k.ensured) != 2 {
		t.Fatalf("notifications right after a failed convergence led to %d attempts in all, want 2 until the delay passes", len(k.ensured))
	}
	now = now.Add(2 * time.Second)
	_, _ = d.observeNotified(1, rules)
	if len(k.ensured) != 3 {
		t.Fatalf("after the delay passed: %d attempts in all, want 3", len(k.ensured))
	}
}

// 門が閉じて何も試さなかった通知の後の見直しは、前の誤りを消さず、回復のログも出さない。テーブルは
// 消えたままなので、直ったとは言えない。agent doctor の check_error も誤りを示し続ける(7b.4 節、10.2c 節)。
func TestKernelGateClosedCheckKeepsTheError(t *testing.T) {
	k := &fakeKernel{}
	d := newTestKernel(t, k, nil, nil)
	k.link = ours(t, d)
	now := time.Unix(1_000_000, 0)
	d.gate.Now = func() time.Time { return now }
	rules := []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	k.publishErr = errors.New("netlink: permission denied")
	k.tableGone = true
	if _, err := d.observeNotified(1, rules); err == nil {
		t.Fatal("a failed republish returned no error")
	}
	want := d.checkError()
	if !strings.Contains(want, "permission denied") {
		t.Fatalf("check error = %q, want the publish error", want)
	}
	for i := 0; i < 3; i++ {
		// 無関係な通知(他のリンクの変更など)が、門が閉じている間に届く
		if _, err := d.observeNotified(1, rules); err != nil {
			t.Fatalf("a check the gate held back returned %v", err)
		}
		if got := d.checkError(); got != want {
			t.Fatalf("a check the gate held back changed the check error from %q to %q", want, got)
		}
	}
	now = now.Add(2 * time.Second)
	_, _ = d.observeNotified(1, rules) // 門が開き、試して同じ誤りで失敗する
	_, _ = d.observeNotified(1, rules) // 門がまた閉じている
	if got := d.checkError(); got != want {
		t.Errorf("check error = %q after the gate closed again, want %q", got, want)
	}
	if n := strings.Count(buf.String(), "works again"); n != 0 {
		t.Errorf("logged a recovery %d times while the table stayed gone:\n%s", n, buf.String())
	}
	if n := strings.Count(buf.String(), "failed: "); n != 1 {
		t.Errorf("logged the same failure %d times, want 1:\n%s", n, buf.String())
	}
	k.publishErr = nil
	now = now.Add(time.Minute)
	if !notified(t, d, 1, rules) || d.checkError() != "" || !strings.Contains(buf.String(), "works again") {
		t.Errorf("a successful repair left check error %q", d.checkError())
	}
}

// エンドポイントの引き直しの後の wgft0 の収束の誤りは、通知の後の見直しでは消えない。通知の後の見直しは
// エンドポイントを扱わないためである。次の 30 秒ごとの見直しの収束が成功すると消える(7b.1 節)。
func TestKernelNotifiedCheckKeepsTheEndpointError(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	k := &fakeKernel{dns: map[string][]netip.Addr{"vps.example": {netip.MustParseAddr("203.0.113.1")}}}
	d := newTestKernel(t, k, nil, nil)
	d.ops.now = func() time.Time { return now }
	w := testWG(t)
	w.Endpoint = "vps.example:51820"
	if _, err := d.build(d.priv, w); err != nil {
		t.Fatal(err)
	}
	if _, err := d.applyRules(1, nil, nil); err != nil {
		t.Fatal(err)
	}
	k.link = ours(t, d)
	observeOnce(t, d, 1, nil)
	now = now.Add(200 * time.Second)
	observeOnce(t, d, 1, nil) // 印を付ける
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	k.ensureErr = errors.New("netlink: device busy")
	if _, err := d.observeCommit(1, nil, d.observePrepare(nil)); err == nil {
		t.Fatal("a failed convergence after the re-resolution was not reported")
	}
	want := d.checkError()
	if !strings.Contains(want, "device busy") {
		t.Fatalf("check error = %q, want the convergence error", want)
	}
	for i := 0; i < 3; i++ {
		if notified(t, d, 1, nil) {
			t.Fatal("a notified check with nothing to repair published")
		}
	}
	if got := d.checkError(); got != want {
		t.Errorf("a notified check changed the check error from %q to %q", want, got)
	}
	if strings.Contains(buf.String(), "works again") {
		t.Errorf("a notified check declared the endpoint convergence recovered:\n%s", buf.String())
	}
	k.ensureErr = nil
	now = now.Add(30 * time.Second)
	observeOnce(t, d, 1, nil)
	if d.checkError() != "" || !strings.Contains(buf.String(), "works again") {
		t.Errorf("the 30-second check's successful convergence left check error %q", d.checkError())
	}
}
