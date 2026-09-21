package agent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	goruntime "runtime"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/tunnel"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/utun"
	"github.com/rahanahu/wgft/proto"
)

// rebuildState.step の判定(仕様 7 節)。判定は、最終ハンドシェイクの値と現在時刻の差ではなく、
// その値を観測してからの時間で行う。now と start は production では単調な読みを持つ time.Now の値で、
// ハンドシェイクの値だけが壁時計の飛びを受ける。この試験は合成した時刻を渡す。実際の time.Now を
// 通る経路は、この後の 2 つの試験が checkTunnel ごと確かめる。
func TestRebuildStateStep(t *testing.T) {
	const after, backoffMax = 300 * time.Second, 900 * time.Second
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	start := now.Add(-time.Hour)

	// 1. 健全なトンネル。ハンドシェイクの値は 145 秒以内に必ず新しくなる(RekeyAfterTime 120 秒 +
	// keepalive 25 秒)。新しい値を観測するたびに起点が進むので、作り直しは起きない
	s := rebuildState{after: after, backoffMax: backoffMax}
	for i := 0; i < 10; i++ {
		at := now.Add(time.Duration(i) * 145 * time.Second)
		if _, rebuild := s.step(at, start, at.Add(-20*time.Second)); rebuild {
			t.Fatalf("healthy tunnel: rebuild = true at step %d, want false", i)
		}
		if s.wait != after {
			t.Fatalf("healthy tunnel: wait = %s at step %d, want %s", s.wait, i, after)
		}
	}

	// 2. 壁時計が前へ飛んでも、ハンドシェイクの値が新しくなっていれば作り直さない。値と現在時刻の
	// 差で測っていた頃は、155 秒以上の前方への飛びが健全なトンネルを 300 秒古く見せていた
	s = rebuildState{after: after, backoffMax: backoffMax}
	s.step(now, start, now.Add(-20*time.Second))
	jumped := now.Add(30 * time.Second)                                            // 単調な時計では 30 秒しか経っていない
	if _, rebuild := s.step(jumped, start, jumped.Add(600*time.Second)); rebuild { // 壁時計が 10 分前へ飛んだ後のハンドシェイク
		t.Error("a forward wall-clock step with a healthy tunnel must not rebuild")
	}
	// 値そのものが 1 時間古く見えても、観測したのが 10 秒前なら作り直さない
	s = rebuildState{after: after, backoffMax: backoffMax}
	s.step(now, start, now.Add(-time.Hour))
	if _, rebuild := s.step(now.Add(10*time.Second), start, now.Add(-time.Hour)); rebuild {
		t.Error("a handshake value that looks 1h old but was first observed 10s ago must not rebuild")
	}

	// 3. 壁時計が後ろへ飛び、ハンドシェイクの値が未来に見えても、値が新しくならなければ作り直す。
	// 値と現在時刻の差で測っていた頃は、この差が負になり作り直しが永久に起きなかった
	s = rebuildState{after: after, backoffMax: backoffMax}
	future := now.Add(time.Hour)
	s.step(now, start, future)
	if _, rebuild := s.step(now.Add(299*time.Second), start, future); rebuild {
		t.Error("299s after observing the value: rebuild = true, want false")
	}
	if _, rebuild := s.step(now.Add(301*time.Second), start, future); !rebuild {
		t.Error("301s after observing a handshake value that never changes: rebuild = false, want true")
	}

	// 4. ハンドシェイクが一度も成立していないときは、トンネルを立てた時刻からの時間で判定する
	s = rebuildState{after: after, backoffMax: backoffMax}
	if _, rebuild := s.step(now, now.Add(-299*time.Second), time.Time{}); rebuild {
		t.Error("299s after the tunnel was built with no handshake: rebuild = true, want false")
	}
	idle, rebuild := s.step(now, now.Add(-301*time.Second), time.Time{})
	if !rebuild || idle != 301*time.Second {
		t.Fatalf("301s after the tunnel was built with no handshake: rebuild = %v idle = %s, want true 5m1s", rebuild, idle)
	}

	// 5. 作り直しをまたいでハンドシェイクがゼロのままなら、値は変わらないので観測の時刻も動かない。
	// 起点は新しいトンネルを立てた時刻になり、作り直しの直後は作り直さない
	s = rebuildState{after: after, backoffMax: backoffMax}
	s.step(now, now.Add(-301*time.Second), time.Time{}) // 1 回目の作り直し
	rebuilt := now
	if _, rebuild := s.step(rebuilt.Add(30*time.Second), rebuilt, time.Time{}); rebuild {
		t.Error("30s after a rebuild with a still-zero handshake: rebuild = true, want false")
	}

	// 6. 作り直しの間隔は、上限まで倍になる
	s = rebuildState{after: after, backoffMax: backoffMax}
	wants := []time.Duration{600 * time.Second, 900 * time.Second, 900 * time.Second, 900 * time.Second}
	wait, built := after, now
	for i, want := range wants {
		// 間隔の手前では作り直さない
		if _, rebuild := s.step(built.Add(wait-time.Second), built, time.Time{}); rebuild {
			t.Errorf("attempt %d: rebuilt %s after the tunnel was built, want no rebuild before %s", i+1, wait-time.Second, wait)
		}
		built = built.Add(wait)
		if _, rebuild := s.step(built, built.Add(-wait), time.Time{}); !rebuild {
			t.Fatalf("attempt %d: rebuild = false, want true", i+1)
		}
		if s.wait != want {
			t.Fatalf("attempt %d: next wait = %s, want %s", i+1, s.wait, want)
		}
		wait = s.wait
	}

	// 7. ゼロでない新しいハンドシェイクを観測したら間隔は初期値に戻る
	if _, rebuild := s.step(built, built, built); rebuild {
		t.Error("a newly observed handshake must not trigger a rebuild")
	}
	if s.wait != after {
		t.Errorf("after a newly observed handshake: wait = %s, want %s", s.wait, after)
	}

	// 8. 閾値を持たない runtime では作り直さない(ゼロ値の rebuildState が毎回作り直すことを避ける)
	var zero rebuildState
	if _, rebuild := zero.step(now, start, time.Time{}); rebuild {
		t.Error("a rebuildState without thresholds must not rebuild")
	}
}

// 作成に失敗したときの再試行の予定(仕様 7 節)。最初の失敗の後は次の判定で試し、続けて失敗する
// ほど間隔を after から上限まで広げる。閉じたときは予定を捨てる。
func TestRebuildStateFailedBuild(t *testing.T) {
	const after, backoffMax = 300 * time.Second, 900 * time.Second
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	s := rebuildState{after: after, backoffMax: backoffMax}

	// 1 回目の失敗は次の判定で試す。以後は 300 秒、600 秒、900 秒と広げ、900 秒で頭打ちにする
	wants := []time.Duration{0, after, 2 * after, backoffMax, backoffMax}
	for i, want := range wants {
		s.failedBuild(now)
		if got := s.retryAt.Sub(now); got != want {
			t.Fatalf("failure %d: next attempt in %s, want %s", i+1, got, want)
		}
		now = s.retryAt
	}

	// 閉じたトンネルを立て直さないよう、予定は clearRetry で消える
	s.clearRetry()
	if !s.retryAt.IsZero() || s.retryWait != 0 {
		t.Fatalf("clearRetry left retryAt=%v retryWait=%s", s.retryAt, s.retryWait)
	}
}

// サーバに届かないままのエージェントが、トンネルを作り直しながらも間隔を広げることを、実際の
// トンネルで確かめる(仕様 7 節)。作り直しのたびに古いトンネルは閉じてから新しいものに置き換わるので、
// goroutine は基準値へ戻る。
func TestCheckTunnelBacksOffWhileTheServerIsUnreachable(t *testing.T) {
	srvKey := newKey(t)
	baseline := goruntime.NumGoroutine()
	// 誰も待ち受けていないポートへ向ける。ハンドシェイクは永久に成立しない
	rt := newRebuildTestRuntime(t, closedUDPPort(t), srvKey.PublicKey(), newKey(t), nil)
	rt.rebuild = rebuildState{after: 150 * time.Millisecond, backoffMax: 600 * time.Millisecond}

	wants := []time.Duration{150 * time.Millisecond, 300 * time.Millisecond, 600 * time.Millisecond}
	prev := rt.tun
	last := rt.tunStart
	for i, want := range wants {
		at := waitRebuild(t, rt, prev, want+2*time.Second)
		if got := at.Sub(last); got < want {
			t.Fatalf("rebuild %d came %s after the previous tunnel was built, want at least %s", i+1, got, want)
		}
		// 置き換えの前に閉じているので、古いトンネルの netstack はもう待ち受けを開けない
		if _, err := prev.ListenUDP(3000); err == nil {
			t.Fatalf("rebuild %d: the replaced tunnel still opened a listener; it was not closed first", i+1)
		}
		prev, last = rt.tun, rt.tunStart
	}

	rt.close()
	assertGoroutinesSettle(t, baseline)
}

// ゼロでない新しいハンドシェイクを観測したら作り直しの間隔が初期値に戻り、作り直しも止まることを、
// 実際のサーバと繋いで確かめる(仕様 7 節)。サーバを止めている間に作り直しが起き、サーバを戻すと
// 転送が戻る。判定は production と同じく実際の time.Now を通る。
func TestCheckTunnelResetsAfterHandshake(t *testing.T) {
	srvKey := newKey(t)
	echo := startUDPEcho(t)
	baseline := goruntime.NumGoroutine()
	srv, port := newServerTunnel(t, srvKey, 0)

	rules := []proto.AgentRule{{
		ID: "r1", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2456},
		Target: echo, Enabled: true,
	}}
	// ピアを先に宣言してから立てる。最初のハンドシェイクが拒まれて 5 秒の再送を待つのを避ける
	agentKey := newKey(t)
	if _, err := srv.SetPeers([]dataplane.Peer{{PublicKey: agentKey.PublicKey(), Address: netip.MustParseAddr("10.200.0.2")}}); err != nil {
		t.Fatalf("declare the agent peer: %v", err)
	}
	rt := newRebuildTestRuntime(t, fmt.Sprintf("127.0.0.1:%d", port), srvKey.PublicKey(), agentKey, rules)
	rt.rebuild = rebuildState{after: time.Second, backoffMax: 2 * time.Second}

	// 1. ハンドシェイクが成立している間は作り直さず、間隔は初期値のままである
	waitHandshake(t, rt, 20*time.Second)
	before := rt.tun
	rt.checkTunnel(time.Now())
	if rt.tun != before {
		t.Fatal("a tunnel with a fresh handshake was rebuilt")
	}
	if rt.rebuild.wait != rt.rebuild.after {
		t.Fatalf("wait = %s while healthy, want %s", rt.rebuild.wait, rt.rebuild.after)
	}

	// 2. サーバを止めるとハンドシェイクが新しくならず、観測してから閾値を過ぎたところで作り直す
	srv.Close()
	waitRebuild(t, rt, before, rt.rebuild.after+5*time.Second)
	if want := 2 * rt.rebuild.after; rt.rebuild.wait != want {
		t.Fatalf("wait = %s after the first rebuild, want %s", rt.rebuild.wait, want)
	}
	if n := len(rt.rl.Status()); n != 1 {
		t.Fatalf("listeners after the rebuild = %d, want 1", n)
	}
	for _, s := range rt.rl.Status() {
		if s.Err != nil {
			t.Fatalf("listener %v after the rebuild: %v", s.Key, s.Err)
		}
	}

	// 3. サーバを同じ鍵とポートで戻すと、作り直したトンネルがハンドシェイクを済ませ、間隔が戻る
	srv2, _ := newServerTunnel(t, srvKey, port)
	if _, err := srv2.SetPeers([]dataplane.Peer{{PublicKey: rt.priv.PublicKey(), Address: netip.MustParseAddr("10.200.0.2")}}); err != nil {
		t.Fatalf("declare the agent peer again: %v", err)
	}
	waitHandshake(t, rt, 20*time.Second)
	rebuilt := rt.tun
	rt.checkTunnel(time.Now())
	if rt.tun != rebuilt {
		t.Fatal("the tunnel was rebuilt again although the handshake had succeeded")
	}
	if rt.rebuild.wait != rt.rebuild.after {
		t.Fatalf("wait = %s after the handshake came back, want %s", rt.rebuild.wait, rt.rebuild.after)
	}

	rt.close()
	srv2.Close()
	assertGoroutinesSettle(t, baseline)
}

// 作り直しがトンネルの作成に失敗したら、エージェントはトンネルの無いまま止まらず、作成を試し直す
// ことを確かめる(仕様 7 節)。失敗は tunnel.New の差し替えで 1 回だけ起こし、実際のネットワークの
// 故障は使わない。サーバは動かしたままにする。健全なトンネルでも最終ハンドシェイクは鍵の寿命まで
// 新しくならないので、短い閾値では作り直しが起き、その 1 回目の作成だけが失敗する。
func TestCheckTunnelRetriesAfterAFailedRebuild(t *testing.T) {
	srvKey := newKey(t)
	echo := startUDPEcho(t)
	baseline := goruntime.NumGoroutine()
	srv, port := newServerTunnel(t, srvKey, 0)

	rules := []proto.AgentRule{{
		ID: "r1", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2456},
		Target: echo, Enabled: true,
	}}
	agentKey := newKey(t)
	if _, err := srv.SetPeers([]dataplane.Peer{{PublicKey: agentKey.PublicKey(), Address: netip.MustParseAddr("10.200.0.2")}}); err != nil {
		t.Fatalf("declare the agent peer: %v", err)
	}
	rt := newRebuildTestRuntime(t, fmt.Sprintf("127.0.0.1:%d", port), srvKey.PublicKey(), agentKey, rules)
	rt.rebuild = rebuildState{after: time.Second, backoffMax: 2 * time.Second}

	// 1. 最初のハンドシェイクを待ってから、次の作成だけを失敗させる
	waitHandshake(t, rt, 20*time.Second)
	failNextTunnel(t)

	// 2. 閾値を過ぎると作り直しが起き、作成に失敗してトンネルの無い状態になる
	deadline := time.Now().Add(rt.rebuild.after + 5*time.Second)
	for rt.tun != nil && time.Now().Before(deadline) {
		rt.checkTunnel(time.Now())
		time.Sleep(10 * time.Millisecond)
	}
	if rt.tun != nil {
		t.Fatal("the failing build did not leave the agent without a tunnel")
	}
	if rt.rebuild.retryAt.IsZero() {
		t.Fatal("no retry was scheduled after the rebuild failed to build")
	}
	// 全体状態は受け取り済みなので、ハートビートは「受け取っていない」とは言わない。理由の文面は
	// 作り直しの失敗と適用の中の失敗で共通である(仕様 7 節)
	if got, want := rt.heartbeat().Tunnel.Reason, "no tunnel; building it failed and will be retried"; got != want {
		t.Fatalf("heartbeat reason while a retry is pending = %q, want %q", got, want)
	}

	// 3. 次の判定で作成を試し直し、今度は成功してリスナーも開き直る
	rt.checkTunnel(time.Now())
	if rt.tun == nil {
		t.Fatal("the retry did not build a tunnel")
	}
	if n := len(rt.rl.Status()); n != 1 {
		t.Fatalf("listeners after the retry = %d, want 1", n)
	}
	for _, s := range rt.rl.Status() {
		if s.Err != nil {
			t.Fatalf("listener %v after the retry: %v", s.Key, s.Err)
		}
	}

	// 4. 立て直したトンネルがハンドシェイクを済ませると、間隔も再試行の予定も初期の状態に戻る
	waitHandshake(t, rt, 20*time.Second)
	rt.checkTunnel(time.Now())
	if rt.rebuild.wait != rt.rebuild.after {
		t.Errorf("wait = %s after the handshake came back, want %s", rt.rebuild.wait, rt.rebuild.after)
	}
	if !rt.rebuild.retryAt.IsZero() {
		t.Errorf("retryAt = %v after a successful build, want none", rt.rebuild.retryAt)
	}

	rt.close()
	srv.Close()
	assertGoroutinesSettle(t, baseline)
}

// 意図して閉じたトンネルを watchdog が立て直さないことを確かめる(仕様 7 節)。rotate-key と停止は
// closeLocked でトンネルを閉じ、その後は別の経路が立て直す。作り直しの失敗で残った再試行の予定も、
// closeLocked が消す。
func TestCheckTunnelDoesNotResurrectAClosedTunnel(t *testing.T) {
	srvKey := newKey(t)

	// 1. 停止や rotate-key と同じく閉じた後は、何度判定しても立て直さない
	rt := newRebuildTestRuntime(t, closedUDPPort(t), srvKey.PublicKey(), newKey(t), nil)
	rt.rebuild = rebuildState{after: 50 * time.Millisecond, backoffMax: 100 * time.Millisecond}
	rt.close()
	for i := 0; i < 5; i++ {
		rt.checkTunnel(time.Now())
		if rt.tun != nil {
			t.Fatal("the watchdog rebuilt a tunnel that was closed on purpose")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 2. 作り直しが作成に失敗して再試行を待っている状態でも、閉じれば予定は消え、立て直さない
	rt2 := newRebuildTestRuntime(t, closedUDPPort(t), srvKey.PublicKey(), newKey(t), nil)
	rt2.rebuild = rebuildState{after: 50 * time.Millisecond, backoffMax: 100 * time.Millisecond}
	failNextTunnel(t)
	deadline := time.Now().Add(5 * time.Second)
	for rt2.tun != nil && time.Now().Before(deadline) {
		rt2.checkTunnel(time.Now())
		time.Sleep(10 * time.Millisecond)
	}
	if rt2.tun != nil || rt2.rebuild.retryAt.IsZero() {
		t.Fatalf("expected a failed build waiting for a retry: tun=%v retryAt=%v", rt2.tun != nil, rt2.rebuild.retryAt)
	}
	rt2.mu.Lock()
	rt2.closeLocked() // rotate-key が全体状態を適用し直す前に行うのと同じ手順
	rt2.mu.Unlock()
	if !rt2.rebuild.retryAt.IsZero() {
		t.Error("closing the tunnel left the watchdog's retry scheduled")
	}
	for i := 0; i < 5; i++ {
		rt2.checkTunnel(time.Now())
		if rt2.tun != nil {
			t.Fatal("the watchdog rebuilt a tunnel after it was closed while a retry was pending")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// failNextTunnel は、次の 1 回の tunnel.New だけを失敗させる。エージェントから見た作成の失敗
// (bind や資源の失敗)を、実際の故障なしに起こすための差し替え口。
func failNextTunnel(t *testing.T) {
	t.Helper()
	real := newTunnel
	var failed atomic.Bool
	newTunnel = func(cfg tunnel.Config) (*tunnel.Tunnel, error) {
		if failed.CompareAndSwap(false, true) {
			return nil, errors.New("simulated failure to create the tunnel")
		}
		return real(cfg)
	}
	t.Cleanup(func() { newTunnel = real })
}

// newRebuildTestRuntime は、endpoint へ向くトンネルと中継を立てた runtime を返す。
// Run と同じ手順(認証情報を読んで最後の全体状態を適用する)を、登録と stream なしで行う。
func newRebuildTestRuntime(t *testing.T, endpoint string, serverPub, priv wgtypes.Key, rules []proto.AgentRule) *runtime {
	t.Helper()
	st := &proto.State{
		Generation: 1,
		WG: proto.WGConfig{
			ServerPubkey: serverPub.String(), Endpoint: endpoint,
			Address: "10.200.0.2/24", MTU: 1420, Keepalive: 1, UDPTimeoutStream: 120,
		},
		Rules: rules,
	}
	rt := &runtime{
		opts: Options{CredentialsPath: filepath.Join(t.TempDir(), "agent.json")},
		f:    &credentials.Credentials{},
		priv: priv,
	}
	if err := rt.apply(st); err != nil {
		t.Fatalf("apply the state: %v", err)
	}
	t.Cleanup(rt.close)
	return rt
}

// waitRebuild は、checkTunnel がトンネルを prev 以外に置き換えるまで呼び続け、置き換わった時刻を返す。
func waitRebuild(t *testing.T, rt *runtime, prev *tunnel.Tunnel, budget time.Duration) time.Time {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		rt.checkTunnel(time.Now())
		if rt.tun != prev {
			return time.Now()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the tunnel was not rebuilt within %s", budget)
	return time.Time{}
}

// waitHandshake は、今のトンネルのハンドシェイクが成立するまで待つ。
func waitHandshake(t *testing.T, rt *runtime, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if !rt.tun.Status().LastHandshake.IsZero() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no handshake within %s", budget)
}

// newServerTunnel は VPS 側のトンネルを立てる。port が 0 なら空いているものを走査で選ぶ
// (bind の成功そのものが空きの証拠になる。utun/utun_test.go と同じ考え方)。
func newServerTunnel(t *testing.T, priv wgtypes.Key, port uint16) (*utun.Tunnel, uint16) {
	t.Helper()
	quiet := func(string, ...any) {}
	addr := netip.MustParseAddr("10.200.0.1")
	if port != 0 {
		s, err := utun.New(utun.Config{PrivateKey: priv, ListenPort: port, Address: addr, MTU: 1420, Logf: quiet})
		if err != nil {
			t.Fatalf("server tunnel on port %d: %v", port, err)
		}
		t.Cleanup(s.Close)
		return s, port
	}
	for p := uint16(51850); p < 51900; p++ {
		s, err := utun.New(utun.Config{PrivateKey: priv, ListenPort: p, Address: addr, MTU: 1420, Logf: quiet})
		if err == nil {
			t.Cleanup(s.Close)
			return s, p
		}
	}
	t.Fatal("no free wg listen port on 127.0.0.1 after 50 attempts")
	return nil, 0
}

// newKey は wg の秘密鍵を 1 つ作る。
func newKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// closedUDPPort は、誰も待ち受けていない 127.0.0.1 のポートを返す。
func closedUDPPort(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := c.LocalAddr().String()
	c.Close()
	return addr
}

// startUDPEcho は中継の宛先(実機の LAN の機器の代わり)を 127.0.0.1 に立てる。
func startUDPEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pc.WriteToUDP(buf[:n], from)
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().String()
}

// assertGoroutinesSettle は、閉じた後に goroutine の数が基準値まで戻ることを確かめる
// (作り直しのたびに古い device と netstack が片付いていることの裏付け)。後片付けは非同期なので、
// 収束を待ってから比べる。
func assertGoroutinesSettle(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		n := goruntime.NumGoroutine()
		if n <= baseline+2 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("goroutines did not settle after close: now %d, baseline %d", n, baseline)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestCheckTunnelBacksOffWhileTheBuildKeepsFailing は、トンネルの作成が失敗し続ける間、再試行の
// 間隔が広がることを確かめる。startTunnelLocked が最初に呼ぶ closeLocked は再試行の予定を消すので、
// 失敗のたびに予定が初期値へ戻ると、30 秒の判定ごとに作成を試し続けてしまう。
func TestCheckTunnelBacksOffWhileTheBuildKeepsFailing(t *testing.T) {
	srvKey := newKey(t)
	rt := newRebuildTestRuntime(t, closedUDPPort(t), srvKey.PublicKey(), newKey(t), nil)
	defer rt.close()
	rt.rebuild = rebuildState{after: 300 * time.Second, backoffMax: 900 * time.Second}

	real := newTunnel
	var builds int
	newTunnel = func(tunnel.Config) (*tunnel.Tunnel, error) {
		builds++
		return nil, errors.New("simulated failure to create the tunnel")
	}
	t.Cleanup(func() { newTunnel = real })

	// 閾値を過ぎた判定で作り直しが起き、作成に失敗する
	now := rt.tunStart.Add(301 * time.Second)
	rt.checkTunnel(now)
	if rt.tun != nil || builds != 1 {
		t.Fatalf("after the failed rebuild: tun=%v builds=%d, want no tunnel and 1 build", rt.tun != nil, builds)
	}
	// 1 回目の再試行は次の判定。以後は 300、600、900、900 秒の間隔を空ける
	for i, gap := range []time.Duration{30 * time.Second, 300 * time.Second, 600 * time.Second, 900 * time.Second, 900 * time.Second} {
		if gap > 30*time.Second {
			rt.checkTunnel(now.Add(gap - time.Second))
			if builds != i+1 {
				t.Fatalf("retry %d came before %s had passed since the previous failure", i+1, gap)
			}
		}
		now = now.Add(gap)
		rt.checkTunnel(now)
		if builds != i+2 {
			t.Fatalf("retry %d did not run %s after the previous failure (builds=%d)", i+1, gap, builds)
		}
	}
}
