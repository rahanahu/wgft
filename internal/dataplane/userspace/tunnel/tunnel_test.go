package tunnel

import (
	"fmt"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/utun"
)

// permanentReceiveError は、回復不能と判定される受信の誤り。net.Error を満たし、Temporary() が
// 偽なので、wireguard-go の device.RoutineReceiveIncoming(device/receive.go)は受信の goroutine を
// そのまま終える。実機の Windows で WSAECONNRESET が起こした停止(GitHub issue #108、設計文書 7 節)と
// 同じ形を、実際のネットワークの故障なしに作る。
type permanentReceiveError struct{}

func (permanentReceiveError) Error() string   { return "simulated permanent receive error" }
func (permanentReceiveError) Timeout() bool   { return false }
func (permanentReceiveError) Temporary() bool { return false }

// deadReceiveBind は conn.Bind を包み、kill を呼んだ後の受信で permanentReceiveError を返す。
// 送信はそのまま通すので、送れるが受けられないトンネルになる。
type deadReceiveBind struct {
	conn.Bind
	dead atomic.Bool
}

func (b *deadReceiveBind) kill() { b.dead.Store(true) }

func (b *deadReceiveBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			if b.dead.Load() {
				return 0, permanentReceiveError{}
			}
			return fn(bufs, sizes, eps)
		}
	}
	return wrapped, actual, nil
}

// 受信の goroutine が回復不能な誤りで終わったトンネルは、エンドポイントを引き直しても ping を
// 送り続けても戻らず、同じ設定で立て直したときだけ戻ることを確かめる(設計文書 7 節の 2 段の回復)。
// エージェントの本体(internal/agent)がこの立て直しを行う判定は internal/agent の試験で確かめる。
func TestDeadReceivePathNeedsANewTunnel(t *testing.T) {
	srvKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	agentKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	agentAddr := netip.MustParseAddr("10.200.0.2")
	serverAddr := netip.MustParseAddr("10.200.0.1")

	// 常駐するサーバ側を先に立ててから goroutine の基準値を取る。以後増えた分がトンネルのものになる
	srv, port := newServerTunnel(t, srvKey, serverAddr)
	if _, err := srv.SetPeers([]dataplane.Peer{{PublicKey: agentKey.PublicKey(), Address: agentAddr}}); err != nil {
		t.Fatalf("declare the agent peer: %v", err)
	}
	baseline := runtime.NumGoroutine()

	// 1. 受信を止められるバインドでトンネルを立て、疎通(ping の往復)を確かめる
	var killable *deadReceiveBind
	realBind := bindForDevice
	bindForDevice = func() conn.Bind {
		b := &deadReceiveBind{Bind: realBind()}
		killable = b
		return b
	}
	t.Cleanup(func() { bindForDevice = realBind })

	cfg := Config{
		PrivateKey: agentKey, ServerPublicKey: srvKey.PublicKey(),
		Endpoint:      fmt.Sprintf("127.0.0.1:%d", port),
		Address:       agentAddr,
		ServerAddress: serverAddr,
		MTU:           1420,
		Keepalive:     time.Second,
		Logf:          func(string, ...any) {},
	}
	tun, err := New(cfg)
	if err != nil {
		t.Fatalf("agent tunnel: %v", err)
	}
	if killable == nil {
		t.Fatal("the test bind was not used by New")
	}
	waitPing(t, tun, true, 20*time.Second, "before the receive path died")

	// 2. 受信を止める。送信は続くので、サーバ側は応答を返し続ける
	killable.kill()
	waitPing(t, tun, false, 10*time.Second, "after the receive path died")

	// 3. 軽い回復(エンドポイントの引き直しと ping)を繰り返しても戻らないことを、区間を取って確かめる
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := tun.ReResolve(); err != nil {
			t.Fatalf("re-resolve: %v", err)
		}
		if _, err := tun.Ping(300 * time.Millisecond); err == nil {
			t.Fatal("ping succeeded again although the receive routine had ended; the simulation is not faithful")
		}
	}

	// 4. 同じ鍵とエンドポイントで立て直すと戻る。古いトンネルは先に閉じる(agent の startTunnelLocked と同じ順序)
	tun.Close()
	bindForDevice = realBind
	tun2, err := New(cfg)
	if err != nil {
		t.Fatalf("rebuild the agent tunnel: %v", err)
	}
	waitPing(t, tun2, true, 20*time.Second, "after the tunnel was rebuilt")

	tun2.Close()
	srv.Close()
	assertGoroutinesSettle(t, baseline)
}

// waitPing は、トンネル内の ping が通る(want が真)か通らない(偽)状態になるまで待つ。
// 上限を超えたら失敗させる。否定の主張には区間そのものが要るので、呼び出し側が別に区間を取る。
func waitPing(t *testing.T, tun *Tunnel, want bool, budget time.Duration, when string) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		_, err := tun.Ping(500 * time.Millisecond)
		if (err == nil) == want {
			return
		}
	}
	st := tun.Status()
	t.Fatalf("ping reachable = %v %s within %s (last handshake %v, rx %d, tx %d, err %v)",
		!want, when, budget, st.LastHandshake, st.RxBytes, st.TxBytes, st.Err)
}

// newServerTunnel は VPS 側のトンネルを空いている listen_port で立てる。ポートは走査で選ぶ
// (bind の成功そのものが空きの証拠になる。utun/utun_test.go と同じ考え方)。
func newServerTunnel(t *testing.T, priv wgtypes.Key, addr netip.Addr) (*utun.Tunnel, uint16) {
	t.Helper()
	for p := uint16(51950); p < 52000; p++ {
		s, err := utun.New(utun.Config{PrivateKey: priv, ListenPort: p, Address: addr, MTU: 1420, Logf: func(string, ...any) {}})
		if err == nil {
			t.Cleanup(s.Close)
			return s, p
		}
	}
	t.Fatal("no free wg listen port on 127.0.0.1 after 50 attempts")
	return nil, 0
}

// assertGoroutinesSettle は、閉じた後に goroutine の数が基準値まで戻ることを確かめる
// (-count を重ねても漏れないため)。後片付けは非同期なので、収束を待ってから比べる。
func assertGoroutinesSettle(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := runtime.NumGoroutine()
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
