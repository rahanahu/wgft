package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/proto"
)

// 仕様 5.2 節の「接続の生死の判定」と「再接続の間隔」の試験。どれも実時間の sleep を同期の手段に
// せず、間隔は runtime の非公開のフィールドで短くする。

// newAliveTestRuntime は stream の試験用の runtime を 1 つ作る。ハートビートのティッカーは事実上
// 無効にし、ping と再接続の間隔だけを短くする。
func newAliveTestRuntime(t *testing.T, endpoint string, pin [32]byte) *runtime {
	t.Helper()
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &runtime{
		dp: newTestUserspace(),
		f: &credentials.Credentials{
			Endpoint:       endpoint,
			CertSHA256:     hex.EncodeToString(pin[:]),
			PermanentToken: "tok",
		},
		priv:                priv,
		heartbeatInterval:   time.Hour,
		pingInterval:        50 * time.Millisecond,
		pongTimeout:         200 * time.Millisecond,
		reconnectBackoffMin: 20 * time.Millisecond,
		reconnectBackoffMax: 20 * time.Millisecond,
		handshakeWake:       make(chan struct{}, 1),
	}
}

// newSilentStreamServer は、認証と公開鍵の受信までは普通に応じ、その後は相手に応じなくなる server を
// 立てる。reading が false なら読みを止めるので、ライブラリが ping に pong を返さなくなり、相手からは
// 半開きの TCP と区別が付かない。reading が true なら読み続けるだけで、こちらからは何も送らない
// (待機中の stream に何も送らない、旧い版の server と同じ振る舞い)。
// 返すチャネルは、接続が確立するたびに 1 件流れる。
func newSilentStreamServer(t *testing.T, reading bool) (endpoint string, pin [32]byte, conns chan struct{}) {
	t.Helper()
	conns = make(chan struct{}, 64)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/stream", func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		ctx := r.Context()
		var first proto.Message
		if _, b, err := ws.Read(ctx); err != nil || json.Unmarshal(b, &first) != nil {
			return
		}
		select {
		case conns <- struct{}{}:
		default:
		}
		if !reading {
			// 読みを止める。ライブラリが ping のフレームを処理しないので pong は返らない
			<-ctx.Done()
			return
		}
		for {
			if _, _, err := ws.Read(ctx); err != nil {
				return
			}
		}
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://"), sha256.Sum256(srv.Certificate().Raw), conns
}

// newRefusingStreamServer は stream の要求をいつも 503 で断る server を立てる。試みの時刻を記録する。
func newRefusingStreamServer(t *testing.T) (endpoint string, pin [32]byte, attempts chan time.Time) {
	t.Helper()
	attempts = make(chan time.Time, 256)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/stream", func(w http.ResponseWriter, r *http.Request) {
		select {
		case attempts <- time.Now():
		default:
		}
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://"), sha256.Sum256(srv.Certificate().Raw), attempts
}

// runStreamLoop は streamLoop を goroutine で動かし、後片付けを登録する。
func runStreamLoop(t *testing.T, rt *runtime) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.streamLoop(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("streamLoop did not return within 10s of the cancel")
		}
	})
}

// (i) バックオフが上限に達していても、WireGuard の新しいハンドシェイクの観測が残りの待ちを打ち切る
// (仕様 5.2 節)。上限に達した状態を作るために、初期値と上限の両方を同じ長い値にしてある。
// 打ち切りが無ければ、2 回目の試みはこの長い値を待つ。
func TestReconnectBackoffAtTheCapIsCutShortByANewHandshake(t *testing.T) {
	const capped = 5 * time.Second
	endpoint, pin, attempts := newRefusingStreamServer(t)
	rt := newAliveTestRuntime(t, endpoint, pin)
	rt.reconnectBackoffMin, rt.reconnectBackoffMax = capped, capped

	runStreamLoop(t, rt)

	var first time.Time
	select {
	case first = <-attempts:
	case <-time.After(5 * time.Second):
		t.Fatal("no first connection attempt within 5s")
	}
	// 通知を捨てるのは接続の試みが戻った後なので、1 回目の試みを見た時点ではまだ捨てられる側に
	// いるかもしれない。待ちに入るのを実時間の sleep で待つ代わりに、2 回目の試みが来るまで
	// 通知を入れ続ける。チャネルは大きさ 1 で送信は非ブロッキングなので、入れ過ぎても害は無い
	deadline := time.After(capped - time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		notifyNonBlocking(rt.handshakeWake)
		select {
		case second := <-attempts:
			if d := second.Sub(first); d > capped/2 {
				t.Errorf("the second attempt came %s after the first; the handshake must cut the %s wait short", d, capped)
			}
			return
		case <-tick.C:
		case <-deadline:
			t.Fatalf("no second attempt within %s; the %s backoff was not cut short by a new handshake", capped-time.Second, capped)
		}
	}
}

// (i-b) 接続していた間に観測したハンドシェイクは、その接続が切れた後の待ちを打ち切らない
// (仕様 5.2 節)。打ち切る根拠になるのは、失敗した後に観測したハンドシェイクだけである。
// server は接続を受けてから閉じるので、通知は接続の最中に入る。
func TestHandshakeSeenWhileConnectedDoesNotCutTheNextBackoff(t *testing.T) {
	const capped = 3 * time.Second
	closeNow := make(chan struct{})
	connected := make(chan struct{}, 8)
	attempts := make(chan time.Time, 64)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/stream", func(w http.ResponseWriter, r *http.Request) {
		select {
		case attempts <- time.Now():
		default:
		}
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		var first proto.Message
		if _, b, err := ws.Read(r.Context()); err != nil || json.Unmarshal(b, &first) != nil {
			return
		}
		select {
		case connected <- struct{}{}:
		default:
		}
		select {
		case <-closeNow:
		case <-r.Context().Done():
		}
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	endpoint, pin := strings.TrimPrefix(srv.URL, "https://"), sha256.Sum256(srv.Certificate().Raw)

	rt := newAliveTestRuntime(t, endpoint, pin)
	rt.reconnectBackoffMin, rt.reconnectBackoffMax = capped, capped
	runStreamLoop(t, rt)

	var first time.Time
	select {
	case first = <-attempts:
	case <-time.After(5 * time.Second):
		t.Fatal("no first connection attempt within 5s")
	}
	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not see the pubkey within 5s")
	}
	// 接続の最中に観測したことにする
	notifyNonBlocking(rt.handshakeWake)
	close(closeNow)

	select {
	case second := <-attempts:
		if d := second.Sub(first); d < capped/2 {
			t.Errorf("the second attempt came %s after the first; a handshake seen while connected must not cut the %s wait short", d, capped)
		}
	case <-time.After(capped + 2*time.Second):
		t.Fatalf("no second attempt within %s", capped+2*time.Second)
	}
}

// (ii) 相手が閉じないまま応じなくなった stream は、ping の pong の期限で検出し、繋ぎ直す
// (仕様 5.2 節)。この server は accept と upgrade までは応じ、その後は読みを止めるので pong も
// 返らない。ping が無ければ、30 秒のハートビートの書き込みが OS の再送の打ち切りまで成功し続ける
// ため、agent は接続が死んだことに気付かない。
func TestSilentPeerIsDetectedByThePingDeadlineAndReconnected(t *testing.T) {
	endpoint, pin, conns := newSilentStreamServer(t, false)
	rt := newAliveTestRuntime(t, endpoint, pin)

	runStreamLoop(t, rt)

	// 判定に要する時間の上限は pingInterval + pongTimeout である。2 本目の接続がその上限の
	// 何倍かの間に現れることを確かめる(実時間の sleep を同期の手段にしない)
	bound := rt.pingInterval + rt.pongTimeout
	for i := 0; i < 2; i++ {
		select {
		case <-conns:
		case <-time.After(20 * bound):
			t.Fatalf("only %d connection(s) within %s; a peer that stops answering must be detected within %s",
				i, 20*bound, bound)
		}
	}
}

// (iii) 待機中の stream に何も送らないが ping には応じる server は、死んだ相手として扱わない
// (仕様 5.2 節)。旧い版の server との互換の試験である。ライブラリは読みを続けている接続で ping に
// 自動で pong を返すので、JSON のメッセージを 1 つも送らない server でも接続は保たれる。
func TestSilentButPingAnsweringServerIsNotTreatedAsDead(t *testing.T) {
	endpoint, pin, conns := newSilentStreamServer(t, true)
	rt := newAliveTestRuntime(t, endpoint, pin)

	runStreamLoop(t, rt)

	select {
	case <-conns:
	case <-time.After(5 * time.Second):
		t.Fatal("no connection within 5s")
	}
	// ping を 20 回以上送る間、接続は 1 本のままである
	select {
	case <-conns:
		t.Errorf("the connection was replaced although every ping was answered")
	case <-time.After(20 * rt.pingInterval):
	}
}

// (iv) API が落ちたままのとき、再接続が密にならない(仕様 5.2 節)。打ち切りの経路が
// ハンドシェイクの観測 1 回につき 1 回の試みしか生まないことは、次の 2 つで確かめる。
// 1 つ目は、通知が無ければ試みの間隔が初期値を下回らないこと。2 つ目は、同じ値の
// ハンドシェイクを何度観測しても通知が生まれないことである(後者は checkTunnel の試験)。
func TestReconnectDoesNotStormWhileTheAPIStaysDown(t *testing.T) {
	const backoffMin = 500 * time.Millisecond
	endpoint, pin, attempts := newRefusingStreamServer(t)
	rt := newAliveTestRuntime(t, endpoint, pin)
	rt.reconnectBackoffMin, rt.reconnectBackoffMax = backoffMin, 2*backoffMin

	runStreamLoop(t, rt)

	var prev time.Time
	for i := 0; i < 3; i++ {
		select {
		case at := <-attempts:
			if !prev.IsZero() {
				if d := at.Sub(prev); d < backoffMin*8/10 {
					t.Errorf("attempt %d came %s after the previous one, below the %s backoff", i, d, backoffMin)
				}
			}
			prev = at
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d attempts within 10s", i)
		}
	}
}

// (iv, 続き) 同じ最終ハンドシェイクの値を何度観測しても、待ちの打ち切りは 1 回しか起きない。
// トンネルとサーバ側のトンネルは実物を立て、checkTunnel が読む値も実物である。
func TestCheckTunnelWakesTheStreamOncePerHandshake(t *testing.T) {
	srvKey := newKey(t)
	srv, port := newServerTunnel(t, srvKey, 0)
	agentKey := newKey(t)
	if _, err := srv.SetPeers([]dataplane.Peer{{PublicKey: agentKey.PublicKey(), Address: netip.MustParseAddr("10.200.0.2")}}); err != nil {
		t.Fatalf("declare the agent peer: %v", err)
	}
	rt := newRebuildTestRuntime(t, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String(), srvKey.PublicKey(), agentKey, nil)
	rt.handshakeWake = make(chan struct{}, 1)
	rt.rebuild = rebuildState{after: time.Hour, backoffMax: time.Hour}

	waitHandshake(t, rt, 20*time.Second)
	rt.checkTunnel(time.Now())
	select {
	case <-rt.handshakeWake:
	default:
		t.Fatal("no wake after the first handshake was observed; a recovered data path must cut the reconnect wait short")
	}
	// 値が変わらない限り、何度観測しても通知は生まれない
	for i := 0; i < 5; i++ {
		rt.checkTunnel(time.Now())
	}
	select {
	case <-rt.handshakeWake:
		t.Error("an unchanged handshake produced another wake; the retry rate must follow the handshake rate")
	default:
	}
}

// 全体状態の適用の間は判定しない(仕様 5.2 節)。適用は TCP の宛先への試し接続を含み、宛先 1 つに
// つき最長 10 秒かかるので、読みが pong の期限より長く止まりうる。判定してしまうと、適用が長い
// だけの健全な接続を切って繋ぎ直す繰り返しになる。相手は pong を返さない server なので、
// applySeq の守りが無ければ必ず切られる。
func TestPingIsNotJudgedWhileAFullStateIsApplied(t *testing.T) {
	// 適用の最中(applySeq が奇数)は ping そのものを送らない。rl.Apply は届かない TCP の宛先 1 つに
	// つき 10 秒を使うので、適用は ping の周期を何度も跨ぎうる。適用が終われば判定は戻る
	t.Run("a long apply outlasts several ping periods", func(t *testing.T) {
		endpoint, pin, conns := newSilentStreamServer(t, false)
		rt := newAliveTestRuntime(t, endpoint, pin)
		rt.applySeq.Store(1)
		assertConnectionIsKept(t, rt, conns)
		// 適用が終われば、応じない相手はこれまでどおり判定して切る
		rt.applySeq.Add(1)
		select {
		case <-conns:
		case <-time.After(20 * (rt.pingInterval + rt.pongTimeout)):
			t.Error("a silent peer must be detected again once the apply has finished")
		}
	})
	// ping を送ってから pong を待つ区間に適用が入って出た場合も判定しない。適用の出入りを
	// 繰り返すことで、どの ping もこの経路に当たるようにする
	t.Run("apply overlaps the pong wait", func(t *testing.T) {
		endpoint, pin, conns := newSilentStreamServer(t, false)
		rt := newAliveTestRuntime(t, endpoint, pin)
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			tick := time.NewTicker(rt.pongTimeout / 10)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
					rt.applySeq.Add(2) // 適用が 1 つ始まって終わったのと同じ変化
				}
			}
		}()
		assertConnectionIsKept(t, rt, conns)
	})
}

// assertConnectionIsKept は、1 本目の接続が確立した後、判定の上限の 10 倍の間に接続が
// 置き換わらないことを確かめる。10 倍は、判定の周期を 2 度以上跨ぐ適用を表す。
func assertConnectionIsKept(t *testing.T, rt *runtime, conns chan struct{}) {
	t.Helper()
	runStreamLoop(t, rt)
	select {
	case <-conns:
	case <-time.After(5 * time.Second):
		t.Fatal("no connection within 5s")
	}
	select {
	case <-conns:
		t.Error("the connection was replaced although a full state was being applied")
	case <-time.After(10 * (rt.pingInterval + rt.pongTimeout)):
	}
}

// pingLoop は pingInterval が 0 以下なら何もしない。streamOnce が常に起こすので、間隔を持たない
// runtime を組む既存の試験が ping を送らないことを確かめる。
func TestPingLoopIsOffWithoutAnInterval(t *testing.T) {
	var closed atomic.Bool
	rt := &runtime{dp: newTestUserspace()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		rt.pingLoop(context.Background(), nil, 0) // ws を触るなら nil で落ちる
		closed.Store(true)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pingLoop did not return although pingInterval is zero")
	}
	if !closed.Load() {
		t.Error("pingLoop returned without running to the end")
	}
}
