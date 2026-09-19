package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/rahanahu/wgft/proto"
)

// errUnauthorized は stream の認証が拒否された(恒久トークンが無効)。復帰は WGFT_JOIN による再登録(仕様 5.1 節)。
var errUnauthorized = errors.New("stream authentication rejected: the permanent token may have been revoked")

// streamLoop は stream に繋ぎ続ける。切れたら指数バックオフ(1 秒-5 分)で繋ぎ直す(仕様 5.2 節)。
// 認証拒否で復帰できないときだけ、誤りを返して終わる。
func (rt *runtime) streamLoop(ctx context.Context) error {
	backoff := time.Second
	for {
		started := time.Now()
		connCtx, cancel := context.WithCancel(ctx)
		rt.streamMu.Lock()
		rt.streamCancel, rt.reconnectNow = cancel, false
		rt.streamMu.Unlock()
		err := rt.streamOnce(connCtx)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		rt.streamMu.Lock()
		now := rt.reconnectNow
		rt.streamMu.Unlock()
		if now {
			log.Printf("stream: reconnecting")
			backoff = time.Second
			continue
		}
		// 1 分以上つながっていたなら、次の失敗はバックオフを最初から
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		switch {
		case errors.Is(err, errUnauthorized):
			// 一時的な失敗(5xx、接続不能)とは区別し、認証拒否だけが復帰経路に入る
			if rerr := rt.recover(); rerr != nil {
				return rerr
			}
			backoff = time.Second
			continue
		case errors.Is(err, ErrPinMismatch):
			// 証明書が変わった。未使用でピンの違う WGFT_JOIN があれば再登録し、なければ再接続を続ける
			if j := rt.joinForNewPin(); j != nil {
				if rerr := rt.recover(); rerr != nil {
					log.Printf("stream: %v; re-registration with the provided join string failed: %v; retrying in %s", err, rerr, backoff)
					break
				}
				backoff = time.Second
				continue
			}
			log.Printf("stream: %v; if the server was rebuilt (teardown --purge), issue a new join string and restart with it in WGFT_JOIN; retrying in %s", err, backoff)
		case websocket.CloseStatus(err) == websocket.StatusCode(proto.CloseSuperseded):
			log.Printf("stream: superseded by another connection for the same agent: double start or copied credentials (agent.json); reconnecting in %s", backoff)
		case websocket.CloseStatus(err) == websocket.StatusCode(proto.CloseRevoked):
			log.Printf("stream: permanent token was revoked; retrying in %s", backoff)
		default:
			log.Printf("stream: disconnected: %v; reconnecting in %s", err, backoff)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 5*time.Minute {
			backoff = 5 * time.Minute
		}
	}
}

// streamOnce は 1 本の接続の寿命。認証 → 公開鍵の送信 → 全体状態の受信とハートビートの送信。
func (rt *runtime) streamOnce(ctx context.Context) error {
	f := rt.f
	pinBytes, err := hex.DecodeString(f.CertSHA256)
	if err != nil || len(pinBytes) != 32 {
		return fmt.Errorf("credentials file: cert_sha256 is invalid")
	}
	var pin [32]byte
	copy(pin[:], pinBytes)
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	ws, resp, err := websocket.Dial(dialCtx, "wss://"+f.Endpoint+"/api/v1/agents/stream", &websocket.DialOptions{
		HTTPClient: PinnedClient(pin),
		HTTPHeader: http.Header{"Authorization": {"Bearer " + f.PermanentToken}},
	})
	cancel()
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return errUnauthorized
		}
		return err
	}
	defer ws.CloseNow()
	ws.SetReadLimit(4 << 20)

	if err := writeJSON(ctx, ws, proto.Message{Type: proto.MsgPublicKey, PublicKey: rt.priv.PublicKey().String()}); err != nil {
		return err
	}
	log.Printf("stream: connected to %s; public key sent", f.Endpoint)

	// ハートビート。30 秒ごとに送るのに加え、stream の接続直後に全体状態を適用した直後と、
	// 以後の世代を適用するたびにも送る(仕様 5.2 節)。applyNotify はサイズ 1 の非ブロッキング通知で、
	// 適用が連続してもハートビートの送信は高々 1 回にまとめる。この goroutine が ws への唯一の書き手であり
	// (読み側の for ループは公開鍵の送信より後は読むだけ)、書き込みが競合することはない。
	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	applyNotify := make(chan struct{}, 1)
	go func() {
		t := time.NewTicker(rt.heartbeatInterval)
		defer t.Stop()
		send := func() (proto.Heartbeat, bool) {
			hb := rt.heartbeat()
			return hb, writeJSON(hbCtx, ws, proto.Message{Type: proto.MsgHeartbeat, Heartbeat: &hb}) == nil
		}
		runHeartbeats(hbCtx.Done(), t.C, applyNotify, rt.handshakeRetryInterval, rt.handshakeRetryTimeout, send)
	}()

	// 世代の比較は同一接続内に限る。最初の全体状態は世代に関わらず必ず適用する
	first := true
	for {
		_, b, err := ws.Read(ctx)
		if err != nil {
			return err
		}
		var m proto.Message
		if err := json.Unmarshal(b, &m); err != nil {
			log.Printf("stream: invalid message: %v", err)
			continue
		}
		if m.Type != proto.MsgState || m.State == nil {
			continue
		}
		if !first && m.State.Generation < rt.generation() {
			log.Printf("stream: generation %d is older than local %d; dropping", m.State.Generation, rt.generation())
			continue
		}
		first = false
		if err := rt.apply(m.State); err != nil {
			log.Printf("stream: applying generation %d: %v", m.State.Generation, err)
		}
		notifyNonBlocking(applyNotify)
	}
}

// notifyNonBlocking はサイズ 1 のチャネルへ待たずに知らせる。既に 1 件溜まっていれば何もしない
// (直近の 1 回分だけを送るコアレシング。仕様 5.2 節のハートビートの節を参照)。
func notifyNonBlocking(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// runHeartbeats はハートビートの送信を担う。tick は 30 秒ごとの通常間隔、notify は全体状態の適用直後の
// 通知(サイズ 1 の非ブロッキングチャネル)。send は 1 回分の送信を行い、送った内容と成功可否を返す。
// 呼び出し元がこれを唯一の goroutine から呼ぶことで、ws への書き込みを直列に保つ。
//
// 適用直後の送信(仕様 5.2 節)は、トンネルを張り直した直後で WireGuard のハンドシェイクがまだ済んで
// いない場合、"handshake not established" の誤りをそのまま報告してしまう。stream は公開の HTTPS を
// 通り、wg のトンネルを経由しないため、apply はハンドシェイクの完了を待たずに戻るからである。
// これを避けるため、適用直後の送信がこの状態を報告した場合に限り、済むまで retryInterval ごとに
// 最長 retryTimeout まで送り直す(retryInterval が 0 以下なら追送りしない)。定期の 30 秒ごとの送信では
// 追送りしない。トンネルの本当の誤り(ハンドシェイク待ち以外)は 1 回報告するだけで、そのつど 10 回近い
// 追送りを起こさない。
func runHeartbeats(done <-chan struct{}, tick <-chan time.Time, notify <-chan struct{}, retryInterval, retryTimeout time.Duration, send func() (proto.Heartbeat, bool)) {
	followUpUntilHandshake := func() bool {
		if retryInterval <= 0 {
			return true
		}
		deadline := time.Now().Add(retryTimeout)
		retry := time.NewTicker(retryInterval)
		defer retry.Stop()
		for {
			select {
			case <-done:
				return false
			case <-retry.C:
				hb, ok := send()
				if !ok {
					return false
				}
				if !needsHandshakeFollowUp(hb.Tunnel) || !time.Now().Before(deadline) {
					return true
				}
			}
		}
	}
	for {
		select {
		case <-done:
			return
		case <-tick:
			if _, ok := send(); !ok {
				return
			}
		case <-notify:
			hb, ok := send()
			if !ok {
				return
			}
			if needsHandshakeFollowUp(hb.Tunnel) && !followUpUntilHandshake() {
				return
			}
		}
	}
}

// needsHandshakeFollowUp は、ハートビートのトンネル状態がハンドシェイク待ちによる誤りかどうかを見る
// (仕様 5.2 節)。トンネルが無い、bind に失敗した、といった本当の誤りとは区別する。
func needsHandshakeFollowUp(t proto.TunnelStatus) bool {
	return t.State == proto.StatusError && t.Reason == reasonHandshakePending
}

func writeJSON(ctx context.Context, ws *websocket.Conn, m proto.Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return ws.Write(wctx, websocket.MessageText, b)
}
