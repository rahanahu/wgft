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

	// ハートビート
	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	go func() {
		t := time.NewTicker(rt.heartbeatInterval)
		defer t.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-t.C:
				hb := rt.heartbeat()
				if err := writeJSON(hbCtx, ws, proto.Message{Type: proto.MsgHeartbeat, Heartbeat: &hb}); err != nil {
					return
				}
			}
		}
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
	}
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
