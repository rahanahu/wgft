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

// defaultReconnectBackoffMin と defaultReconnectBackoffMax は stream を繋ぎ直す間隔の既定の
// 初期値と上限(仕様 5.2 節)。
const (
	defaultReconnectBackoffMin = time.Second
	defaultReconnectBackoffMax = 5 * time.Minute
)

// streamLoop は stream に繋ぎ続ける。切れたら指数バックオフ(1 秒-5 分)で繋ぎ直す(仕様 5.2 節)。
// WireGuard の新しいハンドシェイクを観測したときは、残りの待ちを打ち切って直ちに繋ぎ直す。
// 認証拒否で復帰できないときだけ、誤りを返して終わる。
func (rt *runtime) streamLoop(ctx context.Context) error {
	backoffMin, backoffMax := rt.reconnectBackoffMin, rt.reconnectBackoffMax
	if backoffMin <= 0 {
		backoffMin = defaultReconnectBackoffMin
	}
	if backoffMax < backoffMin {
		backoffMax = max(defaultReconnectBackoffMax, backoffMin)
	}
	backoff := backoffMin
	for {
		started := time.Now()
		connCtx, cancel := context.WithCancel(ctx)
		rt.streamMu.Lock()
		rt.streamCancel, rt.reconnectNow = cancel, false
		rt.streamMu.Unlock()
		// 待ちを抜けて接続を試み始めた(設計文書 10.2c 節の観測)。この記録は再接続の流れを変えない
		rt.noteStreamAttempt()
		err := rt.streamOnce(connCtx)
		cancel()
		rt.noteStreamDisconnected(time.Now(), err)
		// 接続していた間に溜まったハンドシェイクの通知は捨てる。待ちを打ち切る根拠にするのは、
		// この接続の試みが失敗した後に観測したハンドシェイクだけだからである(仕様 5.2 節)。
		// 接続中のハンドシェイクは、その接続が切れる前の経路の話でしかない
		select {
		case <-rt.handshakeWake:
		default:
		}
		if ctx.Err() != nil {
			return nil
		}
		rt.streamMu.Lock()
		now := rt.reconnectNow
		rt.streamMu.Unlock()
		if now {
			log.Printf("stream: reconnecting")
			backoff = backoffMin
			continue
		}
		// 1 分以上つながっていたなら、次の失敗はバックオフを最初から
		if time.Since(started) > time.Minute {
			backoff = backoffMin
		}
		switch {
		case errors.Is(err, errUnauthorized):
			// 一時的な失敗(5xx、接続不能)とは区別し、認証拒否だけが復帰経路に入る
			if rerr := rt.recover(); rerr != nil {
				return rerr
			}
			backoff = backoffMin
			continue
		case errors.Is(err, ErrPinMismatch):
			// 証明書が変わった。未使用でピンの違う WGFT_JOIN があれば再登録し、なければ再接続を続ける
			if j := rt.joinForNewPin(); j != nil {
				if rerr := rt.recover(); rerr != nil {
					log.Printf("stream: %v; re-registration with the provided join string failed: %v; retrying in %s", err, rerr, backoff)
					break
				}
				backoff = backoffMin
				continue
			}
			log.Printf("stream: %v; if the server was rebuilt (teardown --purge), issue a new join string and restart with it in WGFT_JOIN; retrying in %s", err, backoff)
		case websocket.CloseStatus(err) == websocket.StatusCode(proto.CloseSuperseded):
			log.Printf("stream: superseded by another connection for the same agent: double start or copied credentials (agent.json); reconnecting in %s", backoff)
		case websocket.CloseStatus(err) == websocket.StatusCode(proto.CloseRevoked):
			log.Printf("stream: permanent token was revoked; retrying in %s", backoff)
		case websocket.CloseStatus(err) == websocket.StatusCode(proto.CloseProtocolMismatch):
			// 版の範囲に共通部分が無い(仕様 7a.6 節)。通常のバックオフで再接続を続ける
			// (どちらかを上げない限り解決しないが、無闇に速く再試行しても意味が無い)
			log.Printf("stream: %v; the agent or server needs an upgrade to share a protocol version; retrying in %s", err, backoff)
		default:
			log.Printf("stream: disconnected: %v; reconnecting in %s", err, backoff)
		}
		// 待ちに入る間隔と次に試す時刻を控える(設計文書 10.2c 節の観測)。待つ値は下の
		// time.After と同じ backoff であり、この記録は待ちの長さを変えない。記録が動くのは
		// ここだけなので、下の倍加も、上の 4 つの continue が初期値に戻す変更も、次にここを
		// 通るまで観測には現れない
		rt.noteStreamWaiting(time.Now(), backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-rt.handshakeWake:
			// WireGuard の新しいハンドシェイクは、vpsd までの経路が戻ったことを示す。残りの
			// 待ちを打ち切り、バックオフも初期値に戻す(仕様 5.2 節)。1 つのトンネルの最終
			// ハンドシェイクは 2 分に 1 回程度しか新しくならないので、API だけが止まっていても
			// この経路の再試行は 2 分に 1 回を超えない
			log.Printf("stream: a new wireguard handshake shows the server is reachable; reconnecting now")
			backoff = backoffMin
			continue
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > backoffMax {
			backoff = backoffMax
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

	// 版と機能の交渉(仕様 7a.6 節)。agent は対応する範囲を毎回そのまま宣言する。今のところ
	// capabilities の語彙は無いので常に空配列を送り、legacy v0(語彙が無いこと自体)とは区別する
	protoMin, protoMax := proto.SupportedProtocol.Min, proto.SupportedProtocol.Max
	caps := proto.SupportedCapabilities
	if err := writeJSON(ctx, ws, proto.Message{
		Type: proto.MsgPublicKey, PublicKey: rt.priv.PublicKey().String(),
		ProtocolMin: &protoMin, ProtocolMax: &protoMax, Capabilities: &caps,
	}); err != nil {
		return err
	}
	log.Printf("stream: connected to %s; public key sent", f.Endpoint)
	// ここから先がつながっている状態である(設計文書 10.2c 節の観測)。epoch は、この接続の
	// pingLoop が書いた値だけを受け取るための通し番号
	epoch := rt.noteStreamConnected()

	// ハートビート。30 秒ごとに送るのに加え、stream の接続直後に全体状態を適用した直後と、
	// 以後の世代を適用するたびにも送る(仕様 5.2 節)。applyNotify はサイズ 1 の非ブロッキング通知で、
	// 適用が連続してもハートビートの送信は高々 1 回にまとめる。JSON のメッセージを ws へ書くのはこの
	// goroutine だけであり(読み側の for ループは公開鍵の送信より後は読むだけ)、書き込みが競合することはない。
	// pingLoop も ws へ書くが、書くのは制御フレームだけで、ライブラリがフレーム単位で直列化する。
	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()

	// 半開きの TCP の判定(仕様 5.2 節)。読みの期限を相手の送信に結び付けられないので、
	// こちらから ping を送り、pong の期限で経路の生死を測る
	go rt.pingLoop(hbCtx, ws, epoch)

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
		if first {
			// 版の交渉の検査とログは、この接続で受け取る最初の全体状態でだけ行う
			// (以後の全体状態も同じ版で来るはずなので、メッセージごとには行わない。仕様 7a.6 節)
			if err := checkServerProtocolVersion(proto.SupportedProtocol, m.State); err != nil {
				return err
			}
			log.Printf("stream: server selected protocol %s", protocolLabelForState(m.State))
		}
		if !first && m.State.Generation < rt.generation() {
			log.Printf("stream: generation %d is older than local %d; dropping", m.State.Generation, rt.generation())
			continue
		}
		first = false
		// 適用の間は読みが止まるので、pingLoop に判定を見送らせる(仕様 5.2 節)。
		// 入るときと出るときに 1 つ進めるので、適用の最中は値が奇数になる
		rt.applySeq.Add(1)
		applyErr := rt.apply(m.State)
		rt.applySeq.Add(1)
		if applyErr != nil {
			log.Printf("stream: applying generation %d: %v", m.State.Generation, applyErr)
		}
		notifyNonBlocking(applyNotify)
	}
}

// pingLoop は、接続中の stream に pingInterval ごとに WebSocket の ping を送り、pongTimeout 以内に
// pong が返らなければ接続を閉じる(仕様 5.2 節)。閉じると読みの for ループが誤りを返し、streamLoop が
// 繋ぎ直す。pingInterval が 0 以下なら ping を送らない(テストの既定)。
//
// stream が生きているとは、TCP が ESTABLISHED であることではなく、相手の応答が限られた時間の
// 内に届くことである。ハートビートは agent の状態を server に報告するもので、経路の生死は測れない。
// 半開きの TCP への書き込みは何分ものあいだ成功し続けるからである。ping と pong は、stream が
// 双方向に通ることだけを測る。2 つは役割が違い、どちらも要る。
//
// 判定を ws の ping に載せるのは、server が待機中の stream へ定期的な送信を行わず、読みの期限を
// 相手の送信に結び付けられないためである。ping は RFC 6455 が pong の返送を求める制御フレームで、
// coder/websocket は読みを続けている接続で自動的に返す(read.go の opPing の分岐)。旧い版の server も
// 同じライブラリを使うので、JSON のメッセージを増やさずに判定できる。server 側の 90 秒の期限は
// 制御フレームでは戻らない(Conn.Read はデータのメッセージでしか戻らないため)ので、この ping が
// 止まったハートビートの代わりになることはない。
//
// この判定が測るのは、経路が通っていることと、こちらの読みの for ループが動いていることの両方で
// ある。ライブラリは ping と pong を読みの中でしか処理せず、Conn.Ping 自身は接続から読まない
// (ライブラリの注釈が Reader と並行に呼ぶことを求めている)。下の applySeq の守りが要るのはこの
// 性質のためであり、判定の失敗を回線の不調とだけ読んではいけない。
//
// ws への書き手はハートビートの goroutine とこの goroutine の 2 つになるが、ライブラリがフレーム
// 単位で直列化するので混ざらない。Conn.Ping は読みを続ける goroutine と並行に呼ぶ前提の API である。
// epoch は、この pingLoop が属する接続の通し番号である。観測の書き込みはこの番号が今の接続の
// ものである間だけ効く(設計文書 10.2c 節)。
func (rt *runtime) pingLoop(ctx context.Context, ws *websocket.Conn, epoch uint64) {
	if rt.pingInterval <= 0 {
		return
	}
	t := time.NewTicker(rt.pingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		// 全体状態の適用の間は読みの for ループが止まり、pong を処理できない。適用は TCP の宛先への
		// 試し接続を含み、宛先 1 つにつき最長 10 秒かかるので、pong の期限より長くなりうる。値が
		// 奇数なら適用の最中なので ping を送らない。適用が戻らない場合の上限は、server が何も
		// 届かない stream を閉じる 90 秒が与える
		seq := rt.applySeq.Load()
		if seq%2 == 1 {
			continue
		}
		pingCtx, cancel := context.WithTimeout(ctx, rt.pongTimeout)
		// ping を送ってから pong の待ちが終わるまでを観測に写す(設計文書 10.2c 節)。判定の流れは
		// 変えず、ws.Ping の前後に記録を置くだけである
		rt.noteStreamPingSent(time.Now(), epoch)
		err := ws.Ping(pingCtx)
		rt.noteStreamPingAnswered(time.Now(), epoch, err == nil)
		cancel()
		if err == nil {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if rt.applySeq.Load() != seq {
			// ping を送ってから pong を待つ間に適用が挟まり、読みが止まっていた。経路の生死の
			// 証拠にならないので判定を見送り、次の周期で測り直す
			continue
		}
		log.Printf("stream: the server did not answer a ping within %s (%v); the connection is dead, closing it", rt.pongTimeout, err)
		ws.CloseNow()
		return
	}
}

// checkServerProtocolVersion は、server が選んだ版(state.ServerProtocolVersion)が、番号の付いた
// 版として意味を持ち(1 以上)、かつ agent 自身の範囲に入っていることを確かめる(仕様 7a.6 節)。
// フィールドが無ければ legacy v0 の server なので検査しない。server は本来、版 1 以上かつ
// local と agent の範囲の共通部分からしか選ばないので、ここでの失敗は server の実装違反を
// 示す防御的な検査である。1 未満は、agent の範囲がたまたま [1,1] でなくなった場合(将来
// v1 を落として [2,2] になるなど)でも「範囲外」ではなく「そもそも版として無効」だとログで
// 区別できるよう、範囲の検査より先に見る。
func checkServerProtocolVersion(local proto.ProtocolRange, st *proto.State) error {
	if st.ServerProtocolVersion == nil {
		return nil
	}
	v := *st.ServerProtocolVersion
	if v < 1 {
		return fmt.Errorf("server selected protocol version %d, which is not a valid numbered version (versions start at 1)", v)
	}
	if v < local.Min || v > local.Max {
		return fmt.Errorf("server selected protocol version %d, outside the agent's supported range [%d,%d]", v, local.Min, local.Max)
	}
	return nil
}

// protocolLabelForState はログ用の短い表記("legacy v0" または "v1")。
func protocolLabelForState(st *proto.State) string {
	if st.ServerProtocolVersion == nil {
		return "legacy v0"
	}
	return fmt.Sprintf("v%d", *st.ServerProtocolVersion)
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
