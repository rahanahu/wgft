// Package stream は vpsd 側の stream(仕様 5.2 節)。エージェントごとに WebSocket を 1 本持ち、
// 公開鍵の宣言を受け、全体状態を配り、ハートビートを記録する。
package stream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/lograte"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// Backend は Hub が呼ぶ vpsd 側の操作。
type Backend interface {
	// Authenticate は恒久トークンからエージェント名と登録 identity を返す。無効なら
	// store.ErrInvalidToken 相当の誤り。identity は最初の鍵の受信まで保持する。
	Authenticate(permanentToken string) (agent, identity string, err error)
	// ServerPublicKey はサーバの公開鍵(エージェントの鍵と同じなら拒否する)。
	ServerPublicKey() wgtypes.Key
	// OtherAgentHasKey は、他のエージェントが同じ公開鍵を保存しているか。
	OtherAgentHasKey(agent string, key wgtypes.Key) (bool, error)
	// SetPublicKey は認証時の登録 identity を照合してから公開鍵を保存し、wg0 のピアを置き換える。
	SetPublicKey(agent, identity string, key wgtypes.Key) error
	// StateFor はそのエージェントに配る全体状態。identity は認証時の登録で、
	// key はこの接続が認証後に宣言した鍵で、
	// 成功済みの配信状態に属する鍵だけを認める。sel はその stream 接続で選んだ版と、agent が
	// 宣言した機能(仕様 7a.6 節)。sel.Legacy なら agent は legacy v0 なので、実装は
	// server_protocol_version/server_capabilities を全体状態に載せない
	StateFor(agent, identity string, key wgtypes.Key, sel proto.Negotiated) (*proto.State, error)
}

// Status は vpsd が UI に見せる、エージェントごとの stream の状態。
type Status struct {
	Connected     bool
	StreamFrom    string // 接続元 IP
	ConnectedAt   time.Time
	LastHeartbeat time.Time
	Heartbeat     *proto.Heartbeat
	// Protocol はこの接続で交渉した版(仕様 7a.6 節)。未接続なら zero 値(Legacy=false, Version=0)
	Protocol proto.Negotiated
}

type conn struct {
	ws       *websocket.Conn
	from     string
	cancel   context.CancelFunc
	sendMu   sync.Mutex
	key      wgtypes.Key   // declared by this authenticated connection before it is installed
	identity string        // registration authenticated before the first WebSocket message
	pushCh   chan struct{} // one pending push; repeated requests coalesce
	pushDone chan struct{}
	// done は serve が戻ると閉じる。この接続を置き換えた接続は、これが閉じるまで確立前の枠を返さない
	done     chan struct{}
	timedOut atomic.Bool // heartbeatTimer が閉じた(ログの重複を避けるための印)
	// sel はこの接続で交渉した版と機能。serve() が接続の確立前に一度だけ設定し、以後は
	// 読み取り専用として扱う(Push からも参照するが、書き込みは無いので mu は要らない)
	sel proto.Negotiated
}

// heartbeatInterval はエージェントがハートビートを送る間隔(仕様 5.2 節)。
const heartbeatInterval = 30 * time.Second

// defaultHeartbeatTimeout は読みの期限(ハートビート間隔の 3 倍)。
// 期限内にメッセージが来なければ、vpsd 側から理由コード付きで閉じる。
const defaultHeartbeatTimeout = 3 * heartbeatInterval

// writeTimeout は書きの期限(既存の Push の context に揃える)。
const writeTimeout = 10 * time.Second

// 確立前の stream の上限(設計文書 5.2 節、11 節)。恒久トークンの確認を通った stream は送信元ごとの
// 未認証の接続の数から外れる(agentapi の Authenticated)ので、最初のメッセージを受け取って接続を
// 確立するまでの間は、次の 3 つで抑える。
const (
	// defaultFirstMessageTimeout は、最初のメッセージ(pubkey)を待つ期限。エージェントは WebSocket
	// の接続の直後に pubkey を送るので、往復 1 回で届く。
	defaultFirstMessageTimeout = 10 * time.Second
	// firstMessageReadLimit は、最初のメッセージの大きさの上限。今の pubkey は約 130 byte で、
	// capabilities の語彙が増えても収まる大きさにしてある。確立の後は streamReadLimit に戻す。
	firstMessageReadLimit = 4 << 10
	// streamReadLimit は、確立した stream のメッセージ(ハートビート)の大きさの上限。
	streamReadLimit = 1 << 20
	// maxPendingPerAgent は、1 つのエージェントが同時に持てる確立前の stream の数。1 本が半開きの
	// まま期限を待つ間も、つなぎ直しの 1 本が通るよう 2 にしてある。旧接続を置き換えた stream は、
	// 旧接続の serve が戻るまで枠を返さないので、閉じる途中の旧接続もこの数に入る(設計文書 7 節、11 節)。
	maxPendingPerAgent = 2
)

// Hub はエージェントごとの接続と状態を持つ。
type Hub struct {
	backend Backend
	// RateLimit は接続試行の送信元 IP ごとの制限(agentapi のものを使う)。nil なら制限しない
	RateLimit func(remoteAddr string) bool
	// Authenticated は恒久トークンの確認が通った直後に呼ぶ。agentapi はその接続を送信元ごとの
	// 未認証の接続の数から外す(設計文書 11 節)。nil なら何もしない
	Authenticated func(r *http.Request)
	// OnStreamConnect は stream の認証が通って接続が確立したときに呼ぶ(窃取検知の「IP の往復」用。
	// 短命な supersede も取りこぼさないよう、サンプリングではなく接続の事象で記録する)。nil なら何もしない
	OnStreamConnect func(agent, from string)
	// OnHeartbeat は、今の接続からハートビートを受け取って状態に記録した後に、報告された世代を
	// 渡して呼ぶ(設計文書 10.2a 節のルール集合の世代の遅れの記録用)。nil なら何もしない。
	// 呼ぶ間はそのエージェントの hookLock を持つ。接続の置き換えと Disconnect も同じ錠を取るので、
	// 置き換えられた接続や切断された接続のハートビートが、置き換えや切断の後に呼ばれることは無い
	OnHeartbeat func(agent string, generation uint64)
	// HeartbeatTimeout は読みの期限(既定 90 秒。テストで短くできるよう差し替え可能にしてある)
	HeartbeatTimeout time.Duration
	// firstMessageTimeout は最初のメッセージを待つ期限(既定 defaultFirstMessageTimeout。テストが短くする)
	firstMessageTimeout time.Duration

	mu sync.Mutex
	// locks は、同一エージェントの接続処理と hook の直列化に使う。
	// 待機中も参照として数え、最後の利用が終わると表から外す。mu を持ったまま
	// 名前別の錠を待たない。両方が必要なときは agent、hook の順に取る。
	//
	// Backend と差し込み口は次の錠を持って呼ぶ。serve は agent を持って Backend.SetPublicKey を、
	// agent と hook を持って Backend.StateFor を、agent だけを持って OnStreamConnect を呼ぶ。
	// OnHeartbeat は hook を持って呼ぶ。sendState は接続の sendMu を持って Backend.StateFor を
	// 呼び、serve の中では agent も持つ。mu を持ったまま Backend と差し込み口を呼ぶことは無い。
	// vpsd の Backend の SetPublicKey は Daemon の錠を取り、Daemon の錠を持つ apply と Revoke は
	// RetireIfDifferent と Disconnect から hook と mu を取る。Daemon の錠は agent と hook の間に入る
	// (internal/vpsd の Daemon.mu の注釈)。
	locks  map[string]*agentLocks
	conns  map[string]*conn
	status map[string]*Status
	// pending は、エージェントごとの確立前の stream の数(恒久トークンの確認の後、接続の表に
	// 入るまで)。0 になった項目は消す
	pending map[string]int

	pendingLog lograte.Gate // maxPendingPerAgent で断った行
}

type agentLocks struct {
	agent sync.Mutex
	hook  sync.Mutex
	refs  int // h.mu で保護する。錠の待機中と保持中を含む
}

// heldAgentLock は名前別の錠と表の参照を一緒に所有する。
// OnHeartbeat と StatusWithHook の callback は hook を持ち、Hub.mu は持たないため
// Status を呼べる。OnStreamConnect は agent のみを持ち、hook を取れる。
// 同じ錠を再帰的に取る callback は対象外。
type heldAgentLock struct {
	h     *Hub
	name  string
	entry *agentLocks
	hook  bool
}

// New は空の Hub を作る。
func New(b Backend) *Hub {
	return &Hub{
		backend: b, locks: map[string]*agentLocks{},
		conns: map[string]*conn{}, status: map[string]*Status{}, pending: map[string]int{},
		HeartbeatTimeout:    defaultHeartbeatTimeout,
		firstMessageTimeout: defaultFirstMessageTimeout,
	}
}

func (h *Hub) agentLock(name string) *heldAgentLock {
	return h.lockOf(name, false)
}

func (h *Hub) hookLock(name string) *heldAgentLock {
	return h.lockOf(name, true)
}

func (h *Hub) lockOf(name string, hook bool) *heldAgentLock {
	h.mu.Lock()
	l, ok := h.locks[name]
	if !ok {
		l = &agentLocks{}
		h.locks[name] = l
	}
	l.refs++ // pin before waiting so a waiter keeps this entry alive
	h.mu.Unlock()
	mu := &l.agent
	if hook {
		mu = &l.hook
	}
	mu.Lock()
	return &heldAgentLock{h: h, name: name, entry: l, hook: hook}
}

func (l *heldAgentLock) unlock() {
	if l.hook {
		l.entry.hook.Unlock()
	} else {
		l.entry.agent.Unlock()
	}
	l.h.mu.Lock()
	l.entry.refs--
	if l.entry.refs == 0 && l.h.locks[l.name] == l.entry {
		delete(l.h.locks, l.name)
	}
	l.h.mu.Unlock()
	l.entry = nil
}

// Status はエージェントの stream の状態(なければ未接続)。
func (h *Hub) Status(agent string) Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.status[agent]; ok {
		return *s
	}
	return Status{}
}

// StatusWithHook は、そのエージェントの hookLock を持ったまま状態を読み、f に渡して呼ぶ。
// ハートビートは状態を更新してから、同じ錠の中で OnHeartbeat を呼ぶ。この錠を持って読むと、
// 状態の更新だけが済んで OnHeartbeat の記録がまだ済んでいない途中の姿を読まない。管理用 API が
// 状態と、OnHeartbeat が記録する値(vpsd の遅れの始まり)を 1 つの時点の組として返すのに使う
// (設計文書 10.2a 節)。
//
// f は hookLock を持ったまま呼ぶので、そのエージェントの接続処理と Disconnect を待たせる。f の中で
// 長く待つ処理(データベースの読み取りなど)をしない。Status は hookLock を取らないまま残す。
// OnHeartbeat は hookLock を持って呼ばれ、その中から Status を呼んでよいためである。
func (h *Hub) StatusWithHook(agent string, f func(Status)) {
	hook := h.hookLock(agent)
	defer hook.unlock()
	f(h.Status(agent))
}

// ServeHTTP は GET /api/v1/agents/stream。
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.RateLimit != nil && !h.RateLimit(r.RemoteAddr) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	// 1. 認証
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" || tok == r.Header.Get("Authorization") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	agent, identity, err := h.backend.Authenticate(tok)
	if err != nil {
		// トークンが無効(未知・期限切れ・使用済み)なのと、backend 自体が失敗した(SQLite の
		// エラーなど)のとは分ける。前者だけが日常的に起きる想定の応答で、ログは残さない。
		// 後者は原因をログに残し、agent には一時的な失敗として答える(agent 側は再登録ではなく
		// バックオフで再試行する。internal/agent/stream.go の default 分岐)
		if errors.Is(err, ErrUnauthorized) || errors.Is(err, store.ErrInvalidToken) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		log.Printf("stream: authenticate: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// 確立前の stream をエージェントごとに数える。送信元ごとの未認証の数から外す前に確かめ、
	// 断る接続は未認証のまま閉じる
	release, ok := h.reservePending(agent)
	if !ok {
		if h.pendingLog.Allow() {
			log.Printf("stream: %s: refusing a stream: %d streams of this agent are already waiting to be established or for a replaced stream to close", agent, maxPendingPerAgent)
		}
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	if h.Authenticated != nil {
		h.Authenticated(r)
	}
	from, _, _ := net.SplitHostPort(r.RemoteAddr)
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		release()
		return
	}
	// HTTP does not close hijacked connections when the handler returns.
	defer ws.CloseNow()
	ws.SetReadLimit(firstMessageReadLimit)
	h.serve(r.Context(), agent, identity, from, ws, release)
}

// reservePending は agent の確立前の stream の枠を 1 つ取る。上限に達していれば ok は false。
// release は何度呼んでもよく、最初の 1 回だけ枠を返す。
func (h *Hub) reservePending(agent string) (release func(), ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending[agent] >= maxPendingPerAgent {
		return nil, false
	}
	h.pending[agent]++
	var once sync.Once
	return func() {
		once.Do(func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.pending[agent] <= 1 {
				delete(h.pending, agent)
				return
			}
			h.pending[agent]--
		})
	}, true
}

// serve は認証を通った stream を最後まで扱う。release は確立前の stream の枠を返す関数で、serve が
// 必ず 1 回呼ぶ。接続を表に入れた時点で返すが、旧接続を置き換えた場合は、旧接続の serve が戻るまで
// 返さない。置き換えられた旧接続は、読みかけのメッセージを持ったまま、WebSocket の close の期限と
// TLS の close_notify の書き込みの期限の間残りうるので、その間はこの枠で旧接続を数える
// (設計文書 7 節、11 節)。
func (h *Hub) serve(parent context.Context, agent, identity, from string, ws *websocket.Conn, release func()) {
	done := make(chan struct{})
	defer close(done)
	// replaced は、この接続が置き換えた旧接続の done。nil なら枠をすぐに返す
	var replaced <-chan struct{}
	slotReturned := false
	returnSlot := func() {
		if slotReturned {
			return
		}
		slotReturned = true
		if replaced == nil {
			release()
			return
		}
		go func(old <-chan struct{}) {
			<-old
			release()
		}(replaced)
	}
	defer returnSlot()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	c := &conn{ws: ws, from: from, identity: identity, cancel: cancel, pushCh: make(chan struct{}, 1), pushDone: make(chan struct{}), done: done}

	// 2. 鍵の検証(最初のメッセージ)。失敗した接続は旧接続に影響を与えない
	readCtx, readCancel := context.WithTimeout(ctx, h.firstMessageTimeout)
	var first proto.Message
	err := readJSON(readCtx, ws, &first)
	readCancel()
	if err != nil || first.Type != proto.MsgPublicKey {
		ws.Close(websocket.StatusPolicyViolation, "first message must be pubkey")
		return
	}
	ws.SetReadLimit(streamReadLimit)
	key, err := wgtypes.ParseKey(first.PublicKey)
	if err != nil {
		ws.Close(websocket.StatusPolicyViolation, "invalid public key")
		return
	}
	if key == h.backend.ServerPublicKey() {
		ws.Close(websocket.StatusPolicyViolation, "public key equals server key")
		return
	}
	dup, err := h.backend.OtherAgentHasKey(agent, key)
	if err != nil {
		// backend の失敗(SQLite のエラーなど)を「鍵が他のエージェントのもの」という
		// 窃取を示す文言で答えてはいけない。原因はログに残し、agent には一時的な失敗として
		// 答える(SetPublicKey の失敗と同じ形。agent はバックオフで再試行する)
		log.Printf("stream: %s: checking public key: %v", agent, err)
		ws.Close(websocket.StatusInternalError, "internal error")
		return
	}
	if dup {
		ws.Close(websocket.StatusPolicyViolation, "public key belongs to another agent")
		return
	}

	// 2a. 版の交渉(仕様 7a.6 節)。pubkey に protocol_min/protocol_max が両方とも無ければ legacy
	// v0 として扱う。片方だけ無い、または範囲そのものが無効(Min<1 か Min>Max)なら advertisement
	// が壊れているとみなし、共通部分が無い場合とはコード(CloseProtocolMalformed)を分けて断る。
	// どちらの場合も、ピアの置き換えに進まず理由を示して断る
	sel, ok, malformed, reason := negotiateVersion(first)
	if !ok {
		code := proto.CloseProtocolMismatch
		if malformed {
			code = proto.CloseProtocolMalformed
		}
		log.Printf("stream: %s: %s; refusing", agent, reason)
		ws.Close(websocket.StatusCode(code), reason)
		return
	}
	c.sel = sel
	c.key = key

	// 3-5 は同一エージェントで直列化:ピアの置き換え → 旧接続の切断 → 全体状態の送信
	lock := h.agentLock(agent)

	if err := h.backend.SetPublicKey(agent, identity, key); err != nil {
		lock.unlock()
		log.Printf("stream: %s: peer setup: %v", agent, err)
		ws.Close(websocket.StatusInternalError, "peer setup failed")
		return
	}
	hook := h.hookLock(agent)
	// A saved key may have failed publication, or this registration may have
	// been revoked while the connection waited for its first message. Revoke's
	// Disconnect takes hookLock and removes any connection admitted before it.
	if _, err := h.backend.StateFor(agent, identity, key, sel); err != nil {
		hook.unlock()
		lock.unlock()
		log.Printf("stream: %s: state admission: %v", agent, err)
		ws.CloseNow()
		return
	}
	h.mu.Lock()
	if old := h.conns[agent]; old != nil {
		// 旧 TCP が死んでいる場合に備え、常に新しい方を優先する
		go func() {
			old.ws.Close(websocket.StatusCode(proto.CloseSuperseded), "superseded")
			old.cancel()
		}()
		log.Printf("stream: %s: closing old connection from %s as superseded", agent, old.from)
		replaced = old.done
	}
	h.conns[agent] = c
	h.status[agent] = &Status{Connected: true, StreamFrom: from, ConnectedAt: time.Now(), Protocol: sel}
	h.mu.Unlock()
	hook.unlock()
	returnSlot()
	if h.OnStreamConnect != nil {
		h.OnStreamConnect(agent, from)
	}
	st, err := h.sendState(ctx, agent, c)
	lock.unlock()
	if err != nil {
		log.Printf("stream: %s: sending state: %v", agent, err)
		h.drop(agent, c)
		return
	}
	// 選んだ版は接続ごとに 1 回だけログに出す(仕様 7a.6 節。メッセージごとには出さない)
	log.Printf("stream: %s connected from %s, protocol %s, sent generation %d", agent, from, protocolLabel(sel), st.Generation)
	go h.pushWorker(ctx, agent, c)
	defer func() {
		cancel()
		<-c.pushDone
	}()

	// ハートビートを受け続ける。期限内にメッセージが来なければ vpsd 側から理由コード付きで閉じる。
	// readJSON の ctx を期限で切ると、このライブラリは内部で無条件に接続を閉じてしまい
	// (setupReadTimeout → close())、後から理由付きで Close を呼んでも既に閉じた後のため
	// 理由が相手に届かない。そのため読みは ctx のみで待ち、別にタイマーで理由付きの Close を呼ぶ
	// (supersede・revoke と同じ「Close してから cancel する」順序)。
	heartbeatTimer := time.AfterFunc(h.HeartbeatTimeout, func() {
		c.timedOut.Store(true)
		log.Printf("stream: %s: no message within %s; closing: heartbeat timeout", agent, h.HeartbeatTimeout)
		ws.Close(websocket.StatusCode(proto.CloseHeartbeatTimeout), "heartbeat timeout")
	})
	defer heartbeatTimer.Stop()
	for {
		var m proto.Message
		if err := readJSON(ctx, ws, &m); err != nil {
			h.drop(agent, c)
			if ctx.Err() == nil && !c.timedOut.Load() {
				log.Printf("stream: %s disconnected from %s: %v", agent, from, err)
			}
			return
		}
		heartbeatTimer.Reset(h.HeartbeatTimeout)
		if m.Type == proto.MsgHeartbeat && m.Heartbeat != nil {
			hook := h.hookLock(agent)
			h.mu.Lock()
			current := false
			if s := h.status[agent]; s != nil && h.conns[agent] == c {
				s.LastHeartbeat = time.Now()
				// agent の文字列は信頼の境界の外にある(design.md 11 節)。保存する前に
				// 切り詰めて端末の制御文字を無害化する(design.md 5.2 節)
				s.Heartbeat = sanitizeHeartbeat(m.Heartbeat)
				current = true
			}
			h.mu.Unlock()
			if current && h.OnHeartbeat != nil {
				h.OnHeartbeat(agent, m.Heartbeat.Generation)
			}
			hook.unlock()
		}
	}
}

// drop は接続を表から外す(置き換えられた後の旧接続は外さない)。
func (h *Hub) drop(agent string, c *conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conns[agent] == c {
		delete(h.conns, agent)
		if s := h.status[agent]; s != nil {
			s.Connected = false
		}
	}
}

// Push は接続中のエージェントへ最新の全体状態の送信を予約する。
// 接続ごとに待機は 1 件だけで、連続する要求は同じ送信にまとめる。
func (h *Hub) Push(agent string) {
	h.mu.Lock()
	c := h.conns[agent]
	if c != nil {
		select {
		case c.pushCh <- struct{}{}:
		default:
		}
	}
	h.mu.Unlock()
}

// PushAll は接続中の全エージェントへの送信を予約する。
func (h *Hub) PushAll() {
	h.mu.Lock()
	for _, c := range h.conns {
		select {
		case c.pushCh <- struct{}{}:
		default:
		}
	}
	h.mu.Unlock()
}

func (h *Hub) pushWorker(ctx context.Context, agent string, c *conn) {
	defer close(c.pushDone)
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-c.pushCh:
		}
		st, err := h.sendState(ctx, agent, c)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("stream: %s: delivery: %v", agent, err)
			}
			continue
		}
		log.Printf("stream: %s: delivered generation %d", agent, st.Generation)
	}
}

// Disconnect はエージェントの接続を理由付きで閉じる(無効化)。
func (h *Hub) Disconnect(agent string, code int, reason string) {
	// 実行中の OnHeartbeat が終わるのを待ってから外す。外した後にその接続の OnHeartbeat は呼ばれない
	hook := h.hookLock(agent)
	h.mu.Lock()
	c := h.conns[agent]
	delete(h.conns, agent)
	delete(h.status, agent)
	h.mu.Unlock()
	hook.unlock()
	if c != nil {
		// close の応答待ち(最大 5 秒)で呼び出し側(管理用 API)を止めない
		go func() {
			c.ws.Close(websocket.StatusCode(code), reason)
			c.cancel()
		}()
	}
}

// RetireIfDifferent removes a connection whose authenticated registration or
// declared key differs from a newly successful full publication. The removal
// happens before another State can be queued for that connection.
func (h *Hub) RetireIfDifferent(agent, identity, key string) {
	hook := h.hookLock(agent)
	h.mu.Lock()
	c := h.conns[agent]
	if c != nil && c.identity == identity && c.key.String() == key {
		c = nil
	}
	if c != nil {
		delete(h.conns, agent)
		delete(h.status, agent)
	}
	h.mu.Unlock()
	hook.unlock()
	if c != nil {
		c.cancel()
		c.ws.CloseNow()
	}
}

func (h *Hub) sendState(ctx context.Context, agent string, c *conn) (*proto.State, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	h.mu.Lock()
	current := h.conns[agent] == c
	h.mu.Unlock()
	if !current {
		return nil, errors.New("agent connection was replaced")
	}
	// Select the authorized State only after owning this connection's writer.
	// A queued push cannot retain an old State while waiting behind a send.
	st, err := h.backend.StateFor(agent, c.identity, c.key, c.sel)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(proto.Message{Type: proto.MsgState, State: st})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	if err := c.ws.Write(ctx, websocket.MessageText, b); err != nil {
		return nil, err
	}
	return st, nil
}

// negotiateVersion は pubkey メッセージから、この接続の版と機能を決める(仕様 7a.6 節)。
// ok が true なのは、legacy v0(protocol_min/protocol_max が両方とも無い)と、両方の範囲が
// 有効で共通部分がある場合だけ。ok が false のとき、malformed は原因を区別する:
//
//   - true:advertisement 自体が壊れている(片方のフィールドだけがある、または Min<1 か
//     Min>Max の無効な範囲)。相手の実装の不具合であり、版を上げても直らない
//   - false:双方とも有効な範囲を宣言したが共通部分が無い。版を上げれば直る
//
// reason は ok が false のときだけ意味を持つ、そのまま WebSocket の close reason に使える
// 文字列。呼び出し元は first.ProtocolMin/first.ProtocolMax を自分で読み直す必要が無い
// (malformed の場合は片方が nil のことがあるため、直接 deref すると panic しうる)。
func negotiateVersion(m proto.Message) (sel proto.Negotiated, ok bool, malformed bool, reason string) {
	switch {
	case m.ProtocolMin == nil && m.ProtocolMax == nil:
		return proto.Negotiated{Legacy: true}, true, false, ""
	case m.ProtocolMin == nil || m.ProtocolMax == nil:
		missing, present := "protocol_max", "protocol_min"
		if m.ProtocolMin == nil {
			missing, present = "protocol_min", "protocol_max"
		}
		reason = fmt.Sprintf("malformed protocol advertisement: %s is present but %s is missing", present, missing)
		return proto.Negotiated{}, false, true, reason
	}
	remote := proto.ProtocolRange{Min: *m.ProtocolMin, Max: *m.ProtocolMax}
	if !remote.Valid() {
		reason = fmt.Sprintf("malformed protocol advertisement: invalid range [%d,%d]; protocol_min must be at least 1 and at most protocol_max",
			remote.Min, remote.Max)
		return proto.Negotiated{}, false, true, reason
	}
	version, overlap := proto.SelectProtocolVersion(proto.SupportedProtocol, remote)
	if !overlap {
		reason = fmt.Sprintf("no overlapping protocol version: server supports [%d,%d], agent supports [%d,%d]",
			proto.SupportedProtocol.Min, proto.SupportedProtocol.Max, remote.Min, remote.Max)
		return proto.Negotiated{}, false, false, reason
	}
	sel = proto.Negotiated{Version: version, AgentMin: remote.Min, AgentMax: remote.Max}
	if m.Capabilities != nil {
		sel.Capabilities = *m.Capabilities
	}
	return sel, true, false, ""
}

// protocolLabel はログ用の短い表記("legacy v0" または "v1")。
func protocolLabel(sel proto.Negotiated) string {
	if sel.Legacy {
		return "legacy v0"
	}
	return fmt.Sprintf("v%d", sel.Version)
}

func readJSON(ctx context.Context, ws *websocket.Conn, v any) error {
	_, b, err := ws.Read(ctx)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("bad message: %w", err)
	}
	return nil
}

// ErrUnauthorized は Authenticate が返す誤り(Backend が store.ErrInvalidToken をそのまま返してもよい)。
var ErrUnauthorized = errors.New("unauthorized")
