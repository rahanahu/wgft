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

	"github.com/rahanahu/wgft/proto"
)

// Backend は Hub が呼ぶ vpsd 側の操作。
type Backend interface {
	// Authenticate は恒久トークンからエージェント名を返す。無効なら store.ErrInvalidToken 相当の誤り。
	Authenticate(permanentToken string) (agent string, err error)
	// ServerPublicKey はサーバの公開鍵(エージェントの鍵と同じなら拒否する)。
	ServerPublicKey() wgtypes.Key
	// OtherAgentHasKey は、他のエージェントが同じ公開鍵を保存しているか。
	OtherAgentHasKey(agent string, key wgtypes.Key) (bool, error)
	// SetPublicKey は宣言された公開鍵を保存し、wg0 のピアを置き換える(初回なら作る)。
	SetPublicKey(agent string, key wgtypes.Key) error
	// StateFor はそのエージェントに配る全体状態。sel はその stream 接続で選んだ版と、agent が
	// 宣言した機能(仕様 7a.6 節)。sel.Legacy なら agent は legacy v0 なので、実装は
	// server_protocol_version/server_capabilities を全体状態に載せない
	StateFor(agent string, sel proto.Negotiated) (*proto.State, error)
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

// Hub はエージェントごとの接続と状態を持つ。
type Hub struct {
	backend Backend
	// RateLimit は接続試行の送信元 IP ごとの制限(agentapi のものを使う)。nil なら制限しない
	RateLimit func(remoteAddr string) bool
	// OnStreamConnect は stream の認証が通って接続が確立したときに呼ぶ(窃取検知の「IP の往復」用。
	// 短命な supersede も取りこぼさないよう、サンプリングではなく接続の事象で記録する)。nil なら何もしない
	OnStreamConnect func(agent, from string)
	// HeartbeatTimeout は読みの期限(既定 90 秒。テストで短くできるよう差し替え可能にしてある)
	HeartbeatTimeout time.Duration

	mu     sync.Mutex
	locks  map[string]*sync.Mutex // 同一エージェントの接続処理の直列化
	conns  map[string]*conn
	status map[string]*Status
}

// New は空の Hub を作る。
func New(b Backend) *Hub {
	return &Hub{
		backend: b, locks: map[string]*sync.Mutex{}, conns: map[string]*conn{}, status: map[string]*Status{},
		HeartbeatTimeout: defaultHeartbeatTimeout,
	}
}

func (h *Hub) agentLock(name string) *sync.Mutex {
	h.mu.Lock()
	defer h.mu.Unlock()
	l, ok := h.locks[name]
	if !ok {
		l = &sync.Mutex{}
		h.locks[name] = l
	}
	return l
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
	agent, err := h.backend.Authenticate(tok)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	from, _, _ := net.SplitHostPort(r.RemoteAddr)
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	ws.SetReadLimit(1 << 20)
	h.serve(r.Context(), agent, from, ws)
}

func (h *Hub) serve(parent context.Context, agent, from string, ws *websocket.Conn) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	c := &conn{ws: ws, from: from, cancel: cancel}

	// 2. 鍵の検証(最初のメッセージ)。失敗した接続は旧接続に影響を与えない
	readCtx, readCancel := context.WithTimeout(ctx, 30*time.Second)
	var first proto.Message
	err := readJSON(readCtx, ws, &first)
	readCancel()
	if err != nil || first.Type != proto.MsgPublicKey {
		ws.Close(websocket.StatusPolicyViolation, "first message must be pubkey")
		return
	}
	key, err := wgtypes.ParseKey(first.PublicKey)
	if err != nil {
		ws.Close(websocket.StatusPolicyViolation, "invalid public key")
		return
	}
	if key == h.backend.ServerPublicKey() {
		ws.Close(websocket.StatusPolicyViolation, "public key equals server key")
		return
	}
	if dup, err := h.backend.OtherAgentHasKey(agent, key); err != nil || dup {
		ws.Close(websocket.StatusPolicyViolation, "public key belongs to another agent")
		return
	}

	// 2a. 版の交渉(仕様 7a.6 節)。pubkey に protocol_min/protocol_max が無ければ legacy v0 として
	// 扱い、範囲の検査はしない。共通部分が無ければ、ピアの置き換えに進まず双方の範囲を示して断る
	sel, ok := negotiateVersion(first)
	if !ok {
		reason := fmt.Sprintf("no overlapping protocol version: server supports [%d,%d], agent supports [%d,%d]",
			proto.SupportedProtocol.Min, proto.SupportedProtocol.Max, *first.ProtocolMin, *first.ProtocolMax)
		log.Printf("stream: %s: %s; refusing", agent, reason)
		ws.Close(websocket.StatusCode(proto.CloseProtocolMismatch), reason)
		return
	}
	c.sel = sel

	// 3-5 は同一エージェントで直列化:ピアの置き換え → 旧接続の切断 → 全体状態の送信
	lock := h.agentLock(agent)
	lock.Lock()

	if err := h.backend.SetPublicKey(agent, key); err != nil {
		lock.Unlock()
		log.Printf("stream: %s: peer setup: %v", agent, err)
		ws.Close(websocket.StatusInternalError, "peer setup failed")
		return
	}
	h.mu.Lock()
	if old := h.conns[agent]; old != nil {
		// 旧 TCP が死んでいる場合に備え、常に新しい方を優先する
		go func() {
			old.ws.Close(websocket.StatusCode(proto.CloseSuperseded), "superseded")
			old.cancel()
		}()
		log.Printf("stream: %s: closing old connection (%s) as superseded", agent, old.from)
	}
	h.conns[agent] = c
	h.status[agent] = &Status{Connected: true, StreamFrom: from, ConnectedAt: time.Now(), Protocol: sel}
	h.mu.Unlock()
	if h.OnStreamConnect != nil {
		h.OnStreamConnect(agent, from)
	}
	st, err := h.backend.StateFor(agent, sel)
	if err == nil {
		err = c.send(ctx, proto.Message{Type: proto.MsgState, State: st})
	}
	lock.Unlock()
	if err != nil {
		log.Printf("stream: %s: sending state: %v", agent, err)
		h.drop(agent, c)
		return
	}
	// 選んだ版は接続ごとに 1 回だけログに出す(仕様 7a.6 節。メッセージごとには出さない)
	log.Printf("stream: %s connected (%s, protocol %s, sent generation %d)", agent, from, protocolLabel(sel), st.Generation)

	// ハートビートを受け続ける。期限内にメッセージが来なければ vpsd 側から理由コード付きで閉じる。
	// readJSON の ctx を期限で切ると、このライブラリは内部で無条件に接続を閉じてしまい
	// (setupReadTimeout → close())、後から理由付きで Close を呼んでも既に閉じた後のため
	// 理由が相手に届かない。そのため読みは ctx のみで待ち、別にタイマーで理由付きの Close を呼ぶ
	// (supersede・revoke と同じ「Close してから cancel する」順序)。
	heartbeatTimer := time.AfterFunc(h.HeartbeatTimeout, func() {
		c.timedOut.Store(true)
		log.Printf("stream: %s: no message within %s; closing (heartbeat timeout)", agent, h.HeartbeatTimeout)
		ws.Close(websocket.StatusCode(proto.CloseHeartbeatTimeout), "heartbeat timeout")
	})
	defer heartbeatTimer.Stop()
	for {
		var m proto.Message
		if err := readJSON(ctx, ws, &m); err != nil {
			h.drop(agent, c)
			if ctx.Err() == nil && !c.timedOut.Load() {
				log.Printf("stream: %s disconnected (%s): %v", agent, from, err)
			}
			return
		}
		heartbeatTimer.Reset(h.HeartbeatTimeout)
		if m.Type == proto.MsgHeartbeat && m.Heartbeat != nil {
			h.mu.Lock()
			if s := h.status[agent]; s != nil && h.conns[agent] == c {
				s.LastHeartbeat = time.Now()
				s.Heartbeat = m.Heartbeat
			}
			h.mu.Unlock()
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

// Push は接続中のエージェントに全体状態を送り直す(配る内容が変わったとき)。
func (h *Hub) Push(agent string) {
	h.mu.Lock()
	c := h.conns[agent]
	h.mu.Unlock()
	if c == nil {
		return
	}
	st, err := h.backend.StateFor(agent, c.sel)
	if err != nil {
		log.Printf("stream: %s: state: %v", agent, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.send(ctx, proto.Message{Type: proto.MsgState, State: st}); err != nil {
		log.Printf("stream: %s: delivery: %v", agent, err)
		return
	}
	log.Printf("stream: %s: delivered generation %d", agent, st.Generation)
}

// PushAll は接続中の全エージェントに配り直す。
func (h *Hub) PushAll() {
	h.mu.Lock()
	names := make([]string, 0, len(h.conns))
	for n := range h.conns {
		names = append(names, n)
	}
	h.mu.Unlock()
	for _, n := range names {
		h.Push(n)
	}
}

// Disconnect はエージェントの接続を理由付きで閉じる(無効化)。
func (h *Hub) Disconnect(agent string, code int, reason string) {
	h.mu.Lock()
	c := h.conns[agent]
	delete(h.conns, agent)
	delete(h.status, agent)
	h.mu.Unlock()
	if c != nil {
		// close の応答待ち(最大 5 秒)で呼び出し側(管理用 API)を止めない
		go func() {
			c.ws.Close(websocket.StatusCode(code), reason)
			c.cancel()
		}()
	}
}

func (c *conn) send(ctx context.Context, m proto.Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.ws.Write(ctx, websocket.MessageText, b)
}

// negotiateVersion は pubkey メッセージから、この接続の版と機能を決める(仕様 7a.6 節)。
// m に protocol_min/protocol_max が無ければ legacy v0 とみなし、ok は常に true。両方あれば
// proto.SupportedProtocol との共通部分の最大を選ぶ。共通部分が無ければ ok は false で、
// 呼び出し元は m.ProtocolMin/m.ProtocolMax(非 nil であることは保証される)を使って断りの
// メッセージを組み立てる。
func negotiateVersion(m proto.Message) (sel proto.Negotiated, ok bool) {
	if m.ProtocolMin == nil || m.ProtocolMax == nil {
		return proto.Negotiated{Legacy: true}, true
	}
	remote := proto.ProtocolRange{Min: *m.ProtocolMin, Max: *m.ProtocolMax}
	version, overlap := proto.SelectProtocolVersion(proto.SupportedProtocol, remote)
	if !overlap {
		return proto.Negotiated{}, false
	}
	sel = proto.Negotiated{Version: version, AgentMin: remote.Min, AgentMax: remote.Max}
	if m.Capabilities != nil {
		sel.Capabilities = *m.Capabilities
	}
	return sel, true
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
