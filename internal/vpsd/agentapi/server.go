package agentapi

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// Backend はエージェント用 API が呼ぶ vpsd 側の操作。
type Backend interface {
	// Register は登録トークンと任意の名前でエージェントを作り、恒久トークン、割り当てアドレス、
	// 確定した名前(name が空ならトークンに紐付いた名前)を返す。
	// トークンが無効(未知・期限切れ・使用済み)、または name がトークンに紐付いた名前と違うときは store.ErrInvalidToken
	// (理由は分けない。総当たりの手がかりにしない)。
	// トークンは有効だが、紐付いた名前のエージェントがすでにいるときは store.ErrAgentAlreadyRegistered
	// (こちらは正規のトークンを持つ側への応答なので、理由を分けて構わない)。
	Register(joinToken, name, from string) (permanentToken, confirmedName string, addr netip.Addr, err error)
}

// RegisterRequest / RegisterResponse は登録の JSON(仕様 5.1 節)。name は任意。
type RegisterRequest struct {
	Token string `json:"token"`
	Name  string `json:"name,omitempty"`
}

type RegisterResponse struct {
	PermanentToken string `json:"permanent_token"`
	Address        string `json:"address"`
	Name           string `json:"name"` // 確定した名前(name を送らなければトークンに紐付いた名前)
}

// Server はエージェント用 API。
type Server struct {
	cert    tls.Certificate
	backend Backend
	limiter *ipLimiter
	mux     *http.ServeMux
}

// New は証明書を用意してハンドラを組み立てる。
func New(st *store.Store, backend Backend) (*Server, error) {
	cert, err := LoadOrCreateCert(st)
	if err != nil {
		return nil, err
	}
	s := &Server{cert: cert, backend: backend, limiter: newIPLimiter(1, 5), mux: http.NewServeMux()}
	s.mux.HandleFunc("POST /api/v1/agents/register", s.register)
	return s, nil
}

// Fingerprint は証明書の SHA-256(接続文字列用)。
func (s *Server) Fingerprint() [32]byte { return Fingerprint(s.cert) }

// Handle は stream など、後から足すエンドポイントを登録する。
func (s *Server) Handle(pattern string, h http.HandlerFunc) { s.mux.HandleFunc(pattern, h) }

// Allow は送信元 IP のレート制限(stream のハンドラも使う)。
func (s *Server) Allow(remoteAddr string) bool { return s.limiter.Allow(remoteAddr) }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.Allow(r.RemoteAddr) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	var req RegisterRequest
	// 名前は任意(空ならトークンに紐付いた名前)。あれば文字種を検証する。主は IssueJoinToken 側(仕様 5.1 節)で、
	// ここは防御としての二重チェック
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Token == "" || (req.Name != "" && !store.ValidAgentName(req.Name)) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	from, _, _ := net.SplitHostPort(r.RemoteAddr)
	tok, name, addr, err := s.backend.Register(req.Token, req.Name, from)
	if errors.Is(err, store.ErrInvalidToken) {
		// 理由は分けない(総当たりの手がかりにしない)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if errors.Is(err, store.ErrAgentAlreadyRegistered) {
		http.Error(w, "agent already registered", http.StatusConflict)
		return
	}
	if err != nil {
		log.Printf("agent api: register from %s: %v", from, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("agent api: registered agent %s (%s, from %s)", name, addr, from)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RegisterResponse{PermanentToken: tok, Address: addr.String(), Name: name})
}

// serverTimeouts は http.Server の期限(仕様 5 節。占有された接続がファイル記述子を
// 使い果たすのを防ぐ)。テストでは短い値に差し替える。
type serverTimeouts struct {
	ReadHeaderTimeout time.Duration // ヘッダを送り終えるまでの上限。既存
	ReadTimeout       time.Duration // 本文を含む、リクエスト全体を読み終えるまでの上限
	IdleTimeout       time.Duration // 次のリクエストを待つ keep-alive の上限
	MaxHeaderBytes    int
}

// defaultTimeouts は公開の agent API の既定値。
// WriteTimeout は持たない: stream は WebSocket へ hijack した接続で、hijack 後は
// net/http の WriteTimeout が効かないため、書きの期限は stream 側で別に持つ(stream/hub.go)。
var defaultTimeouts = serverTimeouts{
	ReadHeaderTimeout: 10 * time.Second,
	ReadTimeout:       15 * time.Second,
	IdleTimeout:       60 * time.Second,
	MaxHeaderBytes:    64 << 10, // 64 KiB
}

// newHTTPServer は http.Server を組み立てる(テストが短い期限を注入できるよう分けてある)。
func newHTTPServer(addr string, h http.Handler, tlsConfig *tls.Config, t serverTimeouts) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: t.ReadHeaderTimeout,
		ReadTimeout:       t.ReadTimeout,
		IdleTimeout:       t.IdleTimeout,
		MaxHeaderBytes:    t.MaxHeaderBytes,
	}
}

// Serve は TLS で待ち受ける(公開)。
func (s *Server) Serve(addr string) error {
	fp := s.Fingerprint()
	log.Printf("agent api: https://%s; certificate sha256:%x...", addr, fp[:4])
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12}
	srv := newHTTPServer(addr, s, tlsConfig, defaultTimeouts)
	return srv.ListenAndServeTLS("", "")
}
