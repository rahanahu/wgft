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

	"golang.org/x/net/netutil"

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
	log.Printf("agent api: registered agent %s at %s, from %s", name, addr, from)
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
		// HTTP/2 は使わない。エージェントとの通信は登録の POST と WebSocket(HTTP/1.1 の Upgrade)だけで、
		// h2 は公開面を広げるだけになる。空でない map を置くと net/http は h2 を広告しない。
		// 鍵交換の曲線は Go の既定に任せる(既定には耐量子のハイブリッドが含まれ、固定すると外れる)。
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
}

// maxAgentConns はエージェント用 API の同時接続数の固定上限(仕様 11 節)。11a 節の設定項目には
// しない(この上限は一度に受け付ける接続数の話であり、7 節の同時フロー数の上限とは別の軸である)。
// 数百台のエージェントが 1 本ずつ stream(WebSocket)を張っても十分な余裕を持たせてある。
// 上限に達した接続は accept を待つだけで、拒否や RST にはしない。すでに accept 済みで動いている
// stream はこの上限に関わらず切れない(LimitListener は Close されるまで数え続けるだけである)。
const maxAgentConns = 4096

// limitListener は ln の同時接続数を n で制限する(golang.org/x/net はすでに依存にある:
// internal/dataplane/userspace/tunnel が icmp/ipv4 で使っている)。n はテストが小さい値を
// 注入できるよう引数にしてある。
func limitListener(ln net.Listener, n int) net.Listener { return netutil.LimitListener(ln, n) }

// Serve は TLS で待ち受け、そのまま応答を続ける(公開。Listen と ServeListener を続けて呼ぶ)。
func (s *Server) Serve(addr string) error {
	ln, err := s.Listen(addr)
	if err != nil {
		return err
	}
	return s.ServeListener(ln)
}

// Listen は addr の TCP で待ち受けを開く。TLS は ServeListener が掛ける。待ち受けを開くところまでを
// 応答と分けるのは、vpsd が全部の待ち受けを開けてから起動完了のログを出すため(仕様 10.4 節)。
func (s *Server) Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	fp := s.Fingerprint()
	log.Printf("agent api: https://%s; certificate sha256:%x...", addr, fp[:4])
	return ln, nil
}

// ServeListener は Listen で開いた待ち受けで TLS の応答を続ける。
func (s *Server) ServeListener(ln net.Listener) error {
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12}
	srv := newHTTPServer(ln.Addr().String(), s, tlsConfig, defaultTimeouts)
	return srv.ServeTLS(limitListener(ln, maxAgentConns), "", "")
}
