package agentapi

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/netutil"

	"github.com/rahanahu/wgft/internal/lograte"
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
// 使い果たすのを防ぐ)。テストでは短い値に差し替える。keep-alive は使わない(newHTTPServer)ので、
// 次のリクエストを待つ期限(IdleTimeout)は持たない。
type serverTimeouts struct {
	ReadHeaderTimeout time.Duration // ヘッダを送り終えるまでの上限。既存
	ReadTimeout       time.Duration // 本文を含む、リクエスト全体を読み終えるまでの上限
	MaxHeaderBytes    int
}

// defaultTimeouts は公開の agent API の既定値。
// WriteTimeout は持たない: stream は WebSocket へ hijack した接続で、hijack 後は
// net/http の WriteTimeout が効かないため、書きの期限は stream 側で別に持つ(stream/hub.go)。
var defaultTimeouts = serverTimeouts{
	ReadHeaderTimeout: 10 * time.Second,
	ReadTimeout:       15 * time.Second,
	MaxHeaderBytes:    64 << 10, // 64 KiB
}

// newHTTPServer は http.Server を組み立てる(テストが短い期限を注入できるよう分けてある)。
func newHTTPServer(addr string, h http.Handler, tlsConfig *tls.Config, t serverTimeouts) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: t.ReadHeaderTimeout,
		ReadTimeout:       t.ReadTimeout,
		MaxHeaderBytes:    t.MaxHeaderBytes,
		// HTTP/2 は使わない。エージェントとの通信は登録の POST と WebSocket(HTTP/1.1 の Upgrade)だけで、
		// h2 は公開面を広げるだけになる。空でない map を置くと net/http は h2 を広告しない。
		// 鍵交換の曲線は Go の既定に任せる(既定には耐量子のハイブリッドが含まれ、固定すると外れる)。
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:     log.New(&handshakeErrorLog{}, "", 0),
		// stream のハンドラが、認証を通った接続を送信元の未認証の数から外せるようにする(sourcelimit.go)
		ConnContext: withSourceConn,
	}
	// keep-alive は使わない。エージェントは登録と stream の接続のたびに新しい HTTP クライアントを
	// 作るので、応答の後に接続を残しても使い直されない。残すと、未認証の接続として送信元の枠
	// (maxPreAuthConnsPerSource)を占め続ける。WebSocket への切り替え(101)の応答は net/http が
	// Connection: close を付けないので、stream には影響しない。
	srv.SetKeepAlivesEnabled(false)
	return srv
}

// handshakeErrorLog は net/http が書く誤りの行を、このプロセスのログへ渡す。TLS の
// ハンドシェイクを相手が証明書を理由に拒んだ行にだけ、読み方を添える。エージェントは登録のときに
// 固定した証明書のハッシュと合わなければ拒むので、server teardown --purge で作り直した server には、
// 古い証明書を固定したままのエージェントの行が "remote error: tls: bad certificate" として並ぶ。
// どのエージェントかは言えない。相手は名乗る前にハンドシェイクを終え、作り直した server のデータ
// ベースにはそのエージェントの記録も無いためである。送信元のアドレスは net/http の行が既に持つ。
//
// 未認証の相手は、TLS のハンドシェイクを送らずに閉じるだけで、"TLS handshake error" の行を
// 1 本につき 1 行ここに出させられる(仕様 11 節。送信元ごとの上限 maxPreAuthConnsPerSource は
// 同時の本数しか縛らない)。行数は相手の接続の速さで決まり、Docker の既定の json-file のログ
// (回転しない)ではディスクを、systemd では journald の速度の制限を埋める。中継の接続ごとの行を
// 待ち受けごとに 1 分に 1 回へ間引く方針(改訂の記録 2026-09-19)に合わせ、この行を、証明書を
// 理由に拒んだもの(cert)とその他(other)の 2 つに分け、理由ごとに 1 分に 1 回まで間引く。
// cert は運用の案内(badCertHint)を持つので、その他の理由が続いても埋もれないよう別の門を持つ。
// 理由の文面そのもの(TLS の誤りの種類)を鍵にした間引きはしない。ALPN の一覧や暗号方式の一覧
// など相手が送った値をそのまま埋め込む理由文があり(Go の crypto/tls の一部のエラー文言)、鍵の
// 数を相手が増やせてしまうため。間引いた行があれば、次に出す行に件数を添える
// (internal/agent/stream.go の reconnectLog と同じ形)。
//
// この Writer は http.Server.ErrorLog として net/http のすべての誤りの行(ハンドラの panic、
// Accept の誤りなど)も受ける。相手が接続ごとに自由に出させられるのは "TLS handshake error" の
// 行だけなので、間引きはこの行だけに掛け、他の行はそのまま出す。他の行まで間引くと、走査の雑音が
// 門を閉じている間に panic や fd の枯渇のような、運用に要る行が出なくなる。
type handshakeErrorLog struct {
	mu    sync.Mutex
	cert  gatedCount
	other gatedCount
}

// gatedCount は 1 分に 1 回まで開く門(lograte.Gate)と、閉じている間に間引いた回数の組である。
type gatedCount struct {
	gate       lograte.Gate
	suppressed int
}

// allow は、この理由の行を今出してよいかと、出す場合に前回出した行からの間に間引いた回数を返す
// (回数は返した時点で 0 に戻す)。呼び出し側が持つ鎖(handshakeErrorLog.mu)の下で呼ぶ。
func (gc *gatedCount) allow() (open bool, suppressed int) {
	return gc.record(gc.gate.Allow())
}

// record は、gc.gate.Allow() の結果を受け取って帳簿を更新する。門の実時間の判定(allow)から
// 分けてあるので、件数の受け渡しと 0 への戻しは、1 分を待たずに record を直接呼ぶテストで
// 固定できる。
func (gc *gatedCount) record(opened bool) (open bool, suppressed int) {
	if !opened {
		gc.suppressed++
		return false, 0
	}
	suppressed, gc.suppressed = gc.suppressed, 0
	return true, suppressed
}

// badCertHint は、相手が証明書を拒んだハンドシェイクの行に添える句である。
const badCertHint = "; the client refused this server's certificate. An agent does this when it pinned another certificate " +
	"at registration, as after wgft server teardown --purge; the handshake ends before the agent names itself, so this server " +
	"cannot tell which agent it is. That agent needs a new join string from wgft agent join-string --name <agent>"

func (h *handshakeErrorLog) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n")
	if !strings.Contains(line, "TLS handshake error") {
		// 相手が接続ごとに自由に出させられる行ではない(ハンドラの panic、Accept の誤りなど)ので
		// 間引かない。
		log.Print(line)
		return len(p), nil
	}
	// net/http の行は "...: <err>" で終わり、証明書を拒んだ alert のエラー文は "remote error:
	// tls: bad certificate" である(crypto/tls の net.OpError{Op: "remote error", Err: alert(...)})。
	// 行のどこかに部分文字列があるかではなく、行の終わりがこれと一致するかで判定する。相手が
	// ALPN の一覧などに同じ文字列を混ぜても、行の終わりには出ないため判定されない。
	isBadCert := strings.HasSuffix(line, "remote error: tls: bad certificate")

	h.mu.Lock()
	gc := &h.other
	if isBadCert {
		gc = &h.cert
	}
	opened, suppressed := gc.allow()
	h.mu.Unlock()

	if !opened {
		return len(p), nil
	}
	log.Print(formatHandshakeErrorLine(line, isBadCert, suppressed))
	return len(p), nil
}

// formatHandshakeErrorLine は、門を通った行の文面を組み立てる。件数は、前回出した行からの
// 間に間引いた行の数であり、必ずしも同じ文面とは限らない("other" は複数の理由をまとめる)ので、
// 時間の幅や同一性を言わない文面にする(internal/agent/stream.go の reconnectLog と同じ考え方)。
func formatHandshakeErrorLine(line string, isBadCert bool, suppressed int) string {
	if isBadCert {
		line += badCertHint
	}
	if suppressed > 0 {
		line = fmt.Sprintf("%s; %d similar line(s) not logged since the previous one", line, suppressed)
	}
	return line
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
	return s.serveListener(ln, maxAgentConns, maxPreAuthConnsPerSource)
}

// serveListener は ServeListener の本体である。2 つの上限はテストが小さい値を注入できるよう引数にしてある。
func (s *Server) serveListener(ln net.Listener, total, perSource int) error {
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12}
	srv := newHTTPServer(ln.Addr().String(), s, tlsConfig, defaultTimeouts)
	// 送信元ごとの枠を外側に置く。TLS の接続の下に sourceConn が直接来るので、stream のハンドラが
	// 認証を通った接続を枠から外せる(withSourceConn)。上限を超えて閉じた接続は、全体の枠も閉じた
	// ときに返す。
	return srv.ServeTLS(newSourceLimitListener(limitListener(ln, total), perSource), "", "")
}
