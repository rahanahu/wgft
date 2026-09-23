// Package admin は管理用 API(仕様 5, 11 節)。既定は Unix ソケット(root 所有 0600)で待ち受け、
// Web UI と CLI が使う。独自のパスワードは持たず、守りは Unix ソケットのパーミッション、
// Tailscale、SSH 転送という既存の境界と、ブラウザ経路の Host 検査・他オリジン発の変更の拒否で行う。
package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/adminapi"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// Backend は API が呼ぶ vpsd 側の操作。
type Backend interface {
	Rules() ([]proto.Rule, error)
	Generation() (uint64, error)
	// Batch は変更を 1 トランザクションで適用し、成功したら nftables などへ反映する。
	Batch(req BatchRequest) (*store.BatchResult, error)
	// AgentState はそのエージェントに配る全体状態(stream ができるまでの橋渡しにも使う)。
	AgentState(agent string) (*proto.State, error)
	// Agents は登録済みのエージェント。
	Agents() ([]AgentInfo, error)
	// RuleDrops は rule_id → 累積 drop パケット数。
	RuleDrops() (map[string]uint64, error)
	// JoinString は名前に紐付いた接続文字列を発行する(仕様 5.1 節)。
	JoinString(name string) (JoinStringResponse, error)
	// Revoke は恒久トークンを無効化し、ピアとアドレスを回収する(仕様 11 節)。
	Revoke(name string) error
	// Warnings は窃取検知の警告一覧。
	Warnings() ([]Warning, error)
	// DismissWarning は警告を消す(管理者が正当と確認したとき。仕様 5.2 節)。
	DismissWarning(agent, kind, detail string) error
	// CheckConnectivity は TCP ルールの疎通確認(仕様 10.1 節)。
	CheckConnectivity(ruleID string) (ConnCheck, error)
	// ServerInfo は vpsd/VPS の構成と環境(ダッシュボード上部に出す)。
	ServerInfo() (ServerInfo, error)
}

// ServerInfo は vpsd 自身と VPS 環境の情報(仕様 10.1)。
type ServerInfo struct {
	Version          string `json:"version"`
	Mode             string `json:"mode"` // 転送方式 kernel / userspace(仕様 9・11a 節)
	StartedAt        string `json:"started_at"`
	WGInterface      string `json:"wg_interface"`
	WGAddress        string `json:"wg_address"`
	WGPort           int    `json:"wg_port"`
	WGEndpoint       string `json:"wg_endpoint"`
	AgentAPIPort     string `json:"agent_api_port"`
	AdminAddr        string `json:"admin_addr"`
	MTU              int    `json:"mtu"`
	ServerPubKey     string `json:"server_public_key"`
	Kernel           string `json:"kernel"`
	NFT              string `json:"nft"`
	IPForwardSetAt   string `json:"ip_forward_set_at"`
	UDPTimeout       int    `json:"udp_timeout"`
	UDPTimeoutStream int    `json:"udp_timeout_stream"`
}

// ReservedFromServerInfo builds the proto.Reserved set a real Batch refuses a listen_port for,
// from a ServerInfo report of the server's own ports. It mirrors, field for field, how
// internal/vpsd/vpsd.go builds Daemon.reserved at startup (around opts.WGPort/AdminAddr/
// AgentAPIAddr): the WireGuard port is always reserved; the admin API's port is reserved only
// when AdminAddr parses as host:port (a Unix socket, e.g. the default
// "unix:///run/wgft/admin.sock", does not reserve a port); the agent API's port comes from
// AgentAPIPort, which this struct's producers (Daemon.ServerInfo, the admin client's ServerInfo)
// already return net.SplitHostPort'd (an empty or unparseable value reserves nothing for it, the
// same as a net.SplitHostPort failure in vpsd.go).
//
// Both `rule add`/`rule set --dry-run` (cmd/wgft/rule.go) and the Web UI's read-import
// confirmation (webui_import.go's importIssues) call this function so the reserved-port rule
// cannot drift between the two callers the way it once did (design.md's revision record,
// --dry-run entry): the CLI reconstructed the rule from ServerInfo on its own, the Web UI passed
// nil, and only the CLI's copy was ever fixed to match Daemon.reserved.
func ReservedFromServerInfo(info ServerInfo) proto.Reserved {
	reserved := proto.Reserved{uint16(info.WGPort): "WireGuard"}
	if ap, err := netip.ParseAddrPort(info.AdminAddr); err == nil {
		reserved[ap.Port()] = "admin API"
	}
	if ap, err := netip.ParseAddrPort("0.0.0.0:" + info.AgentAPIPort); err == nil {
		reserved[ap.Port()] = "agent API"
	}
	return reserved
}

// この API の読み取り側の型は internal/vpsd/adminapi が持ち、ここで同じ名前に別名を付ける
// (design.md 10.2d 節)。診断(internal/vpsd/doctor)がこれらを証拠として読み、その doctor を
// この package が import する以上、doctor からこの package への import は循環になる。別名なので
// admin.AgentInfo と adminapi.AgentInfo は同一の型であり、JSON の形も呼び出し側も変わらない。
type (
	// ConnCheck は疎通確認の結果。Reach は "target" / "agent" / "none"。
	ConnCheck = adminapi.ConnCheck
	// Warning は窃取検知の警告 1 件。
	Warning = adminapi.Warning
	// AgentInfo はエージェント一覧の 1 行(仕様 10.1 節)。
	AgentInfo = adminapi.AgentInfo
	// BatchResponse はバッチの結果。
	BatchResponse = adminapi.BatchResponse
)

// JoinStringRequest / JoinStringResponse は接続文字列の発行。
type JoinStringRequest struct {
	Name string `json:"name"`
}

// JoinStringResponse は接続文字列の発行結果。ExpiresAt は RFC 3339。
type JoinStringResponse struct {
	JoinString string `json:"join_string"`
	ExpiresAt  string `json:"expires_at"`
}

// BatchRequest はルールの追加・変更・削除をまとめて行う(仕様 5.4 節)。
type BatchRequest struct {
	Upsert []proto.Rule `json:"upsert"` // ID があれば置き換え、なければ追加
	Delete []string     `json:"delete"` // ID
	Force  bool         `json:"force"`  // bind 中のポートとの衝突を無視する
	// ExpectedDigest は任意(空なら検査しない、既存の呼び出し元と互換)。指定すると、
	// Batch はこのバッチが変更しようとしている今のルール集合の proto.RulesDigest と
	// 一致するかを、読み取りと変更を 1 トランザクション/1 ロックの内側で照合する。
	// 一致しなければ何も変えず ErrBatchConflict を返す。読み取ってから Batch を呼ぶまでの
	// 間に他経路(別の CLI 呼び出しや別タブの Web UI)が割り込む競合を塞ぐためのもの
	// (仕様 5.4、10.1 節)。Web UI の読み込み確認・適用はこれを使う(webui_import.go)。
	ExpectedDigest string `json:"expected_digest,omitempty"`
	// Op はこの変更の出どころ(ログの識別用。例 "ui import"、"cli rule add")。
	// 空なら Batch の実装が既定("api")を補う。
	Op string `json:"op,omitempty"`
}

// ErrBatchConflict は Backend.Batch が ExpectedDigest の不一致で拒んだときの誤り。
// 管理用 API は HTTP 409 に写し、Web UI の読み込み確認はこれを、確認ページを描いた後に
// 変わった場合と同じ「re-upload を求める」画面に写す(webui_import.go の uiImportApply)。
var ErrBatchConflict = errors.New("rules changed since the expected digest was read")

// ApplyBatchToRules は ExpectedDigest を照合したうえで、req の upsert/delete を rules に
// ID で当てはめた結果を返す(ID があれば置き換え、なければ追加。delete は最後に外す)。
// 本物の Backend(internal/vpsd の Daemon.Batch)はエージェントの登録確認や nftables への
// 反映、同じ ExpectedDigest の照合も行うが、ここにはその一部が無い。fake や demo の
// Backend 実装(admin_test.go の fakeBackend、tools/uidemo のもの)が、CLI/Web UI から見た
// 見た目だけを本物に合わせるために共有する組み立てである。store.ApplyBatch の mutate に
// そのまま渡せる ([]proto.Rule, error) を返す形にしているのは、rules がその関数の中で
// 読み取る「今の」集合そのもの(トランザクションの内側)であることを利用して、
// ExpectedDigest の照合を読み取りと変更の間に割り込みの余地なく行うためである。
func ApplyBatchToRules(rules []proto.Rule, req BatchRequest) ([]proto.Rule, error) {
	if req.ExpectedDigest != "" && proto.RulesDigest(rules) != req.ExpectedDigest {
		return nil, ErrBatchConflict
	}
	del := make(map[string]bool, len(req.Delete))
	for _, id := range req.Delete {
		del[id] = true
	}
	kept := make([]proto.Rule, 0, len(rules))
	for _, r := range rules {
		if !del[r.ID] {
			kept = append(kept, r)
		}
	}
	byID := make(map[string]int, len(kept))
	for i, r := range kept {
		byID[r.ID] = i
	}
	for _, u := range req.Upsert {
		if i, ok := byID[u.ID]; ok {
			kept[i] = u
		} else {
			byID[u.ID] = len(kept)
			kept = append(kept, u)
		}
	}
	return kept, nil
}

// ErrorBody は失敗時の本文。
type ErrorBody struct {
	Error string `json:"error"`
}

// Server は管理用 API の HTTP ハンドラ。
type Server struct {
	backend Backend
	mux     *http.ServeMux
	// AllowedHosts は localhost / 127.0.0.1 / [::1] に加えて許可する Host(tailnet 名・IP、--admin-host)。
	AllowedHosts []string
}

// New はハンドラを組み立てる。
func New(backend Backend) *Server {
	s := &Server{backend: backend, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /api/v1/rules", s.getRules)
	s.mux.HandleFunc("POST /api/v1/rules/batch", s.postBatch)
	s.mux.HandleFunc("GET /api/v1/agents", s.getAgents)
	s.mux.HandleFunc("POST /api/v1/agents/join-string", s.postJoinString)
	s.mux.HandleFunc("DELETE /api/v1/agents/{name}", s.deleteAgent)
	s.mux.HandleFunc("GET /api/v1/warnings", s.getWarnings)
	s.mux.HandleFunc("POST /api/v1/agents/{name}/dismiss-warning", s.postDismissWarning)
	s.mux.HandleFunc("GET /api/v1/agents/{name}/state", s.getAgentState)
	s.mux.HandleFunc("GET /api/v1/nft", s.getNFT)
	s.mux.HandleFunc("POST /api/v1/rules/{id}/check", s.postCheck)
	s.mux.HandleFunc("GET /api/v1/server", s.getServerInfo)
	s.registerUI()
	return s
}

// securityHeaders は Web UI と JSON の両方の応答に付ける防御的なヘッダ(仕様 11 節)。テンプレートが
// 実際に読み込むもの(/static/ 配下の自オリジンの JS・CSS と、インラインの style 属性)だけを許す。
// 画像、フォント、外部ドメインの読み込みは無いので default-src 'self' の外を空ける必要は無い。
// /static/ の応答は変わらず埋め込みの静的資産なので、Cache-Control: no-store は付けない
// (それ以外の応答には接続文字列などの秘密が乗ることがあるため付ける)。
func securityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy",
		"default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	if !strings.HasPrefix(r.URL.Path, "/static/") {
		h.Set("Cache-Control", "no-store")
	}
}

// ServeHTTP は防御的なヘッダを付けたうえで、Host と Origin の検査(仕様 11 節)を通してから mux に渡す。
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w, r)
	// Host 検査:DNS リバインディングを防ぐ。CLI(Unix ソケット/ループバック)も localhost で通る
	if !s.hostAllowed(hostOnly(r.Host)) {
		writeError(w, http.StatusForbidden, "Host not allowed; open it via SSH forwarding or Tailscale")
		return
	}
	// 他オリジン発の変更の拒否(CSRF):GET/HEAD 以外で、他サイト発なら拒否。CLI はヘッダを送らないので通る
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
			writeError(w, http.StatusForbidden, "cross-origin operations are rejected")
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !s.hostAllowed(originHost(o)) {
			writeError(w, http.StatusForbidden, "cross-origin operations are rejected")
			return
		}
	}
	s.mux.ServeHTTP(w, r)
}

// hostAllowed は Host が許可リストにあるか。localhost 系は常に許可。
func (s *Server) hostAllowed(host string) bool {
	if host == "" {
		return false
	}
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	for _, h := range s.AllowedHosts {
		if host == h {
			return true
		}
	}
	return false
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func originHost(origin string) string {
	origin = strings.TrimPrefix(origin, "http://")
	origin = strings.TrimPrefix(origin, "https://")
	return hostOnly(origin)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorBody{Error: msg})
}

// rulesResponse は GET /api/v1/rules の本文を組み立てる。HTTP の応答と、同じプロセスの中の
// 読み手(Web UI の診断の画面。webui_doctor.go)がここを共有するので、CLI 経由と画面とで違う
// 値を見ることがない(design.md 10.2d 節)。
func (s *Server) rulesResponse() (BatchResponse, error) {
	rules, err := s.backend.Rules()
	if err != nil {
		return BatchResponse{}, err
	}
	if rules == nil {
		rules = []proto.Rule{}
	}
	gen, err := s.backend.Generation()
	if err != nil {
		return BatchResponse{}, err
	}
	drops, err := s.backend.RuleDrops()
	if err != nil {
		return BatchResponse{}, err
	}
	resp := BatchResponse{Generation: gen, Rules: rules, Drops: drops}
	s.withApply(&resp)
	s.withResourceStatus(&resp)
	s.withAgentRuleStatus(&resp)
	return resp, nil
}

func (s *Server) getRules(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rulesResponse()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) postBatch(w http.ResponseWriter, r *http.Request) {
	var req BatchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON: "+err.Error())
		return
	}
	res, err := s.backend.Batch(req)
	if err != nil {
		if errors.Is(err, ErrBatchConflict) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	resp := BatchResponse{Generation: res.Generation, Changed: res.Changed, Rules: res.Rules}
	s.withApply(&resp)
	s.withResourceStatus(&resp)
	s.withAgentRuleStatus(&resp)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) getAgents(w http.ResponseWriter, r *http.Request) {
	names, err := s.backend.Agents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if names == nil {
		names = []AgentInfo{}
	}
	writeJSON(w, http.StatusOK, names)
}

func (s *Server) postJoinString(w http.ResponseWriter, r *http.Request) {
	var req JoinStringRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	res, err := s.backend.JoinString(req.Name)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) deleteAgent(w http.ResponseWriter, r *http.Request) {
	if err := s.backend.Revoke(r.PathValue("name")); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getWarnings(w http.ResponseWriter, r *http.Request) {
	ws, err := s.backend.Warnings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ws == nil {
		ws = []Warning{}
	}
	writeJSON(w, http.StatusOK, ws)
}

func (s *Server) postDismissWarning(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind   string `json:"kind"`
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Kind == "" {
		writeError(w, http.StatusBadRequest, "kind is required")
		return
	}
	if err := s.backend.DismissWarning(r.PathValue("name"), req.Kind, req.Detail); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getAgentState(w http.ResponseWriter, r *http.Request) {
	st, err := s.backend.AgentState(r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) postCheck(w http.ResponseWriter, r *http.Request) {
	res, err := s.backend.CheckConnectivity(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// getNFT は適用中の wgft テーブルをそのまま返す(wgft nft show)。nft の CLI に任せる。
func (s *Server) getNFT(w http.ResponseWriter, r *http.Request) {
	if info, err := s.backend.ServerInfo(); err == nil && info.Mode == "userspace" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "userspace mode: nftables is not used; rules are relayed by the wgft process")
		return
	}
	out, err := exec.Command("nft", "list", "table", "inet", "wgft").CombinedOutput()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("nft: %v: %s", err, out))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(out)
}

// getServerInfo は vpsd/VPS の構成と環境を返す(ダッシュボード上部に加え、`rule add`/`rule set`
// `--dry-run` が予約ポートを組み立てる元にする。design.md 11a 節)。
func (s *Server) getServerInfo(w http.ResponseWriter, r *http.Request) {
	info, err := s.backend.ServerInfo()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// Serve は addr で待ち受け、そのまま応答を続ける(Listen と ServeListener を続けて呼ぶ)。
func Serve(addr string, h http.Handler, warnNonLoopback bool) error {
	ln, err := Listen(addr, warnNonLoopback)
	if err != nil {
		return err
	}
	return ServeListener(ln, h)
}

// Listen は addr で待ち受けを開く。addr が unix:// で始まれば Unix ソケット(0600、root 所有)、
// それ以外は TCP。warnNonLoopback が真で TCP がループバックでなければ起動ログに警告する。
// 待ち受けを開くところまでを応答と分けるのは、vpsd が全部の待ち受けを開けてから起動完了の
// ログを出すため(仕様 10.4 節)。
func Listen(addr string, warnNonLoopback bool) (net.Listener, error) {
	if socket, ok := strings.CutPrefix(addr, "unix://"); ok {
		if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
			return nil, err
		}
		_ = os.Remove(socket) // 古いソケットを掃除
		ln, err := net.Listen("unix", socket)
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(socket, 0o600); err != nil {
			ln.Close()
			return nil, err
		}
		log.Printf("admin api: unix://%s, permissions 0600", socket)
		return ln, nil
	}
	if warnNonLoopback && !isLoopbackAddr(addr) {
		log.Printf("warning: admin api opened on non-loopback %s; SSH port forwarding or Tailscale is recommended", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	log.Printf("admin api: http://%s", addr)
	return ln, nil
}

// adminTimeouts は TCP で開いた管理用 API の http.Server の期限。テストが短い値を注入できるよう
// 分けてある(agentapi.serverTimeouts と同じ形)。
type adminTimeouts struct {
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

// defaultAdminTCPTimeouts は TCP で開いたときの既定値(仕様 11 節)。管理用 API の応答はどれも
// 束縛されている(JSON はバッチの本文の上限、書き出しはルール一覧、読み込みの確認は
// importMaxBytes・importApplyMaxBytes に収まる)ので、WriteTimeout を付けても中断しない。
// Unix ソケットは既存の信頼している境界の内側(root、SSH、Tailscale)だけなので期限を付けない。
var defaultAdminTCPTimeouts = adminTimeouts{
	ReadHeaderTimeout: 10 * time.Second,
	ReadTimeout:       30 * time.Second,
	WriteTimeout:      30 * time.Second,
	IdleTimeout:       120 * time.Second,
}

// newAdminHTTPServer は http.Server を組み立てる(テストが短い期限を注入できるよう分けてある)。
func newAdminHTTPServer(h http.Handler, t adminTimeouts) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: t.ReadHeaderTimeout,
		ReadTimeout:       t.ReadTimeout,
		WriteTimeout:      t.WriteTimeout,
		IdleTimeout:       t.IdleTimeout,
	}
}

// adminServerFor は ln の種類に応じた http.Server を組み立てる(ServeListener と、期限を
// 直接検査するテストが共有する)。
func adminServerFor(ln net.Listener, h http.Handler) *http.Server {
	if ln.Addr().Network() == "unix" {
		return &http.Server{Handler: h}
	}
	return newAdminHTTPServer(h, defaultAdminTCPTimeouts)
}

// ServeListener は Listen で開いた待ち受けで応答を続ける。ln が Unix ソケットなら期限を付けない
// (相手は root か、その root に入れる人に限られる)。TCP なら defaultAdminTCPTimeouts を付ける。
func ServeListener(ln net.Listener, h http.Handler) error {
	return adminServerFor(ln, h).Serve(ln)
}

func isLoopbackAddr(addr string) bool {
	host := hostOnly(addr)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
