// Package admin は管理用 API(仕様 5, 11 節)。既定は Unix ソケット(root 所有 0600)で待ち受け、
// Web UI と CLI が使う。独自のパスワードは持たず、守りは Unix ソケットのパーミッション、
// Tailscale、SSH 転送という既存の境界と、ブラウザ経路の Host 検査・他オリジン発の変更の拒否で行う。
package admin

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

// ConnCheck は疎通確認の結果。Reach は "target" / "agent" / "none"。
type ConnCheck struct {
	OK     bool   `json:"ok"`
	Reach  string `json:"reach"`
	Detail string `json:"detail"`
}

// Warning は窃取検知の警告 1 件。
type Warning struct {
	Agent  string `json:"agent"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	At     string `json:"at"`
}

// AgentInfo はエージェント一覧の 1 行(仕様 10.1 節)。
type AgentInfo struct {
	Name           string `json:"name"`
	Address        string `json:"address"`
	PublicKey      string `json:"public_key,omitempty"`
	RegisteredFrom string `json:"registered_from"`
	CreatedAt      string `json:"created_at"`
	// stream
	Connected     bool               `json:"connected"`
	StreamFrom    string             `json:"stream_from,omitempty"`
	LastHeartbeat string             `json:"last_heartbeat,omitempty"`
	Generation    uint64             `json:"generation"` // 処理済み世代
	Tunnel        proto.TunnelStatus `json:"tunnel"`
	Rules         []proto.RuleStatus `json:"rules,omitempty"`
	// wg
	WGEndpoint    string `json:"wg_endpoint,omitempty"`
	LastHandshake string `json:"last_handshake,omitempty"`
	// 窃取検知
	Warnings []Warning `json:"warnings,omitempty"`
}

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
}

// ApplyBatchToRules は req の upsert/delete を rules に ID で当てはめた結果を返す
// (ID があれば置き換え、なければ追加。delete は最後に外す)。本物の Backend
// (internal/vpsd の Daemon.Batch)はエージェントの登録確認や nftables への反映も
// 行うが、ここにはそれが無い。fake や demo の Backend 実装(admin_test.go の
// fakeBackend、tools/uidemo のもの)が、CLI/Web UI から見た見た目だけを本物に
// 合わせるために共有する、副作用の無い組み立てである。
func ApplyBatchToRules(rules []proto.Rule, req BatchRequest) []proto.Rule {
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
	return kept
}

// BatchResponse はバッチの結果。
type BatchResponse struct {
	Generation uint64            `json:"generation"`
	Changed    bool              `json:"changed"`
	Rules      []proto.Rule      `json:"rules"`
	Drops      map[string]uint64 `json:"drops,omitempty"` // rule_id → 累積 drop パケット数
}

// ErrorBody は失敗時の本文。
type ErrorBody struct {
	Error string `json:"error"`
}

// Server は管理用 API の HTTP ハンドラ。
type Server struct {
	st      *store.Store
	backend Backend
	mux     *http.ServeMux
	// AllowedHosts は localhost / 127.0.0.1 / [::1] に加えて許可する Host(tailnet 名・IP、--admin-host)。
	AllowedHosts []string
}

// New はハンドラを組み立てる。
func New(st *store.Store, backend Backend) *Server {
	s := &Server{st: st, backend: backend, mux: http.NewServeMux()}
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
	s.registerUI()
	return s
}

// ServeHTTP は Host と Origin の検査(仕様 11 節)を通してから mux に渡す。
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) getRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.backend.Rules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rules == nil {
		rules = []proto.Rule{}
	}
	gen, _ := s.backend.Generation()
	drops, _ := s.backend.RuleDrops()
	writeJSON(w, http.StatusOK, BatchResponse{Generation: gen, Rules: rules, Drops: drops})
}

func (s *Server) postBatch(w http.ResponseWriter, r *http.Request) {
	var req BatchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON: "+err.Error())
		return
	}
	res, err := s.backend.Batch(req)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, BatchResponse{Generation: res.Generation, Changed: res.Changed, Rules: res.Rules})
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

// Serve は addr で待ち受ける。addr が unix:// で始まれば Unix ソケット(0600、root 所有)、
// それ以外は TCP。warnNonLoopback が真で TCP がループバックでなければ起動ログに警告する。
func Serve(addr string, h http.Handler, warnNonLoopback bool) error {
	if socket, ok := strings.CutPrefix(addr, "unix://"); ok {
		if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
			return err
		}
		_ = os.Remove(socket) // 古いソケットを掃除
		ln, err := net.Listen("unix", socket)
		if err != nil {
			return err
		}
		if err := os.Chmod(socket, 0o600); err != nil {
			return err
		}
		log.Printf("admin api: unix://%s (0600)", socket)
		return (&http.Server{Handler: h}).Serve(ln)
	}
	if warnNonLoopback && !isLoopbackAddr(addr) {
		log.Printf("warning: admin api opened on non-loopback %s; SSH port forwarding or Tailscale recommended, spec section 11", addr)
	}
	log.Printf("admin api: http://%s", addr)
	return (&http.Server{Addr: addr, Handler: h}).ListenAndServe()
}

func isLoopbackAddr(addr string) bool {
	host := hostOnly(addr)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
