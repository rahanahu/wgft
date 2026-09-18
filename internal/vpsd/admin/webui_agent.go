package admin

import "net/http"

// このファイルはエージェントの追加(接続文字列の発行)、無効化、警告の削除のハンドラを持つ。
// エージェント一覧の表示側(agentToView)はダッシュボードの一部として webui.go にある。

func (s *Server) uiAddAgentForm(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, r, "addAgentTitle", "addagent", map[string]any{})
}

func (s *Server) uiAddAgent(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	res, err := s.backend.JoinString(r.FormValue("name"))
	if err != nil {
		s.renderPage(w, r, "addAgentTitle", "addagent", map[string]any{"Error": err.Error()})
		return
	}
	s.renderPage(w, r, "addAgentTitle", "addagent", map[string]any{"JoinString": res.JoinString, "ExpiresAt": res.ExpiresAt})
}

func (s *Server) uiRevoke(w http.ResponseWriter, r *http.Request) {
	s.redirectOrError(w, r, s.backend.Revoke(r.PathValue("name")))
}

func (s *Server) uiDismissWarning(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	s.redirectOrError(w, r, s.backend.DismissWarning(r.PathValue("name"), r.FormValue("kind"), r.FormValue("detail")))
}
