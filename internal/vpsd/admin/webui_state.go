package admin

import "github.com/rahanahu/wgft/proto"

// このファイルはルールの適用状態の判定(仕様 10.1 節)だけを持つ。ダッシュボードの一覧
// (webui.go の ruleToView)とルール詳細ページ(webui_rule.go の ruleDetailView)の両方が、
// ここの ruleRunState を経由してエージェントの直近のハートビートから状態を引く。

// serverApply は server 側のルールごとの適用状態を返す。報告が無ければ nil。
func (s *Server) serverApply() map[string]RuleApply {
	if st, ok := s.applyStatus(); ok {
		return st.Rules
	}
	return nil
}

// ruleAgentStatus はエージェント 1 台の直近のハートビートから引く、ルールの適用状態の
// 判定に要る部分だけの写し(仕様 10.1 節)。
type ruleAgentStatus struct {
	// Disabled はエージェントが無効であることである(設計文書 5.1 節)。
	Disabled   bool
	Connected  bool
	Generation uint64
	Rules      map[string]proto.RuleStatus
}

// buildAgentIndex はエージェント名 → ruleAgentStatus の表を作る。ruleRunState がこれで
// ルールの持ち主のエージェントを引く。
func buildAgentIndex(agents []AgentInfo) map[string]ruleAgentStatus {
	idx := make(map[string]ruleAgentStatus, len(agents))
	for _, a := range agents {
		rs := make(map[string]proto.RuleStatus, len(a.Rules))
		for _, r := range a.Rules {
			rs[r.ID] = r
		}
		idx[a.Name] = ruleAgentStatus{Disabled: a.Disabled, Connected: a.Connected, Generation: a.Generation, Rules: rs}
	}
	return idx
}

// ruleRunState はルールの適用状態を、server のデータプレーンへの適用状態(設計文書 7a.3 節)と、
// 持ち主のエージェントの直近のハートビートから判定する(仕様 10.1 節)。無効なルールはエージェントへ
// 配らないので、ハートビートの内容に関わらず disabled のままにする。判定の優先順位は、
// エージェントの無効、未登録、未接続が最優先、次に server 側で公開できていないこと(pending と not_active。
// 待ち受けの bind の失敗など)、次に世代の古さ(反映待ち)、最後にエージェントが報告したそのルールの
// 状態(ok/error)である。世代が最新なのにエージェントがまだそのルールを報告していない場合
// (追加直後など)も反映待ちとして扱う。server は nil なら server 側の状態を見ない。
//
// エージェントの無効と未登録は、どちらも故障ではないので灰色にする(設計文書 5.1、10.1 節)。
// 無効なエージェントのルールは server が公開から外し、not_active を報告するので、server 側の状態より
// 先に見る。見ないと、宣言どおりに止めたルールが赤の「公開していない」になる。
func ruleRunState(r *proto.Rule, latestGen uint64, agents map[string]ruleAgentStatus, server map[string]RuleApply, locale string) (badge, label, reason string) {
	if !r.Enabled {
		return "neutral", T(locale, "disabled"), ""
	}
	a, ok := agents[r.Agent]
	switch {
	case !ok:
		return "neutral", T(locale, "agentUnregistered"), ""
	case a.Disabled:
		return "neutral", T(locale, "agentDisabled"), ""
	case !a.Connected:
		return "neutral", T(locale, "agentOffline"), ""
	}
	if sa, ok := server[r.ID]; ok {
		switch sa.ApplyState {
		case ApplyNotActive:
			return "danger", T(locale, "serverNotActive"), sa.Reason
		case ApplyPending:
			return "warning", T(locale, "serverPending"), sa.Reason
		}
	}
	if latestGen > 0 && a.Generation != latestGen {
		return "warning", T(locale, "pending"), ""
	}
	rs, reported := a.Rules[r.ID]
	switch {
	case !reported:
		return "warning", T(locale, "pending"), ""
	case rs.State == proto.StatusError:
		return "danger", T(locale, "stateError"), rs.Reason
	default:
		return "success", T(locale, "applied"), ""
	}
}
