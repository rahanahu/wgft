package admin

import "github.com/rahanahu/wgft/proto"

// このファイルはルールの適用状態の判定(仕様 10.1 節)だけを持つ。ダッシュボードの一覧
// (webui.go の ruleToView)とルール詳細ページ(webui_rule.go の ruleDetailView)の両方が、
// ここの ruleRunState を経由してエージェントの直近のハートビートから状態を引く。

// ruleAgentStatus はエージェント 1 台の直近のハートビートから引く、ルールの適用状態の
// 判定に要る部分だけの写し(仕様 10.1 節)。
type ruleAgentStatus struct {
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
		idx[a.Name] = ruleAgentStatus{Connected: a.Connected, Generation: a.Generation, Rules: rs}
	}
	return idx
}

// ruleRunState はルールの適用状態を、持ち主のエージェントの直近のハートビートから
// 判定する(仕様 10.1 節)。無効なルールはエージェントへ配らないので、
// ハートビートの内容に関わらず disabled のままにする。判定の優先順位は、
// エージェント未登録・未接続が最優先、次に世代の古さ(反映待ち)、最後にエージェントが
// 報告したそのルールの状態(ok/error)である。世代が最新なのにエージェントがまだその
// ルールを報告していない場合(追加直後など)も反映待ちとして扱う。
func ruleRunState(r *proto.Rule, latestGen uint64, agents map[string]ruleAgentStatus, locale string) (badge, label, reason string) {
	if !r.Enabled {
		return "neutral", T(locale, "disabled"), ""
	}
	a, ok := agents[r.Agent]
	if !ok || !a.Connected {
		return "neutral", T(locale, "agentOffline"), ""
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
