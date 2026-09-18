package admin

import (
	"net/http"

	"github.com/rahanahu/wgft/proto"
)

// このファイルはルール詳細ページの分割・統合区画(仕様 10.1、10.2 節)を持つ。組み立てと
// 検査そのものは proto.Rule.Split / proto.Merge / proto.FindMergeBlocker にあり、CLI の
// `rule split` / `rule merge`(cmd/wgft/rule.go)と共有する。ここにあるのは、統合候補を
// 隣接ルールから探して訳済みの理由を添える、Web UI だけの表示組み立てである。

// mergeCandidateView は統合区画の 1 行。候補ならボタンを、候補でなければ Reason を持つ。
type mergeCandidateView struct {
	ID, Ports, Target, Reason string
}

// mergeSection は統合区画のビューを組み立てる(仕様 10.1 節)。同じプロトコルの
// 他のルールから listen_port が直接隣接するもの(直前・直後、それぞれ最大 1 件)を探し、
// proto.FindMergeBlocker が BlockNone を返すものを候補として全部出す。候補が 1 つも
// 無く、隣接ルールがあるときは、直前を優先してその理由を 1 件だけ出す。
func mergeSection(rule proto.Rule, all []proto.Rule, locale string) (candidates []mergeCandidateView, blocked *mergeCandidateView) {
	below, above := mergeNeighbors(rule, all)
	for _, n := range []*proto.Rule{below, above} {
		if n == nil {
			continue
		}
		if proto.FindMergeBlocker(rule, *n) == proto.BlockNone {
			candidates = append(candidates, mergeCandidateToView(*n, ""))
		}
	}
	if len(candidates) > 0 {
		return candidates, nil
	}
	nearest := below
	if nearest == nil {
		nearest = above
	}
	if nearest == nil {
		return nil, nil
	}
	v := mergeCandidateToView(*nearest, mergeBlockerLabel(proto.FindMergeBlocker(rule, *nearest), locale))
	return nil, &v
}

// mergeNeighbors は rule と同じプロトコルの他のルールから、listen_port の範囲が直接
// 隣接するものを探す。プロトコルの名前空間はポートごとに独立なので他は見ない(仕様 5.3
// 節)。範囲は重ならない制約(proto.ValidateRules)があるので、直前・直後それぞれ最大 1 件。
func mergeNeighbors(rule proto.Rule, all []proto.Rule) (below, above *proto.Rule) {
	for i := range all {
		o := &all[i]
		if o.ID == rule.ID || o.Proto != rule.Proto {
			continue
		}
		switch {
		case o.ListenPort.Hi+1 == rule.ListenPort.Lo:
			below = o
		case rule.ListenPort.Hi+1 == o.ListenPort.Lo:
			above = o
		}
	}
	return below, above
}

func mergeCandidateToView(r proto.Rule, reason string) mergeCandidateView {
	return mergeCandidateView{ID: r.ID, Ports: r.ListenPort.String(), Target: r.TargetDisplay(), Reason: reason}
}

var mergeBlockerKeys = map[proto.MergeBlocker]string{
	proto.BlockAgent:       "mbAgent",
	proto.BlockProto:       "mbProto",
	proto.BlockMode:        "mbMode",
	proto.BlockNotAdjacent: "mbNotAdjacent",
	proto.BlockTargetGap:   "mbTargetGap",
	proto.BlockProxyRange:  "mbProxyRange",
	proto.BlockDenyList:    "mbDenyList",
	proto.BlockAllowList:   "mbAllowList",
	proto.BlockRates:       "mbRates",
	proto.BlockEnabled:     "mbEnabled",
}

// mergeBlockerLabel は proto.MergeBlocker を、統合区画に出す訳済みの短い理由に変える。
func mergeBlockerLabel(blk proto.MergeBlocker, locale string) string {
	if key, ok := mergeBlockerKeys[blk]; ok {
		return T(locale, key)
	}
	return string(blk)
}

// uiRuleSplit は分割区画の送信(仕様 10.1 節)。head は元の ID のまま残るので、
// 分割後も同じ /ui/rules/{id} に戻る(CLI の `rule split` と同じ組み立て:proto.Rule.Split)。
func (s *Server) uiRuleSplit(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	locale := resolveLocale(w, r)
	rule, ok := s.findRuleOr404(w, r.PathValue("id"))
	if !ok {
		return
	}
	at, err := proto.ParseSplitPoint(r.FormValue("at"))
	var head, tail proto.Rule
	if err == nil {
		head, tail, err = rule.Split(at, "r_"+newULID())
	}
	if err == nil {
		_, err = s.backend.Batch(BatchRequest{Upsert: []proto.Rule{head, tail}})
	}
	if err != nil {
		d := s.ruleDetailView(rule, locale)
		d.SplitError = err.Error()
		s.renderDetailPage(w, locale, d)
		return
	}
	http.Redirect(w, r, "/ui/rules/"+head.ID, http.StatusSeeOther)
}

// uiRuleMerge は統合区画の送信(仕様 10.1 節)。このルール(パスの ID)が self、
// フォームの other が消える方(proto.Merge と同じ組み立て)。統合後はこのルールの ID の
// ままなので、同じ /ui/rules/{id} に戻る。
func (s *Server) uiRuleMerge(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	locale := resolveLocale(w, r)
	rule, ok := s.findRuleOr404(w, r.PathValue("id"))
	if !ok {
		return
	}
	other, ok := s.findRuleOr404(w, r.FormValue("other"))
	if !ok {
		return
	}
	merged, err := proto.Merge(rule, other)
	if err == nil {
		_, err = s.backend.Batch(BatchRequest{Upsert: []proto.Rule{merged}, Delete: []string{other.ID}})
	}
	if err != nil {
		d := s.ruleDetailView(rule, locale)
		d.MergeError = err.Error()
		s.renderDetailPage(w, locale, d)
		return
	}
	http.Redirect(w, r, "/ui/rules/"+merged.ID, http.StatusSeeOther)
}
