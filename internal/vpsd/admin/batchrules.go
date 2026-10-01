package admin

import (
	"fmt"
	"slices"

	"github.com/rahanahu/wgft/proto"
)

// このファイルは、ルールの一括変更(Batch)の受理の規則と、保存する集合の組み立て方(併合の規則)を
// 1 か所に持つ(仕様 5.4、10.1、11a 節)。本物の Backend(internal/vpsd の Daemon.Batch)、CLI の
// --dry-run(cmd/wgft の runRuleDryRun)、Web UI の読み込みの確認(webui_import.go の
// renderImportConfirm)は、どれもここの関数を呼ぶ。Batch に拒否の理由を足すときは、ここに足すと
// 2 つの事前確認にも届く。
//
// Daemon.Batch が保存の前に確かめる順は次のとおりで、最初に落ちた誤りを返す。1 から 3 と併合は
// AdmitBatch が行う。
//
//  1. ExpectedDigest の照合
//  2. Delete の ID が今の集合にあること
//  3. upsert の行ごとの、エージェントの登録
//  4. 併合(MergeBatch)の後、他テーブルの DNAT と bind 中のポートの検査(internal/vpsd の
//     checkRule。root と nft が要るので、ここには無い)
//  5. 併合した集合全体への proto.ValidateUpsert(internal/vpsd/store の ApplyBatch)
//
// 2 つの事前確認(PreflightBatch)は、このうち 3 と 5 を、すべての理由を集める形で行う。1 は確認
// から適用までの間の変更を塞ぐためのもので、事前確認は行わない。2 は事前確認の入力に Delete が
// 無いか、今の集合から作るので落ちない。4 は管理用 API からは判定できない。

// AdmitBatch は Daemon.Batch の受理の規則のうち、今の集合と登録済みのエージェントだけで決まる
// ものを上の 1 から 3 の順に確かめ、すべて通れば MergeBatch の結果を返す。rules は Batch の
// トランザクションが読んだ「今の」集合、registered はエージェントの名前が登録されているかを答える
// 関数で、無効なエージェントも登録済みである。rules は変えない。
func AdmitBatch(rules []proto.Rule, req BatchRequest, registered func(name string) bool) (BatchMerge, error) {
	if err := checkBatchDigest(rules, req.ExpectedDigest); err != nil {
		return BatchMerge{}, err
	}
	if err := checkBatchDeletes(rules, req.Delete); err != nil {
		return BatchMerge{}, err
	}
	for _, u := range req.Upsert {
		if err := checkUpsertAgent(u, registered); err != nil {
			return BatchMerge{}, err
		}
	}
	return MergeBatch(rules, req), nil
}

// checkBatchDigest は ExpectedDigest を rules と照合する。expected が空なら照合しない。一致
// しなければ ErrBatchConflict を返す。
func checkBatchDigest(rules []proto.Rule, expected string) error {
	if expected != "" && proto.RulesDigest(rules) != expected {
		return ErrBatchConflict
	}
	return nil
}

// checkBatchDeletes は、ids のすべてが rules にあることを確かめ、最初に見つからない ID の誤りを
// 返す。無い ID の削除は成功扱いにしない(`rule ls` の短縮表示をそのまま渡した場合など)。
func checkBatchDeletes(rules []proto.Rule, ids []string) error {
	have := make(map[string]bool, len(rules))
	for _, r := range rules {
		have[r.ID] = true
	}
	for _, id := range ids {
		if !have[id] {
			return fmt.Errorf("rule %q not found", id)
		}
	}
	return nil
}

// AgentNotRegisteredError は、upsert の行が登録されていないエージェントを指すときの誤りである。
// Error の文言は Daemon.Batch と Web UI の読み込みの確認が使う。CLI の --dry-run は Rule から
// 自分の表示を組む。
type AgentNotRegisteredError struct {
	Rule proto.Rule
}

func (e *AgentNotRegisteredError) Error() string {
	return fmt.Sprintf("rule %s: agent %q is not registered", e.Rule.ID, e.Rule.Agent)
}

// checkUpsertAgent は、upsert の行 r が登録済みのエージェントを指すことを確かめる。
func checkUpsertAgent(r proto.Rule, registered func(name string) bool) error {
	if !registered(r.Agent) {
		return &AgentNotRegisteredError{Rule: r}
	}
	return nil
}

// BatchMerge は MergeBatch の結果である。
type BatchMerge struct {
	// Rules は保存する集合である。
	Rules []proto.Rule
	// Added、Updated、Deleted は成功ログ用の ID の列である(internal/vpsd の batchSummary)。
	// Added は今の集合に無かった upsert の行、Updated は今の集合の行と中身が違った upsert の行、
	// Deleted は req.Delete そのものである。
	Added, Updated, Deleted []string
}

// MergeBatch は req の upsert と delete を rules に ID で当てはめた集合を返す。Daemon.Batch が
// 保存する集合の組み立てそのものである。upsert の行は、同じ ID の行があればその位置で置き換え、
// 無ければ末尾に足す。同じ ID が upsert に 2 度あれば後の行が残る。その後で Delete の ID の行を
// 外すので、同じ ID が Upsert と Delete の両方にあれば外れる。rules は変えない。
//
// ExpectedDigest と受理の規則は見ない。それらは AdmitBatch が見る。
func MergeBatch(rules []proto.Rule, req BatchRequest) BatchMerge {
	rules = slices.Clone(rules)
	var m BatchMerge
	byID := map[string]int{}
	for i, r := range rules {
		byID[r.ID] = i
	}
	del := map[string]bool{}
	for _, id := range req.Delete {
		del[id] = true
		m.Deleted = append(m.Deleted, id)
	}
	for _, u := range req.Upsert {
		if i, ok := byID[u.ID]; ok {
			// 読み込みは変わっていない行も upsert に含むので、中身が変わった行だけを記録する
			if proto.RulesDigest([]proto.Rule{rules[i]}) != proto.RulesDigest([]proto.Rule{u}) {
				m.Updated = append(m.Updated, u.ID)
			}
			rules[i] = u
		} else {
			byID[u.ID] = len(rules)
			rules = append(rules, u)
			m.Added = append(m.Added, u.ID)
		}
	}
	out := rules[:0]
	for _, r := range rules {
		if !del[r.ID] {
			out = append(out, r)
		}
	}
	m.Rules = out
	return m
}

// RuleInvalidError は、upsert の行が自身の形の検査(proto.Rule.Validate)に落ちたときの誤りで
// ある。Error の文言は、保存の前の proto.ValidateUpsert が同じ行に返す文言と同じである。
type RuleInvalidError struct {
	Rule proto.Rule
	Err  error
}

func (e *RuleInvalidError) Error() string { return fmt.Sprintf("rule %s: %v", e.Rule.ID, e.Err) }
func (e *RuleInvalidError) Unwrap() error { return e.Err }

// PreflightBatch は、Batch が保存の前に拒む理由のうち管理用 API から観測できるものを、保存せずに
// すべて集める。CLI の --dry-run と Web UI の読み込みの確認が使い、表示の文言は呼び手が誤りから
// 組む。
//
// rows は upsert する行、current は今の集合、set は保存されうる集合で、呼び手が組む。行ごとに、
// current から変わった行の形(proto.Rule.Validate)を確かめ、落ちれば *RuleInvalidError を返して
// その行のエージェントは見ない。形が通った行と変わっていない行は、エージェントの登録
// を確かめる。行ごとの誤りが 1 つも無いときだけ、set 全体に
// proto.ValidateUpsert(ID の重複、予約ポート、listen_port の重なり、変わった行の形)を掛ける。
// 行ごとの誤りを全体の検査がもう一度報告して、同じ行が 2 回出るのを避けるためである。
//
// reserved は呼び手が ReservedFromServerInfo で組んだ、実際の Batch が拒む予約ポートの集合である。
// nil を渡すと、予約ポートに重なる変更を「受理される」と見せかける(設計文書の改訂の記録の
// --dry-run の項)。
func PreflightBatch(rows, current, set []proto.Rule, agents map[string]bool, reserved proto.Reserved) []error {
	var out []error
	registered := func(name string) bool { return agents[name] }
	unchanged := proto.UnchangedIDs(rows, current)
	for _, r := range rows {
		if !unchanged[r.ID] {
			if err := r.Validate(); err != nil {
				out = append(out, &RuleInvalidError{Rule: r, Err: err})
				continue
			}
		}
		if err := checkUpsertAgent(r, registered); err != nil {
			out = append(out, err)
		}
	}
	if len(out) == 0 {
		if err := proto.ValidateUpsert(set, current, reserved); err != nil {
			out = append(out, err)
		}
	}
	return out
}
