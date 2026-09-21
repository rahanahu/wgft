//go:build linux

package vpsd

import (
	"fmt"
	"strings"
)

// idListMax は batchSummary が並べる ID の上限。import は一度に多くのルールへ触れ得るので、
// ログ行が読みにくいほど長くならないよう切る(仕様 10.4 節)。
const idListMax = 20

// batchSummary は Daemon.Batch が成功した後の 1 行のログを組み立てる。
// op は変更の出どころ("cli rule add" など)。空なら "api" を補う。
// changed は store.BatchResult.Changed(配る内容が変わって世代が上がったか)。
func batchSummary(op string, added, updated, deleted []string, generation uint64, changed bool) string {
	op = opOrAPI(op)
	var parts []string
	if len(added) > 0 {
		parts = append(parts, "added "+idList(added))
	}
	if len(updated) > 0 {
		parts = append(parts, "updated "+idList(updated))
	}
	if len(deleted) > 0 {
		parts = append(parts, "deleted "+idList(deleted))
	}
	body := strings.Join(parts, ", ")
	if body == "" {
		body = "no changes"
	}
	suffix := ""
	if !changed {
		suffix = " unchanged"
	}
	return fmt.Sprintf("rules: %s: %s; generation %d%s", op, body, generation, suffix)
}

// idList は ID の集まりを [id1 id2 ...] の形にする。idListMax を超える分は数だけ添える。
func idList(ids []string) string {
	shown := ids
	more := 0
	if len(ids) > idListMax {
		shown = ids[:idListMax]
		more = len(ids) - idListMax
	}
	s := "[" + strings.Join(shown, " ") + "]"
	if more > 0 {
		s += fmt.Sprintf(" (+%d more)", more)
	}
	return s
}

// opOrAPI は op の無い要求(CLI と Web UI 以外から管理用 API を直接呼んだ場合)を "api" と記録する。
func opOrAPI(op string) string {
	if op == "" {
		return "api"
	}
	return op
}
