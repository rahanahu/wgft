package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
)

// ChangeKind は読み込み確認(仕様 10.1 節)の 1 行の種別。
type ChangeKind string

const (
	ChangeAdded     ChangeKind = "added"
	ChangeChanged   ChangeKind = "changed"
	ChangeDeleted   ChangeKind = "deleted"
	ChangeUnchanged ChangeKind = "unchanged"
)

// FieldChange は Changed な行の中で変わったフィールド 1 つ。Field は英語の固定キー
// (agent、target、source_deny など)で、表示用の訳は呼び出し側(Web UI)が持つ。
// Old/New はそのまま表示できる値。接続元制限(source_allow/source_deny)は件数の文字列、
// レートは Rate.String() の形、他は Rule のフィールドの文字列表現である。
type FieldChange struct {
	Field    string
	Old, New string
}

// RuleChange は DiffRules の 1 行。Added/Unchanged では Rule が読み込んだ側の値、
// Deleted では現在の側の値を持つ。Changed では両方を持ち、FieldChanges に変わった
// フィールドを列挙する。
type RuleChange struct {
	Kind         ChangeKind
	Rule         Rule
	Previous     Rule
	FieldChanges []FieldChange
}

// DiffRules は現在のルール集合 current と、読み込んだルール集合 desired を ID で
// 突き合わせ、行ごとの差分を返す(仕様 10.1 節)。desired に無い current の ID は
// Deleted として末尾に付く。順序は desired の順を保ち、その後に Deleted を current の
// 順で並べる。desired の各ルールは ID が確定していること(空 ID への割り当ては呼び出し側
// が DiffRules の前に行うこと)を前提にする。CLI の `rule import` と Web UI の読み込みの
// 確認・適用がこの関数を共有する。
func DiffRules(current, desired []Rule) []RuleChange {
	byID := make(map[string]Rule, len(current))
	for _, r := range current {
		byID[r.ID] = r
	}
	seen := make(map[string]bool, len(desired))
	out := make([]RuleChange, 0, len(desired)+len(current))
	for _, d := range desired {
		seen[d.ID] = true
		if c, ok := byID[d.ID]; ok {
			if fc := fieldChanges(c, d); len(fc) > 0 {
				out = append(out, RuleChange{Kind: ChangeChanged, Rule: d, Previous: c, FieldChanges: fc})
			} else {
				out = append(out, RuleChange{Kind: ChangeUnchanged, Rule: d})
			}
		} else {
			out = append(out, RuleChange{Kind: ChangeAdded, Rule: d})
		}
	}
	for _, c := range current {
		if !seen[c.ID] {
			out = append(out, RuleChange{Kind: ChangeDeleted, Rule: c})
		}
	}
	return out
}

// DeletedIDs は diff の Deleted 行の ID を集める。読み込みの適用(仕様 10.1 節)と CLI の
// `rule import` が、削除するルールの組み立てをここで共有する。
func DeletedIDs(diff []RuleChange) []string {
	var out []string
	for _, c := range diff {
		if c.Kind == ChangeDeleted {
			out = append(out, c.Rule.ID)
		}
	}
	return out
}

// RulesDigest はルール集合の内容だけに依存するハッシュ(SHA-256 の16進表記)を返す。
// ID でソートしてから JSON にすることで、並び順の違いを無視する。Web UI の読み込みの
// 確認ページ(仕様 10.1 節)が、確認を表示した時点の全体と適用しようとする時点の
// 全体を比べ、CLI からの変更などによる食い違いを検出するために使う。group、note、
// 接続元制限、レートの変更は世代を上げない(5.3 節)ため、世代だけの照合では見逃す。
func RulesDigest(rules []Rule) string {
	sorted := append([]Rule(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	b, err := json.Marshal(sorted)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func fieldChanges(prev, next Rule) []FieldChange {
	var out []FieldChange
	add := func(field, oldV, newV string) {
		if oldV != newV {
			out = append(out, FieldChange{Field: field, Old: oldV, New: newV})
		}
	}
	add("agent", prev.Agent, next.Agent)
	add("group", prev.Group, next.Group)
	add("note", prev.Note, next.Note)
	add("proto", string(prev.Proto), string(next.Proto))
	add("listen_port", prev.ListenPort.String(), next.ListenPort.String())
	add("target", prev.TargetDisplay(), next.TargetDisplay())
	add("vps_mode", string(prev.VPSMode), string(next.VPSMode))
	add("proxy_protocol", boolField(prev.ProxyProtocol), boolField(next.ProxyProtocol))
	// 拒否/許可リストは集合として比べる(equalPrefixSet)。件数が同じでも内容が入れ替わって
	// いれば差分とし、Old/New には件数でなく CIDR そのものの一覧を持たせる(add はここでは
	// 使わない。件数が同じ入れ替えでは old==new の文字列になり、add の等値検査で落ちるため)。
	if !equalPrefixSet(prev.SourceDeny, next.SourceDeny) {
		out = append(out, FieldChange{Field: "source_deny", Old: joinPrefixes(prev.SourceDeny), New: joinPrefixes(next.SourceDeny)})
	}
	if !equalPrefixSet(prev.SourceAllow, next.SourceAllow) {
		out = append(out, FieldChange{Field: "source_allow", Old: joinPrefixes(prev.SourceAllow), New: joinPrefixes(next.SourceAllow)})
	}
	add("new_flow_rate", rateField(prev.NewFlowRate), rateField(next.NewFlowRate))
	add("packet_rate", rateField(prev.PacketRate), rateField(next.PacketRate))
	add("per_source_rate", rateField(prev.PerSourceRate), rateField(next.PerSourceRate))
	add("enabled", boolField(prev.Enabled), boolField(next.Enabled))
	return out
}

func boolField(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func rateField(r *Rate) string {
	if r == nil {
		return ""
	}
	return r.String()
}

// joinPrefixes は拒否/許可リストの FieldChange.Old/New に持たせる表示用の値。CIDR を
// 文字列でソートして ", " でつなぐ(空なら空文字列)。Web UI(fieldChangeText)がこれを
// 前後で比べ、増えた・減った CIDR だけを確認ページに出す。
func joinPrefixes(list []netip.Prefix) string {
	if len(list) == 0 {
		return ""
	}
	strs := make([]string, len(list))
	for i, p := range list {
		strs[i] = p.String()
	}
	sort.Strings(strs)
	return strings.Join(strs, ", ")
}
