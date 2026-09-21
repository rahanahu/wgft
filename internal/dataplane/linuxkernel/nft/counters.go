//go:build linux

package nft

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
)

// Drop はルールごと・種類ごとの累積 drop 数(コメントで識別する)。
type Drop struct {
	RuleID  string
	Kind    string // deny | allow | per_source | src_flow | new_flow | packet
	Packets uint64
	Bytes   uint64
}

// ReadDrops は filter_pre の各 drop 行のカウンタを、コメントから読む(仕様 6.1 節)。
// テーブル差し替えの直前に呼び、増分を SQLite に累積する。テーブルがなければ空を返す。
func ReadDrops() ([]Drop, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
	rules, err := c.GetRules(t, &nftables.Chain{Name: "filter_pre", Table: t})
	if err != nil {
		// テーブルがまだない(初回)
		return nil, nil
	}
	var out []Drop
	for _, r := range rules {
		comment, ok := userdata.GetString(r.UserData, userdata.TypeComment)
		if !ok {
			continue
		}
		id, kind := parseComment(comment)
		if id == "" {
			continue
		}
		for _, e := range r.Exprs {
			if ct, ok := e.(*expr.Counter); ok {
				out = append(out, Drop{RuleID: id, Kind: kind, Packets: ct.Packets, Bytes: ct.Bytes})
			}
		}
	}
	return out, nil
}

// parseComment は "wgft:<id>:<kind>" を分ける。id にコロンは入らない前提(ルール ID は r_ULID)。
func parseComment(comment string) (id, kind string) {
	const p = "wgft:"
	if len(comment) <= len(p) || comment[:len(p)] != p {
		return "", ""
	}
	rest := comment[len(p):]
	for i := len(rest) - 1; i >= 0; i-- {
		if rest[i] == ':' {
			return rest[:i], rest[i+1:]
		}
	}
	return "", ""
}
