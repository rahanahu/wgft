package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"

	"github.com/rahanahu/wgft/proto"
)

const generationMeta = "generation"

// Rules は現在のルール集合を並び順で返す。
func (s *Store) Rules() ([]proto.Rule, error) {
	return s.rulesTx(s.db)
}

type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

func (s *Store) rulesTx(q querier) ([]proto.Rule, error) {
	rows, err := q.Query("SELECT json FROM rules ORDER BY position")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []proto.Rule
	for rows.Next() {
		var js string
		if err := rows.Scan(&js); err != nil {
			return nil, err
		}
		var r proto.Rule
		if err := json.Unmarshal([]byte(js), &r); err != nil {
			return nil, fmt.Errorf("rules JSON: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Generation は現在の世代。ルールが 1 つもなければ 0。
func (s *Store) Generation() (uint64, error) {
	return generationTx(s.db)
}

func generationTx(q querier) (uint64, error) {
	var v []byte
	err := q.QueryRow("SELECT value FROM meta WHERE key = ?", generationMeta).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(string(v), 10, 64)
}

// BatchResult はバッチの結果。
type BatchResult struct {
	Rules      []proto.Rule
	Generation uint64
	Changed    bool // エージェントに配る内容が変わった(世代が上がった)
}

// ApplyBatch はルール集合の変更を 1 トランザクションで行う(仕様 5.4 節)。
// mutate は現在の集合を受け取り、変更後の集合を返す。検証は変更後の全体に対して行い、
// エージェントに配る部分(id、proto、listen_port、target、enabled)に差があれば世代を 1 だけ上げる。
// 接続元制限だけの変更では世代は上がらない。
func (s *Store) ApplyBatch(reserved proto.Reserved, mutate func(rules []proto.Rule) ([]proto.Rule, error)) (*BatchResult, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	before, err := s.rulesTx(tx)
	if err != nil {
		return nil, err
	}
	after, err := mutate(cloneRules(before))
	if err != nil {
		return nil, err
	}
	if err := proto.ValidateRules(after, reserved); err != nil {
		return nil, err
	}
	gen, err := generationTx(tx)
	if err != nil {
		return nil, err
	}
	changed := !reflect.DeepEqual(agentView(before), agentView(after))
	if changed {
		gen++
		if _, err := tx.Exec("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
			generationMeta, []byte(strconv.FormatUint(gen, 10))); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec("DELETE FROM rules"); err != nil {
		return nil, err
	}
	for i, r := range after {
		js, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec("INSERT INTO rules (id, position, json) VALUES (?, ?, ?)", r.ID, i, string(js)); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &BatchResult{Rules: after, Generation: gen, Changed: changed}, nil
}

func agentView(rules []proto.Rule) []proto.AgentRule {
	out := make([]proto.AgentRule, 0, len(rules))
	for i := range rules {
		out = append(out, rules[i].ForAgent())
	}
	return out
}

func cloneRules(rules []proto.Rule) []proto.Rule {
	out := make([]proto.Rule, len(rules))
	for i, r := range rules {
		out[i] = r
		out[i].SourceAllow = append([]netip.Prefix(nil), r.SourceAllow...)
		out[i].SourceDeny = append([]netip.Prefix(nil), r.SourceDeny...)
		if r.NewFlowRate != nil {
			v := *r.NewFlowRate
			out[i].NewFlowRate = &v
		}
		if r.PacketRate != nil {
			v := *r.PacketRate
			out[i].PacketRate = &v
		}
		if r.PerSourceRate != nil {
			v := *r.PerSourceRate
			out[i].PerSourceRate = &v
		}
	}
	return out
}
