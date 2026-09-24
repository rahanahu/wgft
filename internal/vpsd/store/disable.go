package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/rahanahu/wgft/proto"
)

// ErrAgentNotFound は、名前に当たるエージェントの行が無いことを表す。SetAgentDisabled は
// *AgentNotFoundError を返し、errors.Is(err, ErrAgentNotFound) で判定できる。
var ErrAgentNotFound = errors.New("agent not found")

// AgentNotFoundError は、名前に当たるエージェントが登録されていないときの誤り。
type AgentNotFoundError struct{ Name string }

func (e *AgentNotFoundError) Error() string { return fmt.Sprintf("agent %q is not registered", e.Name) }

// Is は errors.Is(err, ErrAgentNotFound) を成り立たせる。
func (e *AgentNotFoundError) Is(target error) bool { return target == ErrAgentNotFound }

// disabledTime は disabled_at の列の値を Agent.DisabledAt に写す。NULL は有効でゼロ値になる。
func disabledTime(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.Unix(v.Int64, 0)
}

// disabledAgentsTx は無効なエージェントの名前の集合を返す(仕様 5.1 節)。
func disabledAgentsTx(q querier) (map[string]bool, error) {
	rows, err := q.Query("SELECT name FROM agents WHERE disabled_at IS NOT NULL")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[n] = true
	}
	return out, rows.Err()
}

// DeliveredRule はルール r のうちエージェントに配る写しを返す(仕様 5.1、5.3 節)。持ち主の
// エージェントが無効なら、保存値に関わらず Enabled を false にする。保存値そのものには触れない。
// 配る写しの正本はこの 1 か所であり、全体状態を組み立てる vpsd の AgentState と、世代を進めるか
// どうかを決める agentView の両方がこれを使う。2 か所が別々に写すと、配る内容と世代の比較が
// ずれ、配る内容が変わったのに世代が進まない(エージェントが受け取らない)ことが起きうる。
func DeliveredRule(r *proto.Rule, agentDisabled bool) proto.AgentRule {
	ar := r.ForAgent()
	if agentDisabled {
		ar.Enabled = false
	}
	return ar
}

// AgentDisabledResult は SetAgentDisabled の結果。
type AgentDisabledResult struct {
	// Changed は無効と有効の状態が変わったか。変わったときだけ世代が 1 つ進む。
	Changed bool
	// Generation は操作の後の世代。
	Generation uint64
	// Rules は操作の後のルール集合(保存値のまま)。呼び出し側はこれを適用する。
	Rules []proto.Rule
	// DisabledAt は操作の後の disabled_at。有効ならゼロ値。
	DisabledAt time.Time
}

// SetAgentDisabled はエージェントを無効にする(disabled が真)か、有効に戻す(仕様 5.1 節)。
// 行が無ければ *AgentNotFoundError を返す。
//
// 状態が変わるときだけ disabled_at を書き、世代を 1 つ進める。配る写しの enabled と、全体状態の
// 無効を示すフィールドが変わるためである(3 節の世代の定義)。既に無効なエージェントの無効化と、
// 既に有効なエージェントの有効化は何も書かず、世代も進めない。既に無効なエージェントの無効化は、
// 最初に無効にした時刻を書き換えない。
//
// check は、状態が変わる場合に限り、書き込みの前に同じトランザクションの中で今のルール集合を
// 渡して呼ぶ。誤りを返せば何も保存しない。有効化の書き込みの時の検査(ルールのバッチの upsert と
// 同じもの)に使う。nil なら呼ばない。
func (s *Store) SetAgentDisabled(name string, disabled bool, now time.Time, check func(rules []proto.Rule) error) (*AgentDisabledResult, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var cur sql.NullInt64
	err = tx.QueryRow("SELECT disabled_at FROM agents WHERE name = ?", name).Scan(&cur)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &AgentNotFoundError{Name: name}
	}
	if err != nil {
		return nil, err
	}
	rules, err := s.rulesTx(tx)
	if err != nil {
		return nil, err
	}
	gen, err := generationTx(tx)
	if err != nil {
		return nil, err
	}
	if cur.Valid == disabled {
		return &AgentDisabledResult{Generation: gen, Rules: rules, DisabledAt: disabledTime(cur)}, tx.Commit()
	}
	if check != nil {
		if err := check(cloneRules(rules)); err != nil {
			return nil, err
		}
	}
	next := sql.NullInt64{}
	if disabled {
		next = sql.NullInt64{Int64: now.Unix(), Valid: true}
	}
	if _, err := tx.Exec("UPDATE agents SET disabled_at = ? WHERE name = ?", next, name); err != nil {
		return nil, err
	}
	gen++
	if _, err := tx.Exec("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		generationMeta, []byte(strconv.FormatUint(gen, 10))); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &AgentDisabledResult{Changed: true, Generation: gen, Rules: rules, DisabledAt: disabledTime(next)}, nil
}
