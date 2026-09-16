package store

import "time"

// 窃取検知の警告(仕様 5.2 節)。警告は (agent, kind, detail) で重複排除し、再発時は時刻だけ更新する。

// 警告の種類。
const (
	WarnIPMismatch = "ip-mismatch" // stream 接続元 IP と wg エンドポイント IP の食い違い。detail は両 IP
	WarnIPFlapping = "ip-flapping" // 同じチャネルの IP が 10 分以内に以前の値へ往復。detail はチャネルと 2 つの IP
)

// Warning は 1 件の警告。
type Warning struct {
	Agent     string
	Kind      string
	Detail    string
	CreatedAt time.Time
}

// AddWarning は警告を記録する(同じ内容なら時刻を更新するだけ)。
func (s *Store) AddWarning(agent, kind, detail string) error {
	_, err := s.db.Exec(`INSERT INTO warnings (agent, kind, detail, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(agent, kind, detail) DO UPDATE SET created_at = excluded.created_at`,
		agent, kind, detail, time.Now().Unix())
	return err
}

// Warnings は全警告を新しい順に返す。
func (s *Store) Warnings() ([]Warning, error) {
	rows, err := s.db.Query("SELECT agent, kind, detail, created_at FROM warnings ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Warning
	for rows.Next() {
		var w Warning
		var ts int64
		if err := rows.Scan(&w.Agent, &w.Kind, &w.Detail, &ts); err != nil {
			return nil, err
		}
		w.CreatedAt = time.Unix(ts, 0)
		out = append(out, w)
	}
	return out, rows.Err()
}

// AgentWarnings はそのエージェントの警告。
func (s *Store) AgentWarnings(agent string) ([]Warning, error) {
	all, err := s.Warnings()
	if err != nil {
		return nil, err
	}
	var out []Warning
	for _, w := range all {
		if w.Agent == agent {
			out = append(out, w)
		}
	}
	return out, nil
}

// ClearWarning は種類と detail を指定して警告を消す(detail が空ならその種類を全部)。
func (s *Store) ClearWarning(agent, kind, detail string) error {
	if detail == "" {
		_, err := s.db.Exec("DELETE FROM warnings WHERE agent = ? AND kind = ?", agent, kind)
		return err
	}
	_, err := s.db.Exec("DELETE FROM warnings WHERE agent = ? AND kind = ? AND detail = ?", agent, kind, detail)
	return err
}
