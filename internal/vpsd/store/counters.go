package store

// ルールごとの累積 drop 数(仕様 6.1 節)。テーブル差し替えの直前に読んだカウンタの増分を足す。
// meter の状態は差し替えでリセットされるが、短時間のすり抜けにとどまる。

// AddDrops は増分を累積する(1 トランザクション)。
func (s *Store) AddDrops(deltas []DropDelta) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, d := range deltas {
		if _, err := tx.Exec(`INSERT INTO drop_counters (rule_id, kind, packets, bytes) VALUES (?, ?, ?, ?)
			ON CONFLICT(rule_id, kind) DO UPDATE SET packets = packets + excluded.packets, bytes = bytes + excluded.bytes`,
			d.RuleID, d.Kind, d.Packets, d.Bytes); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DropDelta は 1 行分の増分。
type DropDelta struct {
	RuleID  string
	Kind    string
	Packets uint64
	Bytes   uint64
}

// RuleDrops はルールごとの累積 drop 数(全種類の合計)。rule_id → packets。
func (s *Store) RuleDrops() (map[string]uint64, error) {
	rows, err := s.db.Query("SELECT rule_id, sum(packets) FROM drop_counters GROUP BY rule_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]uint64{}
	for rows.Next() {
		var id string
		var p uint64
		if err := rows.Scan(&id, &p); err != nil {
			return nil, err
		}
		out[id] = p
	}
	return out, rows.Err()
}
