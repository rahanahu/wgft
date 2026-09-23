package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

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

// AddIPMismatchWarning は ip-mismatch の警告を記録する。ただし、その組が確認済みなら記録しない
// (仕様 5.2 節)。確認済みかどうかの判定と記録を 1 つの文で行うので、監視の回が確認済みの組を
// 読んでからこの記録までの間に管理者が警告を消しても、消した警告は戻らない。IP は NormalizeIP で
// そろえてから照合する。記録した(新規か時刻の更新)なら true を返す。
func (s *Store) AddIPMismatchWarning(agent, streamIP, wgIP string) (bool, error) {
	sIP, wIP := NormalizeIP(streamIP), NormalizeIP(wgIP)
	res, err := s.db.Exec(`INSERT INTO warnings (agent, kind, detail, created_at)
		SELECT ?, ?, ?, ? WHERE NOT EXISTS (
			SELECT 1 FROM warning_acks WHERE agent = ? AND kind = ? AND stream_ip = ? AND wg_ip = ?)
		ON CONFLICT(agent, kind, detail) DO UPDATE SET created_at = excluded.created_at`,
		agent, WarnIPMismatch, IPMismatchDetail(sIP, wIP), time.Now().Unix(),
		agent, WarnIPMismatch, sIP, wIP)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
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
// 確認済みの組は残さない。管理者の「警告を消す」は DismissWarning を使う。
func (s *Store) ClearWarning(agent, kind, detail string) error {
	if detail == "" {
		_, err := s.db.Exec("DELETE FROM warnings WHERE agent = ? AND kind = ?", agent, kind)
		return err
	}
	_, err := s.db.Exec("DELETE FROM warnings WHERE agent = ? AND kind = ? AND detail = ?", agent, kind, detail)
	return err
}

// NormalizeIP は IP の文字列を比較用の形にそろえる。IPv4 射影の IPv6 アドレスは IPv4 にする。
// "ip:port" と "[ip]:port" はポートを落として IP にする。IP として読めなければそのまま返す
// (空は空のまま。観測できないことを表す)。
func NormalizeIP(s string) string {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().String()
	}
	return s
}

// SamePair は、確認済みの組が観測した 2 つの IP の組と同じかを返す。IP は正規化して比べる。
func (a Ack) SamePair(streamIP, wgIP string) bool {
	return a.StreamIP == NormalizeIP(streamIP) && a.WGIP == NormalizeIP(wgIP)
}

// IPPairState は、観測した stream の接続元 IP と wg エンドポイント IP の組の状態(仕様 5.2 節)。
type IPPairState int

const (
	IPPairUnobserved   IPPairState = iota // どちらかの IP を観測できない
	IPPairMatch                           // 2 つの IP が一致する
	IPPairMismatch                        // 食い違い。確認済みの組ではない
	IPPairAcknowledged                    // 食い違い。そのエージェントの確認済みの組と同じ
)

// ClassifyIPPair は観測した 2 つの IP を正規化して比べ、acks(そのエージェントの確認済みの組)と
// 照合する。15 秒ごとの監視と Web UI のダッシュボードが同じ判定を使うための唯一の比較である。
// IP は IP だけでも "ip:port" でもよく、空は観測できないことを表す。
func ClassifyIPPair(streamIP, wgIP string, acks []Ack) IPPairState {
	sIP, wIP := NormalizeIP(streamIP), NormalizeIP(wgIP)
	switch {
	case sIP == "" || wIP == "":
		return IPPairUnobserved
	case sIP == wIP:
		return IPPairMatch
	}
	for _, a := range acks {
		if a.SamePair(sIP, wIP) {
			return IPPairAcknowledged
		}
	}
	return IPPairMismatch
}

// IPMismatchDetail は ip-mismatch の detail を組み立てる。parseIPMismatchDetail と対になる。
func IPMismatchDetail(streamIP, wgIP string) string {
	return fmt.Sprintf("stream %s / wg %s", streamIP, wgIP)
}

// parseIPMismatchDetail は ip-mismatch の detail から 2 つの IP を正規化して取り出す。
func parseIPMismatchDetail(detail string) (streamIP, wgIP string, ok bool) {
	rest, found := strings.CutPrefix(detail, "stream ")
	if !found {
		return "", "", false
	}
	sPart, wPart, found := strings.Cut(rest, " / wg ")
	if !found {
		return "", "", false
	}
	sa, err1 := netip.ParseAddr(sPart)
	wa, err2 := netip.ParseAddr(wPart)
	if err1 != nil || err2 != nil {
		return "", "", false
	}
	return sa.Unmap().String(), wa.Unmap().String(), true
}

// Ack は ip-mismatch の確認済みの組(仕様 5.2 節)。管理者が警告を消したときに記録し、
// 同じ組の食い違いが続く間は警告を出し直さない。IP は NormalizeIP でそろえた値で、ポートを含まない。
type Ack struct {
	Agent     string
	Kind      string
	StreamIP  string
	WGIP      string
	CreatedAt time.Time
}

// DismissWarning は管理者の「警告を消す」を 1 トランザクションで行う(仕様 5.2 節)。
// 種類と detail で選んだ警告を消し(detail が空ならその種類を全部)、種類が ip-mismatch なら、
// 消した各警告の 2 つの IP の組を確認済みの組として記録する。記録した組を返す。
// detail から IP を読み取れない警告と、agents に行が無いエージェント(無効化の後に残った警告)の
// 警告は、組を記録せずに消すだけにする。
func (s *Store) DismissWarning(agent, kind, detail string) ([]Ack, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var details []string
	registered := false
	if kind == WarnIPMismatch {
		var one int
		switch err := tx.QueryRow("SELECT 1 FROM agents WHERE name = ?", agent).Scan(&one); {
		case err == nil:
			registered = true
		case !errors.Is(err, sql.ErrNoRows):
			return nil, err
		}
	}
	if registered {
		q, args := "SELECT detail FROM warnings WHERE agent = ? AND kind = ?", []any{agent, kind}
		if detail != "" {
			q, args = q+" AND detail = ?", append(args, detail)
		}
		rows, err := tx.Query(q, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err != nil {
				rows.Close()
				return nil, err
			}
			details = append(details, d)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	now := time.Now()
	var acks []Ack
	for _, d := range details {
		sIP, wIP, ok := parseIPMismatchDetail(d)
		if !ok {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO warning_acks (agent, kind, stream_ip, wg_ip, created_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(agent, kind, stream_ip, wg_ip) DO UPDATE SET created_at = excluded.created_at`,
			agent, kind, sIP, wIP, now.Unix()); err != nil {
			return nil, err
		}
		acks = append(acks, Ack{Agent: agent, Kind: kind, StreamIP: sIP, WGIP: wIP, CreatedAt: time.Unix(now.Unix(), 0)})
	}
	if detail == "" {
		_, err = tx.Exec("DELETE FROM warnings WHERE agent = ? AND kind = ?", agent, kind)
	} else {
		_, err = tx.Exec("DELETE FROM warnings WHERE agent = ? AND kind = ? AND detail = ?", agent, kind, detail)
	}
	if err != nil {
		return nil, err
	}
	return acks, tx.Commit()
}

// WarningAcks はその種類の確認済みの組を全エージェント分返す。
func (s *Store) WarningAcks(kind string) ([]Ack, error) {
	rows, err := s.db.Query("SELECT agent, kind, stream_ip, wg_ip, created_at FROM warning_acks WHERE kind = ? ORDER BY agent, stream_ip, wg_ip", kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ack
	for rows.Next() {
		var a Ack
		var ts int64
		if err := rows.Scan(&a.Agent, &a.Kind, &a.StreamIP, &a.WGIP, &ts); err != nil {
			return nil, err
		}
		a.CreatedAt = time.Unix(ts, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteWarningAck は確認済みの組を 1 つ捨てる(仕様 5.2 節の、一致と別の組の観測)。
func (s *Store) DeleteWarningAck(a Ack) error {
	_, err := s.db.Exec("DELETE FROM warning_acks WHERE agent = ? AND kind = ? AND stream_ip = ? AND wg_ip = ?",
		a.Agent, a.Kind, a.StreamIP, a.WGIP)
	return err
}
