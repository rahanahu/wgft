package store

import (
	"database/sql"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

// ip-mismatch の警告を消すと、消した警告の 2 つの IP の組が確認済みの組として残る(仕様 5.2 節)。
// 識別は正規化した IP で、detail の文字列そのものではない。
func TestDismissIPMismatchRecordsAck(t *testing.T) {
	s := openTemp(t)
	registerAgent(t, s, "home")
	if err := s.AddWarning("home", WarnIPMismatch, IPMismatchDetail("::ffff:198.51.100.7", "203.0.113.9")); err != nil {
		t.Fatal(err)
	}
	acks, err := s.DismissWarning("home", WarnIPMismatch, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(acks) != 1 || acks[0].StreamIP != "198.51.100.7" || acks[0].WGIP != "203.0.113.9" {
		t.Fatalf("returned acks = %+v", acks)
	}
	if ws, _ := s.AgentWarnings("home"); len(ws) != 0 {
		t.Errorf("warning must be removed, got %+v", ws)
	}
	got, err := s.WarningAcks(WarnIPMismatch)
	if err != nil || len(got) != 1 || got[0].Agent != "home" || got[0].StreamIP != "198.51.100.7" || got[0].WGIP != "203.0.113.9" {
		t.Fatalf("WarningAcks = %+v, %v", got, err)
	}
}

// detail を指定したときは、その警告の組だけを確認済みにする。
func TestDismissIPMismatchWithDetailAcksOnlyThatPair(t *testing.T) {
	s := openTemp(t)
	registerAgent(t, s, "home")
	a := IPMismatchDetail("198.51.100.7", "203.0.113.9")
	b := IPMismatchDetail("198.51.100.7", "203.0.113.10")
	for _, d := range []string{a, b} {
		if err := s.AddWarning("home", WarnIPMismatch, d); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DismissWarning("home", WarnIPMismatch, b); err != nil {
		t.Fatal(err)
	}
	got, _ := s.WarningAcks(WarnIPMismatch)
	if len(got) != 1 || got[0].WGIP != "203.0.113.10" {
		t.Fatalf("WarningAcks = %+v, want only the dismissed pair", got)
	}
	ws, _ := s.AgentWarnings("home")
	if len(ws) != 1 || ws[0].Detail != a {
		t.Errorf("remaining warnings = %+v, want only %q", ws, a)
	}
}

// ip-flapping を消す操作は行を消すだけで、確認済みの組を残さない。
func TestDismissIPFlappingLeavesNoAck(t *testing.T) {
	s := openTemp(t)
	registerAgent(t, s, "home")
	if err := s.AddWarning("home", WarnIPFlapping, "wg endpoint alternated between 198.51.100.7 and 203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	// 組を記録するかは種類で決める。detail が ip-mismatch と同じ形でも、ip-flapping なら記録しない
	if err := s.AddWarning("home", WarnIPFlapping, IPMismatchDetail("198.51.100.7", "203.0.113.9")); err != nil {
		t.Fatal(err)
	}
	acks, err := s.DismissWarning("home", WarnIPFlapping, "")
	if err != nil || len(acks) != 0 {
		t.Fatalf("DismissWarning = %+v, %v", acks, err)
	}
	if ws, _ := s.AgentWarnings("home"); len(ws) != 0 {
		t.Errorf("warning must be removed, got %+v", ws)
	}
	for _, kind := range []string{WarnIPFlapping, WarnIPMismatch} {
		if got, _ := s.WarningAcks(kind); len(got) != 0 {
			t.Errorf("WarningAcks(%s) = %+v, want none", kind, got)
		}
	}
}

// IP を読み取れない detail の ip-mismatch は、消すだけで組を残さない。
func TestDismissIPMismatchUnparsableDetail(t *testing.T) {
	s := openTemp(t)
	registerAgent(t, s, "home")
	if err := s.AddWarning("home", WarnIPMismatch, "something else"); err != nil {
		t.Fatal(err)
	}
	acks, err := s.DismissWarning("home", WarnIPMismatch, "")
	if err != nil || len(acks) != 0 {
		t.Fatalf("DismissWarning = %+v, %v", acks, err)
	}
	if ws, _ := s.AgentWarnings("home"); len(ws) != 0 {
		t.Errorf("warning must be removed, got %+v", ws)
	}
}

// registerAgent はエージェントを agents に登録する。確認済みの組は登録済みのエージェントにだけ残る。
func registerAgent(t *testing.T, s *Store, name string) {
	t.Helper()
	tok, err := s.IssueJoinToken(name, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(tok, name, "203.0.113.2", netip.MustParsePrefix("10.200.0.0/24")); err != nil {
		t.Fatal(err)
	}
}

// agents に行が無いエージェント(削除の後に残った警告)の ip-mismatch は、消すだけで組を残さない。
// 削除は組を消すので、ここで組を残すと削除の後に誰のものでもない組が残り続ける。
func TestDismissIPMismatchUnregisteredAgentLeavesNoAck(t *testing.T) {
	s := openTemp(t)
	if err := s.AddWarning("gone", WarnIPMismatch, IPMismatchDetail("198.51.100.7", "203.0.113.9")); err != nil {
		t.Fatal(err)
	}
	acks, err := s.DismissWarning("gone", WarnIPMismatch, "")
	if err != nil || len(acks) != 0 {
		t.Fatalf("DismissWarning = %+v, %v; want no acknowledgement", acks, err)
	}
	if ws, _ := s.AgentWarnings("gone"); len(ws) != 0 {
		t.Errorf("warning must be removed, got %+v", ws)
	}
	if got, _ := s.WarningAcks(WarnIPMismatch); len(got) != 0 {
		t.Errorf("WarningAcks = %+v, want none", got)
	}
}

// AddIPMismatchWarning は、確認済みの組の警告を記録しない。照合は正規化した IP で行い、
// 別の組や別のエージェントは通常どおり記録する。
func TestAddIPMismatchWarningSkipsAcknowledgedPair(t *testing.T) {
	s := openTemp(t)
	registerAgent(t, s, "home")
	if err := s.AddWarning("home", WarnIPMismatch, IPMismatchDetail("198.51.100.7", "203.0.113.9")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DismissWarning("home", WarnIPMismatch, ""); err != nil {
		t.Fatal(err)
	}
	for _, sIP := range []string{"198.51.100.7", "::ffff:198.51.100.7"} {
		added, err := s.AddIPMismatchWarning("home", sIP, "203.0.113.9")
		if err != nil || added {
			t.Fatalf("AddIPMismatchWarning(%s) = %v, %v; want not added", sIP, added, err)
		}
	}
	if ws, _ := s.AgentWarnings("home"); len(ws) != 0 {
		t.Fatalf("the acknowledged pair must not be recorded, got %+v", ws)
	}
	if added, err := s.AddIPMismatchWarning("home", "198.51.100.7", "203.0.113.10"); err != nil || !added {
		t.Fatalf("a different pair = %v, %v; want added", added, err)
	}
	if added, err := s.AddIPMismatchWarning("office", "198.51.100.7", "203.0.113.9"); err != nil || !added {
		t.Fatalf("another agent = %v, %v; want added", added, err)
	}
	ws, _ := s.Warnings()
	if len(ws) != 2 {
		t.Fatalf("warnings = %+v, want the two unacknowledged ones", ws)
	}
}

// 確認済みの組は開き直しても残る(server の再起動)。
func TestWarningAckSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	registerAgent(t, s, "home")
	if err := s.AddWarning("home", WarnIPMismatch, IPMismatchDetail("198.51.100.7", "203.0.113.9")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DismissWarning("home", WarnIPMismatch, ""); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got, _ := s.WarningAcks(WarnIPMismatch); len(got) != 1 {
		t.Fatalf("after reopen WarningAcks = %+v", got)
	}
}

// エージェントの削除は、そのエージェントの確認済みの組を消す。他のエージェントの分は残す。
func TestRevokeDeletesWarningAcks(t *testing.T) {
	s := openTemp(t)
	pfx := netip.MustParsePrefix("10.200.0.0/24")
	for _, name := range []string{"home", "office"} {
		tok, err := s.IssueJoinToken(name, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Register(tok, name, "203.0.113.2", pfx); err != nil {
			t.Fatal(err)
		}
		if err := s.AddWarning(name, WarnIPMismatch, IPMismatchDetail("198.51.100.7", "203.0.113.9")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DismissWarning(name, WarnIPMismatch, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RevokeAgent("home"); err != nil {
		t.Fatal(err)
	}
	got, err := s.WarningAcks(WarnIPMismatch)
	if err != nil || len(got) != 1 || got[0].Agent != "office" {
		t.Fatalf("WarningAcks after revoke = %+v, %v; want only office", got, err)
	}
}

// v7 の DB を開くと最新の版に上がり、既存の警告を保ったまま確認済みの組を記録できる。
func TestMigrationFromV7AddsWarningAcks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	dsn, err := sqliteDSN(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		if _, err := db.Exec(migrations[i]); err != nil {
			t.Fatalf("v%d: %v", i+1, err)
		}
	}
	if _, err := db.Exec("PRAGMA user_version = 7"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO warnings (agent, kind, detail, created_at) VALUES ('home', 'ip-mismatch', ?, 1)",
		IPMismatchDetail("198.51.100.7", "203.0.113.9")); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != len(migrations) {
		t.Fatalf("user_version = %d, %v; want %d", version, err, len(migrations))
	}
	if ws, _ := s.AgentWarnings("home"); len(ws) != 1 {
		t.Fatalf("warnings after migration = %+v", ws)
	}
	registerAgent(t, s, "home")
	acks, err := s.DismissWarning("home", WarnIPMismatch, "")
	if err != nil || len(acks) != 1 {
		t.Fatalf("DismissWarning after migration = %+v, %v", acks, err)
	}
}

// v8 の DB は、v7 までしか知らない版(v1.1.0 の server)には新しすぎる。v1.1.0 の Open と同じ
// 判定を、移行の数を 7 に絞って確かめる。
func TestV8DatabaseIsNewerForV7Binary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	saved := migrations
	defer func() { migrations = saved }()
	migrations = saved[:8]
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	migrations = saved[:7]
	_, err = Open(path)
	if err == nil || err.Error() != fmt.Sprintf("%v: version 8, while this binary supports up to 7", ErrSchemaNewer) {
		t.Fatalf("Open with 7 migrations = %v, want ErrSchemaNewer for version 8", err)
	}
	if _, err := OpenReadOnly(path); err == nil {
		t.Fatal("OpenReadOnly with 7 migrations must refuse a version 8 database")
	}
}
