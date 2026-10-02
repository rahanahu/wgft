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
		added, _, err := s.AddIPMismatchWarning("home", sIP, "203.0.113.9")
		if err != nil || added {
			t.Fatalf("AddIPMismatchWarning(%s) = %v, %v; want not added", sIP, added, err)
		}
	}
	if ws, _ := s.AgentWarnings("home"); len(ws) != 0 {
		t.Fatalf("the acknowledged pair must not be recorded, got %+v", ws)
	}
	if added, _, err := s.AddIPMismatchWarning("home", "198.51.100.7", "203.0.113.10"); err != nil || !added {
		t.Fatalf("a different pair = %v, %v; want added", added, err)
	}
	if added, _, err := s.AddIPMismatchWarning("office", "198.51.100.7", "203.0.113.9"); err != nil || !added {
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

// insertWarningAt は created_at を指定して警告の行を直接入れる。上限の前の版で増えた行を持つ
// データベースを再現するために使う。
func insertWarningAt(t *testing.T, s *Store, agent, kind, detail string, at int64) {
	t.Helper()
	if _, err := s.db.Exec("INSERT INTO warnings (agent, kind, detail, created_at) VALUES (?, ?, ?, ?)",
		agent, kind, detail, at); err != nil {
		t.Fatal(err)
	}
}

func warningDetails(t *testing.T, s *Store, agent, kind string) map[string]bool {
	t.Helper()
	ws, err := s.AgentWarnings(agent)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, w := range ws {
		if w.Agent != agent {
			t.Fatalf("AgentWarnings(%q) returned a row of %q", agent, w.Agent)
		}
		if w.Kind == kind {
			out[w.Detail] = true
		}
	}
	return out
}

func flapDetail(i int) string {
	return fmt.Sprintf("wg endpoint alternated between 198.51.100.%d and 203.0.113.9", i)
}

// ip-flapping の行は、エージェントごとに MaxFlappingWarnings 行までに絞る(仕様 5.2 節)。上限を
// 超えた行を持つ既存のデータベースは、次の記録で、いま記録した行と日時の新しい行だけになる。
// 上限に達した後も新しい往復は記録され、ほかのエージェントとほかの種類の行は減らない。
func TestFlappingWarningsKeepNewestPerAgent(t *testing.T) {
	s := openTemp(t)
	const extra = 10
	base := time.Now().Unix() - 100000
	for i := 0; i < MaxFlappingWarnings+extra; i++ {
		insertWarningAt(t, s, "home", WarnIPFlapping, flapDetail(i), base+int64(i))
		insertWarningAt(t, s, "home", WarnIPMismatch, IPMismatchDetail(fmt.Sprintf("198.51.100.%d", i), "203.0.113.9"), base+int64(i))
		insertWarningAt(t, s, "other", WarnIPFlapping, flapDetail(i), base+int64(i))
	}

	if err := s.AddWarning("home", WarnIPFlapping, "stream alternated between 192.0.2.1 and 192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	got := warningDetails(t, s, "home", WarnIPFlapping)
	if len(got) != MaxFlappingWarnings {
		t.Fatalf("home ip-flapping rows = %d, want %d", len(got), MaxFlappingWarnings)
	}
	if !got["stream alternated between 192.0.2.1 and 192.0.2.2"] {
		t.Error("the warning just recorded must be kept")
	}
	// 残るのは古い行のうち新しい MaxFlappingWarnings-1 行。
	for i := 0; i < MaxFlappingWarnings+extra; i++ {
		want := i >= extra+1
		if got[flapDetail(i)] != want {
			t.Errorf("legacy row %d kept = %v, want %v", i, got[flapDetail(i)], want)
		}
	}
	if n := len(warningDetails(t, s, "home", WarnIPMismatch)); n != MaxFlappingWarnings+extra {
		t.Errorf("home ip-mismatch rows = %d, want %d untouched", n, MaxFlappingWarnings+extra)
	}
	if n := len(warningDetails(t, s, "other", WarnIPFlapping)); n != MaxFlappingWarnings+extra {
		t.Errorf("other agent's ip-flapping rows = %d, want %d untouched", n, MaxFlappingWarnings+extra)
	}
	// ip-mismatch の上限は ip-flapping と別に数える。ip-mismatch の記録は ip-flapping の行を減らさない。
	if added, _, err := s.AddIPMismatchWarning("home", "192.0.2.1", "203.0.113.9"); err != nil || !added {
		t.Fatalf("AddIPMismatchWarning = %v, %v", added, err)
	}
	if n := len(warningDetails(t, s, "home", WarnIPMismatch)); n != MaxIPMismatchWarnings {
		t.Errorf("home ip-mismatch rows after recording one = %d, want %d", n, MaxIPMismatchWarnings)
	}
	if n := len(warningDetails(t, s, "home", WarnIPFlapping)); n != MaxFlappingWarnings {
		t.Errorf("home ip-flapping rows after an ip-mismatch record = %d, want %d", n, MaxFlappingWarnings)
	}

	// 上限に達した後も検知は止まらない。新しい組は記録され、最も古い行が消える。
	if err := s.AddWarning("home", WarnIPFlapping, "stream alternated between 192.0.2.3 and 192.0.2.4"); err != nil {
		t.Fatal(err)
	}
	got = warningDetails(t, s, "home", WarnIPFlapping)
	if len(got) != MaxFlappingWarnings || !got["stream alternated between 192.0.2.3 and 192.0.2.4"] ||
		!got["stream alternated between 192.0.2.1 and 192.0.2.2"] || got[flapDetail(extra+1)] {
		t.Errorf("after a second new pair: %d rows, new=%v previous=%v oldest legacy kept=%v",
			len(got), got["stream alternated between 192.0.2.3 and 192.0.2.4"],
			got["stream alternated between 192.0.2.1 and 192.0.2.2"], got[flapDetail(extra+1)])
	}

	// 既にある組の再検出は時刻を更新するだけで、行を増やさず、その行を最も新しい側に移す。
	if err := s.AddWarning("home", WarnIPFlapping, flapDetail(extra+2)); err != nil {
		t.Fatal(err)
	}
	if err := s.AddWarning("home", WarnIPFlapping, "stream alternated between 192.0.2.5 and 192.0.2.6"); err != nil {
		t.Fatal(err)
	}
	got = warningDetails(t, s, "home", WarnIPFlapping)
	if len(got) != MaxFlappingWarnings || !got[flapDetail(extra+2)] || got[flapDetail(extra+3)] {
		t.Errorf("after re-detecting row %d: %d rows, re-detected kept=%v next oldest kept=%v",
			extra+2, len(got), got[flapDetail(extra+2)], got[flapDetail(extra+3)])
	}
}

// 時計が戻って既存の行の日時が未来にあっても、いま記録した往復は残る。
func TestFlappingWarningCapKeepsNewRecordWhenClockWentBack(t *testing.T) {
	s := openTemp(t)
	future := time.Now().Unix() + 100000
	for i := 0; i < MaxFlappingWarnings; i++ {
		insertWarningAt(t, s, "home", WarnIPFlapping, flapDetail(i), future+int64(i))
	}
	if err := s.AddWarning("home", WarnIPFlapping, "stream alternated between 192.0.2.1 and 192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	got := warningDetails(t, s, "home", WarnIPFlapping)
	if len(got) != MaxFlappingWarnings || !got["stream alternated between 192.0.2.1 and 192.0.2.2"] || got[flapDetail(0)] {
		t.Errorf("rows = %d, new kept = %v, oldest kept = %v", len(got),
			got["stream alternated between 192.0.2.1 and 192.0.2.2"], got[flapDetail(0)])
	}
}

// AgentWarnings はそのエージェントの行だけを、新しい順に返す。
func TestAgentWarningsReturnsOnlyThatAgentNewestFirst(t *testing.T) {
	s := openTemp(t)
	insertWarningAt(t, s, "home", WarnIPFlapping, flapDetail(1), 100)
	insertWarningAt(t, s, "other", WarnIPFlapping, flapDetail(2), 300)
	insertWarningAt(t, s, "home", WarnIPMismatch, IPMismatchDetail("198.51.100.7", "203.0.113.9"), 200)
	ws, err := s.AgentWarnings("home")
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 2 || ws[0].Kind != WarnIPMismatch || ws[1].Kind != WarnIPFlapping ||
		ws[0].CreatedAt.Unix() != 200 || ws[1].CreatedAt.Unix() != 100 {
		t.Errorf("AgentWarnings(home) = %+v", ws)
	}
}

// 最後に検出した日時が同じ秒の行どうしでは、後から記録した行を新しいものとして残す。
func TestFlappingWarningCapBreaksTiesByInsertionOrder(t *testing.T) {
	s := openTemp(t)
	at := time.Now().Unix() - 100
	for i := 0; i < MaxFlappingWarnings+5; i++ {
		insertWarningAt(t, s, "home", WarnIPFlapping, flapDetail(i), at)
	}
	if err := s.AddWarning("home", WarnIPFlapping, "stream alternated between 192.0.2.1 and 192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	got := warningDetails(t, s, "home", WarnIPFlapping)
	for i := 0; i < MaxFlappingWarnings+5; i++ {
		if want := i >= 6; got[flapDetail(i)] != want {
			t.Errorf("row %d inserted at the same second kept = %v, want %v", i, got[flapDetail(i)], want)
		}
	}
}

// AgentWarnings は同じ秒の警告を記録した順に返す。全警告を読んで絞っていた以前の版と同じ順序で、
// 主キー(種類と detail)の順ではない。
func TestAgentWarningsKeepsInsertionOrderWithinSameSecond(t *testing.T) {
	s := openTemp(t)
	insertWarningAt(t, s, "home", WarnIPMismatch, IPMismatchDetail("198.51.100.9", "203.0.113.9"), 100)
	insertWarningAt(t, s, "home", WarnIPFlapping, "wg endpoint alternated between 198.51.100.2 and 203.0.113.9", 100)
	insertWarningAt(t, s, "home", WarnIPFlapping, "stream alternated between 198.51.100.1 and 203.0.113.9", 100)
	insertWarningAt(t, s, "home", WarnIPMismatch, IPMismatchDetail("198.51.100.1", "203.0.113.9"), 100)
	insertWarningAt(t, s, "home", WarnIPFlapping, flapDetail(5), 200)
	all, err := s.Warnings()
	if err != nil {
		t.Fatal(err)
	}
	ws, err := s.AgentWarnings("home")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		flapDetail(5),
		IPMismatchDetail("198.51.100.9", "203.0.113.9"),
		"wg endpoint alternated between 198.51.100.2 and 203.0.113.9",
		"stream alternated between 198.51.100.1 and 203.0.113.9",
		IPMismatchDetail("198.51.100.1", "203.0.113.9"),
	}
	if len(ws) != len(want) || len(all) != len(want) {
		t.Fatalf("AgentWarnings = %+v, Warnings = %+v", ws, all)
	}
	for i := range want {
		if ws[i].Detail != want[i] || all[i].Detail != want[i] {
			t.Errorf("row %d: AgentWarnings %q, Warnings %q, want %q", i, ws[i].Detail, all[i].Detail, want[i])
		}
	}
}

func mismatchDetail(i int) string {
	return IPMismatchDetail(fmt.Sprintf("198.51.100.%d", i), "203.0.113.9")
}

func warningAcksOf(t *testing.T, s *Store) []Ack {
	t.Helper()
	acks, err := s.WarningAcks(WarnIPMismatch)
	if err != nil {
		t.Fatal(err)
	}
	return acks
}

// ip-mismatch の行は、エージェントごとに MaxIPMismatchWarnings 行までに絞る(仕様 5.2 節)。上限を
// 超えた行を持つ既存のデータベースは、次の記録で、いま記録した行と日時の新しい行だけになる。
// ip-flapping の行とは別に数え、ほかのエージェントの行は減らない。
func TestIPMismatchWarningsKeepNewestPerAgent(t *testing.T) {
	s := openTemp(t)
	const extra = 10
	base := time.Now().Unix() - 100000
	for i := 0; i < MaxIPMismatchWarnings+extra; i++ {
		insertWarningAt(t, s, "home", WarnIPMismatch, mismatchDetail(i), base+int64(i))
		insertWarningAt(t, s, "home", WarnIPFlapping, flapDetail(i), base+int64(i))
		insertWarningAt(t, s, "other", WarnIPMismatch, mismatchDetail(i), base+int64(i))
	}

	newPair := IPMismatchDetail("192.0.2.1", "203.0.113.9")
	if added, _, err := s.AddIPMismatchWarning("home", "192.0.2.1", "203.0.113.9"); err != nil || !added {
		t.Fatalf("AddIPMismatchWarning = %v, %v", added, err)
	}
	got := warningDetails(t, s, "home", WarnIPMismatch)
	if len(got) != MaxIPMismatchWarnings {
		t.Fatalf("home ip-mismatch rows = %d, want %d", len(got), MaxIPMismatchWarnings)
	}
	if !got[newPair] {
		t.Error("the warning just recorded must be kept")
	}
	// 残るのは古い行のうち新しい MaxIPMismatchWarnings-1 行。
	for i := 0; i < MaxIPMismatchWarnings+extra; i++ {
		if want := i >= extra+1; got[mismatchDetail(i)] != want {
			t.Errorf("legacy row %d kept = %v, want %v", i, got[mismatchDetail(i)], want)
		}
	}
	if n := len(warningDetails(t, s, "home", WarnIPFlapping)); n != MaxFlappingWarnings+extra {
		t.Errorf("home ip-flapping rows = %d, want %d untouched", n, MaxFlappingWarnings+extra)
	}
	if n := len(warningDetails(t, s, "other", WarnIPMismatch)); n != MaxIPMismatchWarnings+extra {
		t.Errorf("other agent's ip-mismatch rows = %d, want %d untouched", n, MaxIPMismatchWarnings+extra)
	}

	// 上限に達した後も検知は止まらない。新しい組は記録され、最も古い行が消える。
	if added, _, err := s.AddIPMismatchWarning("home", "192.0.2.3", "203.0.113.9"); err != nil || !added {
		t.Fatalf("AddIPMismatchWarning = %v, %v", added, err)
	}
	got = warningDetails(t, s, "home", WarnIPMismatch)
	if len(got) != MaxIPMismatchWarnings || !got[IPMismatchDetail("192.0.2.3", "203.0.113.9")] ||
		!got[newPair] || got[mismatchDetail(extra+1)] {
		t.Errorf("after a second new pair: %d rows, new=%v previous=%v oldest legacy kept=%v",
			len(got), got[IPMismatchDetail("192.0.2.3", "203.0.113.9")], got[newPair], got[mismatchDetail(extra+1)])
	}

	// 既にある組の再検出は時刻を更新するだけで、行を増やさず、その行を最も新しい側に移す。
	if added, _, err := s.AddIPMismatchWarning("home", fmt.Sprintf("198.51.100.%d", extra+2), "203.0.113.9"); err != nil || !added {
		t.Fatalf("re-detecting = %v, %v", added, err)
	}
	if added, _, err := s.AddIPMismatchWarning("home", "192.0.2.5", "203.0.113.9"); err != nil || !added {
		t.Fatalf("AddIPMismatchWarning = %v, %v", added, err)
	}
	got = warningDetails(t, s, "home", WarnIPMismatch)
	if len(got) != MaxIPMismatchWarnings || !got[mismatchDetail(extra+2)] || got[mismatchDetail(extra+3)] {
		t.Errorf("after re-detecting row %d: %d rows, re-detected kept=%v next oldest kept=%v",
			extra+2, len(got), got[mismatchDetail(extra+2)], got[mismatchDetail(extra+3)])
	}
	if acks := warningAcksOf(t, s); len(acks) != 0 {
		t.Errorf("trimming must not record acknowledgements, got %+v", acks)
	}
}

// ip-flapping の記録は ip-mismatch の行を減らさない。2 つの種類はそれぞれの上限を持つ。
func TestFlappingRecordLeavesIPMismatchRows(t *testing.T) {
	s := openTemp(t)
	base := time.Now().Unix() - 100000
	for i := 0; i < MaxIPMismatchWarnings; i++ {
		insertWarningAt(t, s, "home", WarnIPMismatch, mismatchDetail(i), base+int64(i))
	}
	for i := 0; i < MaxFlappingWarnings+5; i++ {
		if err := s.AddWarning("home", WarnIPFlapping, flapDetail(i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(warningDetails(t, s, "home", WarnIPMismatch)); n != MaxIPMismatchWarnings {
		t.Errorf("home ip-mismatch rows = %d, want %d untouched", n, MaxIPMismatchWarnings)
	}
	if n := len(warningDetails(t, s, "home", WarnIPFlapping)); n != MaxFlappingWarnings {
		t.Errorf("home ip-flapping rows = %d, want %d", n, MaxFlappingWarnings)
	}
}

// 時計が戻って既存の行の日時が未来にあっても、いま記録した食い違いは残る。IPv4 射影の形やポート
// つきで与えた組も、正規化した detail の行として記録し、その行を残す。
func TestIPMismatchWarningCapKeepsNewRecordWhenClockWentBack(t *testing.T) {
	for _, c := range []struct{ streamIP, wgIP string }{
		{"192.0.2.1", "203.0.113.9"},
		{"::ffff:192.0.2.1", "[::ffff:203.0.113.9]:51820"},
	} {
		s := openTemp(t)
		future := time.Now().Unix() + 100000
		for i := 0; i < MaxIPMismatchWarnings; i++ {
			insertWarningAt(t, s, "home", WarnIPMismatch, mismatchDetail(i), future+int64(i))
		}
		if added, _, err := s.AddIPMismatchWarning("home", c.streamIP, c.wgIP); err != nil || !added {
			t.Fatalf("AddIPMismatchWarning(%s, %s) = %v, %v", c.streamIP, c.wgIP, added, err)
		}
		got := warningDetails(t, s, "home", WarnIPMismatch)
		newPair := IPMismatchDetail("192.0.2.1", "203.0.113.9")
		if len(got) != MaxIPMismatchWarnings || !got[newPair] || got[mismatchDetail(0)] {
			t.Errorf("%s / %s: rows = %d, new kept = %v, oldest kept = %v",
				c.streamIP, c.wgIP, len(got), got[newPair], got[mismatchDetail(0)])
		}
	}
}

// 最後に検出した日時が同じ秒の行どうしでは、後から記録した行を新しいものとして残す。
func TestIPMismatchWarningCapBreaksTiesByInsertionOrder(t *testing.T) {
	s := openTemp(t)
	at := time.Now().Unix() - 100
	for i := 0; i < MaxIPMismatchWarnings+5; i++ {
		insertWarningAt(t, s, "home", WarnIPMismatch, mismatchDetail(i), at)
	}
	if added, _, err := s.AddIPMismatchWarning("home", "192.0.2.1", "203.0.113.9"); err != nil || !added {
		t.Fatalf("AddIPMismatchWarning = %v, %v", added, err)
	}
	got := warningDetails(t, s, "home", WarnIPMismatch)
	for i := 0; i < MaxIPMismatchWarnings+5; i++ {
		if want := i >= 6; got[mismatchDetail(i)] != want {
			t.Errorf("row %d inserted at the same second kept = %v, want %v", i, got[mismatchDetail(i)], want)
		}
	}
}

// 上限で行を消しても確認済みの組は変わらない。確認済みの組の観測は、上限を超えた行があっても
// 記録せず、行も消さない。
func TestIPMismatchWarningCapLeavesAcksAlone(t *testing.T) {
	s := openTemp(t)
	registerAgent(t, s, "home")
	acked := IPMismatchDetail("192.0.2.7", "203.0.113.9")
	if err := s.AddWarning("home", WarnIPMismatch, acked); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DismissWarning("home", WarnIPMismatch, acked); err != nil {
		t.Fatal(err)
	}
	before := warningAcksOf(t, s)
	if len(before) != 1 {
		t.Fatalf("WarningAcks = %+v, want the dismissed pair", before)
	}

	base := time.Now().Unix() - 100000
	for i := 0; i < MaxIPMismatchWarnings+10; i++ {
		insertWarningAt(t, s, "home", WarnIPMismatch, mismatchDetail(i), base+int64(i))
	}
	// 確認済みの組は記録しない。記録しなかった回は行を消さない。
	if added, _, err := s.AddIPMismatchWarning("home", "192.0.2.7", "203.0.113.9"); err != nil || added {
		t.Fatalf("the acknowledged pair = %v, %v; want not added", added, err)
	}
	if n := len(warningDetails(t, s, "home", WarnIPMismatch)); n != MaxIPMismatchWarnings+10 {
		t.Errorf("rows after an unrecorded observation = %d, want %d unchanged", n, MaxIPMismatchWarnings+10)
	}

	if added, _, err := s.AddIPMismatchWarning("home", "192.0.2.1", "203.0.113.9"); err != nil || !added {
		t.Fatalf("AddIPMismatchWarning = %v, %v", added, err)
	}
	if n := len(warningDetails(t, s, "home", WarnIPMismatch)); n != MaxIPMismatchWarnings {
		t.Errorf("rows after a record = %d, want %d", n, MaxIPMismatchWarnings)
	}
	after := warningAcksOf(t, s)
	if len(after) != len(before) || after[0] != before[0] {
		t.Errorf("WarningAcks after trimming = %+v, want unchanged %+v", after, before)
	}
	// 上限で行を消した後も、確認済みの組は警告にならない。
	if added, _, err := s.AddIPMismatchWarning("home", "::ffff:192.0.2.7", "203.0.113.9"); err != nil || added {
		t.Fatalf("the acknowledged pair after trimming = %v, %v; want not added", added, err)
	}
	if got := warningDetails(t, s, "home", WarnIPMismatch); got[acked] {
		t.Error("the acknowledged pair must not be recorded after trimming")
	}
}

// 上限で消えた行の組は確認済みにならない。「警告を消す」で確認済みになるのは、そのとき残っている
// 行の組だけであり、消えた組は再び観測すれば記録される。
func TestIPMismatchWarningCapDoesNotAcknowledgeTrimmedPair(t *testing.T) {
	s := openTemp(t)
	registerAgent(t, s, "home")
	trimmed := IPMismatchDetail("192.0.2.7", "203.0.113.9")
	if added, _, err := s.AddIPMismatchWarning("home", "192.0.2.7", "203.0.113.9"); err != nil || !added {
		t.Fatalf("AddIPMismatchWarning = %v, %v", added, err)
	}
	// 同じ秒でも後から記録した行が新しい。上限の数だけ新しい組を記録すると、最初の組が消える。
	for i := 0; i < MaxIPMismatchWarnings; i++ {
		if added, _, err := s.AddIPMismatchWarning("home", fmt.Sprintf("198.51.100.%d", i), "203.0.113.9"); err != nil || !added {
			t.Fatalf("AddIPMismatchWarning(%d) = %v, %v", i, added, err)
		}
	}
	got := warningDetails(t, s, "home", WarnIPMismatch)
	if len(got) != MaxIPMismatchWarnings || got[trimmed] {
		t.Fatalf("rows = %d, trimmed pair kept = %v", len(got), got[trimmed])
	}
	if acks := warningAcksOf(t, s); len(acks) != 0 {
		t.Fatalf("trimming must not record acknowledgements, got %+v", acks)
	}
	acks, err := s.DismissWarning("home", WarnIPMismatch, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(acks) != MaxIPMismatchWarnings {
		t.Errorf("dismissing all acknowledged %d pairs, want %d", len(acks), MaxIPMismatchWarnings)
	}
	for _, a := range acks {
		if a.SamePair("192.0.2.7", "203.0.113.9") {
			t.Error("dismissing all must not acknowledge the trimmed pair")
		}
	}
	if added, _, err := s.AddIPMismatchWarning("home", "192.0.2.7", "203.0.113.9"); err != nil || !added {
		t.Fatalf("the trimmed pair observed again = %v, %v; want added", added, err)
	}
}

// AddIPMismatchWarning は、行を新しく作ったときだけ created を返す。同じ組の記録は時刻を更新するだけで
// recorded は true、created は false である。確認済みの組は、どちらも false で行も作らない。
func TestAddIPMismatchWarningReportsCreation(t *testing.T) {
	s := openTemp(t)
	registerAgent(t, s, "home")
	rec, created, err := s.AddIPMismatchWarning("home", "192.0.2.1", "203.0.113.9")
	if err != nil || !rec || !created {
		t.Fatalf("first record = %v, %v, %v; want recorded and created", rec, created, err)
	}
	rec, created, err = s.AddIPMismatchWarning("home", "192.0.2.1", "203.0.113.9")
	if err != nil || !rec || created {
		t.Fatalf("repeat = %v, %v, %v; want recorded, not created", rec, created, err)
	}
	rec, created, err = s.AddIPMismatchWarning("home", "192.0.2.1", "203.0.113.10")
	if err != nil || !rec || !created {
		t.Fatalf("new pair = %v, %v, %v; want recorded and created", rec, created, err)
	}
	ws, err := s.AgentWarnings("home")
	if err != nil || len(ws) != 2 {
		t.Fatalf("warnings = %+v, %v; want 2 rows", ws, err)
	}
}

// 確認済みの組の行が(AddWarning などで)残っていても、AddIPMismatchWarning は更新も新規作成もしない。
func TestAddIPMismatchWarningLeavesAnAcknowledgedPairsRowAlone(t *testing.T) {
	s := openTemp(t)
	registerAgent(t, s, "home")
	detail := IPMismatchDetail("198.51.100.7", "203.0.113.9")
	if err := s.AddWarning("home", WarnIPMismatch, detail); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DismissWarning("home", WarnIPMismatch, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.AddWarning("home", WarnIPMismatch, detail); err != nil {
		t.Fatal(err)
	}
	rec, created, err := s.AddIPMismatchWarning("home", "198.51.100.7", "203.0.113.9")
	if err != nil || rec || created {
		t.Fatalf("acknowledged pair with a leftover row = %v, %v, %v; want neither recorded nor created", rec, created, err)
	}
}

// 上限を超えた既存のデータベースでも、既存の組を更新するだけの記録で、行は上限まで減り、更新した行は残る
// (仕様 5.2 節)。
func TestAddIPMismatchWarningTrimsOnAnUpdateOnlyRecord(t *testing.T) {
	s := openTemp(t)
	registerAgent(t, s, "home")
	const extra = 10
	base := time.Now().Unix() - 100000
	for i := 0; i < MaxIPMismatchWarnings+extra; i++ {
		insertWarningAt(t, s, "home", WarnIPMismatch, mismatchDetail(i), base+int64(i))
	}
	// 最も古い行の組を観測する。更新だけの記録でも、その行は最も新しくなって残る
	rec, created, err := s.AddIPMismatchWarning("home", "198.51.100.0", "203.0.113.9")
	if err != nil || !rec || created {
		t.Fatalf("update = %v, %v, %v; want recorded, not created", rec, created, err)
	}
	got := warningDetails(t, s, "home", WarnIPMismatch)
	if len(got) != MaxIPMismatchWarnings {
		t.Fatalf("rows after an update-only record = %d, want %d", len(got), MaxIPMismatchWarnings)
	}
	if !got[mismatchDetail(0)] || got[mismatchDetail(1)] {
		t.Errorf("updated row kept = %v, next oldest kept = %v; want true, false", got[mismatchDetail(0)], got[mismatchDetail(1)])
	}
}
