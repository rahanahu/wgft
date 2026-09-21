package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestJournalModeWALDoesNotHonorBusyTimeout documents, with a direct reproduction, why Open cannot
// rely on pragma order (or the DSN busy_timeout parameter) alone: switching journal_mode to WAL for
// the first time is not retried by SQLite's own busy handler even once busy_timeout is already set
// on the connection. Without this, it would be easy to "fix" the production bug by only reordering
// the PRAGMA statements and ship something that still fails.
func TestJournalModeWALDoesNotHonorBusyTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create empty db file: %v", err)
	}
	ctx := context.Background()

	blocker, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open blocker: %v", err)
	}
	defer blocker.Close()
	blocker.SetMaxOpenConns(1)
	conn, err := blocker.Conn(ctx)
	if err != nil {
		t.Fatalf("blocker conn: %v", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("BEGIN IMMEDIATE: %v", err)
	}
	defer conn.ExecContext(ctx, "COMMIT")

	victim, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open victim: %v", err)
	}
	defer victim.Close()
	victim.SetMaxOpenConns(1)
	// busy_timeout set first, exactly as sqliteDSN orders it, and still on the connection when the
	// next statement runs (same *sql.DB, MaxOpenConns(1)).
	if _, err := victim.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		t.Fatalf("set busy_timeout: %v", err)
	}

	start := time.Now()
	_, err = victim.ExecContext(ctx, "PRAGMA journal_mode=WAL")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("want journal_mode=WAL to fail while another connection holds the database, got nil error")
	}
	if !isSQLiteBusy(err) {
		t.Fatalf("err = %v (%T), want isSQLiteBusy(err) == true", err, err)
	}
	// The whole point: it must fail almost immediately, not after waiting anywhere near the 5s
	// busy_timeout. A generous bound (1s) keeps this from being timing-fragile while still proving
	// the busy handler was not invoked.
	if elapsed > time.Second {
		t.Errorf("journal_mode=WAL took %s to fail; want it to fail immediately (busy_timeout is not honored for this statement)", elapsed)
	}
}

// TestIsSQLiteBusyCodeMatchesExtendedForms is the regression test for a review finding:
// modernc.org/sqlite enables extended result codes on every connection (see isSQLiteBusy's
// comment), so a busy failure is not guaranteed to arrive as the plain primary code 5. Before this
// mask, Open's retry loop compared Code() for exact equality with 5 and would have missed
// BUSY_RECOVERY, BUSY_SNAPSHOT and BUSY_TIMEOUT, returning the error immediately instead of
// retrying within its own openBusyRetryWindow, on exactly the kind of restart-time contention this
// fix targets (BUSY_RECOVERY in particular is another connection recovering a WAL file after a
// crash). The exact-equality comparison cannot be reproduced with a real driver error in this test
// (modernc.org/sqlite's *Error has no exported constructor, and a genuine busy_timeout expiry
// observed while writing this fix still came back as plain 5, not BUSY_TIMEOUT, with this
// driver/SQLite version), so this checks isSQLiteBusyCode's masking logic directly against the
// literal codes from sqlite.org/rescode.html instead.
func TestIsSQLiteBusyCodeMatchesExtendedForms(t *testing.T) {
	const (
		sqliteBusyRecovery = 261 // SQLITE_BUSY | (1<<8)
		sqliteBusySnapshot = 517 // SQLITE_BUSY | (2<<8)
		sqliteBusyTimeout  = 773 // SQLITE_BUSY | (3<<8)
		sqliteLocked       = 6   // a different primary code, must not match
		sqliteCantOpen     = 14  // a different primary code, must not match
	)
	busy := []int{sqliteBusy, sqliteBusyRecovery, sqliteBusySnapshot, sqliteBusyTimeout}
	for _, code := range busy {
		if !isSQLiteBusyCode(code) {
			t.Errorf("isSQLiteBusyCode(%d) = false, want true", code)
		}
	}
	notBusy := []int{0, sqliteLocked, sqliteCantOpen}
	for _, code := range notBusy {
		if isSQLiteBusyCode(code) {
			t.Errorf("isSQLiteBusyCode(%d) = true, want false", code)
		}
	}
}

// TestOpenWaitsOutAHeldLock is the regression test for the production bug: a fresh database (a
// first-ever start, or one recreated after `server teardown --purge` or restoring from backup)
// switches journal_mode to WAL for the first time as part of Open's connection setup. If another
// process holds the file for even a few milliseconds at that moment (a restart, a binary swap,
// `wgft server teardown`, the CLI), the old Open (three PRAGMA statements sent in the order
// journal_mode, foreign_keys, busy_timeout) failed immediately with "database is locked
// (SQLITE_BUSY)" instead of waiting for the lock to clear (docs/design.md 9 節, 改訂の記録
// 2026-09-20).
//
// This test holds a write lock on a fresh database file from a second connection and calls Open
// concurrently. It fails under the old code: verified by hand while writing it, by temporarily
// restoring the old three-statement PRAGMA loop with no retry in Open, which made this test fail
// with "database is locked (SQLITE_BUSY)" returned in well under a millisecond; reverted
// afterwards. It also fails if Open's busy retry is removed but sqliteDSN's ordering is kept (see
// TestJournalModeWALDoesNotHonorBusyTimeout: the DSN's busy_timeout is not enough by itself).
//
// The two things this test checks (Open does not fail instantly, and Open does eventually succeed
// once the lock clears) are deliberately proven with two different, narrow synchronisation points
// instead of one shared wall-clock duration. An earlier version held the lock for a fixed 300ms
// from a second goroutine (Sleep then release) and asserted Open's total elapsed time fell in a
// window around that; under go test -race -count=20 run alongside this package's other heavy
// neighbours, that Sleep itself was repeatedly observed firing anywhere from several seconds to
// over a minute late (real host scheduler contention from running many concurrent -race binaries
// at once, confirmed by this package's own tests being clean in isolation under the same flags),
// which made Open's own retry window expire for a reason unrelated to the code under test, no
// matter how generous that window was made. Releasing the lock explicitly, right after confirming
// Open is still blocked, removes that dependency on a background goroutine's wall-clock wake-up
// entirely: this test now holds the lock for as long as it takes to make and check one non-blocking
// observation, not for any fixed duration.
//
// The blocker connection's own COMMIT (its RESERVED-to-EXCLUSIVE promotion) needs busy_timeout
// set on it too, for a reason unrelated to Open's retry window: Open's retry loop opens a fresh
// connection roughly every 20ms and reads PRAGMA user_version off it (a brief SHARED lock) before
// finding the file still busy. Under scheduler contention that SHARED hold can stretch long
// enough to collide with this goroutine's own COMMIT; a connection without busy_timeout fails
// such a collision immediately (SQLite's default retry is none), which surfaced as this test
// itself failing with "database is locked (SQLITE_BUSY)" at the COMMIT below, not as Open failing.
// Reproduced directly: 4 of 280 runs, under 4 concurrent `go test -race` loads on unrelated
// packages, failed this way, always in well under a second, confirming it is this collision and
// not Open's 5s window (production's Open is unaffected; this is the test's other connection).
func TestOpenWaitsOutAHeldLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	// Open のロック待ちを試すには、Open 自身が最初に開く「まっさらな」ファイルが要る。ensureCreated と
	// 同じ 0 バイトのファイルを先に置く(ロック保持側と Open の両方が同じ 1 つの新規ファイルを
	// 見る必要があるため、ここでは ensureCreated を呼ばず直接作る)。
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create empty db file: %v", err)
	}

	blocker, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open blocker: %v", err)
	}
	defer blocker.Close()
	blocker.SetMaxOpenConns(1)

	ctx := context.Background()
	conn, err := blocker.Conn(ctx)
	if err != nil {
		t.Fatalf("blocker conn: %v", err)
	}
	defer conn.Close()
	// この接続にも busy_timeout を効かせておく。理由は Open の retry を試すためではなく、この
	// 接続自身が後で出す COMMIT (RESERVED から EXCLUSIVE への昇格) を守るため。Open は 20ms
	// おきに新しい接続を開いて PRAGMA user_version を読み(一瞬の SHARED ロック)、それに
	// 失敗して初めて次の接続を試みる。ホストの CPU が詰まっているとき、そのどれかの SHARED
	// ロックの解放がスケジューラの都合で伸び、ちょうどこの COMMIT の昇格とぶつかることがある。
	// busy_timeout を持たない接続の COMMIT は、SQLite の既定 (リトライ 0) でこの一瞬の衝突にも
	// 即座に失敗するため、以前はこの COMMIT 自体が "database is locked (SQLITE_BUSY)" で
	// 失敗することがあった (4 並列の CPU 負荷の下で 280 回中 4 回、再現して確認: エラーも
	// 発生までの時間もここで固定した想定と一致し、Open 自身の 5 秒の再試行区間には無関係だった)。
	// ここで busy_timeout を設定すれば、この一瞬の衝突は COMMIT 自身のリトライで吸収される。
	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		t.Fatalf("set busy_timeout on the blocker connection: %v", err)
	}
	// BEGIN IMMEDIATE がロックを掴む地点。journal_mode を WAL に変えるにはこのファイルへの排他アクセスが
	// 要るので、Open 側の最初の接続確立はこのロックとぶつかる。
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("BEGIN IMMEDIATE: %v", err)
	}

	type openResult struct {
		s   *Store
		err error
	}
	done := make(chan openResult, 1)
	go func() {
		s, err := Open(path)
		done <- openResult{s, err}
	}()

	// The old code failed in well under a millisecond (see the test comment above); Open must
	// still be running well past that. This bound only has to be comfortably larger than an instant
	// failure, not tied to how long the lock ends up held, so it stays small and safe under
	// contention: a false failure here would mean Open returned (successfully or not) in under
	// 200ms while a lock is provably still held, which the old code did in under 1ms and the fixed
	// code cannot do at all (nothing releases the lock until the COMMIT below runs).
	select {
	case r := <-done:
		t.Fatalf("Open returned (err=%v) while the lock was still held; want it still retrying", r.err)
	case <-time.After(200 * time.Millisecond):
	}

	// Release the lock now, synchronously, from this goroutine: no background Sleep whose wake-up
	// time the test depends on.
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		t.Fatalf("COMMIT: %v", err)
	}

	// Open must now complete, and succeed. The bound here is a pure hang-guard, not a timing
	// assertion: production's openBusyRetryWindow (5s) already bounds Open's real retrying, so 20s
	// leaves generous room for scheduler contention on a busy host without this test ever
	// depending on exactly how much of that room gets used.
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Open after the lock was released: %v", r.err)
		}
		defer r.s.Close()
	case <-time.After(20 * time.Second):
		t.Fatal("Open did not return within 20s of the lock being released; want it to complete promptly once unblocked")
	}
}
