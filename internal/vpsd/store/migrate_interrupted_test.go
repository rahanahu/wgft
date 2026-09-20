package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// TestInterruptedMigrationStepLeavesNoPartialSchema answers a review question about Open's busy
// retry: if a BUSY (in any of its extended forms; see isSQLiteBusy) interrupts migrate() partway
// through applying migrations[i], can the retried Open ever trip over a half-applied step?
//
// migrate() applies each schema version's DDL and the PRAGMA user_version bump that records it
// inside the same *sql.Tx, and commits them together, so the schema DDL and the version bump are
// either both visible or neither is. migrate()'s three failure exits all leave the step's
// transaction with no durable effect: a failed Exec calls tx.Rollback() explicitly; a failed
// Commit needs no explicit Rollback, because database/sql already considers a Tx finished once
// Commit has been called (success or failure) and SQLite itself never makes a transaction's writes
// visible unless Commit actually succeeds. This reproduces the common shape of both: begins
// migrations[0]'s transaction on a raw connection, applies its DDL and the user_version bump, then
// rolls it back instead of committing (standing in for whichever of the two calls migrate() would
// have hit BUSY on, and for the database/sql-internal unwind after a failed Commit). It then calls
// the real Open on the same file and checks the migration actually ran (not silently skipped,
// believing the abandoned attempt already applied it) and left a consistent, fully migrated schema
// with no error.
func TestInterruptedMigrationStepLeavesNoPartialSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")

	dsn, err := sqliteDSN(path)
	if err != nil {
		t.Fatalf("sqliteDSN: %v", err)
	}
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	raw.SetMaxOpenConns(1)
	tx, err := raw.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := tx.Exec(migrations[0]); err != nil {
		t.Fatalf("apply migrations[0]: %v", err)
	}
	if _, err := tx.Exec("PRAGMA user_version = 1"); err != nil {
		t.Fatalf("set user_version: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open after an abandoned, uncommitted migration step: %v", err)
	}
	defer s.Close()

	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("PRAGMA user_version: %v", err)
	}
	if version != len(migrations) {
		t.Errorf("user_version = %d, want %d (fully migrated)", version, len(migrations))
	}
	// A meta write only succeeds if the v1 "meta" table (migrations[0]) really exists.
	if err := s.SetMeta("k", []byte("v")); err != nil {
		t.Errorf("SetMeta after re-migration: %v", err)
	}
}
