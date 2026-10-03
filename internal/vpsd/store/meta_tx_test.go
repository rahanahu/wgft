package store

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestSetMetaAndDeleteDoesBothOrNeither checks the transaction behind the confirmed ip_forward
// record (design.md 6.1 節): setting the confirmed record and deleting the planned one happen
// together. When the delete fails, the set is rolled back, so the database never holds both
// records because of this call, and never loses the planned record without gaining the
// confirmed one.
func TestSetMetaAndDeleteDoesBothOrNeither(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.SetMeta("planned", []byte("t0")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMetaAndDelete("confirmed", []byte("t1"), "planned"); err != nil {
		t.Fatal(err)
	}
	if b, err := s.GetMeta("confirmed"); err != nil || string(b) != "t1" {
		t.Errorf("confirmed = %q, %v; want t1", b, err)
	}
	if _, err := s.GetMeta("planned"); !errors.Is(err, ErrNotFound) {
		t.Errorf("planned is still there: %v", err)
	}

	// A missing key to delete is not an error.
	if err := s.SetMetaAndDelete("confirmed", []byte("t2"), "planned"); err != nil {
		t.Errorf("deleting a missing key failed: %v", err)
	}

	// The delete fails after the set has run inside the transaction: neither takes effect.
	if err := s.SetMeta("planned", []byte("t3")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER keep_planned BEFORE DELETE ON meta WHEN old.key = 'planned' BEGIN SELECT RAISE(ABORT, 'kept'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMetaAndDelete("confirmed", []byte("t4"), "planned"); err == nil {
		t.Fatal("SetMetaAndDelete succeeded although the delete was refused")
	}
	if b, err := s.GetMeta("confirmed"); err != nil || string(b) != "t2" {
		t.Errorf("confirmed = %q, %v; want t2, the value before the failed call", b, err)
	}
	if b, err := s.GetMeta("planned"); err != nil || string(b) != "t3" {
		t.Errorf("planned = %q, %v; want t3 kept", b, err)
	}
}

// TestDeleteMeta checks that DeleteMeta removes a key and accepts a missing one.
func TestDeleteMeta(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SetMeta("k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteMeta("k"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMeta("k"); !errors.Is(err, ErrNotFound) {
		t.Errorf("k is still there: %v", err)
	}
	if err := s.DeleteMeta("k"); err != nil {
		t.Errorf("deleting a missing key failed: %v", err)
	}
}
