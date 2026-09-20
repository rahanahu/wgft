//go:build !windows

package store

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOpenSetsDBAndSidecarModesTo0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetMeta("k", []byte("v")); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode = %04o, want 0600", path, fi.Mode().Perm())
	}
	for _, p := range []string{path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %04o, want 0600", p, fi.Mode().Perm())
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
