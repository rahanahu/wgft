//go:build !windows

package credentials

import (
	"os"
	"testing"
)

// assertFileSecured is credentials_test.go's cross-platform entry point (see
// secure_windows_test.go for the Windows counterpart, which checks the DACL instead of a
// Unix permission bit).
func assertFileSecured(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perm = %o, want 600", info.Mode().Perm())
	}
}
