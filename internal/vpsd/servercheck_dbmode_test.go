package vpsd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrintDBModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+"-wal", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	printDBModes(&out, path)
	got := out.String()
	if !strings.Contains(got, "server database file mode: "+path+" is 0600") {
		t.Fatalf("db mode line missing: %q", got)
	}
	if !strings.Contains(got, "server database file mode: "+path+"-wal is 0600") {
		t.Fatalf("wal mode line missing: %q", got)
	}
	if strings.Contains(got, path+"-shm") {
		t.Fatalf("unexpected shm line for missing file: %q", got)
	}
}
