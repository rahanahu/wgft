package agent

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestListenControlExplainsLongPath は、sun_path に収まらないパスで制御ソケットを開けないとき、
// エラーがバイト数と対処を言うことを確かめる。Go の net は OS を呼ぶ前に拒否するので、
// ディレクトリが実在しなくても同じエラーになる。
func TestListenControlExplainsLongPath(t *testing.T) {
	path := ControlPath(filepath.Join(t.TempDir(), strings.Repeat("d", 120), "agent.json"))
	ln, err := listenControl(path)
	if err == nil {
		ln.Close()
		t.Fatalf("listenControl(%d-byte path) succeeded; want an error", len(path))
	}
	for _, want := range []string{"shorter data directory", "bytes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestListenControlShortPath は、短いパスでは説明を足さずに開けることを確かめる。
func TestListenControlShortPath(t *testing.T) {
	dir := t.TempDir()
	path := ControlPath(filepath.Join(dir, "agent.json"))
	if len(path) > controlPathLimit {
		t.Skipf("temp dir %q is already too long for a Unix socket", dir)
	}
	ln, err := listenControl(path)
	if err != nil {
		t.Fatalf("listenControl(%q): %v", path, err)
	}
	ln.Close()
}
