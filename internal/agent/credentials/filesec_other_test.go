//go:build !windows

package credentials

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSecureExistingDoesNotChangeUnixPermissions は、secureExisting が Unix では no-op で
// あることを確かめる。管理者が意図して 0400 に絞ったファイルを、この修正が 0600 へ緩めて
// しまわないための回帰テスト(9 節:余分な権限だけを外し、それ以外は変えない)。
func TestSecureExistingDoesNotChangeUnixPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte("{}"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := secureExisting(path); err != nil {
		t.Fatalf("secureExisting = %v, want nil (no-op on Unix)", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Errorf("perm changed to %o, want unchanged 0400", info.Mode().Perm())
	}
}

// TestLoadDoesNotChmodOnUnix は、Load がこの修正で agent.json の権限を書き換えないことを
// 確かめる回帰テスト。deploy/agent.compose.yaml のように cap_drop: [ALL] で動き、ボリューム
// のファイルを所有しない構成でも、この修正の前と同じく Load が失敗しないことを兼ねて確かめる
// (0400 は所有者なら chmod できずとも読めるので、Load 自体は通る)。
func TestLoadDoesNotChmodOnUnix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := (&Credentials{Name: "x"}).Save(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Errorf("Load changed perm to %o, want unchanged 0400", info.Mode().Perm())
	}
}

// TestSecureSocketIgnoresChmodFailure は、chmod が失敗しても SecureSocket が nil を返す
// (制御ソケットを開けなくする理由にしない、この修正より前と同じ挙動)ことを確かめる。
// 存在しないディレクトリの下のパスを使って chmod を確実に失敗させる。
func TestSecureSocketIgnoresChmodFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist", "agent.json.sock")
	if err := SecureSocket(path); err != nil {
		t.Errorf("SecureSocket = %v, want nil even when chmod fails", err)
	}
}
