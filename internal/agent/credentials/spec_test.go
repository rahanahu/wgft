package credentials

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// このファイルは、言語に依らない仕様(docs/design/spec/credentials.md)の fixture と、認証情報ファイルの
// 読み書きを照らす。fixture はリポジトリの直下の testdata/spec にあり、Rust の実装も読む。fixture は
// agent.json の中身そのもので、Save と同じく末尾に改行を持たない。秘密の値は本物ではない値に
// 置き換えてある。

var specDir = filepath.Join("..", "..", "..", "testdata", "spec")

// TestSpecCredentialsRoundTrip は、ラボで記録した v1 の agent.json を Load が読み、Save が同じ
// byte 列に書き戻すことを確かめる。どのキーも型が知っていて、キーの順と省略と字下げが型のとおりで
// あることの確かめになる。
func TestSpecCredentialsRoundTrip(t *testing.T) {
	for _, name := range []string{"agent-userspace.json", "agent-kernel.json", "agent-rotated.json", "agent-unregistered.json"} {
		want, err := os.ReadFile(filepath.Join(specDir, "credentials", name))
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "agent.json")
		if err := os.WriteFile(path, want, 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := Load(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := f.Save(path); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s:\n got %s\nwant %s", name, got, want)
		}
		if f.WGPrivateKey != "" {
			if _, err := f.PrivateKey(); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
}

// TestSpecCredentialsNames は、credentials.md のファイルの名前と上限を固定する。
func TestSpecCredentialsNames(t *testing.T) {
	if tempPrefix != ".wgft-credentials-" || MaxFileSize != 512<<20 {
		t.Errorf("tempPrefix %q, MaxFileSize %d", tempPrefix, MaxFileSize)
	}
}
