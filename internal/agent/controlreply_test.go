package agent

import (
	"os"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/flock"
)

// 制御ソケットの rotate-key の応答の行。成功は "ok <公開鍵>\n"、失敗は "error: <本文>\n" である。
// CLI はこの行を読んで表示するので、接頭辞と改行は外から見える約束になる。

// 成功の応答は "ok " に新しい公開鍵と改行が続く 1 行で、その鍵は保存した鍵の公開鍵と一致する。
func TestControlRotateKeyReplyOnSuccess(t *testing.T) {
	oldKey := newKey(t)
	rt := newRebuildTestRuntime(t, closedUDPPort(t), newKey(t).PublicKey(), oldKey, nil)
	ask := serveTestControl(t, rt)
	rt.mu.Lock()
	rt.f.WGPrivateKey = oldKey.String()
	rt.mu.Unlock()

	line := ask(t, "rotate-key")

	g, err := credentials.Load(rt.opts.CredentialsPath)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := g.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if saved == oldKey {
		t.Fatal("the saved key is still the old key")
	}
	if want := "ok " + saved.PublicKey().String() + "\n"; line != want {
		t.Errorf("reply %q, want %q", line, want)
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.priv != saved {
		t.Error("the runtime does not use the key it saved")
	}
}

// 保存に失敗したときの応答は "error: " に本文と改行が続く 1 行で、今の鍵は変わらない。
func TestControlRotateKeyReplyOnSaveFailure(t *testing.T) {
	oldKey := newKey(t)
	rt := newRebuildTestRuntime(t, closedUDPPort(t), newKey(t).PublicKey(), oldKey, nil)
	ask := serveTestControl(t, rt)
	// serveTestControl の後で CredentialsPath を差し替えると、制御ソケットを開いた goroutine の読み取りと
	// 競合する。パスは変えず、認証情報ファイルの場所にディレクトリを置いて保存を失敗させる。
	if err := os.Mkdir(rt.opts.CredentialsPath, 0o700); err != nil {
		t.Fatal(err)
	}
	rt.mu.Lock()
	rt.f.WGPrivateKey = oldKey.String()
	path := rt.opts.CredentialsPath
	before := rt.us().tun
	rt.mu.Unlock()
	if before == nil {
		t.Fatal("no tunnel is running before the request")
	}

	line := ask(t, "rotate-key")

	want := "error: " + path + " is not a regular file, so it was left untouched: " + flock.ErrNotRegular.Error() + "\n"
	if line != want {
		t.Errorf("reply %q, want %q", line, want)
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.f.WGPrivateKey != oldKey.String() || rt.priv != oldKey {
		t.Error("the old key is not in effect after the failed rotate-key")
	}
	// 閉じたトンネルは dataplane が nil に置き換えるので、同じ値が残っていれば閉じていない
	if rt.us().tun != before {
		t.Error("the running tunnel was closed or replaced although the key was not saved")
	}
}
