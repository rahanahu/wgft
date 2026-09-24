package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/startup"
)

// reconcileMode の表(仕様 11a 節)。記録の無いファイルはユーザー空間モード、設定の省略もユーザー空間
// モードを指す。kernel から userspace への切り替えだけを mode-gate で拒み、省略による切り替えも同じく拒む。
func TestReconcileMode(t *testing.T) {
	cases := []struct {
		name           string
		recorded, want string
		mode           string
		record         bool
		category       startup.Category // 空なら誤りなし
		mentions       []string
	}{
		{name: "no record, unset", recorded: "", want: "", mode: "userspace"},
		{name: "no record, userspace", recorded: "", want: "userspace", mode: "userspace"},
		{name: "userspace record, unset", recorded: "userspace", want: "", mode: "userspace"},
		{name: "no record, kernel passes and records", recorded: "", want: "kernel", mode: "kernel", record: true},
		{name: "userspace record, kernel passes and records", recorded: "userspace", want: "kernel", mode: "kernel", record: true},
		{name: "kernel record, kernel", recorded: "kernel", want: "kernel", mode: "kernel"},
		{name: "kernel record, userspace is refused", recorded: "kernel", want: "userspace",
			category: startup.CategoryModeGate, mentions: []string{"wgft agent teardown", "WGFT_MODE=kernel", "kernel to userspace"}},
		{name: "kernel record, unset is refused", recorded: "kernel", want: "",
			category: startup.CategoryModeGate, mentions: []string{"wgft agent teardown", "WGFT_MODE=kernel", "unset"}},
		{name: "unknown record", recorded: "proxy", want: "",
			category: startup.CategoryConflict, mentions: []string{`"proxy"`, "agent.json"}},
		{name: "unknown setting", recorded: "", want: "kernal",
			category: startup.CategoryConfig, mentions: []string{`"kernal"`, "kernel or userspace"}},
		{name: "unknown setting with a kernel record", recorded: "kernel", want: "Kernel",
			category: startup.CategoryConfig, mentions: []string{`"Kernel"`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mode, record, err := reconcileMode(c.recorded, c.want)
			if c.category == "" {
				if err != nil {
					t.Fatalf("err = %v, want none", err)
				}
				if mode != c.mode || record != c.record {
					t.Errorf("= %q, %v; want %q, %v", mode, record, c.mode, c.record)
				}
				return
			}
			r := startup.Of(err)
			if r == nil || r.Category != c.category || r.Subject != "WGFT_MODE" {
				t.Fatalf("err = %v, want a %s refusal about WGFT_MODE", err, c.category)
			}
			for _, m := range c.mentions {
				if !strings.Contains(err.Error(), m) {
					t.Errorf("refusal %q does not mention %q", err, m)
				}
			}
			if strings.ContainsAny(err.Error(), "()") {
				t.Errorf("refusal %q uses round parentheses; tool output avoids them", err)
			}
		})
	}
}

// enterMode は切り替えを記録して保存し、関門で止めるときも、カーネルモードを持たないビルドで止める
// ときも、認証情報ファイルに何も書かない(仕様 11a 節)。
func TestEnterMode(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "agent.json")
		if body != "" {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return path
	}
	read := func(t *testing.T, path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		return string(b)
	}
	load := func(t *testing.T, path string) *credentials.Credentials {
		t.Helper()
		f, err := credentials.LoadOrNew(path)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}

	t.Run("kernel is recorded before anything else is written", func(t *testing.T) {
		setKernelModeAvailable(t, true)
		path := write(t, `{"name":"home"}`)
		f := load(t, path)
		mode, err := enterMode(f, "kernel", path)
		if err != nil || mode != "kernel" {
			t.Fatalf("= %q, %v; want kernel", mode, err)
		}
		if got := load(t, path).Mode; got != "kernel" {
			t.Errorf("saved mode = %q, want kernel", got)
		}
	})
	t.Run("a fresh data dir records kernel too", func(t *testing.T) {
		setKernelModeAvailable(t, true)
		path := write(t, "")
		if _, err := enterMode(load(t, path), "kernel", path); err != nil {
			t.Fatal(err)
		}
		if got := load(t, path).Mode; got != "kernel" {
			t.Errorf("saved mode = %q, want kernel", got)
		}
	})
	t.Run("the gate writes nothing", func(t *testing.T) {
		body := `{"name":"home","mode":"kernel"}`
		path := write(t, body)
		if _, err := enterMode(load(t, path), "userspace", path); startup.Of(err) == nil {
			t.Fatalf("err = %v, want a refusal", err)
		}
		if got := read(t, path); got != body {
			t.Errorf("the refused start rewrote agent.json:\n%s", got)
		}
	})
	t.Run("userspace writes nothing", func(t *testing.T) {
		body := `{"name":"home"}`
		path := write(t, body)
		if _, err := enterMode(load(t, path), "", path); err != nil {
			t.Fatal(err)
		}
		if got := read(t, path); got != body {
			t.Errorf("a userspace start rewrote agent.json:\n%s", got)
		}
	})
	t.Run("a build without kernel mode stops before recording", func(t *testing.T) {
		setKernelModeAvailable(t, false)
		body := `{"name":"home"}`
		path := write(t, body)
		_, err := enterMode(load(t, path), "kernel", path)
		if r := startup.Of(err); r == nil || r.Category != startup.CategoryPrerequisite {
			t.Fatalf("err = %v, want a prerequisite refusal", err)
		}
		if got := read(t, path); got != body {
			t.Errorf("the refused start recorded something:\n%s", got)
		}
	})
}

func setKernelModeAvailable(t *testing.T, v bool) {
	t.Helper()
	old := kernelModeAvailable
	kernelModeAvailable = v
	t.Cleanup(func() { kernelModeAvailable = old })
}

// 停止中の rotate-key は、カーネルモードでは消す鍵を 1 つ前の鍵として残し、続けて 2 回実行しても
// 1 つ前の鍵を空で上書きしない。ユーザー空間モードは 1 つ前の鍵を持たない(仕様 7b.4 節)。
func TestRotateKeyWhileStoppedKeepsThePreviousKeyInKernelMode(t *testing.T) {
	for _, mode := range []string{"kernel", ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.json")
			f := &credentials.Credentials{Name: "home", Mode: mode}
			if _, err := f.EnsureKey(); err != nil {
				t.Fatal(err)
			}
			key := f.WGPrivateKey
			if err := f.Save(path); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				msg, err := RotateKey(path)
				if err != nil {
					t.Fatalf("rotate-key #%d: %v", i+1, err)
				}
				if got := strings.Contains(msg, "previous key"); got != (mode == "kernel") {
					t.Errorf("rotate-key #%d message mentions the previous key: %v, want %v: %q", i+1, got, mode == "kernel", msg)
				}
				g, err := credentials.Load(path)
				if err != nil {
					t.Fatal(err)
				}
				want := ""
				if mode == "kernel" {
					want = key
				}
				if g.WGPrivateKey != "" || g.PreviousWGPrivateKey != want {
					t.Errorf("after rotate-key #%d: key %q previous %q; want an empty key and previous %q", i+1, g.WGPrivateKey, g.PreviousWGPrivateKey, want)
				}
			}
		})
	}
}

// 稼働中の rotate-key は、カーネルモードでは今の鍵を 1 つ前の鍵として、新しい鍵と同じ保存で残す
// (仕様 7b.4 節)。wgft0 を書き換える前に落ちても、保存した認証情報ファイルから所有を判定できる。
func TestRotateKeyWhileRunningKeepsThePreviousKeyInKernelMode(t *testing.T) {
	for _, mode := range []string{"kernel", ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			oldKey := newKey(t)
			rt := newRebuildTestRuntime(t, closedUDPPort(t), newKey(t).PublicKey(), oldKey, nil)
			rt.mu.Lock()
			rt.f.Mode, rt.f.WGPrivateKey = mode, oldKey.String()
			rt.mu.Unlock()
			pub, err := rt.rotateKey()
			if err != nil {
				t.Fatalf("rotate-key: %v", err)
			}
			g, err := credentials.Load(rt.opts.CredentialsPath)
			if err != nil {
				t.Fatal(err)
			}
			k, err := g.PrivateKey()
			if err != nil || k.PublicKey() != pub {
				t.Fatalf("saved key %v, %v; want the rotated key", k.PublicKey(), err)
			}
			want := ""
			if mode == "kernel" {
				want = oldKey.String()
			}
			if g.PreviousWGPrivateKey != want {
				t.Errorf("saved previous key %q, want %q", g.PreviousWGPrivateKey, want)
			}
		})
	}
}

// 稼働中の rotate-key の保存が失敗したら、メモリの上の今の鍵と 1 つ前の鍵を元に戻し、トンネルの鍵も
// 変えない(仕様 7b.4 節)。戻さないと、次の rotate-key の後に落ちたとき、wgft0 の鍵がどちらとも一致しない。
func TestRotateKeyWhileRunningRestoresTheKeysWhenSaveFails(t *testing.T) {
	oldKey := newKey(t)
	rt := newRebuildTestRuntime(t, closedUDPPort(t), newKey(t).PublicKey(), oldKey, nil)
	rt.mu.Lock()
	rt.f.Mode, rt.f.WGPrivateKey, rt.f.PreviousWGPrivateKey = "kernel", oldKey.String(), "earlier"
	rt.opts.CredentialsPath = filepath.Join(t.TempDir(), "missing", "agent.json") // 保存が失敗する場所
	rt.mu.Unlock()
	if _, err := rt.rotateKey(); err == nil {
		t.Fatal("rotate-key succeeded although the credentials file cannot be saved")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.f.WGPrivateKey != oldKey.String() || rt.f.PreviousWGPrivateKey != "earlier" {
		t.Errorf("after a failed save: key %q previous %q; want %q and %q", rt.f.WGPrivateKey, rt.f.PreviousWGPrivateKey, oldKey.String(), "earlier")
	}
	if rt.priv != oldKey {
		t.Error("the runtime switched to the new key although it was not saved")
	}
}

// 停止中の rotate-key はロックを取ってから書き換える。判定の後に起動したエージェントがロックを持って
// いれば、稼働中として扱い、認証情報ファイルを書き換えない(仕様 9 節)。
func TestRotateKeyWhileStoppedTakesTheLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	f := &credentials.Credentials{Name: "home", Mode: "kernel"}
	if _, err := f.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := credentials.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	old := inspectLock
	inspectLock = func(string) (credentials.State, error) { return credentials.Unlocked, nil }
	t.Cleanup(func() { inspectLock = old })

	_, err = RotateKey(path)
	if err == nil || !strings.Contains(err.Error(), "agent is running") {
		t.Fatalf("err = %v, want the running path's error for an agent that holds the lock", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Errorf("rotate-key rewrote agent.json while another process held the lock:\n%s", after)
	}
}

// 認証情報ファイルが無ければ、停止中の rotate-key はロックファイルを作らずに誤りを返す。一度も起動して
// いないホストに、呼び出し元の権限のロックファイルを残さないためである。
func TestRotateKeyWithoutCredentialsLeavesNoLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if _, err := RotateKey(path); err == nil {
		t.Fatal("rotate-key succeeded without a credentials file")
	}
	if _, err := os.Stat(credentials.LockPath(path)); !os.IsNotExist(err) {
		t.Errorf("a lock file was created: %v", err)
	}
}

// ロックファイルがあって誰も持っていなければ、停止中の rotate-key は書き換えの間ロックを持つ(仕様 9 節)。
func TestRotateKeyWhileStoppedHoldsTheLockWhileWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	f := &credentials.Credentials{Name: "home"}
	if _, err := f.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	lock, err := credentials.Acquire(path) // ロックファイルを作ってから放す。停止したエージェントの跡である
	if err != nil {
		t.Fatal(err)
	}
	lock.Release()
	var held credentials.State
	rotateKeyLockedHook = func() { held, _ = credentials.Inspect(path) }
	t.Cleanup(func() { rotateKeyLockedHook = nil })
	if _, err := RotateKey(path); err != nil {
		t.Fatal(err)
	}
	if held != credentials.Locked {
		t.Errorf("the lock state while rewriting agent.json was %v, want locked", held)
	}
}

// ロックファイルが無ければ、停止中の rotate-key はロックファイルを作らずに鍵を作り直す。作ると、
// 呼び出し元(root)の権限のロックファイルが残り、非特権で動くエージェントの起動を塞ぐ(10.2c 節)。
func TestRotateKeyWithoutALockFileLeavesNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	f := &credentials.Credentials{Name: "home", Mode: "kernel"}
	if _, err := f.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	key := f.WGPrivateKey
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := RotateKey(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(credentials.LockPath(path)); !os.IsNotExist(err) {
		t.Errorf("stopped rotate-key created a lock file: %v", err)
	}
	g, err := credentials.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if g.WGPrivateKey != "" || g.PreviousWGPrivateKey != key {
		t.Errorf("key %q previous %q; want the key cleared and kept as the previous key", g.WGPrivateKey, g.PreviousWGPrivateKey)
	}
}
