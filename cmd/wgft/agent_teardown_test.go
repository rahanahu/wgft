package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rahanahu/wgft/internal/startup"
)

// Linux 以外のビルドでは、agent teardown は何も読まずに種別 prerequisite の拒否になり、一発実行の
// 書き出しで終了コード 3 で止まる(設計文書 10.3・11b 節)。
func TestAgentTeardownOffLinuxIsAPrerequisiteRefusal(t *testing.T) {
	old := agentGOOS
	agentGOOS = "darwin"
	t.Cleanup(func() { agentGOOS = old })
	dir := t.TempDir()
	root := newRootCmd()
	root.SetArgs([]string{"agent", "teardown", "--config", filepath.Join(dir, "none.env"), "--data-dir", dir})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	err := root.Execute()
	if got := exitCode(err); got != exitRefusal {
		t.Fatalf("err=%v exitCode=%d, want %d", err, got, exitRefusal)
	}
	if r := startup.Of(err); r == nil || r.Category != startup.CategoryPrerequisite || r.Subject != "operating system" {
		t.Errorf("refusal = %v, want a prerequisite refusal about the operating system", r)
	}
	if got := err.Error(); len(got) < 16 || got[:16] != "cannot continue " {
		t.Errorf("message = %q, want the one-shot opening", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.json.lock")); !os.IsNotExist(err) {
		t.Errorf("a lock file exists after the refusal: %v", err)
	}
}

// 値だけで判定できる WGFT_WG_INTERFACE の誤りは、何も読む前に種別 config の拒否になる。
func TestAgentTeardownChecksTheInterfaceName(t *testing.T) {
	old := agentGOOS
	agentGOOS = "linux"
	t.Cleanup(func() { agentGOOS = old })
	dir := t.TempDir()
	root := newRootCmd()
	root.SetArgs([]string{"agent", "teardown", "--config", filepath.Join(dir, "none.env"), "--data-dir", dir, "--wg-interface", "a/b"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	err := root.Execute()
	if r := startup.Of(err); r == nil || r.Category != startup.CategoryConfig {
		t.Errorf("err = %v, want a config refusal", err)
	}
}

// WGFT_DATA_DIR が空のとき、pubkey と rotate-key は agent.json を / やカレントに作らず、種別 config で拒否する。
func TestAgentKeyCommandsRejectEmptyDataDir(t *testing.T) {
	for _, sub := range []string{"pubkey", "rotate-key"} {
		t.Run(sub, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			root := newRootCmd()
			root.SetArgs([]string{"agent", sub, "--config", filepath.Join(dir, "none.env"), "--data-dir", ""})
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			err := root.Execute()
			if r := startup.Of(err); r == nil || r.Category != startup.CategoryConfig {
				t.Fatalf("err = %v, want a config refusal", err)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "agent.json")); !os.IsNotExist(statErr) {
				t.Errorf("agent.json was created in the current directory: %v", statErr)
			}
		})
	}
}
