package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/buildinfo"
	"github.com/rahanahu/wgft/proto"
)

// --version prints the version string alone, with nothing before or after it (no "wgft
// version" prefix). README's install-check commands and scripts rely on being able to
// compare `wgft --version`'s output as-is.
func TestVersionFlag(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(buf.String())
	if got != buildinfo.Version {
		t.Errorf("--version = %q, want %q", got, buildinfo.Version)
	}
}

// `wgft version` prints the version string on its own first line (the same contract as
// --version), followed by the range of protocol versions this binary supports
// (design.md 7a.6 section). That range is a static property of the binary, not of any one
// agent connection, which is why it belongs next to the version rather than in `agent ls`.
func TestVersionSubcommand(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("version = %q, want 2 lines (version, protocol range)", buf.String())
	}
	if lines[0] != buildinfo.Version {
		t.Errorf("version line 1 = %q, want %q", lines[0], buildinfo.Version)
	}
	// Pinned as a literal rather than derived from proto.SupportedProtocol, so that a
	// change to the supported range has to be made here too instead of this test
	// silently following the implementation. (While Min and Max are both 1 no test can
	// catch the two being swapped, since either order prints "v1-v1".)
	const wantProto = "protocol range: v1-v1"
	if lines[1] != wantProto {
		t.Errorf("version line 2 = %q, want %q", lines[1], wantProto)
	}
}

// TestVersionSubcommandRangeComesFromProto pins the range line to proto.SupportedProtocol
// rather than to whatever string happens to be correct today. TestVersionSubcommand's
// literal alone cannot do that: while the supported range is v1-v1, an implementation that
// printed a hardcoded "protocol range: v1-v1" and never read proto.SupportedProtocol would
// satisfy it. Widening the range here and asserting the output follows is what makes the
// claim in design.md 7a.6 -- that the line reports the range built into this binary --
// actually checked. Min and Max are set to different values so their order is pinned too.
func TestVersionSubcommandRangeComesFromProto(t *testing.T) {
	saved := proto.SupportedProtocol
	t.Cleanup(func() { proto.SupportedProtocol = saved })
	proto.SupportedProtocol = proto.ProtocolRange{Min: 2, Max: 7}

	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("version = %q, want 2 lines", buf.String())
	}
	if want := "protocol range: v2-v7"; lines[1] != want {
		t.Errorf("version line 2 = %q, want %q (the range must be read from proto.SupportedProtocol)", lines[1], want)
	}
}

// 拒否の書き出しは、そのコマンドが常駐プロセスを起動するかどうかで決まる(設計文書 11b 節)。
// 設定を読む層は共有しているので、同じ設定の誤りが両方の経路に出る。`server check` と
// `server run` は buildServerOptions を共有しており、それでも文面が分かれることを固定する。
func TestRefusalWordingFollowsTheCommand(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.env")
	if err := os.WriteFile(bad, []byte("not a pair\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const startupWording = "refusing to start ["
	const oneShotWording = "cannot continue ["
	for _, tc := range []struct {
		name string
		args []string
		want string
		// serverSide は、Linux 以外のビルドでは差し替えになる `server` の一群である
		// (cmd/wgft/server_other.go)。設定を読む手前で Linux 専用である旨を答えるので、
		// 拒否の文面そのものがこのビルドには無い。
		serverSide bool
	}{
		{"server run starts a daemon", []string{"server", "run", "--config", bad, "--data-dir", dir}, startupWording, true},
		{"agent run starts a daemon", []string{"agent", "run", "--config", bad, "--data-dir", dir}, startupWording, false},
		{"server check starts nothing", []string{"server", "check", "--config", bad, "--data-dir", dir}, oneShotWording, true},
		{"agent doctor starts nothing", []string{"agent", "doctor", "--config", bad, "--data-dir", dir}, oneShotWording, false},
		{"status starts nothing", []string{"status", "--config", bad}, oneShotWording, false},
		{"rule ls starts nothing", []string{"rule", "ls", "--config", bad}, oneShotWording, false},
		{"agent pubkey starts nothing", []string{"agent", "pubkey", "--config", bad, "--data-dir", dir}, oneShotWording, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newRootCmd()
			root.SetArgs(tc.args)
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			err := root.Execute()
			if err == nil {
				t.Fatal("a dotenv that is not in KEY=value form must be refused")
			}
			if tc.serverSide && runtime.GOOS != "linux" {
				// 差し替えの側も確かめる。この一群は設定を読まないので拒否にはならず、
				// 再試行で直りうる失敗と同じ終了コード 1 で終わる(設計文書 11b 節)。
				if !strings.Contains(err.Error(), "the server runs on Linux only") {
					t.Errorf("message = %q, want the Linux-only answer this build gives", err.Error())
				}
				if got := exitCode(err); got != 1 {
					t.Errorf("exitCode = %d, want 1", got)
				}
				return
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("message = %q, want it to contain %q", err.Error(), tc.want)
			}
			// 文面だけの区別である。設定の誤りは、どちらの経路でも終了コード 3 で終わる。
			if got := exitCode(err); got != exitRefusal {
				t.Errorf("exitCode = %d, want %d", got, exitRefusal)
			}
		})
	}
}
