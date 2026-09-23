//go:build !linux

package main

import (
	"io"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/startup"
)

// server の一群は、Linux 以外のビルドでは差し替えになる(cmd/wgft/server_other.go)。この差し替えが
// 返すのは種別 prerequisite の拒否であり、終了コードは 3 である。Linux でないことは再試行でも再起動でも
// 消えないので、設計文書 11b 節の非対称の規則の拒否の側に当たる。書き出しは、そのコマンドが常駐
// プロセスを起動するかどうかで分かれる。
//
// 各ケースにはフラグを 1 つ付ける。一群そのものも同じ拒否を返すので、フラグの無い呼び出しでは、
// サブコマンドが消えて一群の RunE に拾われても区別が付かない。一群はフラグを解釈するので、消えた
// サブコマンドのフラグは unknown flag になって現れる。
//
// この検査は Linux では走らない(このファイルのビルドタグ)。CI の windows-test と macos-test が
// 実際に走らせる。
func TestLinuxOnlyServerGroupRefuses(t *testing.T) {
	const reason = "the server runs on Linux only"
	const subject = "[prerequisite operating system]"
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"run starts a daemon", []string{"server", "run"}, "refusing to start " + subject},
		{"run with the flags the Linux build takes", []string{"server", "run", "--mode", "kernel", "--wg-endpoint", "vps.example.com:51820"}, "refusing to start " + subject},
		{"check starts nothing", []string{"server", "check", "--config", "server.env"}, "cannot continue " + subject},
		{"nft starts nothing", []string{"server", "nft", "--admin", "unix:///run/wgft/admin.sock"}, "cannot continue " + subject},
		{"teardown starts nothing", []string{"server", "teardown", "--purge", "--yes"}, "cannot continue " + subject},
		{"doctor starts nothing", []string{"server", "doctor", "--json"}, "cannot continue " + subject},
		{"the group itself starts nothing", []string{"server"}, "cannot continue " + subject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newRootCmd()
			root.SetArgs(tc.args)
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			err := root.Execute()
			if err == nil {
				t.Fatal("the server is not in this build; the command must fail")
			}
			if !strings.Contains(err.Error(), reason) {
				t.Errorf("message = %q, want it to name the reason %q", err.Error(), reason)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("message = %q, want it to open with %q", err.Error(), tc.want)
			}
			r := startup.Of(err)
			if r == nil {
				t.Fatalf("error = %q, want a startup refusal: not being Linux is a prerequisite no retry can bring", err.Error())
			}
			if r.Category != startup.CategoryPrerequisite {
				t.Errorf("category = %q, want %q: the host cannot provide kernel WireGuard", r.Category, startup.CategoryPrerequisite)
			}
			if got := exitCode(err); got != exitRefusal {
				t.Errorf("exitCode = %d, want %d", got, exitRefusal)
			}
		})
	}
}

// 差し替えの --help は、Linux 向けの説明を出さない。表の説明は同じパスのコマンドにも当たるので、
// 注記で断らないと、動かないコマンドについて機能を肯定形で述べる。
func TestLinuxOnlyServerHelpSaysItIsNotHere(t *testing.T) {
	for _, args := range [][]string{
		{"server", "--help"},
		{"server", "run", "--help"},
		{"help", "server", "run"},
		{"help", "server", "doctor"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			root := newRootCmd()
			var out strings.Builder
			root.SetArgs(args)
			root.SetOut(&out)
			root.SetErr(io.Discard)
			if err := root.Execute(); err != nil {
				t.Fatalf("help must not fail: %v", err)
			}
			got := out.String()
			if !strings.Contains(got, "Not available in this build") {
				t.Errorf("help = %q, want it to say the command is not available in this build", got)
			}
			for key, text := range helpTexts {
				if !strings.HasPrefix(key, "server") || text.Long == "" {
					continue
				}
				first := strings.SplitN(text.Long, "\n", 2)[0]
				if strings.Contains(got, first) {
					t.Errorf("help carries the Linux build's text for %q: %q", key, first)
				}
			}
		})
	}
}
