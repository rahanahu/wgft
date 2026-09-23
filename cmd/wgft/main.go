// wgft は VPS で受けた TCP/UDP を WireGuard 経由で自宅のサービスへ届けるツール。
// vpsd と agent は同一バイナリで、サブコマンドで切り替える(仕様 2 節)。
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/buildinfo"
	"github.com/rahanahu/wgft/internal/startup"
	"github.com/rahanahu/wgft/proto"
)

// cobra's default MousetrapHelpText (spf13/cobra@v1.10.2 cobra.go:72) tells a user who
// double-clicks the .exe in Explorer to open cmd.exe. docs/setup.md's Windows procedure
// uses PowerShell instead ($env:WGFT_JOIN, .\wgft.exe agent run), which cmd.exe does not
// accept, so the default sends the user to the wrong shell. init overrides it here rather
// than in newRootCmd because it must run before cobra's Windows-only preExecHook, which
// fires inside (*Command).Execute before any command-specific setup.
func init() {
	// The scenario this message exists for is a user double-clicking the file they just
	// downloaded from the Releases page, which is named wgft-windows-amd64.exe. Renaming
	// it to wgft.exe is a step in docs/setup.md's Windows procedure, which they have not
	// followed yet at this point, so a hardcoded ".\wgft.exe" example would usually name a
	// file that does not exist. os.Args[0] is set by the Go runtime from the command line
	// Explorer used to start the process, which for a double-click is the executable's own
	// path (e.g. `C:\Users\name\Downloads\wgft-windows-amd64.exe`), so filepath.Base gives
	// the real file name. Base only returns "." or a bare separator for an empty or
	// all-separator input, neither of which a real launch path produces; exeName falls back
	// to the setup guide's own name for that unlikely case rather than printing either.
	name := exeName()
	cobra.MousetrapHelpText = fmt.Sprintf(`wgft is a command line tool; double-clicking it does not run it.

Open PowerShell in the folder holding this .exe and run:
  .\%s --help

See the Windows setup guide on GitHub at docs/setup.md for the full procedure, including the join command.
`, name)
	// The default 5s auto-close (cobra.go:81) is too short for this longer message.
	// 0 makes cobra print "Press return to continue..." and wait for Enter
	// (command_win.go:32-35) instead, so the window stays open until the user is done
	// reading it.
	cobra.MousetrapDisplayDuration = 0
}

// exeName returns the file name the user actually double-clicked, falling back to the name
// docs/setup.md's Windows procedure uses if os.Args[0] is empty or is only separators (Base
// then returns "." or a bare separator, neither a usable example).
func exeName() string {
	name := filepath.Base(os.Args[0])
	if name == "" || name == "." || name == string(filepath.Separator) {
		return "wgft.exe"
	}
	return name
}

// exitRefusal は、再起動では直らない失敗で起動を中止したときの終了コード。設計文書 11b 節の
// 4 つの種別(config、prerequisite、conflict、mode-gate)がここに写る。同梱の unit は
// RestartPreventExitStatus に入れているので、systemd はこの終了コードでは再起動しない。
// それ以外の失敗は終了コード 1 にして、unit の再起動に任せる。
const exitRefusal = 3

// exitUnavailable は、コマンドが求められた報告そのものを作れなかったときの終了コードである。
// `wgft server doctor`(設計文書 10.2a 節)と `wgft status`(10.2b 節)が使う。どちらも 0(壊れた・
// degraded な項目が無い)と 1(ある)を監視に伝える約束なので、管理用 API に届かない場合や
// 引数が誤っている場合を 1 に混ぜると、監視が「転送が止まった」「配置が劣化した」と読んでしまう。
// 11b 節の終了コード 3 とは目的が別で、あちらは起動の拒否を監督するプロセスに伝えるものである。
const exitUnavailable = 2

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "wgft",
		Short:         "Forward TCP/UDP received at a VPS to home services over WireGuard",
		Version:       effectiveVersion(),
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	// buildinfo.Version is embedded at build time with -X (scripts/build-release.sh,
	// .goreleaser.yaml). --version prints that bare string alone (e.g. "v0.1.0" or
	// "dev"), matching what the release assets use; `wgft version` prints it as its
	// first line and adds the supported protocol range below it (7a.6 section).
	root.SetVersionTemplate("{{.Version}}\n")
	root.AddCommand(
		newServerCmd(),
		newAgentCmd(),
		newRuleCmd(),
		newStatusCmd(),
		newVersionCmd(),
	)
	applyHelp(root)
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the wgft version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if _, err := fmt.Fprintln(out, effectiveVersion()); err != nil {
				return err
			}
			// This is the range this binary supports (design.md 7a.6 section), not the
			// version negotiated with any one agent; "wgft agent ls" prints that instead,
			// per connection, in its PROTO column.
			_, err := fmt.Fprintf(out, "protocol range: v%d-v%d\n", proto.SupportedProtocol.Min, proto.SupportedProtocol.Max)
			return err
		},
	}
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(exitCode(err))
	}
}

// exitCode は Execute の失敗を終了コードに振り分ける。判定は 1 か所で、型を見るだけで済む。
// 起動の拒否(*startup.Refusal)は 3、報告を作れなかった失敗(*unavailableError)は 2、
// それ以外は 1 である。server も agent も、どの層も同じ型を返す(設計文書 11b 節)。かつては
// wg.StartupRefusal、cmd の configError、agent.ConfigRefusal の 3 つを並べて見ており、新しい
// 失敗を足すときに写し忘れる余地があった。2 つ目の型は `wgft server doctor` のために足したが、
// `wgft status` も同じ型を使う。終了コード 2 の意味はどちらも 10.2a 節と 10.2b 節にそれぞれ定める。
func exitCode(err error) int {
	if startup.IsRefusal(err) {
		return exitRefusal
	}
	var un *unavailableError
	if errors.As(err, &un) {
		return exitUnavailable
	}
	return 1
}

// unavailableError は「求められた報告を作れなかった」失敗である。起動の拒否と同じく 1 つの型
// だけを見て終了コードを決める形を保つ(設計文書 11b 節の写し忘れを防ぐ理由は同じ)。
type unavailableError struct{ err error }

func (e *unavailableError) Error() string { return e.err.Error() }
func (e *unavailableError) Unwrap() error { return e.err }

// unavailable は err を終了コード 2 の失敗として包む。
func unavailable(err error) error { return &unavailableError{err: err} }

// effectiveVersion は -X で埋めた buildinfo.Version を返す。埋められていない(`go install ...@v0.1.0` で
// 入れた)場合は、モジュールの版をビルド情報から取る。それも無ければ dev のまま。
func effectiveVersion() string {
	if buildinfo.Version != "dev" {
		return buildinfo.Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return buildinfo.Version
}
