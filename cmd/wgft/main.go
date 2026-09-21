// wgft は VPS で受けた TCP/UDP を WireGuard 経由で自宅のサービスへ届けるツール。
// vpsd と agent は同一バイナリで、サブコマンドで切り替える(仕様 2 節)。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/buildinfo"
	"github.com/rahanahu/wgft/internal/startup"
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

See the Windows setup guide on GitHub (docs/setup.md) for the full procedure, including the join command.
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

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "wgft",
		Short:         "Forward TCP/UDP received at a VPS to home services over WireGuard",
		Version:       effectiveVersion(),
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	// buildinfo.Version is embedded at build time with -X (scripts/build-release.sh,
	// .goreleaser.yaml). --version and `wgft version` both print the bare
	// string (e.g. "v0.1.0" or "dev"), matching what the release assets use.
	root.SetVersionTemplate("{{.Version}}\n")
	root.AddCommand(
		newServerCmd(),
		newAgentCmd(),
		newRuleCmd(),
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
			_, err := fmt.Fprintln(cmd.OutOrStdout(), effectiveVersion())
			return err
		},
	}
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(exitCode(err))
	}
}

// exitCode は Execute の失敗を終了コードに振り分ける。判定は 1 か所、1 つの型で済む。起動の拒否
// (*startup.Refusal)は 3、それ以外は 1 である。server も agent も、どの層も同じ型を返す
// (設計文書 11b 節)。かつては wg.StartupRefusal、cmd の configError、agent.ConfigRefusal の
// 3 つを並べて見ており、新しい失敗を足すときに写し忘れる余地があった。
func exitCode(err error) int {
	if startup.IsRefusal(err) {
		return exitRefusal
	}
	return 1
}

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
