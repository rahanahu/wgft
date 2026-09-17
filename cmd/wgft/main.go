// wgft は VPS で受けた TCP/UDP を WireGuard 経由で自宅のサービスへ届けるツール。
// vpsd と agent は同一バイナリで、サブコマンドで切り替える(仕様 2 節)。
package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/buildinfo"
)

// exitConfigRefusal は、他人の wg インタフェースやポート・アドレスの衝突で
// 起動を中止したときの終了コード。systemd の RestartPreventExitStatus に入れて、
// 設定ミスで再起動ループにならないようにする。
const exitConfigRefusal = 3

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
		if isStartupRefusal(err) {
			os.Exit(exitConfigRefusal)
		}
		os.Exit(1)
	}
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
