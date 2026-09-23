//go:build !linux

package main

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/startup"
)

// newServerCmd は Linux 以外のビルドでの server サブコマンド。server はカーネルの WireGuard と nftables を
// 使うので Linux でしか動かない。Windows と macOS のバイナリが持つのはエージェントと CLI だけである。
//
// 一群を 1 つのコマンドに畳まず、Linux 側と同じ木の形を保つのは、拒否の文面がコマンドごとに決まる
// ためである(設計文書 11b 節)。常駐プロセスを起動するのは `server run` だけなので、注記を持つのも
// `run` だけであり、残りは markOneShotRefusals が一発実行の側に倒す。1 つのコマンドに畳むと、
// `server run` まで一発実行の文面になる。
func newServerCmd() *cobra.Command {
	root := &cobra.Command{
		Use:         "server",
		Short:       "VPS-side daemon; Linux only, not available in this build",
		Long:        linuxOnlyLong,
		Annotations: map[string]string{ownHelpAnnotation: "yes"},
		Args:        cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return linuxOnlyRefusal()
		},
	}
	run := linuxOnlyServerCmd("run", "run the daemon; Linux only, not available in this build")
	// 常駐プロセスの起動を止めた拒否なので、書き出しは `refusing to start` のままである
	// (設計文書 11b 節)。
	run.Annotations[daemonAnnotation] = "yes"
	root.AddCommand(
		run,
		linuxOnlyServerCmd("check", "check the config and environment; Linux only, not available in this build"),
		linuxOnlyServerCmd("nft", "print the applied table inet wgft; Linux only, not available in this build"),
		linuxOnlyServerCmd("teardown", "remove what wgft created; Linux only, not available in this build"),
		linuxOnlyServerCmd("doctor", "diagnose the forwarding path; Linux only, not available in this build"),
	)
	return root
}

// linuxOnlyServerCmd は、Linux 以外のビルドで server の 1 つのサブコマンドの代わりに置くコマンドである。
// DisableFlagParsing を付けてあるので、Linux の側で受け付けるフラグを付けて呼んでも、フラグの誤りでは
// なく Linux 専用である旨で止まる。
func linuxOnlyServerCmd(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Long:  linuxOnlyLong,
		// 表の Linux 向けの説明を当てない。当てると、動かないコマンドの機能を肯定形で述べる。
		Annotations:        map[string]string{ownHelpAnnotation: "yes"},
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// DisableFlagParsing を付けたコマンドでは cobra が --help を拾わないので、ここで拾う。
			// `--` より後ろはフラグではないので見ない。help は pflag の bool フラグなので、
			// `-h`、`--help` に加えて `--help=true`、`-h=true`、`--help=false`、`-h=false` も
			// pflag と同じく strconv.ParseBool で解く。値が真に解けない場合、実物の cobra は
			// フラグの誤りとしてコマンド全体を止めるが、この差し替えは help か拒否かの二択しか
			// 持たないので、help ではない側、つまり拒否に倒す。
			for _, a := range args {
				if a == "--" {
					break
				}
				if a == "-h" || a == "--help" {
					return cmd.Help()
				}
				if v, ok := boolFlagValue(a, "--help"); ok && v {
					return cmd.Help()
				}
				if v, ok := boolFlagValue(a, "-h"); ok && v {
					return cmd.Help()
				}
			}
			return linuxOnlyRefusal()
		},
	}
}

// boolFlagValue は、引数 a が `<name>=<値>` の形なら、値を strconv.ParseBool で解いて返す。pflag は
// bool フラグの `=` の後ろをこの関数と同じ規則で解く。値が解けなければ ok は false であり、呼び出し側は
// help とは扱わない。
func boolFlagValue(a, name string) (v bool, ok bool) {
	prefix := name + "="
	if !strings.HasPrefix(a, prefix) {
		return false, false
	}
	v, err := strconv.ParseBool(a[len(prefix):])
	return v, err == nil
}

// linuxOnlyLong は、差し替えのコマンドの --help に出る説明である。Linux 向けの説明の代わりに置く。
const linuxOnlyLong = `Not available in this build. The server uses kernel WireGuard and nftables,
so it runs on Linux only; the Windows and macOS builds carry the agent and the
rule CLI. Each server subcommand refuses to run here and exits with code 3,
as a prerequisite the host cannot provide.`

// linuxOnlyRefusal は、Linux 以外のビルドで server の一群が返す拒否である。種別は prerequisite で
// ある。ホストが備えるべきものの欠如であり、再試行でも再起動でも現れない(設計文書 11b 節)ので、
// 終了コードは 3 になる。3 にする理由はこの分類であって、再起動を止める効果ではない。この拒否が起きる
// ホストには systemd が無く、同梱物にも Linux 以外で server を監督するものは無いので、終了コード 3 が
// 再起動を止める効果はそこでは働かない。効果は、運用者と監視が再試行で直る失敗と区別できることに
// とどまる。
func linuxOnlyRefusal() error {
	return startup.Prerequisite("operating system", "the server runs on Linux only; this build carries the agent and the rule CLI")
}
