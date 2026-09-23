//go:build !linux

package main

import (
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
		Use:   "server",
		Short: "VPS-side daemon; Linux only, not available in this build",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return linuxOnlyRefusal()
		},
	}
	run := linuxOnlyServerCmd("run", "run the daemon; Linux only, not available in this build")
	// 常駐プロセスの起動を止めた拒否なので、書き出しは `refusing to start` のままである
	// (設計文書 11b 節)。
	run.Annotations = map[string]string{daemonAnnotation: "yes"}
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
		Use:                use,
		Short:              short,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return linuxOnlyRefusal()
		},
	}
}

// linuxOnlyRefusal は、Linux 以外のビルドで server の一群が返す拒否である。種別は prerequisite で
// ある。ホストが備えるべきものの欠如であり、再試行では現れない(設計文書 11b 節)。したがって終了
// コードは 3 になり、同梱の unit の RestartPreventExitStatus=3 が再起動を止める。2026-09-23 までは
// 普通のエラーだったので終了コード 1 になり、Linux でないという直りようのない前提の不成立で、監督する
// プロセスが再起動を繰り返した。
func linuxOnlyRefusal() error {
	return startup.Prerequisite("operating system", "the server runs on Linux only; this build carries the agent and the rule CLI")
}
