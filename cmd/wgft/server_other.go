//go:build !linux

package main

import (
	"errors"

	"github.com/spf13/cobra"
)

// newServerCmd は Linux 以外のビルドでの server サブコマンド。server はカーネルの WireGuard と nftables を
// 使うので Linux でしか動かない。Windows と macOS のバイナリが持つのはエージェントと CLI だけである。
func newServerCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "server",
		Short:              "Run the VPS side; Linux only, not available in this build",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("the server runs on Linux only; this build carries the agent and the rule CLI")
		},
	}
}
