package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd"
)

// --version と `wgft version` はどちらもバージョン文字列だけを出す(前後に
// "wgft version" などを付けない)。README の取得コマンドやスクリプトが
// `wgft --version` の出力をそのまま比較できることを保証する。
func TestVersionFlag(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(buf.String())
	if got != vpsd.Version {
		t.Errorf("--version = %q, want %q", got, vpsd.Version)
	}
}

func TestVersionSubcommand(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(buf.String())
	if got != vpsd.Version {
		t.Errorf("version = %q, want %q", got, vpsd.Version)
	}
}
