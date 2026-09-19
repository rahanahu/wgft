//go:build linux

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// server の値の誤りと必須の値の欠落は、システムに触る前に終了コード 3 で止まる(仕様 11a 節)。
func TestServerConfigErrorsExitCode(t *testing.T) {
	none := filepath.Join(t.TempDir(), "none.env")
	cases := []struct {
		name string
		env  map[string]string
		args []string
	}{
		// 型付きのフラグ(--wg-port 70000)は cobra が解析の段階で弾くので、unit が使う環境変数とファイルの経路で確かめる
		{"port", map[string]string{"WGFT_WG_ENDPOINT": "vps.example.com:51820", "WGFT_WG_PORT": "70000"}, nil},
		{"mtu", map[string]string{"WGFT_WG_ENDPOINT": "vps.example.com:51820", "WGFT_MTU": "big"}, nil},
		{"flows", map[string]string{"WGFT_WG_ENDPOINT": "vps.example.com:51820", "WGFT_MAX_TCP_FLOWS": "0"}, nil},
		{"per-source flows", map[string]string{"WGFT_WG_ENDPOINT": "vps.example.com:51820", "WGFT_MAX_UDP_FLOWS_PER_SOURCE": "-1"}, nil},
		{"no endpoint", map[string]string{"WGFT_WG_ENDPOINT": ""}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			root := newRootCmd()
			root.SetArgs(append([]string{"server", "run", "--mode", "kernel", "--config", none, "--data-dir", t.TempDir()}, tc.args...))
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			err := root.Execute()
			if got := exitCode(err); err == nil || got != exitConfigRefusal {
				t.Errorf("err=%v exitCode=%d, want %d", err, got, exitConfigRefusal)
			}
		})
	}
}

// buildServerOptions は、接続元 IP ごとの上限(server だけの設定)を vpsd.Options.Limits まで
// 運ぶ。既定値、明示した値、0(上限なし)を確かめる(仕様 7, 11a 節)。
func TestServerOptionsPerSourceLimits(t *testing.T) {
	build := func(t *testing.T, env map[string]string) (udp, tcp int) {
		none := filepath.Join(t.TempDir(), "none.env")
		for k, v := range env {
			t.Setenv(k, v)
		}
		cmd := &cobra.Command{Use: "run", RunE: func(*cobra.Command, []string) error { return nil }}
		registerServerFlags(cmd)
		cmd.SetArgs([]string{"--wg-endpoint", "vps.example.com:51820", "--config", none})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		opts, _, err := buildServerOptions(cmd)
		if err != nil {
			t.Fatal(err)
		}
		return opts.Limits.UDPPerSourceCap(), opts.Limits.TCPPerSourceCap()
	}

	// t.Setenv persists for the rest of a test, so each case needs its own subtest (fresh t)
	// to get isolated environments; otherwise env vars set by an earlier case would leak into
	// the next one.
	t.Run("defaults", func(t *testing.T) {
		if udp, tcp := build(t, nil); udp != 256 || tcp != 128 {
			t.Errorf("defaults: udp=%d tcp=%d, want 256 128", udp, tcp)
		}
	})
	t.Run("custom udp", func(t *testing.T) {
		if udp, tcp := build(t, map[string]string{"WGFT_MAX_UDP_FLOWS_PER_SOURCE": "200"}); udp != 200 || tcp != 128 {
			t.Errorf("custom udp: udp=%d tcp=%d, want 200 128", udp, tcp)
		}
	})
	t.Run("tcp disabled", func(t *testing.T) {
		if udp, tcp := build(t, map[string]string{"WGFT_MAX_TCP_FLOWS_PER_SOURCE": "0"}); udp != 256 || tcp != 0 {
			t.Errorf("tcp disabled: udp=%d tcp=%d, want 256 0", udp, tcp)
		}
	})
}

// server は、読めない設定ファイルに条件付きで 0644 を勧める(server の設定だけのファイルなら秘密は無い)。
func TestServerUnreadableHint(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a non-root user")
	}
	p := filepath.Join(t.TempDir(), "wgft.env")
	if err := os.WriteFile(p, []byte("WGFT_MODE=kernel\n"), 0); err != nil {
		t.Fatal(err)
	}
	root := newRootCmd()
	root.SetArgs([]string{"server", "run", "--config", p, "--data-dir", t.TempDir()})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	err := root.Execute()
	if got := exitCode(err); err == nil || got != exitConfigRefusal {
		t.Fatalf("err=%v exitCode=%d, want %d", err, got, exitConfigRefusal)
	}
	if msg := err.Error(); !strings.Contains(msg, "only server settings") || !strings.Contains(msg, "chmod 0644 "+p) {
		t.Errorf("server の直し方が違う: %v", err)
	}
}
