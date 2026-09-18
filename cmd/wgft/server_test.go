//go:build linux

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
