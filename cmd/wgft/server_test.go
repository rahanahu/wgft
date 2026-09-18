//go:build linux

package main

import (
	"path/filepath"
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
			root.SetOut(new(discard))
			root.SetErr(new(discard))
			err := root.Execute()
			if got := exitCode(err); err == nil || got != exitConfigRefusal {
				t.Errorf("err=%v exitCode=%d, want %d", err, got, exitConfigRefusal)
			}
		})
	}
}

type discard struct{}

func (*discard) Write(p []byte) (int, error) { return len(p), nil }
