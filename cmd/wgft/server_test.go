//go:build linux

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
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
		{"wg address not a prefix", map[string]string{"WGFT_WG_ENDPOINT": "vps.example.com:51820", "WGFT_WG_ADDRESS": "not-an-address"}, nil},
		{"wg address missing prefix length", map[string]string{"WGFT_WG_ENDPOINT": "vps.example.com:51820", "WGFT_WG_ADDRESS": "10.200.0.1"}, nil},
		// userspace モード:agent-api/admin の構文の誤りは applyNFT より後(admin.Listen/agentAPI.Listen)
		// でしか気付けなかったので、kernel モードで確かめると非 root では bringUpWG の CAP_NET_ADMIN 不足
		// (classifyPrivilege)で先に終了コード 3 になり、この構文検査を実際には試さないまま通ってしまう
		// (手を動かして確認した)。WGFT_ADMIN を非特権で書ける unix ソケットにし、wg のポートをサブテスト間で
		// 衝突しないように分けて、目的の値だけを壊す。
		{"agent api missing port", map[string]string{"WGFT_WG_ENDPOINT": "vps.example.com:51820", "WGFT_WG_PORT": "51821", "WGFT_ADMIN": "unix:///tmp/wgft-test-agent-api-missing-port-admin.sock", "WGFT_AGENT_API": "0.0.0.0"}, []string{"--mode", "userspace"}},
		{"admin missing port", map[string]string{"WGFT_WG_ENDPOINT": "vps.example.com:51820", "WGFT_WG_PORT": "51822", "WGFT_ADMIN": "127.0.0.1"}, []string{"--mode", "userspace"}},
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

// A conntrack read that still fails after table inet wgft is applied (internal/vpsd's
// applyThenReadConntrack, docs/design.md 改訂の記録 2026-09-20) is a permanent environment
// problem, not one retrying fixes, so vpsd.Run wraps it as a *wg.StartupRefusal. This must map to
// exit code 3 like the other startup refusals (an unrecognized wg interface, a bound WireGuard
// port, no WireGuard kernel support), so the shipped server.service's
// RestartPreventExitStatus=3 stops systemd from restarting it every 2 seconds forever, instead of
// the generic exit code 1 ReadUDPTimeouts's error used to produce (the actual production bug:
// found on a module-less Debian 12 lab VM, 83 restarts in about 3 minutes before this fix).
func TestConntrackReadFailureExitsWithConfigRefusal(t *testing.T) {
	err := &wg.StartupRefusal{Reason: "reading the conntrack UDP timeouts after applying table inet wgft: read /proc/sys/net/netfilter/nf_conntrack_udp_timeout: no such file or directory"}
	if !isStartupRefusal(err) {
		t.Errorf("isStartupRefusal(%v) = false, want true", err)
	}
	if got := exitCode(err); got != exitConfigRefusal {
		t.Errorf("exitCode(%v) = %d, want %d", err, got, exitConfigRefusal)
	}
}

// Kernel mode started without root or CAP_NET_ADMIN used to fail at the first privileged netlink
// or wgctrl call with a generic EPERM/EACCES, exit code 1, so the shipped server.service
// (Restart=on-failure, RestartSec=2, RestartPreventExitStatus=3, which does not include 1)
// restarted it every 2 seconds forever until someone reinstalled the unit correctly or switched to
// userspace mode. internal/dataplane/linuxkernel/wg.classifyPrivilege now wraps that class of
// error as a *wg.StartupRefusal (docs/design.md 9, 11a 節), which must map to exit code 3 like the
// other startup refusals.
func TestServerPrivilegeErrorExitsWithConfigRefusal(t *testing.T) {
	err := &wg.StartupRefusal{Reason: "kernel mode needs CAP_NET_ADMIN: operation not permitted. Run as root or with that capability, as the shipped server.service does (AmbientCapabilities=CAP_NET_ADMIN), or set WGFT_MODE=userspace, which needs neither"}
	if !isStartupRefusal(err) {
		t.Errorf("isStartupRefusal(%v) = false, want true", err)
	}
	if got := exitCode(err); got != exitConfigRefusal {
		t.Errorf("exitCode(%v) = %d, want %d", err, got, exitConfigRefusal)
	}
}

// buildServerOptions は、接続元 IP ごとの上限(server だけの設定)を
// vpsd.Options.AdmissionLimits まで運ぶ。既定値、明示した値、0(上限なし)を確かめる(仕様 7, 11a 節)。
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
		return opts.AdmissionLimits.UDPPerSourceCap(), opts.AdmissionLimits.TCPPerSourceCap()
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
