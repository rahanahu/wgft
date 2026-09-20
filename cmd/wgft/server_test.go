//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/startup"
)

// server の値の誤りと必須の値の欠落は、システムに触る前に終了コード 3 で止まる(設計文書 11b 節)。
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
		// agent API は TCP だけで待ち受ける(agentapi.Listen)。unix:// を通すと net.Listen("tcp", "unix://...") まで
		// 届いて終了コード 1 になり、unit が再起動を繰り返す
		{"agent api unix socket", map[string]string{"WGFT_WG_ENDPOINT": "vps.example.com:51820", "WGFT_WG_PORT": "51823", "WGFT_ADMIN": "unix:///tmp/wgft-test-agent-api-unix-admin.sock", "WGFT_AGENT_API": "unix:///tmp/wgft-test-agent-api.sock"}, []string{"--mode", "userspace"}},
		{"agent api bad port", map[string]string{"WGFT_WG_ENDPOINT": "vps.example.com:51820", "WGFT_WG_PORT": "51824", "WGFT_ADMIN": "unix:///tmp/wgft-test-agent-api-bad-port-admin.sock", "WGFT_AGENT_API": "0.0.0.0:notaport"}, []string{"--mode", "userspace"}},
		{"admin unix without a path", map[string]string{"WGFT_WG_ENDPOINT": "vps.example.com:51820", "WGFT_WG_PORT": "51825", "WGFT_ADMIN": "unix://"}, []string{"--mode", "userspace"}},
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
			if got := exitCode(err); err == nil || got != exitRefusal {
				t.Errorf("err=%v exitCode=%d, want %d", err, got, exitRefusal)
			}
		})
	}
}

// A privilege failure from kernel mode (no root, no CAP_NET_ADMIN) is a prerequisite refusal, and
// cmd/wgft must map any refusal, whatever layer raised it, to exit code 3 so the shipped
// server.service's RestartPreventExitStatus=3 stops the 2-second restart loop. The counterpart is
// that an ordinary error keeps exit code 1: since 2026-09-21 that is deliberately where a conflict
// with someone else's resource lands (another WireGuard on the port, a foreign interface with the
// same name, an overlapping address range) and where a conntrack read failing after the table is
// applied lands, because the other owner may release it and the unit then starts by itself
// (docs/design.md 11b 節).
func TestExitCodeFollowsTheRefusalType(t *testing.T) {
	refusals := []error{
		startup.Prerequisite("CAP_NET_ADMIN", "kernel mode needs CAP_NET_ADMIN: operation not permitted"),
		startup.Prerequisite("wireguard module", "this kernel has no WireGuard support"),
		startup.Config("WGFT_MTU", "%q is not an integer between 576 and 9216", "big"),
		startup.Conflict("WGFT_WG_ADDRESS", "wg address range differs from the recorded one"),
		startup.ModeGate("WGFT_MODE", "changing mode from kernel to userspace: a kernel wg interface remains"),
	}
	for _, err := range refusals {
		if got := exitCode(err); got != exitRefusal {
			t.Errorf("exitCode(%v) = %d, want %d", err, got, exitRefusal)
		}
		// wrapping by an outer layer must not hide the refusal
		if got := exitCode(fmt.Errorf("server: %w", err)); got != exitRefusal {
			t.Errorf("exitCode(wrapped %v) = %d, want %d", err, got, exitRefusal)
		}
	}
	retryable := []error{
		errors.New("listen port 51820 is already in use by existing WireGuard \"wg0\""),
		errors.New("UDP port 51820 is already bound by another process"),
		errors.New("address range 10.200.0.1/24 overlaps with existing interface \"eth0\""),
		errors.New("wgft0 already exists but was not created by wgft, key does not match"),
		fmt.Errorf("reading the conntrack UDP timeouts after applying table inet wgft: %w", os.ErrNotExist),
		errors.New("server database is in use by another process"),
	}
	for _, err := range retryable {
		if got := exitCode(err); got != 1 {
			t.Errorf("exitCode(%v) = %d, want 1 (a restart may fix it)", err, got)
		}
	}
}

// TestEveryServerSettingIsCheckedAtTheDoor is the class-level test the per-setting cases above
// cannot be: it walks every WGFT_* setting the server reads (serverSpecs, so a new setting shows up
// here on its own) and requires a malformed value for each one to exit 3 without touching anything.
// The class, not the instances, is what kept coming back: three separate settings in turn passed the
// door and then failed deep inside vpsd.Run, where a bad value is indistinguishable from an
// environment failure and becomes exit code 1 plus a restart loop (WGFT_WG_ADDRESS, WGFT_AGENT_API's
// unix:// and its port; docs/design.md 11b 節).
//
// "Without touching anything" is checked against the data dir: no wgft.sqlite, no WAL sidecars, no
// admin socket. The test runs `server run` in userspace mode as an unprivileged user, like
// TestServerConfigErrorsExitCode above and for the same reason: in kernel mode a non-root run hits
// bringUpWG's missing CAP_NET_ADMIN first, which is itself a refusal (exit 3), so the door check
// under test would never run and the case would pass for the wrong reason.
func TestEveryServerSettingIsCheckedAtTheDoor(t *testing.T) {
	// One malformed value per setting. A setting whose bad value cannot be judged from the value
	// alone is listed with an empty string and skipped, with the reason, so that adding a setting
	// to serverSpecs without deciding this fails the test.
	bad := map[string]string{
		"WGFT_MODE":                     "kernal",
		"WGFT_DATA_DIR":                 "", // judged below: the dir is also where the test looks for leftovers
		"WGFT_WG_INTERFACE":             "wgft0/../etc",
		"WGFT_WG_PORT":                  "70000",
		"WGFT_WG_ADDRESS":               "10.200.0.1",
		"WGFT_WG_ENDPOINT":              "vps.example.com",
		"WGFT_MTU":                      "1",
		"WGFT_AGENT_API":                "0.0.0.0:notaport",
		"WGFT_AGENT_API_HOST":           "vps.example.com",
		"WGFT_ADMIN":                    "unix://",
		"WGFT_ADMIN_TAILSCALE":          "ture",
		"WGFT_ADMIN_HOST":               "", // a Host name list has no syntax to get wrong
		"WGFT_MAX_UDP_FLOWS":            "0",
		"WGFT_MAX_TCP_FLOWS":            "one",
		"WGFT_MAX_UDP_FLOWS_PER_SOURCE": "-1",
		"WGFT_MAX_TCP_FLOWS_PER_SOURCE": "70000",
	}
	// Reasons for the settings with no malformed value, so the skip is a decision, not an omission.
	noBadValue := map[string]string{
		"WGFT_ADMIN_HOST": "a comma-separated list of Host header names; any string is a valid name to accept",
		"WGFT_DATA_DIR":   "an empty value is the only values-only error, and it is checked by TestServerEmptyDataDirIsRefused",
	}
	for _, sp := range serverSpecs() {
		if _, ok := bad[sp.Env]; !ok {
			t.Errorf("%s is read by serverSpecs but has no malformed value in this table; add one, or add a reason to noBadValue", sp.Env)
		}
	}
	for _, sp := range serverSpecs() {
		value := bad[sp.Env]
		if value == "" {
			if _, ok := noBadValue[sp.Env]; !ok {
				t.Errorf("%s has an empty malformed value and no reason in noBadValue", sp.Env)
			}
			continue
		}
		t.Run(sp.Env, func(t *testing.T) {
			dataDir := t.TempDir()
			sock := filepath.Join(t.TempDir(), "admin.sock")
			// A valid baseline for everything else, so the one bad value is what stops the start.
			for k, v := range map[string]string{
				"WGFT_WG_ENDPOINT": "vps.example.com:51820",
				"WGFT_ADMIN":       "unix://" + sock,
				"WGFT_AGENT_API":   "127.0.0.1:0",
				"WGFT_WG_PORT":     "51820",
			} {
				if k != sp.Env {
					t.Setenv(k, v)
				}
			}
			t.Setenv(sp.Env, value)
			args := []string{"server", "run", "--config", filepath.Join(t.TempDir(), "none.env"), "--data-dir", dataDir}
			// A flag outranks the environment (11a 節), so the mode cannot be passed as a flag in
			// the WGFT_MODE case: it would overwrite the malformed value under test. "kernal" stops
			// at the door before anything privileged is attempted, so leaving the flag out is safe.
			if sp.Env != "WGFT_MODE" {
				args = append(args, "--mode", "userspace")
			}
			root := newRootCmd()
			root.SetArgs(args)
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			// If a check is missing, Execute reaches vpsd.Run and serves forever; without this
			// guard the case would hang until the package timeout instead of reporting the hole.
			done := make(chan error, 1)
			go func() { done <- root.Execute() }()
			var err error
			select {
			case err = <-done:
			case <-time.After(30 * time.Second):
				t.Fatalf("%s=%q: server run did not return; the door does not check this setting", sp.Env, value)
			}
			if err == nil {
				t.Fatalf("%s=%q started", sp.Env, value)
			}
			if got := exitCode(err); got != exitRefusal {
				t.Fatalf("%s=%q: err=%v exitCode=%d, want %d", sp.Env, value, err, got, exitRefusal)
			}
			if r := startup.Of(err); r == nil || r.Category != startup.CategoryConfig {
				t.Errorf("%s=%q: refusal = %v, want category %q", sp.Env, value, r, startup.CategoryConfig)
			}
			// Nothing touched: no database (nor its WAL sidecars) and no admin socket.
			entries, rerr := os.ReadDir(dataDir)
			if rerr != nil {
				t.Fatal(rerr)
			}
			for _, e := range entries {
				t.Errorf("%s=%q created %s in the data dir; values-only checks must run before anything is touched", sp.Env, value, e.Name())
			}
			if _, serr := os.Stat(sock); serr == nil {
				t.Errorf("%s=%q opened the admin socket before the door check", sp.Env, value)
			}
		})
	}
}

// An empty WGFT_DATA_DIR is its own case: the table above uses the data dir to look for leftovers,
// so it cannot pass an empty one. Without this check MkdirAll("") fails inside `server run` as an
// ordinary error and the unit loops on a value that never becomes valid by itself.
func TestServerEmptyDataDirIsRefused(t *testing.T) {
	t.Setenv("WGFT_WG_ENDPOINT", "vps.example.com:51820")
	t.Setenv("WGFT_DATA_DIR", "  ")
	root := newRootCmd()
	root.SetArgs([]string{"server", "run", "--mode", "userspace", "--config", filepath.Join(t.TempDir(), "none.env")})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	err := root.Execute()
	if got := exitCode(err); err == nil || got != exitRefusal {
		t.Fatalf("err=%v exitCode=%d, want %d", err, got, exitRefusal)
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
	if got := exitCode(err); err == nil || got != exitRefusal {
		t.Fatalf("err=%v exitCode=%d, want %d", err, got, exitRefusal)
	}
	if msg := err.Error(); !strings.Contains(msg, "only server settings") || !strings.Contains(msg, "chmod 0644 "+p) {
		t.Errorf("server の直し方が違う: %v", err)
	}
}

// validateListenAddr の受け付けと拒否の境目。unix:// を受け付けるのは、Unix ソケットで待ち受けられる
// 管理 API だけである。
func TestValidateListenAddr(t *testing.T) {
	for _, tc := range []struct {
		val       string
		allowUnix bool
		ok        bool
	}{
		{"0.0.0.0:8443", false, true},
		{":8443", false, true},
		{"[::1]:8686", true, true},
		{"127.0.0.1:8686", true, true},
		{"unix:///run/wgft/admin.sock", true, true},
		{"unix:///run/wgft/admin.sock", false, false},
		{"unix://", true, false},
		{"unix://", false, false},
		{"0.0.0.0", false, false},
		{"0.0.0.0:", false, false},
		{"0.0.0.0:notaport", false, false},
		{"0.0.0.0:70000", false, false},
		{"", true, false},
	} {
		err := validateListenAddr("WGFT_X", tc.val, tc.allowUnix)
		if (err == nil) != tc.ok {
			t.Errorf("validateListenAddr(%q, allowUnix=%v) = %v, want ok=%v", tc.val, tc.allowUnix, err, tc.ok)
		}
		if r := startup.Of(err); err != nil && (r == nil || r.Category != startup.CategoryConfig) {
			t.Errorf("validateListenAddr(%q): %v is not a config refusal", tc.val, err)
		}
	}
}

// 入口の新しい検査の受け付けと拒否の境目。どれも値の形だけを見る。
func TestDoorValueChecks(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		ok   bool
	}{
		{"endpoint host:port", validateHostPort("WGFT_WG_ENDPOINT", "vps.example.com:51820"), true},
		{"endpoint v6 host:port", validateHostPort("WGFT_WG_ENDPOINT", "[2001:db8::1]:51820"), true},
		{"endpoint without port", validateHostPort("WGFT_WG_ENDPOINT", "vps.example.com"), false},
		{"endpoint without host", validateHostPort("WGFT_WG_ENDPOINT", ":51820"), false},
		{"endpoint bad port", validateHostPort("WGFT_WG_ENDPOINT", "vps.example.com:nope"), false},
		{"bool true", validateBool("WGFT_ADMIN_TAILSCALE", "true"), true},
		{"bool yes", validateBool("WGFT_ADMIN_TAILSCALE", "yes"), true},
		{"bool off", validateBool("WGFT_ADMIN_TAILSCALE", "off"), true},
		{"bool empty", validateBool("WGFT_ADMIN_TAILSCALE", ""), true},
		{"bool typo", validateBool("WGFT_ADMIN_TAILSCALE", "ture"), false},
		{"iface wgft0", validateInterfaceName("WGFT_WG_INTERFACE", "wgft0"), true},
		{"iface 15 bytes", validateInterfaceName("WGFT_WG_INTERFACE", "abcdefghijklmno"), true},
		{"iface empty", validateInterfaceName("WGFT_WG_INTERFACE", ""), false},
		{"iface 16 bytes", validateInterfaceName("WGFT_WG_INTERFACE", "abcdefghijklmnop"), false},
		{"iface dots", validateInterfaceName("WGFT_WG_INTERFACE", ".."), false},
		{"iface slash", validateInterfaceName("WGFT_WG_INTERFACE", "wg/0"), false},
		{"iface colon", validateInterfaceName("WGFT_WG_INTERFACE", "wg:0"), false},
		{"iface space", validateInterfaceName("WGFT_WG_INTERFACE", "wg 0"), false},
	} {
		if (tc.err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, tc.err, tc.ok)
		}
		if r := startup.Of(tc.err); tc.err != nil && (r == nil || r.Category != startup.CategoryConfig) {
			t.Errorf("%s: %v is not a config refusal", tc.name, tc.err)
		}
	}
}
