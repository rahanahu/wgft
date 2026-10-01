//go:build linux

package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/vpsd"
	"github.com/rahanahu/wgft/internal/vpsd/servercheck"
)

// serverDataDirSetting は server のデータの置き場 WGFT_DATA_DIR である。run、check、teardown が
// 共有する。
func serverDataDirSetting() spec {
	return spec{Env: "WGFT_DATA_DIR", Flag: "data-dir", Default: "/var/lib/wgft"}
}

// serverSpecs は server の設定項目(WGFT_ 名とフラグ別名。仕様 11a 節)。run と check はこの全部を
// フラグ別名として登録する。
func serverSpecs() []spec {
	return append([]spec{
		{Env: "WGFT_MODE", Flag: "mode", Default: "",
			Usage: "forwarding mode kernel or userspace, env WGFT_MODE; recorded on first run and checked thereafter"},
		serverDataDirSetting().withUsage("data dir, env WGFT_DATA_DIR; holds wgft.sqlite"),
		{Env: "WGFT_WG_INTERFACE", Flag: "wg-interface", Default: "wgft0",
			Usage: "WireGuard interface name, env WGFT_WG_INTERFACE"},
		{Env: "WGFT_WG_PORT", Flag: "wg-port", Default: "51820", Kind: flagUint16,
			Usage: "WireGuard listen UDP port, env WGFT_WG_PORT"},
		{Env: "WGFT_WG_ADDRESS", Flag: "wg-address", Default: "10.200.0.1/24",
			Usage: "wg address range, env WGFT_WG_ADDRESS"},
		{Env: "WGFT_WG_ENDPOINT", Flag: "wg-endpoint", Default: "",
			Usage: "WireGuard reachable host:port handed to agents, env WGFT_WG_ENDPOINT"},
		{Env: "WGFT_MTU", Flag: "mtu", Default: "1420", Kind: flagInt,
			Usage: "wg MTU, env WGFT_MTU"},
		{Env: "WGFT_AGENT_API", Flag: "agent-api", Default: "0.0.0.0:8443",
			Usage: "agent API listen address, env WGFT_AGENT_API, public"},
		{Env: "WGFT_AGENT_API_HOST", Flag: "agent-api-host", Default: "",
			Usage: "host:port to embed in the join string, env WGFT_AGENT_API_HOST"},
		adminSetting().withUsage("admin API listen address, env WGFT_ADMIN; unix:///path or host:port"),
		{Env: "WGFT_ADMIN_TAILSCALE", Flag: "admin-tailscale", Default: "false", Kind: flagBool,
			Usage: "also listen on the tailnet address, env WGFT_ADMIN_TAILSCALE"},
		{Env: "WGFT_ADMIN_HOST", Flag: "admin-host", Default: "", Slice: true, Kind: flagStringSlice,
			Usage: "extra names allowed by the Host check, env WGFT_ADMIN_HOST, comma-separated"},
	}, append(limitSpecs(), perSourceLimitSpecs()...)...)
}

// registerServerFlags は run / check にフラグ別名を付ける。
func registerServerFlags(f *cobra.Command) {
	fl := f.Flags()
	registerSpecFlags(fl, serverSpecs()...)
	fl.String("config", defaultConfigPath, "dotenv config file")
}

// serverTeardownSpecs は server teardown の設定項目である。
func serverTeardownSpecs() []spec {
	return []spec{serverDataDirSetting().withUsage("data dir, env WGFT_DATA_DIR")}
}

// buildServerOptions は設定層から vpsd.Options を組む。
//
// ここが server の「入口」である(設計文書 11b 節)。値だけから判定できる誤りは、wg インタフェース、
// 待ち受け、サーバのデータベースに触れる前に、すべてここで終了コード 3 の拒否にする。入口を通り抜けた
// 値が起動の後半(net.Listen、netip.ParsePrefix、netlink の書き込み)で初めて失敗すると、そこでは
// 環境由来の失敗と区別が付かず、終了コード 1 の再起動の繰り返しになる。同じ穴が 3 回見つかっている
// (WGFT_WG_ADDRESS、WGFT_AGENT_API の unix://、WGFT_AGENT_API のポート)。設定項目を足すときは、
// この関数に検査を足し、cmd/wgft/server_test.go の TestEveryServerSettingIsCheckedAtTheDoor の表に
// 壊れた値を 1 つ加える。
func buildServerOptions(cmd *cobra.Command) (vpsd.Options, *config, error) {
	configPath := resolveConfigPath(cmd, defaultConfigPath)
	c, err := loadConfig(cmd, serverSpecs(), configPath)
	if err != nil {
		return vpsd.Options{}, nil, withUnreadableHint(err, configPath, serverUnreadableHint)
	}
	// WGFT_MODE は、値そのものの誤り(kernel でも userspace でもない)だけをここで弾く。初回に
	// 必須であることと、記録との食い違いの関門は、記録を読める internal/vpsd が判定する(9・11a 節)。
	if m := c.str("WGFT_MODE"); m != "" && m != "kernel" && m != "userspace" {
		return vpsd.Options{}, nil, configErrorf("WGFT_MODE", "must be kernel or userspace, not %q", m)
	}
	if strings.TrimSpace(c.str("WGFT_DATA_DIR")) == "" {
		return vpsd.Options{}, nil, configErrorf("WGFT_DATA_DIR", "is empty; give the directory that holds wgft.sqlite, for example /var/lib/wgft")
	}
	if err := validateInterfaceName("WGFT_WG_INTERFACE", c.str("WGFT_WG_INTERFACE")); err != nil {
		return vpsd.Options{}, nil, err
	}
	port, err := strconv.ParseUint(c.str("WGFT_WG_PORT"), 10, 16)
	if err != nil || port == 0 {
		return vpsd.Options{}, nil, configErrorf("WGFT_WG_PORT", "%q is not a UDP port between 1 and 65535", c.str("WGFT_WG_PORT"))
	}
	// MTU の範囲も値だけで判定できる。範囲の外の値は netlink の LinkSetMTU が EINVAL で返すだけで、
	// 環境由来の失敗と区別が付かない。下限は IPv4 の実用の最小、上限はジャンボフレームに合わせる。
	mtu, err := strconv.Atoi(c.str("WGFT_MTU"))
	if err != nil || mtu < minMTU || mtu > maxMTU {
		return vpsd.Options{}, nil, configErrorf("WGFT_MTU", "%q is not an integer between %d and %d", c.str("WGFT_MTU"), minMTU, maxMTU)
	}
	// WGFT_WG_ADDRESS の構文は、値そのものが原因の失敗であり、環境には触れていないここで弾く。
	// これを弾かずに進むと internal/vpsd.Run の netip.ParsePrefix まで届く(改訂の記録 2026-09-20)。
	// 食い違い(記録済みの帯との不一致)の判定は従来どおり internal/vpsd 側で行う。
	if _, err := netip.ParsePrefix(c.str("WGFT_WG_ADDRESS")); err != nil {
		return vpsd.Options{}, nil, configErrorf("WGFT_WG_ADDRESS", "%q is not a valid address/prefix such as 10.200.0.1/24: %v", c.str("WGFT_WG_ADDRESS"), err)
	}
	if err := validateListenAddr("WGFT_AGENT_API", c.str("WGFT_AGENT_API"), false); err != nil {
		return vpsd.Options{}, nil, err
	}
	if err := validateListenAddr("WGFT_ADMIN", c.str("WGFT_ADMIN"), true); err != nil {
		return vpsd.Options{}, nil, err
	}
	// エンドポイントと接続文字列のホストは、待ち受けには使わないが、値の形が違えば接続文字列が
	// 作れず、エージェントはトンネルを張れない。起動してから気付く項目にせず、入口で弾く。
	if v := c.str("WGFT_WG_ENDPOINT"); v != "" {
		if err := validateHostPort("WGFT_WG_ENDPOINT", v); err != nil {
			return vpsd.Options{}, nil, err
		}
	}
	if v := c.str("WGFT_AGENT_API_HOST"); v != "" {
		if err := validateHostPort("WGFT_AGENT_API_HOST", v); err != nil {
			return vpsd.Options{}, nil, err
		}
	}
	if err := validateBool("WGFT_ADMIN_TAILSCALE", c.str("WGFT_ADMIN_TAILSCALE")); err != nil {
		return vpsd.Options{}, nil, err
	}
	limits, err := limitsFromConfig(c)
	if err != nil {
		return vpsd.Options{}, nil, err
	}
	admission, err := perSourceLimitsFromConfig(c)
	if err != nil {
		return vpsd.Options{}, nil, err
	}
	stateDir := c.str("WGFT_DATA_DIR")
	opts := vpsd.Options{
		Limits:          limits,
		AdmissionLimits: admission,
		Version:         effectiveVersion(),
		Mode:            c.str("WGFT_MODE"),
		DBPath:          stateDir + "/wgft.sqlite",
		WGInterface:     c.str("WGFT_WG_INTERFACE"),
		WGPort:          uint16(port),
		WGAddress:       c.str("WGFT_WG_ADDRESS"),
		WGEndpoint:      c.str("WGFT_WG_ENDPOINT"),
		MTU:             mtu,
		AgentAPIAddr:    c.str("WGFT_AGENT_API"),
		AgentAPIHost:    c.str("WGFT_AGENT_API_HOST"),
		AdminAddr:       c.str("WGFT_ADMIN"),
		AdminTailscale:  c.boolVal("WGFT_ADMIN_TAILSCALE"),
		AdminHost:       c.slice("WGFT_ADMIN_HOST"),
	}
	return opts, c, nil
}

// validateListenAddr checks that val is a syntactically valid listen address before anything is
// touched: host:port with a port net.Listen can resolve, or, only where allowUnix is set, a
// unix:// socket with a path. Only the admin API can listen on a Unix socket (admin.Listen); the
// agent API is TCP only (agentapi.Listen calls net.Listen("tcp", addr)), so a unix:// value there
// is a configuration error like any other. Without this check a bad value reaches admin.Listen
// or agentapi.Listen deep inside vpsd.Run (after wg is already up), whose generic net.Listen
// error is indistinguishable from a genuine environment problem (a port already in use, an
// address not yet configured) and becomes exit code 1: the shipped unit's Restart=on-failure
// loops on it forever even though a syntax error never fixes itself by retrying
// (docs/design.md 11b 節). A real bind failure (EADDRINUSE and similar) still reaches net.Listen
// unchanged and keeps exit code 1, since retrying that can genuinely help.
func validateListenAddr(env, val string, allowUnix bool) error {
	if socket, ok := strings.CutPrefix(val, "unix://"); ok {
		if !allowUnix {
			return configErrorf(env, "%q is a unix socket, but this listener is TCP only; give host:port", val)
		}
		if socket == "" {
			return configErrorf(env, "%q has no socket path after unix://", val)
		}
		return nil
	}
	_, port, err := net.SplitHostPort(val)
	if err != nil {
		return configErrorf(env, "%q is not a valid host:port: %v", val, err)
	}
	if port == "" {
		return configErrorf(env, "%q has no port", val)
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return configErrorf(env, "%q has an invalid port: %v", val, err)
	}
	return nil
}

// serverCheckOptions は server の設定から server check が読む項目を写す。
func serverCheckOptions(o vpsd.Options) servercheck.Options {
	return servercheck.Options{
		DBPath:       o.DBPath,
		WGInterface:  o.WGInterface,
		WGPort:       o.WGPort,
		WGAddress:    o.WGAddress,
		AgentAPIAddr: o.AgentAPIAddr,
		Mode:         o.Mode,
	}
}

func newServerCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "server",
		Short: "VPS-side daemon; start it with server run",
	}

	run := &cobra.Command{
		Use:   "run",
		Short: "run the daemon; unit ExecStart or Docker entrypoint",
		Args:  cobra.NoArgs,
		// 常駐プロセスを起動するので、起動の拒否の文面はそのままである(設計文書 11b 節)。
		Annotations: map[string]string{daemonAnnotation: "yes"},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, c, err := buildServerOptions(cmd)
			if err != nil {
				return err
			}
			// 必須なのは run だけである。check は設定と環境を見るだけなので、エンドポイントが
			// 決まっていない段階でも動く(10.3 節の初回セットアップの順序)。
			if opts.WGEndpoint == "" {
				return configErrorf("WGFT_WG_ENDPOINT", "is required; set it with --wg-endpoint: the host:port that agents connect to, for example vps.example.com:51820")
			}
			adopt, _ := cmd.Flags().GetBool("adopt-existing")
			opts.AdoptExisting = adopt
			if err := os.MkdirAll(c.str("WGFT_DATA_DIR"), 0o700); err != nil {
				return fmt.Errorf("data dir: %w", err)
			}
			fmt.Fprintln(os.Stderr, "effective config:")
			c.print(os.Stderr)
			applyMemoryLimit(os.Stderr, opts.Limits, true)
			return vpsd.Run(opts)
		},
	}
	registerServerFlags(run)
	run.Flags().Bool("adopt-existing", false, "adopt an existing interface whose key does not match; default is to treat it as someone else's and abort")

	check := &cobra.Command{
		Use:   "check",
		Short: "check the config and environment without starting; read-only",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, c, err := buildServerOptions(cmd)
			if err != nil {
				return err
			}
			fmt.Println("effective config:")
			c.print(os.Stdout)
			applyMemoryLimit(os.Stdout, opts.Limits, false)
			fmt.Println()
			return servercheck.Check(serverCheckOptions(opts), os.Stdout)
		},
	}
	registerServerFlags(check)

	nft := &cobra.Command{
		Use: "nft", Short: "print the applied table inet wgft as-is", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			out, err := c.NFT()
			if err != nil {
				return err
			}
			fmt.Print(out)
			return nil
		},
	}
	registerSpecFlags(nft.Flags(), adminClientSpec())

	// doctor の実装は build tag の無い cmd/wgft/doctor.go にあり、管理用 API しか使わない。
	// 登録だけがこのファイル(Linux)にあるので、Linux 以外のビルドでは server の一群ごと
	// 拒否する代替に置き換わり、doctor も現れない(設計文書 10.2a 節)。
	root.AddCommand(run, check, newTeardownCmd(), nft, newServerDoctorCmd())
	return root
}

func newTeardownCmd() *cobra.Command {
	var o vpsd.TeardownOptions
	cmd := &cobra.Command{
		Use:   "teardown",
		Short: "remove what wgft created: table inet wgft and the wg interface",
		Long: `Clean up after a stopped server. Removes only what wgft created itself.
Refuses if it is still running: run systemctl disable --now wgft first. Removes table inet wgft and the wg
interface, and with --purge the server database too, including keys, certificates, rules and agents. Other tables, firewall ports, and ip_forward are not
reverted automatically; it only prints a list to revert by hand.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := loadConfig(cmd, serverTeardownSpecs(), resolveConfigPath(cmd, defaultConfigPath))
			if err != nil {
				return err
			}
			o.DBPath = c.str("WGFT_DATA_DIR") + "/wgft.sqlite"
			return vpsd.Teardown(o, os.Stdout)
		},
	}
	f := cmd.Flags()
	registerSpecFlags(f, serverTeardownSpecs()...)
	f.String("config", defaultConfigPath, "dotenv config file")
	f.BoolVar(&o.Purge, "purge", false, "also remove the server database: keys, certificates, rules, agents; agents must re-register")
	f.BoolVar(&o.DryRun, "dry-run", false, "only print what would be removed and the list to revert by hand")
	f.BoolVar(&o.Yes, "yes", false, "skip the --purge confirmation")
	f.BoolVar(&o.Adopt, "adopt-existing", false, "remove wg even when the key does not match or the server database is missing")
	return cmd
}

// serverUnreadableHint は、server が設定ファイルを読めないときの直し方。server の設定項目に秘密は無いが、
// 同じファイルに agent の WGFT_JOIN を書くこともできるので、0644 は server の設定だけのファイルに限って勧める(仕様 11a 節)。
func serverUnreadableHint(path string) string {
	return fmt.Sprintf("The provided server.service runs as an unprivileged user. If the file holds only server settings, which are not secret, make it readable: chmod 0644 %s", path)
}

// minMTU と maxMTU は WGFT_MTU の範囲(入口の検査)。下限は IPv4 のホストが必ず扱える 576、
// 上限はジャンボフレームの 9216 である。範囲の外の値はカーネルが EINVAL で返すだけなので、
// 環境由来の失敗と区別が付く形で入口で弾く。
const (
	minMTU = 576
	maxMTU = 9216
)
