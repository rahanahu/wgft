//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/vpsd"
)

// serverSpecs は server の設定項目(WGFT_ 名とフラグ別名。仕様 11a 節)。
func serverSpecs() []spec {
	return append([]spec{
		{Env: "WGFT_MODE", Flag: "mode", Default: ""},
		{Env: "WGFT_DATA_DIR", Flag: "data-dir", Default: "/var/lib/wgft"},
		{Env: "WGFT_WG_INTERFACE", Flag: "wg-interface", Default: "wgft0"},
		{Env: "WGFT_WG_PORT", Flag: "wg-port", Default: "51820"},
		{Env: "WGFT_WG_ADDRESS", Flag: "wg-address", Default: "10.200.0.1/24"},
		{Env: "WGFT_WG_ENDPOINT", Flag: "wg-endpoint", Default: ""},
		{Env: "WGFT_MTU", Flag: "mtu", Default: "1420"},
		{Env: "WGFT_AGENT_API", Flag: "agent-api", Default: "0.0.0.0:8443"},
		{Env: "WGFT_AGENT_API_HOST", Flag: "agent-api-host", Default: ""},
		{Env: "WGFT_ADMIN", Flag: "admin", Default: "unix:///run/wgft/admin.sock"},
		{Env: "WGFT_ADMIN_TAILSCALE", Flag: "admin-tailscale", Default: "false"},
		{Env: "WGFT_ADMIN_HOST", Flag: "admin-host", Default: "", Slice: true},
	}, append(limitSpecs(), perSourceLimitSpecs()...)...)
}

// registerServerFlags は run / check にフラグ別名を付ける。
func registerServerFlags(f *cobra.Command) {
	fl := f.Flags()
	fl.String("mode", "", "forwarding mode kernel or userspace, env WGFT_MODE; recorded on first run and checked thereafter")
	fl.String("data-dir", "/var/lib/wgft", "data dir, env WGFT_DATA_DIR; holds wgft.sqlite")
	fl.String("wg-interface", "wgft0", "WireGuard interface name, env WGFT_WG_INTERFACE")
	fl.Uint16("wg-port", 51820, "WireGuard listen UDP port, env WGFT_WG_PORT")
	fl.String("wg-address", "10.200.0.1/24", "wg address range, env WGFT_WG_ADDRESS")
	fl.String("wg-endpoint", "", "WireGuard reachable host:port handed to agents, env WGFT_WG_ENDPOINT")
	fl.Int("mtu", 1420, "wg MTU, env WGFT_MTU")
	fl.String("agent-api", "0.0.0.0:8443", "agent API listen address, env WGFT_AGENT_API, public")
	fl.String("agent-api-host", "", "host:port to embed in the join string, env WGFT_AGENT_API_HOST")
	fl.String("admin", "unix:///run/wgft/admin.sock", "admin API listen address, env WGFT_ADMIN; unix:///path or host:port")
	fl.Bool("admin-tailscale", false, "also listen on the tailnet address, env WGFT_ADMIN_TAILSCALE")
	fl.StringSlice("admin-host", nil, "extra names allowed by the Host check, env WGFT_ADMIN_HOST, comma-separated")
	registerLimitFlags(fl)
	registerPerSourceLimitFlags(fl)
	fl.String("config", defaultConfigPath, "dotenv config file")
}

// buildServerOptions は設定層から vpsd.Options を組む。
func buildServerOptions(cmd *cobra.Command) (vpsd.Options, *config, error) {
	c, err := loadConfig(cmd, serverSpecs(), resolveConfigPath(cmd, defaultConfigPath))
	if err != nil {
		return vpsd.Options{}, nil, withUnreadableHint(err, serverUnreadableHint)
	}
	port, err := strconv.ParseUint(c.str("WGFT_WG_PORT"), 10, 16)
	if err != nil {
		return vpsd.Options{}, nil, configErrorf("WGFT_WG_PORT: %q is not a port number", c.str("WGFT_WG_PORT"))
	}
	mtu, err := strconv.Atoi(c.str("WGFT_MTU"))
	if err != nil {
		return vpsd.Options{}, nil, configErrorf("WGFT_MTU: %q is not an integer", c.str("WGFT_MTU"))
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

func newServerCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "server",
		Short: "VPS-side daemon; start it with server run",
		Long: `VPS-side daemon. Converges wg to the declared state, applies the SQLite rules to nftables, and listens on the admin API.
Config is passed via WGFT_* environment variables (or their dotenv, or flags). The admin API has no password and by default
listens on a Unix socket (root-owned 0600).`,
	}

	run := &cobra.Command{
		Use:   "run",
		Short: "run the daemon; unit ExecStart or Docker entrypoint",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, c, err := buildServerOptions(cmd)
			if err != nil {
				return err
			}
			if opts.WGEndpoint == "" {
				return configErrorf("WGFT_WG_ENDPOINT (--wg-endpoint) is required: the host:port that agents connect to, for example vps.example.com:51820")
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
			return vpsd.Check(opts, os.Stdout)
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
	nft.Flags().String("admin", "unix:///run/wgft/admin.sock", "admin API address, env WGFT_ADMIN")

	root.AddCommand(run, check, newTeardownCmd(), nft)
	return root
}

func newTeardownCmd() *cobra.Command {
	var o vpsd.TeardownOptions
	cmd := &cobra.Command{
		Use:   "teardown",
		Short: "remove what wgft created: table inet wgft and the wg interface",
		Long: `Clean up after a stopped server. Removes only what wgft created itself.
Refuses if it is still running (run systemctl disable --now wgft first). Removes table inet wgft and the wg
interface, and with --purge the server database (keys, certificates, rules, agents) too. Other tables, firewall ports, and ip_forward are not
reverted automatically; it only prints a list to revert by hand.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := loadConfig(cmd, []spec{{Env: "WGFT_DATA_DIR", Flag: "data-dir", Default: "/var/lib/wgft"}}, resolveConfigPath(cmd, defaultConfigPath))
			if err != nil {
				return err
			}
			o.DBPath = c.str("WGFT_DATA_DIR") + "/wgft.sqlite"
			return vpsd.Teardown(o, os.Stdout)
		},
	}
	f := cmd.Flags()
	f.String("data-dir", "/var/lib/wgft", "data dir, env WGFT_DATA_DIR")
	f.String("config", defaultConfigPath, "dotenv config file")
	f.BoolVar(&o.Purge, "purge", false, "also remove the server database (keys, certificates, rules, agents); agents must re-register")
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

// isStartupRefusal は、設定が原因の起動中止(他人の wg インタフェース、ポートやアドレスの衝突)かを返す。
func isStartupRefusal(err error) bool {
	var refusal *wg.StartupRefusal
	return errors.As(err, &refusal)
}
