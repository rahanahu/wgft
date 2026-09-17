package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/agent"
)

// agentConfigPath は agent の dotenv 既定(仕様 11a 節)。置き場は OS ごと(paths_*.go)。
var agentConfigPath = joinPath(defaultConfigDir(), "agent.env")

// ago は RFC3339 の時刻を「N 秒前」にする。空なら "-"。
func ago(s string) string {
	if s == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return time.Since(t).Truncate(time.Second).String() + " ago"
}

// agentSpecs は agent run の設定項目。
func agentSpecs() []spec {
	return []spec{
		{Env: "WGFT_DATA_DIR", Flag: "data-dir", Default: defaultDataDir()},
		{Env: "WGFT_JOIN", Flag: "join", Default: "", Secret: true},
		{Env: "WGFT_NAME", Flag: "name", Default: ""},
	}
}

// agentCredentialsPath は WGFT_DATA_DIR から agent.json (認証情報) のパスを決める(home 側コマンド用)。
func agentCredentialsPath(cmd *cobra.Command) (string, error) {
	c, err := loadConfig(cmd, []spec{{Env: "WGFT_DATA_DIR", Flag: "data-dir", Default: defaultDataDir()}}, resolveConfigPath(cmd, agentConfigPath))
	if err != nil {
		return "", err
	}
	return c.str("WGFT_DATA_DIR") + "/agent.json", nil
}

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "agent: run it on the agent host, manage it from the VPS side",
		Long: `Agent-related commands.

On the agent host:
  run           run the agent: bring up the tunnel and relay incoming traffic to the LAN
  pubkey        print the wg public key; generate and save one if absent
  rotate-key    regenerate the wg key pair

On the VPS (against the admin API):
  ls            list registered agents
  join-string   issue a join string; one-time
  revoke        revoke a permanent token
  warnings      list theft-detection warnings
  dismiss-warning  dismiss a warning`,
	}

	// --- 自宅側 ---
	run := &cobra.Command{
		Use:   "run",
		Short: "run the agent; agent host",
		Long: `Agent host daemon. Brings up the tunnel and listeners first from the key in the credentials file (agent.json) and the last full state,
then connects to the server stream to receive the full state. On first run it registers with the join string (WGFT_JOIN); the name (WGFT_NAME) is
optional and normally left unset, since the join string is already bound to a name.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := loadConfig(cmd, agentSpecs(), resolveConfigPath(cmd, agentConfigPath))
			if err != nil {
				return err
			}
			if err := os.MkdirAll(c.str("WGFT_DATA_DIR"), 0o700); err != nil {
				return fmt.Errorf("data dir: %w", err)
			}
			opts := agent.Options{
				CredentialsPath: c.str("WGFT_DATA_DIR") + "/agent.json",
				Join:            c.str("WGFT_JOIN"),
				Name:            c.str("WGFT_NAME"),
			}
			fmt.Fprintln(os.Stderr, "effective config:")
			c.print(os.Stderr)
			return agent.Run(opts)
		},
	}
	rf := run.Flags()
	rf.String("data-dir", defaultDataDir(), "data dir, env WGFT_DATA_DIR; holds agent.json")
	rf.String("join", "", "join string wgft://host:port/token#sha256:..., env WGFT_JOIN")
	rf.String("name", "", "agent name, env WGFT_NAME; optional, the join string is already bound to a name")
	rf.String("config", agentConfigPath, "dotenv config file")

	pubkey := &cobra.Command{
		Use:   "pubkey",
		Short: "print the wg public key; agent host; generates and saves one to the credentials file if absent",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			sp, err := agentCredentialsPath(cmd)
			if err != nil {
				return err
			}
			k, err := agent.PublicKey(sp)
			if err != nil {
				return err
			}
			fmt.Println(k)
			return nil
		},
	}
	pubkey.Flags().String("data-dir", defaultDataDir(), "data dir, env WGFT_DATA_DIR")
	pubkey.Flags().String("config", agentConfigPath, "dotenv config file")

	rotate := &cobra.Command{
		Use:   "rotate-key",
		Short: "regenerate the wg key pair; agent host; via the control socket if running, or by editing the credentials file directly if stopped",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			sp, err := agentCredentialsPath(cmd)
			if err != nil {
				return err
			}
			msg, err := agent.RotateKey(sp)
			if err != nil {
				return err
			}
			fmt.Println(msg)
			return nil
		},
	}
	rotate.Flags().String("data-dir", defaultDataDir(), "data dir, env WGFT_DATA_DIR")
	rotate.Flags().String("config", agentConfigPath, "dotenv config file")

	// --- VPS 側(管理用 API 経由) ---
	var name string
	joinString := &cobra.Command{
		Use: "join-string", Short: "issue an agent join string; VPS side; one-time, default 1 hour", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			res, err := c.JoinString(name)
			if err != nil {
				return err
			}
			fmt.Println(res.JoinString)
			fmt.Fprintf(os.Stderr, "expires %s. it contains a #, so write it into dotenv as-is without quotes\n", res.ExpiresAt)
			return nil
		},
	}
	joinString.Flags().StringVar(&name, "name", "", "agent name")
	addAdminFlag(joinString)
	_ = joinString.MarkFlagRequired("name")

	var asJSON bool
	ls := &cobra.Command{
		Use: "ls", Short: "list registered agents; VPS side", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			agents, err := c.Agents()
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(agents)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tADDRESS\tSTREAM\tHEARTBEAT\tGEN\tTUNNEL\tWG_ENDPOINT\tHANDSHAKE\tRULES\tWARN")
			for _, a := range agents {
				stream := "-"
				if a.Connected {
					stream = a.StreamFrom
				}
				tun := a.Tunnel.State
				if a.Tunnel.Reason != "" {
					tun += " (" + a.Tunnel.Reason + ")"
				}
				rules := ""
				for _, r := range a.Rules {
					if r.State != "ok" {
						rules += r.ID + ":" + r.Reason + " "
					}
				}
				if rules == "" && len(a.Rules) > 0 {
					rules = fmt.Sprintf("%d ok", len(a.Rules))
				}
				warn := ""
				if n := len(a.Warnings); n > 0 {
					warn = fmt.Sprintf("%d", n)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n", a.Name, a.Address, stream, ago(a.LastHeartbeat), a.Generation, tun, a.WGEndpoint, ago(a.LastHandshake), rules, warn)
			}
			return w.Flush()
		},
	}
	ls.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	addAdminFlag(ls)

	revoke := &cobra.Command{
		Use: "revoke <name>", Short: "revoke a permanent token; VPS side; reclaims the peer and address, the name can be reused", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			if err := c.Revoke(args[0]); err != nil {
				return err
			}
			fmt.Printf("revoked %s\n", args[0])
			return nil
		},
	}
	addAdminFlag(revoke)

	warnings := &cobra.Command{
		Use: "warnings", Short: "list theft-detection warnings; VPS side; spec section 5.2", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			ws, err := c.Warnings()
			if err != nil {
				return err
			}
			if len(ws) == 0 {
				fmt.Println("no warnings")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "AGENT\tKIND\tDETAIL\tAT")
			for _, x := range ws {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", x.Agent, x.Kind, x.Detail, x.At)
			}
			w.Flush()
			fmt.Fprintln(os.Stderr, "action: dismiss-warning if legitimate, revoke if suspicious")
			return nil
		},
	}
	addAdminFlag(warnings)

	dismiss := &cobra.Command{
		Use: "dismiss-warning <name> <kind> [detail]", Short: "dismiss a warning; VPS side; once confirmed legitimate, spec section 5.2", Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			detail := ""
			if len(args) == 3 {
				detail = args[2]
			}
			if err := c.DismissWarning(args[0], args[1], detail); err != nil {
				return err
			}
			fmt.Printf("dismissed warning for %s: %s\n", args[0], args[1])
			return nil
		},
	}
	addAdminFlag(dismiss)

	cmd.AddCommand(run, pubkey, rotate, joinString, ls, revoke, warnings, dismiss)
	return cmd
}
