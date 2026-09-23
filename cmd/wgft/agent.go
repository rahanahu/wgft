package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/agent"
	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
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
	return append([]spec{
		{Env: "WGFT_DATA_DIR", Flag: "data-dir", Default: defaultDataDir()},
		{Env: "WGFT_JOIN", Flag: "join", Default: "", Secret: true},
		{Env: "WGFT_NAME", Flag: "name", Default: ""},
		{Env: allowtargets.Env, Flag: "agent-allow-targets", Default: "", Slice: true},
	}, limitSpecs()...)
}

// allowTargetsFromConfig は宛先の許可一覧を読む(仕様 7 節)。構文の誤りは、他の値の誤りと同じく
// 入口での config の拒否として扱い、終了コード 3 で止める(設計文書 11b 節)。
// 値が無ければ nil を返す(制限なし)。
func allowTargetsFromConfig(c *config) (*allowtargets.List, error) {
	l, err := allowtargets.Parse(c.str(allowtargets.Env))
	if err != nil {
		return nil, configErrorf(allowtargets.Env, "%v", err)
	}
	return l, nil
}

// buildAgentOptions は agent run の「入口」である(設計文書 11b 節)。値だけから判定できる誤りは、
// 認証情報ファイル、トンネル、待ち受けに触れる前にすべてここで拒否する。設定項目を足すときは、
// ここに検査を足し、cmd/wgft/agent_test.go の TestEveryAgentSettingIsCheckedAtTheDoor の表に
// 壊れた値を 1 つ加える。
//
// WGFT_JOIN の構文だけは例外で、internal/agent の ensureRegistered が登録の直前に判定する。
// 登録済みの agent は compose に残った古い WGFT_JOIN を読まないので(11a 節が意図的に許す居座り)、
// 入口で構文を拒否すると、今まで動いていた agent が値の誤りだけで止まる。値が使われるかどうかが
// 認証情報ファイルの中身で決まるため、値だけからは判定できない項目である。誤りに気付けるよう、
// 入口では警告を 1 行出す。
func buildAgentOptions(cmd *cobra.Command) (agent.Options, *config, error) {
	configPath := resolveConfigPath(cmd, agentConfigPath)
	c, err := loadConfig(cmd, agentSpecs(), configPath)
	if err != nil {
		return agent.Options{}, nil, withUnreadableHint(err, configPath, agentUnreadableHint)
	}
	if strings.TrimSpace(c.str("WGFT_DATA_DIR")) == "" {
		return agent.Options{}, nil, configErrorf("WGFT_DATA_DIR", "is empty; give the directory that holds agent.json")
	}
	limits, err := limitsFromConfig(c)
	if err != nil {
		return agent.Options{}, nil, err
	}
	allow, err := allowTargetsFromConfig(c)
	if err != nil {
		return agent.Options{}, nil, err
	}
	join := c.str("WGFT_JOIN")
	if join != "" {
		if _, err := agent.ParseJoin(join); err != nil {
			log.Printf("warning: WGFT_JOIN is malformed: %v; it is used only for a first registration or after a revocation, so this agent starts if it is already registered", err)
		}
	}
	return agent.Options{
		AllowTargets:    allow,
		Limits:          limits,
		CredentialsPath: joinPath(c.str("WGFT_DATA_DIR"), "agent.json"),
		Join:            join,
		Name:            c.str("WGFT_NAME"),
		Version:         effectiveVersion(),
	}, c, nil
}

// agentCredentialsPath は WGFT_DATA_DIR から agent.json (認証情報) のパスを決める(home 側コマンド用)。
func agentCredentialsPath(cmd *cobra.Command) (string, error) {
	c, err := loadConfig(cmd, []spec{{Env: "WGFT_DATA_DIR", Flag: "data-dir", Default: defaultDataDir()}}, resolveConfigPath(cmd, agentConfigPath))
	if err != nil {
		return "", err
	}
	return joinPath(c.str("WGFT_DATA_DIR"), "agent.json"), nil
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
  doctor        diagnose this host's own agent, running or stopped

On the VPS, against the admin API:
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
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, c, err := buildAgentOptions(cmd)
			if err != nil {
				return err
			}
			if err := credentials.EnsureDataDir(c.str("WGFT_DATA_DIR")); err != nil {
				return fmt.Errorf("data dir: %w", err)
			}
			fmt.Fprintln(os.Stderr, "effective config:")
			c.print(os.Stderr)
			applyMemoryLimit(os.Stderr, opts.Limits, true)
			return agent.Run(opts)
		},
	}
	rf := run.Flags()
	rf.String("data-dir", defaultDataDir(), "data dir, env WGFT_DATA_DIR; holds agent.json")
	registerLimitFlags(rf)
	rf.String("join", "", "join string wgft://host:port/token#sha256:..., env WGFT_JOIN")
	rf.String("name", "", "agent name, env WGFT_NAME; optional, the join string is already bound to a name")
	rf.String("agent-allow-targets", "",
		"comma-separated targets the server may send traffic to, env "+allowtargets.Env+"; entries are CIDR, CIDR:port or CIDR:lo-hi; unset means no restriction")
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
			fmt.Fprintln(w, "NAME\tADDRESS\tSTREAM\tHEARTBEAT\tGEN\tTUNNEL\tWG_ENDPOINT\tHANDSHAKE\tRULES\tPROTO\tWARN")
			for _, a := range agents {
				stream := "-"
				if a.Connected {
					stream = a.StreamFrom
				}
				// PROTO is the protocol version negotiated on this agent's current
				// connection (design.md 7a.6 section), not the range this binary
				// supports ("wgft version" prints that range). It is only meaningful
				// while connected, so a disconnected agent shows "-" rather than the
				// version negotiated on a stream that has since dropped.
				protoVal := "-"
				if a.Connected {
					switch {
					case a.AgentProtocolLegacy:
						protoVal = "legacy"
					case a.ProtocolVersion >= 1:
						protoVal = fmt.Sprintf("v%d", a.ProtocolVersion)
					default:
						// An old server does not report protocol_version or
						// agent_protocol_legacy (added 2026-09-19); both are then Go's
						// zero value. That is neither a numbered version nor legacy, so
						// show "-" rather than the misleading "v0".
						protoVal = "-"
					}
				}
				tun := a.Tunnel.State
				if a.Tunnel.Reason != "" {
					tun += ": " + a.Tunnel.Reason
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
				// a.Tunnel and a.Rules keep the last heartbeat's content after the stream drops
				// (design.md 5.2 section); without this, a disconnected agent still prints TUNNEL
				// ok and a clean RULES count. Prefix both with "last:" so they read as history, not
				// as the current state; HEARTBEAT already shows how old that history is.
				if !a.Connected {
					if tun != "" {
						tun = "last:" + tun
					}
					if rules != "" {
						rules = "last:" + rules
					}
				}
				warn := ""
				if n := len(a.Warnings); n > 0 {
					warn = fmt.Sprintf("%d", n)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n", a.Name, a.Address, stream, ago(a.LastHeartbeat), a.Generation, tun, a.WGEndpoint, ago(a.LastHandshake), rules, protoVal, warn)
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
		Use: "warnings", Short: "list theft-detection warnings; VPS side", Args: cobra.NoArgs,
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
		Use: "dismiss-warning <name> <kind> [detail]", Short: "dismiss a warning once confirmed legitimate; VPS side", Args: cobra.RangeArgs(2, 3),
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

	cmd.AddCommand(run, pubkey, rotate, newAgentDoctorCmd(), joinString, ls, revoke, warnings, dismiss)
	return cmd
}

// agentUnreadableHint は、agent が設定ファイルを読めないときの直し方。agent の設定は WGFT_JOIN を含みうるので、
// 全員に読ませる権限は勧めず、agent の利用者のグループにだけ読ませる(仕様 11a 節)。
func agentUnreadableHint(path string) string {
	return fmt.Sprintf("It may hold WGFT_JOIN, so let only the agent's group read it; with the provided agent.service: chown root:wgft %s && chmod 0640 %s", path, path)
}
