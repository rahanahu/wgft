package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/agent"
	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/startup"
)

// agentGOOS はエージェントの入口が Linux 以外での kernel の指定を判定するための OS 名である。
// 値は runtime.GOOS で、テストだけが Linux 以外のビルドを模すために差し替える。
var agentGOOS = runtime.GOOS

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
		{Env: "WGFT_MODE", Flag: "mode", Default: ""},
		{Env: "WGFT_WG_INTERFACE", Flag: "wg-interface", Default: "wgft0"},
		{Env: allowtargets.Env, Flag: "agent-allow-targets", Default: "", Slice: true},
	}, limitSpecs()...)
}

// logUnusedKernelLimits は、カーネルモードで同時フロー数の上限が設定されていれば、使わないことを
// 1 行出す(設計文書 7b.1 節)。拒否にしないのは、モードを切り替えても同じ agent.env を使えるように
// するためである。既定値のままなら何も出さない。
func logUnusedKernelLimits(opts agent.Options, c *config) {
	if opts.Mode != "kernel" {
		return
	}
	var set []string
	for _, env := range []string{"WGFT_MAX_UDP_FLOWS", "WGFT_MAX_TCP_FLOWS"} {
		if c.source(env) != "default" {
			set = append(set, env)
		}
	}
	if len(set) > 0 {
		log.Printf("%s: unused in kernel mode, where the host's conntrack holds the flows; the setting is kept so the same agent.env works in both modes", strings.Join(set, " and "))
	}
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
	// WGFT_MODE は値そのものの誤りと、Linux 以外での kernel の指定をここで弾く。記録との照合と切り替えの
	// 関門は、記録を読める internal/agent が判定する(設計文書 11a・11b 節)。省略は userspace を指す
	mode := c.str("WGFT_MODE")
	if mode != "" && mode != "kernel" && mode != "userspace" {
		return agent.Options{}, nil, configErrorf("WGFT_MODE", "must be kernel or userspace, not %q", mode)
	}
	if mode == "kernel" && agentGOOS != "linux" {
		return agent.Options{}, nil, startup.Prerequisite("WGFT_MODE", "the agent's kernel mode needs Linux, and this is %s; leave WGFT_MODE unset or set it to userspace", agentGOOS)
	}
	// インタフェース名はカーネルモードでだけ使うが、値だけで判定できるので、モードによらずここで弾く。
	// 後でカーネルモードへ切り替えたときに、起動の後半で初めて失敗しないためである
	if err := validateInterfaceName("WGFT_WG_INTERFACE", c.str("WGFT_WG_INTERFACE")); err != nil {
		return agent.Options{}, nil, err
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
		Mode:            mode,
		Name:            c.str("WGFT_NAME"),
		Version:         effectiveVersion(),
		WGInterface:     c.str("WGFT_WG_INTERFACE"),
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
  disable       stop forwarding an agent's rules, keeping its registration
  enable        undo a disable
  revoke        revoke a permanent token
  warnings      list theft-detection warnings
  dismiss-warning  dismiss a warning`,
	}

	// --- 自宅側 ---
	run := &cobra.Command{
		Use:   "run",
		Short: "run the agent; agent host",
		Args:  cobra.NoArgs,
		// 常駐プロセスを起動するので、起動の拒否の文面はそのままである(設計文書 11b 節)。
		Annotations: map[string]string{daemonAnnotation: "yes"},
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
			logUnusedKernelLimits(opts, c)
			return agent.Run(opts)
		},
	}
	rf := run.Flags()
	rf.String("data-dir", defaultDataDir(), "data dir, env WGFT_DATA_DIR; holds agent.json")
	registerLimitFlags(rf)
	rf.String("join", "", "join string wgft://host:port/token#sha256:..., env WGFT_JOIN")
	rf.String("name", "", "agent name, env WGFT_NAME; optional, the join string is already bound to a name")
	rf.String("mode", "", "forwarding mode userspace or kernel, env WGFT_MODE; unset means userspace, and kernel is Linux only")
	rf.String("wg-interface", "wgft0", "kernel-mode WireGuard interface name, env WGFT_WG_INTERFACE; unused in userspace mode")
	rf.String("agent-allow-targets", "",
		"comma-separated targets the server may send traffic to, env "+allowtargets.Env+"; entries are CIDR, CIDR:port or CIDR:lo-hi; unset means no restriction")
	rf.String("config", agentConfigPath, "dotenv config file")

	pubkey := &cobra.Command{
		Use:   "pubkey",
		Short: "print the wg public key; agent host; generates and saves one if absent while the agent is stopped",
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
			fmt.Fprintln(w, "NAME\tSTATE\tADDRESS\tSTREAM\tHEARTBEAT\tGEN\tTUNNEL\tWG_ENDPOINT\tHANDSHAKE\tRULES\tPROTO\tWARN")
			for _, a := range agents {
				// STATE is enabled/disabled, a declared state (design.md section 5.1), not a
				// health word: a disabled agent can still be connected with a live tunnel
				// while forwarding nothing, so folding this into STREAM or TUNNEL would hide
				// that, and calling it "ok" would read as a health check it is not.
				state := "enabled"
				if a.Disabled {
					state = "disabled"
					if a.DisabledAt != "" {
						state = "disabled " + ago(a.DisabledAt)
					}
				}
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
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n", a.Name, state, a.Address, stream, ago(a.LastHeartbeat), a.Generation, tun, a.WGEndpoint, ago(a.LastHandshake), rules, protoVal, warn)
			}
			return w.Flush()
		},
	}
	ls.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	addAdminFlag(ls)

	disable := &cobra.Command{
		Use: "disable <name>", Short: "stop forwarding an agent's rules, keeping its registration; VPS side", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			res, err := c.DisableAgent(args[0])
			if err != nil {
				return err
			}
			if !res.Changed {
				fmt.Printf("agent %s is already disabled; nothing changed\n", args[0])
				return nil
			}
			fmt.Printf("disabled agent %s at generation %d: its rules stop forwarding and open sessions are cut; registration, keys and rule settings are kept. Undo: wgft agent enable %s\n", args[0], res.Generation, args[0])
			return nil
		},
	}
	addAdminFlag(disable)

	enable := &cobra.Command{
		Use: "enable <name>", Short: "undo an agent disable; VPS side", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			res, err := c.EnableAgent(args[0])
			if err != nil {
				return err
			}
			if !res.Changed {
				fmt.Printf("agent %s is already enabled; nothing changed\n", args[0])
				return nil
			}
			fmt.Printf("enabled agent %s at generation %d: its rules forward again as each rule's own enabled setting decides\n", args[0], res.Generation)
			return nil
		},
	}
	addAdminFlag(enable)

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
			// dismiss-warning の応答は本文を持たず、何かを実際に消したかを machine-readable に
			// 伝えない(設計文書 7a.11 節)。消す前に一覧を読み、対象が無ければそう言う。agent
			// disable/enable の「既に X; 何も変わらなかった」と同じ形にそろえ、どちらの場合も
			// 終了コードは 0 のままにする(要求された操作を完了できたことが成功、7a.11 節)。
			ws, err := c.Warnings()
			if err != nil {
				return err
			}
			found, sameKind := false, false
			for _, w := range ws {
				if w.Agent != args[0] || w.Kind != args[1] {
					continue
				}
				sameKind = true
				if detail == "" || w.Detail == detail {
					found = true
					break
				}
			}
			if !found {
				if detail != "" && sameKind {
					// エージェントと種類は一致する警告があるが、渡した detail のものは無い
					// (ip-mismatch は detail が必ず組で違うので、渡した組を勘違いしている
					// ことが多い)。「消した」と誤って言わないことに加え、警告が無いという
					// のとも違う事実を言う。
					fmt.Printf("no %s warning for %s matches that detail; nothing changed. See wgft agent warnings for the current entries.\n", args[1], args[0])
				} else {
					fmt.Printf("no %s warning for %s to dismiss; nothing changed\n", args[1], args[0])
				}
				return nil
			}
			if err := c.DismissWarning(args[0], args[1], detail); err != nil {
				return err
			}
			fmt.Printf("dismissed warning for %s: %s\n", args[0], args[1])
			return nil
		},
	}
	addAdminFlag(dismiss)

	cmd.AddCommand(run, pubkey, rotate, newAgentDoctorCmd(), joinString, ls, disable, enable, revoke, warnings, dismiss)
	return cmd
}

// agentUnreadableHint は、agent が設定ファイルを読めないときの直し方。agent の設定は WGFT_JOIN を含みうるので、
// 全員に読ませる権限は勧めず、agent の利用者のグループにだけ読ませる(仕様 11a 節)。
//
// 勧める所有者とパーミッションが既に満たされている配置もある。そのときに同じ操作を勧めるだけ
// では、実行しても何も変わらない。読んだのがエージェントを動かす利用者ではない場合が残るので、
// その場合を最後に書く。
func agentUnreadableHint(path string) string {
	return fmt.Sprintf("It may hold WGFT_JOIN, so let the agent's group read it rather than every local user; with the provided agent.service, which runs the agent as the wgft user: chown root:wgft %s && chmod 0640 %s. "+
		"If the file already has that owner, group and mode, the user that read it here is not the one the agent runs as", path, path)
}
