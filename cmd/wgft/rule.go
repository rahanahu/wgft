package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/oklog/ulid/v2"
	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/proto"
)

// adminClient は WGFT_ADMIN(またはフラグ --admin、dotenv)からクライアントを作る。
// 既定は Unix ソケット。パスワードは無い(仕様 11 節)。
func adminClient(cmd *cobra.Command) (*admin.Client, error) {
	c, err := loadConfig(cmd, []spec{{Env: "WGFT_ADMIN", Flag: "admin", Default: "unix:///run/wgft/admin.sock"}}, resolveConfigPath(cmd, defaultConfigPath))
	if err != nil {
		return nil, err
	}
	return &admin.Client{Base: strings.TrimRight(c.str("WGFT_ADMIN"), "/")}, nil
}

// addAdminFlag は管理系サブコマンドに --admin と --config を付ける。
func addAdminFlag(c *cobra.Command) {
	c.Flags().String("admin", "unix:///run/wgft/admin.sock", "admin API address, env WGFT_ADMIN")
	c.Flags().String("config", defaultConfigPath, "dotenv config file")
}

func newRuleID() string { return "r_" + ulid.Make().String() }

// packetRateTCPNotice は、TCP のルールで packet_rate を保存する CLI の出力に付ける旨
// (design.md 7a.9 節。書き出しと読み込みの互換のため値そのものは受け付けて保存するが、
// TCP には効かない)。Web UI の同じ旨(packetTCPNoEffectNote)と文言を揃える。
const packetRateTCPNotice = "note: packet_rate is stored but has no effect on TCP rules"

// notePacketRateTCP は、r が TCP かつ packet_rate を持つときだけ旨を stderr に 1 行出す。
func notePacketRateTCP(r *proto.Rule) {
	if r.Proto == proto.TCP && r.PacketRate != nil {
		fmt.Fprintln(os.Stderr, packetRateTCPNotice)
	}
}

// newRuleCmd は `wgft rule` の木を組み立てる。サブコマンドはそれぞれ newRuleXxxCmd が作る。
func newRuleCmd() *cobra.Command {
	root := &cobra.Command{Use: "rule", Short: "Manage forwarding rules via the admin API"}
	root.PersistentFlags().String("admin", "unix:///run/wgft/admin.sock", "admin API address, env WGFT_ADMIN")
	root.PersistentFlags().String("config", defaultConfigPath, "dotenv config file")
	root.AddCommand(
		newRuleAddCmd(),
		newRuleLsCmd(),
		newRuleRmCmd(),
		newRuleSetCmd(),
		newRuleEnableCmd("enable", true),
		newRuleEnableCmd("disable", false),
		newRuleSplitCmd(),
		newRuleMergeCmd(),
		newRuleImportCmd(),
		newRuleDenyCmd(),
		newRuleAllowCmd(),
		newRuleRateCmd(),
	)
	return root
}

// newRuleAddCmd は `rule add`。--udp か --tcp のどちらか 1 つと --to が要る。
func newRuleAddCmd() *cobra.Command {
	var (
		agent, udp, tcp, to string
		group, note         string
		proxy, proxyProto   bool
		force, disabled     bool
		dryRun              bool
	)
	add := &cobra.Command{
		Use:   "add",
		Short: "Add a rule",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if (udp == "") == (tcp == "") {
				return fmt.Errorf("specify exactly one of --udp or --tcp")
			}
			r := proto.Rule{ID: newRuleID(), Agent: agent, Group: group, Note: note, Target: to, VPSMode: proto.ModeKernel, Enabled: !disabled,
				SourceAllow: []netip.Prefix{}, SourceDeny: []netip.Prefix{}}
			var err error
			if udp != "" {
				r.Proto = proto.UDP
				r.ListenPort, err = proto.ParsePortRange(udp)
			} else {
				r.Proto = proto.TCP
				r.ListenPort, err = proto.ParsePortRange(tcp)
			}
			if err != nil {
				return err
			}
			if proxyProto && !proxy {
				return fmt.Errorf("--proxy-protocol only applies to proxy mode; add --proxy")
			}
			if proxy {
				r.VPSMode = proto.ModeProxy
				r.ProxyProtocol = proxyProto
			}
			if err := r.Validate(); err != nil {
				return err
			}
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			if dryRun {
				return runRuleDryRun(c, []proto.Rule{r})
			}
			res, err := c.Batch(admin.BatchRequest{Upsert: []proto.Rule{r}, Force: force, Op: "cli rule add"})
			if err != nil {
				return err
			}
			fmt.Printf("added %s at generation %d\n", r.ID, res.Generation)
			return nil
		},
	}
	add.Flags().StringVar(&agent, "agent", "", "agent name")
	add.Flags().StringVar(&udp, "udp", "", "UDP port to listen on at the VPS; range allowed")
	add.Flags().StringVar(&tcp, "tcp", "", "TCP port to listen on at the VPS; range allowed")
	add.Flags().StringVar(&to, "to", "", "target host:port on the home side; for a listen port range, the first port; the rest follow in order")
	add.Flags().StringVar(&group, "group", "", "group to bundle rules under; optional, alphanumerics and - _ ., up to 32 chars")
	add.Flags().StringVar(&note, "note", "", "note describing the rule's purpose; optional, up to 120 chars")
	add.Flags().BoolVar(&proxy, "proxy", false, "server accepts and relays TCP in proxy mode")
	add.Flags().BoolVar(&proxyProto, "proxy-protocol", false, "add a PROXY protocol v2 header; use with --proxy")
	add.Flags().BoolVar(&force, "force", false, "ignore conflicts with ports already bound on the VPS")
	add.Flags().BoolVar(&disabled, "disabled", false, "add in a disabled state")
	add.Flags().BoolVar(&dryRun, "dry-run", false, "check the rule and print what would change, without saving it")
	_ = add.MarkFlagRequired("agent")
	_ = add.MarkFlagRequired("to")
	return add
}

// newRuleLsCmd は `rule ls`。group ごとにまとめ、空の group(その他)は最後に出す(仕様 10.2 節)。
func newRuleLsCmd() *cobra.Command {
	var asJSON bool
	ls := &cobra.Command{
		Use: "ls", Short: "List rules", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			res, err := c.Rules()
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			byGroup := map[string][]proto.Rule{}
			var groups []string
			hasTCPPacketRate := false
			for _, r := range res.Rules {
				if _, ok := byGroup[r.Group]; !ok {
					groups = append(groups, r.Group)
				}
				byGroup[r.Group] = append(byGroup[r.Group], r)
				if r.Proto == proto.TCP && r.PacketRate != nil {
					hasTCPPacketRate = true
				}
			}
			sort.Slice(groups, func(i, j int) bool {
				if (groups[i] == "") != (groups[j] == "") {
					return groups[j] == ""
				}
				return groups[i] < groups[j]
			})
			for _, g := range groups {
				name := g
				if name == "" {
					name = "ungrouped"
				}
				fmt.Printf("# %s: %d\n", name, len(byGroup[g]))
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintf(w, "  ID\tAGENT\tPROTO\tLISTEN\tTARGET\tMODE\tENABLED\tDENY\tALLOW\tRATES\tDROPPED\tREFUSED\tAGENT_STATE\tNOTE\n")
				for _, r := range byGroup[g] {
					rates := []string{}
					for nm, v := range map[string]*proto.Rate{"new": r.NewFlowRate, "pkt": r.PacketRate, "src": r.PerSourceRate} {
						if v != nil {
							rates = append(rates, nm+"="+v.String())
						}
					}
					sort.Strings(rates)
					fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\t%v\t%d\t%d\t%s\t%d\t%d\t%s\t%s\n", short(r.ID), r.Agent, r.Proto, r.ListenPort, r.TargetDisplay(), r.VPSMode, r.Enabled,
						len(r.SourceDeny), len(r.SourceAllow), strings.Join(rates, ","), res.Drops[r.ID], resourceRefusalTotal(res.ResourceRefusals, r.ID),
						agentRuleNote(res.AgentRuleStates, r.ID), truncNote(r.Note))
				}
				w.Flush()
			}
			fmt.Printf("generation %d\n", res.Generation)
			if line := flowBudgetLine(res.FlowBudget); line != "" {
				fmt.Println(line)
			}
			if hasTCPPacketRate {
				fmt.Fprintln(os.Stderr, packetRateTCPNotice)
			}
			return nil
		},
	}
	ls.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return ls
}

// newRuleRmCmd は `rule rm`。複数の ID を 1 バッチで消す。ID は他のサブコマンドと同じく前方一致で受ける。
func newRuleRmCmd() *cobra.Command {
	return &cobra.Command{
		Use: "rm <id>...", Short: "Delete rules", Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			ids := make([]string, 0, len(args))
			for _, a := range args {
				r, err := findRule(c, a)
				if err != nil {
					return err
				}
				ids = append(ids, r.ID)
			}
			res, err := c.Batch(admin.BatchRequest{Delete: ids, Op: "cli rule rm"})
			if err != nil {
				return err
			}
			fmt.Printf("deleted at generation %d\n", res.Generation)
			return nil
		},
	}
}

// newRuleEnableCmd は `rule enable` と `rule disable`。enabled の値だけが違う。
func newRuleEnableCmd(use string, enabled bool) *cobra.Command {
	return &cobra.Command{
		Use: use + " <id>", Short: map[bool]string{true: "Enable a rule", false: "Disable a rule"}[enabled], Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			r, err := findRule(c, args[0])
			if err != nil {
				return err
			}
			r.Enabled = enabled
			res, err := c.Batch(admin.BatchRequest{Upsert: []proto.Rule{*r}, Op: "cli rule " + use})
			if err != nil {
				return err
			}
			fmt.Printf("%s at generation %d\n", use, res.Generation)
			return nil
		},
	}
}

// newRuleSplitCmd は `rule split`。範囲を 1 バッチで 2 つに分け、実効宛先を変えないのでセッションは残る(仕様 5.4、7 節)。
// 組み立てと検査は proto.Rule.Split が持ち、CLI と Web UI の分割区画で共有する(仕様 10.1、10.2 節)。
func newRuleSplitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "split <id> <port>",
		Short: "Split a range into two just before <port>; done in one batch, sessions stay up",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			r, err := findRule(c, args[0])
			if err != nil {
				return err
			}
			at, err := proto.ParseSplitPoint(args[1])
			if err != nil {
				return err
			}
			head, tail, err := r.Split(at, newRuleID())
			if err != nil {
				return err
			}
			res, err := c.Batch(admin.BatchRequest{Upsert: []proto.Rule{head, tail}, Op: "cli rule split"})
			if err != nil {
				return err
			}
			fmt.Printf("split into %s covering %s and %s covering %s at generation %d\n", head.ID, head.ListenPort, tail.ID, tail.ListenPort, res.Generation)
			return nil
		},
	}
}

// newRuleMergeCmd は `rule merge`。隣接する 2 つを 1 バッチで 1 つにする。
// 組み立てと検査は proto.Merge が持ち、CLI と Web UI の統合区画で共有する(仕様 10.1、10.2 節)。
// 統合したルールは id1 の ID・group・note・拒否/許可リスト・レート・enabled を保つ。
func newRuleMergeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "merge <id1> <id2>",
		Short: "Merge two adjacent rules into one; done in one batch, sessions stay up",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			a, err := findRule(c, args[0])
			if err != nil {
				return err
			}
			b, err := findRule(c, args[1])
			if err != nil {
				return err
			}
			merged, err := proto.Merge(*a, *b)
			if err != nil {
				return err
			}
			res, err := c.Batch(admin.BatchRequest{Upsert: []proto.Rule{merged}, Delete: []string{b.ID}, Op: "cli rule merge"})
			if err != nil {
				return err
			}
			fmt.Printf("merged into %s covering %s at generation %d\n", merged.ID, merged.ListenPort, res.Generation)
			return nil
		},
	}
}

// newRuleImportCmd は `rule import`。JSON の配列で全ルールを置き換える。
func newRuleImportCmd() *cobra.Command {
	var force bool
	importCmd := &cobra.Command{
		Use: "import <file.json>", Short: "Replace all rules with JSON, an array of rules", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			var rules []proto.Rule
			if err := json.Unmarshal(b, &rules); err != nil {
				return err
			}
			for i := range rules {
				if rules[i].ID == "" {
					rules[i].ID = newRuleID()
				}
			}
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			cur, err := c.Rules()
			if err != nil {
				return err
			}
			// 削除対象の抽出は proto.DiffRules/DeletedIDs を Web UI の読み込み確認・適用
			// (仕様 10.1 節)と共有する。ExpectedDigest には今読んだ cur.Rules のハッシュを
			// 渡し、この読み取りと Batch の間に他経路(別の CLI 呼び出しや Web UI)が割り込んで
			// 変更しても、それを黙って上書きせず誤りにする(Web UI の読み込み確認・適用と
			// 同じ保証。仕様 5.4、10.1 節)。
			del := proto.DeletedIDs(proto.DiffRules(cur.Rules, rules))
			res, err := c.Batch(admin.BatchRequest{Upsert: rules, Delete: del, Force: force, ExpectedDigest: proto.RulesDigest(cur.Rules), Op: "cli rule import"})
			if err != nil {
				return err
			}
			fmt.Printf("replaced with %d rules at generation %d\n", len(res.Rules), res.Generation)
			for _, r := range rules {
				if r.Proto == proto.TCP && r.PacketRate != nil {
					fmt.Fprintln(os.Stderr, packetRateTCPNotice)
					break
				}
			}
			return nil
		},
	}
	importCmd.Flags().BoolVar(&force, "force", false, "ignore conflicts with ports already bound on the VPS")
	return importCmd
}

// newRestrictionCmd は接続元制限(deny / allow の CIDR、レート)を変える共通形。
// 配る内容は変わらないので世代は上がらない(仕様 5.3 節)。op はログの出どころ
// ("cli rule deny add" など。仕様 10.4 節の rules ログ)。after は成功後に結果のルールを
// 見て追加の出力をする任意のフック(例:packet_rate の TCP への旨。呼び出し元の大半は
// 要らないので省略できる)。
func newRestrictionCmd(use, short, op string, edit func(r *proto.Rule, args []string) error, nargs cobra.PositionalArgs, after ...func(r *proto.Rule)) *cobra.Command {
	return &cobra.Command{
		Use: use, Short: short, Args: nargs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			r, err := findRule(c, args[0])
			if err != nil {
				return err
			}
			if err := edit(r, args[1:]); err != nil {
				return err
			}
			res, err := c.Batch(admin.BatchRequest{Upsert: []proto.Rule{*r}, Op: op})
			if err != nil {
				return err
			}
			if res.Changed {
				fmt.Printf("applied at generation %d\n", res.Generation)
			} else {
				fmt.Println("applied; generation unchanged")
			}
			for _, fn := range after {
				fn(r)
			}
			return nil
		},
	}
}

// newRuleDenyCmd は `rule deny add|rm`。
func newRuleDenyCmd() *cobra.Command {
	deny := &cobra.Command{Use: "deny", Short: "Manage the deny list source_deny"}
	deny.AddCommand(
		newRestrictionCmd("add <id> <cidr>...", "add deny CIDRs; active flows are cut immediately", "cli rule deny add", func(r *proto.Rule, a []string) error {
			ps, err := proto.ParseSources(a)
			r.SourceDeny = proto.AddSources(r.SourceDeny, ps)
			return err
		}, cobra.MinimumNArgs(2)),
		newRestrictionCmd("rm <id> <cidr>...", "remove deny CIDRs", "cli rule deny rm", func(r *proto.Rule, a []string) error {
			ps, err := proto.ParseSources(a)
			r.SourceDeny = proto.RemoveSources(r.SourceDeny, ps)
			return err
		}, cobra.MinimumNArgs(2)),
	)
	return deny
}

// newRuleAllowCmd は `rule allow add|rm`。
func newRuleAllowCmd() *cobra.Command {
	allow := &cobra.Command{Use: "allow", Short: "Manage the allow list source_allow; when non-empty, drop everything except the listed CIDRs"}
	allow.AddCommand(
		newRestrictionCmd("add <id> <cidr>...", "add allow CIDRs", "cli rule allow add", func(r *proto.Rule, a []string) error {
			ps, err := proto.ParseSources(a)
			r.SourceAllow = proto.AddSources(r.SourceAllow, ps)
			return err
		}, cobra.MinimumNArgs(2)),
		newRestrictionCmd("rm <id> <cidr>...", "remove allow CIDRs", "cli rule allow rm", func(r *proto.Rule, a []string) error {
			ps, err := proto.ParseSources(a)
			r.SourceAllow = proto.RemoveSources(r.SourceAllow, ps)
			return err
		}, cobra.MinimumNArgs(2)),
	)
	return allow
}

// newRuleRateCmd は `rule rate new-flow|packet|per-source`。none か off で解除する。
func newRuleRateCmd() *cobra.Command {
	setRate := func(use, short, op string, set func(r *proto.Rule, rate *proto.Rate), after ...func(r *proto.Rule)) *cobra.Command {
		return newRestrictionCmd(use, short, op, func(r *proto.Rule, a []string) error {
			if a[0] == "none" || a[0] == "off" {
				set(r, nil)
				return nil
			}
			rate, err := proto.ParseRate(a[0])
			if err != nil {
				return err
			}
			set(r, &rate)
			return nil
		}, cobra.ExactArgs(2), after...)
	}
	rate := &cobra.Command{Use: "rate", Short: "Configure rate limits in N/second; none to clear"}
	rate.AddCommand(
		setRate("new-flow <id> <rate>", "cap on new flows for the whole rule", "cli rule rate new-flow", func(r *proto.Rule, v *proto.Rate) { r.NewFlowRate = v }),
		setRate("packet <id> <rate>", "cap on packets for the whole rule", "cli rule rate packet", func(r *proto.Rule, v *proto.Rate) { r.PacketRate = v }, notePacketRateTCP),
		setRate("per-source <id> <rate>", "cap on new flows per source IP", "cli rule rate per-source", func(r *proto.Rule, v *proto.Rate) { r.PerSourceRate = v }),
	)
	return rate
}

// newRuleSetCmd は `rule set`。group と note だけを ID そのままで変える(仕様 10.2 節)。
func newRuleSetCmd() *cobra.Command {
	var setGroup, setNote string
	var dryRun bool
	set := &cobra.Command{
		Use:   "set <id>",
		Short: "Change only an existing rule's group / note; ID stays, no effect on forwarding",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("group") && !cmd.Flags().Changed("note") {
				return fmt.Errorf("specify either --group or --note")
			}
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			r, err := findRule(c, args[0])
			if err != nil {
				// findRule reads GET /api/v1/rules itself, ahead of runRuleDryRun's own reads;
				// without this, a --dry-run whose admin API cannot be reached at all exited 1
				// or 2 depending on which of the two GET /api/v1/rules calls happened to fail
				// first (findRule's or runRuleDryRun's), while docs/design.md 11a 節,
				// helptext.go and every other --dry-run failure promise 2 (unavailable). "no
				// matching rule" and "matches multiple rules" are not an availability problem,
				// so only the wrapped case (findRule's own read failing) is converted here;
				// rule rm/enable/disable and rule set without --dry-run are untouched and keep
				// exit 1 for all three cases, as before.
				var un *rulesUnreachableError
				if dryRun && errors.As(err, &un) {
					return unavailable(un.err)
				}
				return err
			}
			if cmd.Flags().Changed("group") {
				r.Group = setGroup
			}
			if cmd.Flags().Changed("note") {
				r.Note = setNote
			}
			if err := r.Validate(); err != nil {
				return err
			}
			if dryRun {
				return runRuleDryRun(c, []proto.Rule{*r})
			}
			res, err := c.Batch(admin.BatchRequest{Upsert: []proto.Rule{*r}, Op: "cli rule set"})
			if err != nil {
				return err
			}
			if res.Changed {
				fmt.Printf("applied at generation %d\n", res.Generation)
			} else {
				fmt.Println("applied; group/note do not affect forwarding, so generation is unchanged")
			}
			return nil
		},
	}
	set.Flags().StringVar(&setGroup, "group", "", `group, or "" to clear it`)
	set.Flags().StringVar(&setNote, "note", "", `note, or "" to clear it`)
	set.Flags().BoolVar(&dryRun, "dry-run", false, "check the change and print what would change, without saving it")
	return set
}

// runRuleDryRun implements --dry-run for `rule add` and `rule set` (design.md 11a 節): it
// matches, as far as the admin API lets it observe, the admission judgment a real Batch makes
// before saving, and never calls Batch itself. It reads the server's own reserved ports from
// GET /api/v1/server (via reservedFromServerInfo), the current rules, and the registered
// agents, computes the issues the same way ruleDryRunIssues does, prints the non-unchanged rows
// of the diff and the issues found (if any), and returns a non-nil error only when there are
// issues, so the exit code is 1 exactly when this change would not be accepted.
//
// If any of these three reads fails -- including an admin API too old to have
// GET /api/v1/server -- this returns exit code 2 (unavailable) rather than falling back to no
// reserved ports: "whether this change would be accepted could not be determined" must not be
// confused with "it would be accepted." Continuing with an empty reserved set is exactly the
// defect an independent review found (proto.ValidateUpsert's reserved argument was nil here,
// so a rule overlapping the VPS's own WireGuard, admin API, or agent API port printed "accepted"
// and was then refused by the real Batch that store.ApplyBatch runs). rule add/rule set without
// --dry-run never call GET /api/v1/server, so they are unaffected.
//
// It does not try to reach any rule's target, does not check for a port already bound by
// another process on the VPS, and does not check for a DNAT some other nftables table has
// installed on the port (e.g. by Docker, which is refused even with --force): the former is
// "wgft server doctor <rule>"'s job, and the latter two need root and nft, which are not
// reachable through the admin API this command talks to.
func runRuleDryRun(c *admin.Client, upsert []proto.Rule) error {
	info, err := c.ServerInfo()
	if err != nil {
		return unavailable(fmt.Errorf("reading server info: %w", err))
	}
	current, err := c.Rules()
	if err != nil {
		return unavailable(fmt.Errorf("reading rules: %w", err))
	}
	agentList, err := c.Agents()
	if err != nil {
		return unavailable(fmt.Errorf("reading agents: %w", err))
	}
	agents := make(map[string]bool, len(agentList))
	for _, a := range agentList {
		agents[a.Name] = true
	}
	desired, _ := admin.ApplyBatchToRules(current.Rules, admin.BatchRequest{Upsert: upsert})

	fmt.Println("dry-run: changes if this were applied:")
	printed := false
	for _, chg := range proto.DiffRules(current.Rules, desired) {
		if chg.Kind == proto.ChangeUnchanged {
			continue
		}
		printed = true
		fmt.Printf("  %s %s\n", dryRunChangeSymbol(chg.Kind), dryRunRuleSummary(chg.Rule))
		for _, fc := range chg.FieldChanges {
			fmt.Printf("      %s: %q -> %q\n", fc.Field, fc.Old, fc.New)
		}
	}
	if !printed {
		fmt.Println("  no changes")
	}

	issues := ruleDryRunIssues(upsert, current.Rules, agents, reservedFromServerInfo(info))
	if len(issues) > 0 {
		fmt.Println("dry-run: issues found; nothing was saved:")
		for _, msg := range issues {
			fmt.Printf("  %s\n", msg)
		}
		return fmt.Errorf("dry-run found %d issue%s", len(issues), pluralS(len(issues)))
	}
	fmt.Println("dry-run: no issues found; this change would likely be accepted. Nothing was saved.")
	return nil
}

// reservedFromServerInfo builds the proto.Reserved set a real Batch would refuse a listen_port
// for, from GET /api/v1/server's report of the server's own ports. It delegates to
// admin.ReservedFromServerInfo, the rule internal/vpsd/vpsd.go's construction of Daemon.reserved
// at startup mirrors, so this CLI path and the Web UI's read-import confirmation
// (internal/vpsd/admin/webui_import.go's importIssues) share one implementation instead of two
// that can drift apart the way they once did (design.md's revision record, --dry-run entry).
func reservedFromServerInfo(info *admin.ServerInfo) proto.Reserved {
	return admin.ReservedFromServerInfo(*info)
}

// ruleDryRunIssues collects the reasons a dry run would refuse upsert. A row's own shape
// (proto.Rule.Validate) is not checked here: both callers of runRuleDryRun (`rule add` and
// `rule set`'s RunE, cmd/wgft/rule.go) already run it and return early on failure before ever
// calling runRuleDryRun, so a re-check here could never fail and would only mislead a reader of
// this function into thinking shape errors are caught at this point. Per row of upsert, it
// checks the agent's registration against the names GET /api/v1/agents returns, matching what
// Daemon.Batch itself checks per row of req.Upsert (internal/vpsd/admin_backend.go). Only if
// every row passes does it check the merged set (current with upsert applied, via the exported
// admin.ApplyBatchToRules, the same helper the fake and demo Backends use to build that set) for
// ID duplicates, reserved ports, and listen_port overlaps with proto.ValidateUpsert, matching
// what store.ApplyBatch validates before saving (internal/vpsd/store/rules.go). reserved must be
// built from the same GET /api/v1/server response this dry run just read
// (reservedFromServerInfo); passing nil here was the defect an independent review found.
func ruleDryRunIssues(upsert, current []proto.Rule, agents map[string]bool, reserved proto.Reserved) []string {
	var out []string
	for _, r := range upsert {
		if !agents[r.Agent] {
			out = append(out, fmt.Sprintf("%s: agent %q is not registered", dryRunRuleLabel(r, current), r.Agent))
		}
	}
	if len(out) == 0 {
		desired, _ := admin.ApplyBatchToRules(current, admin.BatchRequest{Upsert: upsert})
		if err := proto.ValidateUpsert(desired, current, reserved); err != nil {
			out = append(out, redactThrowawayRuleIDs(err.Error(), upsert, current))
		}
	}
	return out
}

// ruleIsNew reports whether r is a row "rule add" is about to create with a throwaway ID this
// invocation just made up, as opposed to a row already saved under that ID (current has it,
// always true for every row "rule set" passes, which only ever edits an existing rule).
func ruleIsNew(r proto.Rule, current []proto.Rule) bool {
	for _, c := range current {
		if c.ID == r.ID {
			return false
		}
	}
	return true
}

// dryRunRuleLabel identifies a rule in a --dry-run issue message. A row not yet in current is
// being added with a throwaway ID: newRuleID() gives every invocation, including a --dry-run
// one, a fresh ULID, so the ID on this upsert row is never the ID the row gets once an actual
// "rule add" saves it. Printing that disposable ID would name a rule that will never exist, so
// such a row is identified by its summary instead. A row already in current (always true for
// "rule set", which edits an existing rule) is identified by its real, saved ID.
func dryRunRuleLabel(r proto.Rule, current []proto.Rule) string {
	if ruleIsNew(r, current) {
		return "new rule " + dryRunRuleSummary(r)
	}
	return "rule " + short(r.ID)
}

// redactThrowawayRuleIDs replaces, in msg, every upsert row's throwaway ID with the same label
// dryRunRuleLabel gives that row. msg is an error string proto.ValidateUpsert returned
// (proto/rule.go's validateRuleSet): a reserved-port collision, an ID duplicate or a listen_port
// overlap all embed the offending row's ID verbatim ("rule %s: ...", "rule ID %s is duplicated",
// "rule %s %s/%s overlaps rule %s %s"), with no way for proto to know that, for a brand new row
// upsert holds only for this one dry run, that ID is disposable: dryRunRuleLabel's own doc comment
// explains why printing it would name a rule that will never exist. A row already in current keeps
// its real, saved ID untouched (never disposable, so never replaced). This is the fix for the
// defect an independent review found: only the "agent not registered" issue used dryRunRuleLabel;
// the reserved-port, duplicate-ID and listen_port-overlap issues, which come from
// proto.ValidateUpsert instead, printed the raw throwaway ID.
func redactThrowawayRuleIDs(msg string, upsert, current []proto.Rule) string {
	for _, r := range upsert {
		if ruleIsNew(r, current) {
			msg = strings.ReplaceAll(msg, r.ID, dryRunRuleLabel(r, current))
		}
	}
	return msg
}

// dryRunChangeSymbol is runRuleDryRun's display symbol for a proto.RuleChange.Kind.
func dryRunChangeSymbol(k proto.ChangeKind) string {
	switch k {
	case proto.ChangeAdded:
		return "+"
	case proto.ChangeChanged:
		return "~"
	case proto.ChangeDeleted:
		return "-"
	default:
		return " "
	}
}

// dryRunRuleSummary is runRuleDryRun's one-line description of a rule.
func dryRunRuleSummary(r proto.Rule) string {
	return fmt.Sprintf("%s %s -> %s %s", strings.ToUpper(string(r.Proto)), r.ListenPort.String(), r.Agent, r.TargetDisplay())
}

// short はルール ID を短く表示する(先頭 12 文字)。findRule が前方一致で受けるので選択には困らない。
func short(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}

// truncNote は一覧用に note を 40 文字で切る。
func truncNote(s string) string {
	r := []rune(s)
	if len(r) > 40 {
		return string(r[:39]) + "…"
	}
	return s
}

// resourceRefusalTotal は、そのルールに対する Resource Guard の拒否の総数(理由を問わない)。
// design.md 7a.10 節「拒否の報告」の値で、report を持たない Backend や、その理由でまだ 1 度も
// 拒んでいないルールでは 0 になる(RATES 列の DROPPED と違い、こちらは wgft 自身の資源が理由)。
func resourceRefusalTotal(refusals map[string]map[string]uint64, ruleID string) uint64 {
	var total uint64
	for _, n := range refusals[ruleID] {
		total += n
	}
	return total
}

// agentRuleNote renders one rule's agent-side status for the human `rule ls` table (design.md 10.1,
// 7a.11 節): "ok" if its agent reported it fine, "error: <reason>" if it reported an error, or "-" if
// nothing has been reported yet (whether or not the agent is connected). A "last:" prefix marks a
// disconnected agent's status as history, matching `agent ls`'s RULES column (design.md 5.2 節): for
// a never-reported rule this reads as "last:-" (the agent went offline, or never connected, before
// reporting on it). Backend without the optional interface at all (states is nil) reads the same as
// "-": the table is not a contract, so it need not distinguish "not implemented" from "connected,
// not yet reported" the way the JSON does. This is unrelated to REFUSED, which counts Resource
// Guard's own refusals, not the agent's.
func agentRuleNote(states map[string]admin.AgentRuleStatus, ruleID string) string {
	st, ok := states[ruleID]
	if !ok {
		return "-"
	}
	note := "-"
	if st.State != "" {
		note = st.State
		if st.State != proto.StatusOK {
			note = "error: " + st.Reason
		}
	}
	if !st.Connected {
		note = "last:" + note
	}
	return note
}

// flowBudgetLine は "generation" の行に続けて出す、プロセス全体のフロー予算の要約
// (design.md 7a.10 節)。report を持たない Backend では空文字を返し、何も出さない。
// kernel モードは UDP を Go 側で数えないので "udp" は出ない。
func flowBudgetLine(budget map[proto.Proto]admin.FlowBudget) string {
	if len(budget) == 0 {
		return ""
	}
	protos := make([]proto.Proto, 0, len(budget))
	for p := range budget {
		protos = append(protos, p)
	}
	sort.Slice(protos, func(i, j int) bool { return protos[i] < protos[j] })
	parts := make([]string, 0, len(protos))
	for _, p := range protos {
		b := budget[p]
		parts = append(parts, fmt.Sprintf("%s %d/%d", p, b.InUse, b.Limit))
	}
	return "flow budget: " + strings.Join(parts, ", ")
}

// rulesUnreachableError marks that findRule's own call to GET /api/v1/rules failed, as opposed to
// that call succeeding and no rule matching id. Its Error() text is unchanged from the wrapped
// error, so rule rm/enable/disable and rule set without --dry-run, which all just "return err"
// unchanged, keep exit code 1 for every findRule failure exactly as before (exitCode only special-
// cases *unavailableError and startup.Refusal); only rule set --dry-run looks for this type, to
// give findRule's own read the same exit code 2 as runRuleDryRun's reads.
type rulesUnreachableError struct{ err error }

func (e *rulesUnreachableError) Error() string { return e.err.Error() }
func (e *rulesUnreachableError) Unwrap() error { return e.err }

// findRule は ID の完全一致か、前方一致が 1 つだけのルールを返す。
func findRule(c *admin.Client, id string) (*proto.Rule, error) {
	res, err := c.Rules()
	if err != nil {
		return nil, &rulesUnreachableError{err: err}
	}
	var matches []proto.Rule
	for _, r := range res.Rules {
		if r.ID == id {
			return &r, nil
		}
		if strings.HasPrefix(r.ID, id) {
			matches = append(matches, r)
		}
	}
	switch len(matches) {
	case 1:
		return &matches[0], nil
	case 0:
		return nil, fmt.Errorf("rule %q not found", id)
	}
	return nil, fmt.Errorf("rule %q matches multiple rules", id)
}
