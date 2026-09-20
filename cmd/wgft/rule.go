package main

import (
	"encoding/json"
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
	)
	add := &cobra.Command{
		Use:   "add",
		Short: "Add a rule",
		Example: `  wgft rule add --agent home --udp 2456-2457 --to 192.168.1.20:2456
  wgft rule add --agent home --tcp 443 --to 192.168.1.30:443 --proxy --proxy-protocol`,
		Args: cobra.NoArgs,
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
	add.Flags().StringVar(&to, "to", "", "target host:port on the home side; for a listen port range, the first port (the rest follow in order)")
	add.Flags().StringVar(&group, "group", "", "group to bundle rules under; optional, alphanumerics and - _ ., up to 32 chars")
	add.Flags().StringVar(&note, "note", "", "note describing the rule's purpose; optional, up to 120 chars")
	add.Flags().BoolVar(&proxy, "proxy", false, "server accepts and relays TCP in proxy mode")
	add.Flags().BoolVar(&proxyProto, "proxy-protocol", false, "add a PROXY protocol v2 header; use with --proxy")
	add.Flags().BoolVar(&force, "force", false, "ignore conflicts with ports already bound on the VPS")
	add.Flags().BoolVar(&disabled, "disabled", false, "add in a disabled state")
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
				fmt.Printf("# %s (%d)\n", name, len(byGroup[g]))
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintf(w, "  ID\tAGENT\tPROTO\tLISTEN\tTARGET\tMODE\tENABLED\tDENY\tALLOW\tRATES\tDROPPED\tREFUSED\tNOTE\n")
				for _, r := range byGroup[g] {
					rates := []string{}
					for nm, v := range map[string]*proto.Rate{"new": r.NewFlowRate, "pkt": r.PacketRate, "src": r.PerSourceRate} {
						if v != nil {
							rates = append(rates, nm+"="+v.String())
						}
					}
					sort.Strings(rates)
					fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\t%v\t%d\t%d\t%s\t%d\t%d\t%s\n", short(r.ID), r.Agent, r.Proto, r.ListenPort, r.TargetDisplay(), r.VPSMode, r.Enabled,
						len(r.SourceDeny), len(r.SourceAllow), strings.Join(rates, ","), res.Drops[r.ID], resourceRefusalTotal(res.ResourceRefusals, r.ID), truncNote(r.Note))
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
	set.Flags().StringVar(&setGroup, "group", "", `group ("" to clear)`)
	set.Flags().StringVar(&setNote, "note", "", `note ("" to clear)`)
	return set
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

// findRule は ID の完全一致か、前方一致が 1 つだけのルールを返す。
func findRule(c *admin.Client, id string) (*proto.Rule, error) {
	res, err := c.Rules()
	if err != nil {
		return nil, err
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
