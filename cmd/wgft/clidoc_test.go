//go:build linux

package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// docs/cli.md はコマンドのヘルプから生成する。ヘルプを変えたら次で書き直す:
//
//	go test ./cmd/wgft -run TestCLIDocUpToDate -update
var updateCLIDoc = flag.Bool("update", false, "rewrite docs/cli.md from the command help")

const cliDocPath = "../../docs/cli.md"

// 既定のパスが OS で変わるので、生成と照合は Linux でだけ行う(このファイルのビルドタグ)。
func TestCLIDocUpToDate(t *testing.T) {
	got := renderCLIDoc(newRootCmd())
	if *updateCLIDoc {
		if err := os.WriteFile(cliDocPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(cliDocPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatalf("%s is out of date; run: go test ./cmd/wgft -run TestCLIDocUpToDate -update", cliDocPath)
	}
}

// helpTexts のキーはすべて実在するコマンドを指し、実行できるコマンドにはすべて使用例がある。
func TestHelpTextsCoverCommands(t *testing.T) {
	root := newRootCmd()
	seen := map[string]bool{}
	for _, c := range documentedCommands(root) {
		key := helpKey(c)
		seen[key] = true
		if c.Runnable() && c.Example == "" && key != "version" {
			t.Errorf("wgft %s has no example", key)
		}
	}
	for key := range helpTexts {
		if !seen[key] {
			t.Errorf("helpTexts has an entry for %q, which is not a command", key)
		}
	}
}

// documentedCommands は文書に載せるコマンドを、表示順(親の次に子を名前順)で返す。
func documentedCommands(root *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		out = append(out, c)
		subs := append([]*cobra.Command(nil), c.Commands()...)
		sort.Slice(subs, func(i, j int) bool { return subs[i].Name() < subs[j].Name() })
		for _, s := range subs {
			if s.Name() == "help" || s.Name() == "completion" || s.Hidden {
				continue
			}
			walk(s)
		}
	}
	walk(root)
	return out
}

func renderCLIDoc(root *cobra.Command) string {
	root.InitDefaultHelpFlag()
	cmds := documentedCommands(root)
	var b strings.Builder
	b.WriteString("# wgft command reference\n\n")
	b.WriteString("Generated from the command help; do not edit by hand. `wgft <command> --help` prints the same text.\n")
	b.WriteString("To regenerate after changing the help: `go test ./cmd/wgft -run TestCLIDocUpToDate -update`.\n\n")
	b.WriteString("## Commands\n\n| Command | What it does |\n|---|---|\n")
	for _, c := range cmds[1:] {
		if !c.Runnable() {
			continue
		}
		fmt.Fprintf(&b, "| [`%s`](#%s) | %s |\n", c.CommandPath(), anchor(c), firstSentence(c.Short))
	}
	for _, c := range cmds {
		fmt.Fprintf(&b, "\n## %s\n\n", c.CommandPath())
		desc := c.Long
		if desc == "" {
			desc = strings.ToUpper(c.Short[:1]) + c.Short[1:] + "."
		}
		if strings.Contains(desc, "\n  ") {
			// 字下げで揃えた一覧を含む説明は、そのままの形で見せる
			fmt.Fprintf(&b, "```text\n%s\n```\n", desc)
		} else {
			fmt.Fprintf(&b, "%s\n", desc)
		}
		if c.Runnable() {
			fmt.Fprintf(&b, "\n```text\n%s\n```\n", c.UseLine())
		}
		if c.Example != "" {
			fmt.Fprintf(&b, "\nExamples:\n\n```sh\n%s\n```\n", dedent(c.Example))
		}
		if f := c.NonInheritedFlags().FlagUsages(); strings.TrimSpace(strings.ReplaceAll(f, "-h, --help", "")) != "" {
			fmt.Fprintf(&b, "\nFlags:\n\n```text\n%s```\n", dropHelpFlag(f))
		}
		if f := c.InheritedFlags().FlagUsages(); f != "" {
			fmt.Fprintf(&b, "\nFlags inherited from parent commands:\n\n```text\n%s```\n", f)
		}
	}
	return b.String()
}

func anchor(c *cobra.Command) string { return strings.ReplaceAll(c.CommandPath(), " ", "-") }

func firstSentence(s string) string {
	if i := strings.Index(s, ";"); i > 0 {
		s = s[:i]
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func dedent(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimPrefix(l, "  ")
	}
	return strings.Join(lines, "\n")
}

// dropHelpFlag は、全コマンドに共通の -h, --help の行を除く。
func dropHelpFlag(usages string) string {
	var keep []string
	for _, l := range strings.SplitAfter(usages, "\n") {
		if !strings.Contains(l, "-h, --help") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "")
}
