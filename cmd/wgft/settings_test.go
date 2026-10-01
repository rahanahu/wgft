package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// walkCommands は root から下のすべてのコマンドに fn を呼ぶ。親の永続フラグを各コマンドの
// Flags に加えてから呼ぶ。実行のときに cobra が加えるのと同じで、resolveConfig が
// cmd.Flags().Lookup で見るのはこの集合である。
func walkCommands(c *cobra.Command, fn func(*cobra.Command)) {
	c.InheritedFlags()
	fn(c)
	for _, s := range c.Commands() {
		walkCommands(s, fn)
	}
}

// 設定項目のフラグ別名は、どれも spec から registerSpecFlags で登録する。手で登録すると、名前と
// 既定値が設定の解決の側と食い違っても誰も気付かない。フラグの説明に "env WGFT_" を書いたフラグが
// spec から登録されていること、その spec の Env が説明に書いた名前であることを確かめる。
func TestEveryEnvFlagIsRegisteredFromASpec(t *testing.T) {
	seen := 0
	walkCommands(newRootCmd(), func(c *cobra.Command) {
		check := func(f *pflag.Flag) {
			ann := f.Annotations[specEnvAnnotation]
			mentions := strings.Contains(f.Usage, "env WGFT_")
			switch {
			case mentions && len(ann) != 1:
				t.Errorf("%s --%s names a WGFT_ setting in its usage but was not registered from a spec", c.CommandPath(), f.Name)
			case len(ann) == 1 && !strings.Contains(f.Usage, "env "+ann[0]):
				t.Errorf("%s --%s comes from the spec of %s, but its usage %q does not name it", c.CommandPath(), f.Name, ann[0], f.Usage)
			case len(ann) == 1:
				seen++
			}
		}
		c.LocalFlags().VisitAll(check)
	})
	if seen == 0 {
		t.Fatal("no flag was registered from a spec; the walk found nothing to check")
	}
}

// assertRegistersSpecs は、cmd が specs のうち except に無いもののフラグ別名を、同じ spec から
// 登録したことを確かめる。名前、注記の Env、既定値、説明を比べる。
func assertRegistersSpecs(t *testing.T, cmd *cobra.Command, specs []spec, except map[string]bool) {
	t.Helper()
	for _, sp := range specs {
		f := cmd.Flags().Lookup(sp.Flag)
		if except[sp.Flag] {
			if f != nil {
				t.Errorf("%s registers --%s, listed as not registered; remove it from the exceptions", cmd.CommandPath(), sp.Flag)
			}
			continue
		}
		if f == nil {
			t.Errorf("%s resolves %s but has no --%s flag", cmd.CommandPath(), sp.Env, sp.Flag)
			continue
		}
		want := sp.Default
		if sp.Kind == flagStringSlice {
			want = "[]"
		}
		if ann := f.Annotations[specEnvAnnotation]; len(ann) != 1 || ann[0] != sp.Env || f.DefValue != want || f.Usage != sp.Usage {
			t.Errorf("%s --%s: env %v default %q usage %q; the spec says %s, %q, %q", cmd.CommandPath(), sp.Flag, ann, f.DefValue, f.Usage, sp.Env, want, sp.Usage)
		}
	}
}

// commandAt は root から args の道筋のコマンドを返す。
func commandAt(t *testing.T, root *cobra.Command, args ...string) *cobra.Command {
	t.Helper()
	c, rest, err := root.Find(args)
	if err != nil || len(rest) != 0 || c.Name() != args[len(args)-1] {
		t.Fatalf("command %q not found: %v", strings.Join(args, " "), err)
	}
	c.InheritedFlags()
	return c
}

// エージェントの側のコマンドが、設定を解決する spec の一覧のフラグ別名を、その一覧から登録して
// いることを確かめる。agent doctor は agent run と同じ agentSpecs で解決するが、フラグ別名は
// データの置き場とフロー数の上限だけを持つ(10.2c 節)。
func TestAgentCommandsRegisterTheSpecsTheyResolve(t *testing.T) {
	root := newRootCmd()
	assertRegistersSpecs(t, commandAt(t, root, "agent", "run"), agentSpecs(), nil)
	assertRegistersSpecs(t, commandAt(t, root, "agent", "doctor"), agentSpecs(),
		map[string]bool{"join": true, "name": true, "mode": true, "wg-interface": true, "agent-allow-targets": true})
	assertRegistersSpecs(t, commandAt(t, root, "agent", "teardown"), agentTeardownSpecs(), nil)
	assertRegistersSpecs(t, commandAt(t, root, "agent", "pubkey"), agentCredentialsSpecs(), nil)
	assertRegistersSpecs(t, commandAt(t, root, "agent", "rotate-key"), agentCredentialsSpecs(), nil)
}

// 管理用 API に接続するコマンドは、adminClient が解決する adminClientSpec から --admin を登録する。
// server run と server check の --admin は待ち受けの設定で、serverSpecs の側で確かめる。
func TestAdminFlagsComeFromTheClientSpec(t *testing.T) {
	n := 0
	walkCommands(newRootCmd(), func(c *cobra.Command) {
		if c.Flags().Lookup("admin") == nil {
			return
		}
		switch c.CommandPath() {
		case "wgft server run", "wgft server check":
			return
		}
		assertRegistersSpecs(t, c, []spec{adminClientSpec()}, nil)
		n++
	})
	if n == 0 {
		t.Fatal("no command has an --admin flag")
	}
}
