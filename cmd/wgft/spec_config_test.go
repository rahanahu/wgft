package main

// docs/design/spec/cli-config.md の fixture(testdata/spec/config)と、Go の v1 の実装を照らす。
// fixture は Rust の実装も読む言語に依らない形で、書き換えるのは v1 の振る舞いを意図して変えたとき
// だけである。そのため -update のような書き戻しの手段は置かない。

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/startup"
)

// specConfigDir は fixture の置き場である。go test はパッケージのディレクトリで動く。
var specConfigDir = filepath.Join("..", "..", "testdata", "spec", "config")

// specConfigLoad は fixture の JSON を v に読む。知らないキーは誤りにする。fixture の綴りの誤りで
// 項目が黙って空になり、何も確かめない試験になることを防ぐためである。
func specConfigLoad(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(specConfigDir, name))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// specConfigClearEnv は、エージェントが読む WGFT_* と WGFT_CONFIG と GOMEMLIMIT を外す。試験を動かす
// ホストの環境が結果に混ざらないようにするためである。t.Setenv が試験の後に元へ戻す。
func specConfigClearEnv(t *testing.T) {
	t.Helper()
	names := []string{"WGFT_CONFIG", "GOMEMLIMIT"}
	for _, sp := range agentSpecs() {
		names = append(names, sp.Env)
	}
	for _, n := range names {
		t.Setenv(n, "")
		if err := os.Unsetenv(n); err != nil {
			t.Fatal(err)
		}
	}
}

// specConfigAgentRun は、フラグを解釈した `wgft agent run` のコマンドを返す。RunE は呼ばない。
func specConfigAgentRun(t *testing.T, args []string) *cobra.Command {
	t.Helper()
	cmd, _, err := newRootCmd().Find([]string{"agent", "run"})
	if err != nil || cmd.Name() != "run" {
		t.Fatalf("find agent run: %v, %v", cmd, err)
	}
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("parse flags %q: %v", args, err)
	}
	return cmd
}

// specConfigWriteDotenv は input を 0600 のファイルに書き、そのパスを返す。input が nil なら書かずに、
// 存在しないファイルのパスを返す。0600 にするのは、秘密を含むファイルの権限の警告を出さないためである。
func specConfigWriteDotenv(t *testing.T, input *string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.env")
	if input != nil {
		if err := os.WriteFile(path, []byte(*input), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestSpecConfigDotenv(t *testing.T) {
	var fx struct {
		Description string `json:"description"`
		OK          []struct {
			Name  string            `json:"name"`
			Input *string           `json:"input"`
			Want  map[string]string `json:"want"`
		} `json:"ok"`
		Error []struct {
			Name           string   `json:"name"`
			Input          *string  `json:"input"`
			Line           int      `json:"line"`
			Reason         string   `json:"reason"`
			MustNotContain []string `json:"must_not_contain"`
		} `json:"error"`
	}
	specConfigLoad(t, "dotenv.json", &fx)
	if len(fx.OK) == 0 || len(fx.Error) == 0 {
		t.Fatal("dotenv.json has no cases")
	}
	for _, c := range fx.OK {
		t.Run("ok/"+c.Name, func(t *testing.T) {
			path := specConfigWriteDotenv(t, c.Input)
			got, err := parseDotenv(path)
			if err != nil {
				t.Fatalf("parseDotenv: %v", err)
			}
			if len(got) != len(c.Want) {
				t.Errorf("got %q, want %q", got, c.Want)
			}
			for k, v := range c.Want {
				if g, ok := got[k]; !ok || g != v {
					t.Errorf("key %q: got %q (present %v), want %q", k, g, ok, v)
				}
			}
		})
	}
	for _, c := range fx.Error {
		t.Run("error/"+c.Name, func(t *testing.T) {
			path := specConfigWriteDotenv(t, c.Input)
			_, err := parseDotenv(path)
			if err == nil {
				t.Fatal("parseDotenv accepted the input")
			}
			r := startup.Of(err)
			subject := fmt.Sprintf("%s:%d", path, c.Line)
			if r == nil || r.Category != startup.CategoryConfig || r.Subject != subject || r.Reason != c.Reason {
				t.Fatalf("got %v, want a config refusal about %s with reason %q", err, subject, c.Reason)
			}
			if got, want := err.Error(), "refusing to start [config "+subject+"]: "+c.Reason; got != want {
				t.Errorf("message:\n got %q\nwant %q", got, want)
			}
			if got := exitCode(err); got != exitRefusal {
				t.Errorf("exit code %d, want %d", got, exitRefusal)
			}
			// パスは呼び出し側が決めるので、行の中身を繰り返していないかはパスを除いて確かめる
			rest := strings.ReplaceAll(err.Error(), path, "")
			for _, s := range c.MustNotContain {
				if strings.Contains(rest, s) {
					t.Errorf("message %q repeats %q from the line", err.Error(), s)
				}
			}
			if got, want := startup.OneShot(err).Error(), "cannot continue [config "+subject+"]: "+c.Reason; got != want {
				t.Errorf("one-shot message:\n got %q\nwant %q", got, want)
			}
		})
	}
}

func TestSpecConfigEffectiveConfig(t *testing.T) {
	var fx struct {
		Description string `json:"description"`
		Cases       []struct {
			Name   string            `json:"name"`
			Note   string            `json:"note"`
			Config string            `json:"config"`
			Dotenv *string           `json:"dotenv"`
			Env    map[string]string `json:"env"`
			Args   []string          `json:"args"`
			Want   string            `json:"want"`
		} `json:"cases"`
	}
	specConfigLoad(t, "effective-config.json", &fx)
	if len(fx.Cases) == 0 {
		t.Fatal("effective-config.json has no cases")
	}
	for _, c := range fx.Cases {
		t.Run(c.Name, func(t *testing.T) {
			specConfigClearEnv(t)
			for k, v := range c.Env {
				t.Setenv(k, v)
			}
			path := specConfigWriteDotenv(t, c.Dotenv)
			args := append([]string{}, c.Args...)
			switch c.Config {
			case "flag":
				args = append(args, "--config", path)
			case "env":
				t.Setenv("WGFT_CONFIG", path)
			default:
				t.Fatalf("config %q is neither flag nor env", c.Config)
			}
			cmd := specConfigAgentRun(t, args)
			// agent run と同じ順で、設定ファイルのパスを決めてから設定を読む
			cfg, err := loadConfig(cmd, agentSpecs(), resolveConfigPath(cmd, agentConfigPath))
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			var b bytes.Buffer
			// agent run は見出しの行を書いてから print を呼ぶ(agent.go の RunE)
			b.WriteString("effective config:\n")
			cfg.print(&b)
			if got := b.String(); got != c.Want {
				t.Errorf("effective config:\n got %q\nwant %q", got, c.Want)
			}
		})
	}
}

func TestSpecConfigValuesAtTheDoor(t *testing.T) {
	var fx struct {
		Description string `json:"description"`
		Cases       []struct {
			Env     map[string]string `json:"env"`
			Args    []string          `json:"args"`
			GOOS    string            `json:"goos"`
			Message string            `json:"message"`
		} `json:"cases"`
	}
	specConfigLoad(t, "values.json", &fx)
	if len(fx.Cases) == 0 {
		t.Fatal("values.json has no cases")
	}
	for i, c := range fx.Cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			specConfigClearEnv(t)
			t.Setenv("WGFT_DATA_DIR", t.TempDir())
			for k, v := range c.Env {
				t.Setenv(k, v)
			}
			if c.GOOS != "" {
				saved := agentGOOS
				agentGOOS = c.GOOS
				t.Cleanup(func() { agentGOOS = saved })
			}
			args := append(append([]string{}, c.Args...), "--config", specConfigWriteDotenv(t, nil))
			_, _, err := buildAgentOptions(specConfigAgentRun(t, args))
			if c.Message == "" {
				if err != nil {
					t.Fatalf("env %q args %q: refused at the door: %v", c.Env, c.Args, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("env %q args %q: passed the door, want %q", c.Env, c.Args, c.Message)
			}
			if got := err.Error(); got != c.Message {
				t.Errorf("env %q args %q:\n got %q\nwant %q", c.Env, c.Args, got, c.Message)
			}
			if got := exitCode(err); got != exitRefusal {
				t.Errorf("exit code %d, want %d", got, exitRefusal)
			}
		})
	}
}

func TestSpecConfigAllowTargets(t *testing.T) {
	var fx struct {
		Description string `json:"description"`
		OK          []struct {
			Input      string  `json:"input"`
			Normalized *string `json:"normalized"`
		} `json:"ok"`
		Error []struct {
			Input string `json:"input"`
			Error string `json:"error"`
		} `json:"error"`
	}
	specConfigLoad(t, "allow-targets.json", &fx)
	if len(fx.OK) == 0 || len(fx.Error) == 0 {
		t.Fatal("allow-targets.json has no cases")
	}
	for _, c := range fx.OK {
		l, err := allowtargets.Parse(c.Input)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.Input, err)
			continue
		}
		switch {
		case c.Normalized == nil && l != nil:
			t.Errorf("Parse(%q) = %q, want no list", c.Input, l.String())
		case c.Normalized != nil && l == nil:
			t.Errorf("Parse(%q) = no list, want %q", c.Input, *c.Normalized)
		case c.Normalized != nil && l.String() != *c.Normalized:
			t.Errorf("Parse(%q) = %q, want %q", c.Input, l.String(), *c.Normalized)
		}
	}
	for _, c := range fx.Error {
		_, err := allowtargets.Parse(c.Input)
		if err == nil || err.Error() != c.Error {
			t.Errorf("Parse(%q) error:\n got %v\nwant %q", c.Input, err, c.Error)
		}
	}
}

func TestSpecConfigRefusalsAndExitCodes(t *testing.T) {
	var fx struct {
		Description string `json:"description"`
		Cases       []struct {
			Name     string `json:"name"`
			Kind     string `json:"kind"`
			Category string `json:"category"`
			Subject  string `json:"subject"`
			Reason   string `json:"reason"`
			Hint     string `json:"hint"`
			OneShot  bool   `json:"one_shot"`
			Wrap     string `json:"wrap"`
			Message  string `json:"message"`
			Exit     int    `json:"exit"`
		} `json:"cases"`
	}
	specConfigLoad(t, "refusals.json", &fx)
	if len(fx.Cases) == 0 {
		t.Fatal("refusals.json has no cases")
	}
	build := map[string]func(subject, format string, a ...any) *startup.Refusal{
		"config":       startup.Config,
		"prerequisite": startup.Prerequisite,
		"conflict":     startup.Conflict,
		"mode-gate":    startup.ModeGate,
	}
	for _, c := range fx.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var err error
			switch c.Kind {
			case "refusal":
				mk, ok := build[c.Category]
				if !ok {
					t.Fatalf("unknown category %q", c.Category)
				}
				r := mk(c.Subject, "%s", c.Reason)
				if string(r.Category) != c.Category {
					t.Fatalf("category %q, want %q", r.Category, c.Category)
				}
				r.Hint = c.Hint
				err = r
				if c.OneShot {
					err = startup.OneShot(err)
				}
			case "unavailable":
				err = unavailable(errors.New(c.Reason))
			case "error":
				err = errors.New(c.Reason)
			default:
				t.Fatalf("unknown kind %q", c.Kind)
			}
			if c.Wrap != "" {
				err = fmt.Errorf("%s%w", c.Wrap, err)
			}
			if got := err.Error(); got != c.Message {
				t.Errorf("message:\n got %q\nwant %q", got, c.Message)
			}
			if got := exitCode(err); got != c.Exit {
				t.Errorf("exit code %d, want %d", got, c.Exit)
			}
		})
	}
}
