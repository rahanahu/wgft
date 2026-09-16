package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func testSpecs() []spec {
	return []spec{
		{Env: "WGFT_WG_ENDPOINT", Flag: "wg-endpoint", Default: ""},
		{Env: "WGFT_MTU", Flag: "mtu", Default: "1420"},
		{Env: "WGFT_ADMIN_HOST", Flag: "admin-host", Default: "", Slice: true},
		{Env: "WGFT_ADMIN_TAILSCALE", Flag: "admin-tailscale", Default: "false"},
		{Env: "WGFT_JOIN", Flag: "join", Default: "", Secret: true},
	}
}

func testCmd() *cobra.Command {
	c := &cobra.Command{Use: "t", Run: func(*cobra.Command, []string) {}}
	f := c.Flags()
	f.String("wg-endpoint", "", "")
	f.Int("mtu", 1420, "")
	f.StringSlice("admin-host", nil, "")
	f.Bool("admin-tailscale", false, "")
	f.String("join", "", "")
	f.String("config", "", "")
	return c
}

// 優先順位:フラグ > 環境変数 > ファイル > 既定。出所も記録する。
func TestConfigPrecedence(t *testing.T) {
	dir := t.TempDir()
	envfile := filepath.Join(dir, "c.env")
	os.WriteFile(envfile, []byte("WGFT_WG_ENDPOINT=from-file:1\nWGFT_MTU=1400\n"), 0o600)
	t.Setenv("WGFT_WG_ENDPOINT", "from-env:2")

	cmd := testCmd()
	cmd.SetArgs([]string{"--wg-endpoint", "from-flag:3"})
	cmd.Execute()

	c, err := loadConfig(cmd, testSpecs(), envfile)
	if err != nil {
		t.Fatal(err)
	}
	// endpoint: flag が勝つ
	if c.str("WGFT_WG_ENDPOINT") != "from-flag:3" || c.vals["WGFT_WG_ENDPOINT"].source != "flag" {
		t.Errorf("endpoint = %+v", c.vals["WGFT_WG_ENDPOINT"])
	}
	// mtu: env なし・ファイルあり
	if c.str("WGFT_MTU") != "1400" || c.vals["WGFT_MTU"].source != "file" {
		t.Errorf("mtu = %+v", c.vals["WGFT_MTU"])
	}
	// admin-tailscale: どこにも無いので既定
	if c.boolVal("WGFT_ADMIN_TAILSCALE") || c.vals["WGFT_ADMIN_TAILSCALE"].source != "default" {
		t.Errorf("tailscale = %+v", c.vals["WGFT_ADMIN_TAILSCALE"])
	}
}

// dotenv の最小構文:引用符で始まる値と空白入りの値はエラー。
func TestDotenvSyntax(t *testing.T) {
	dir := t.TempDir()
	mk := func(body string) string {
		p := filepath.Join(dir, "x.env")
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	// 正常:# 行コメント、# を含む値(JOIN の #sha256)
	m, err := parseDotenv(mk("# comment\nWGFT_JOIN=wgft://h:1/tok#sha256:ab\n"))
	if err != nil || m["WGFT_JOIN"] != "wgft://h:1/tok#sha256:ab" {
		t.Fatalf("join parse: %v %q", err, m["WGFT_JOIN"])
	}
	// 引用符で始まる値はエラー
	if _, err := parseDotenv(mk(`WGFT_NAME="home"` + "\n")); err == nil {
		t.Error("引用符付きの値がエラーにならない")
	}
	// 値に空白はエラー
	if _, err := parseDotenv(mk("WGFT_NAME=a b\n")); err == nil {
		t.Error("空白入りの値がエラーにならない")
	}
}

// 出所付き印字でトークンは伏せ字になる。
func TestConfigPrintRedaction(t *testing.T) {
	t.Setenv("WGFT_JOIN", "wgft://secret/token#sha256:xx")
	cmd := testCmd()
	cmd.SetArgs(nil)
	cmd.Execute()
	c, _ := loadConfig(cmd, testSpecs(), filepath.Join(t.TempDir(), "none.env"))
	var buf bytes.Buffer
	c.print(&buf)
	out := buf.String()
	if strings.Contains(out, "secret/token") {
		t.Errorf("JOIN が伏せ字になっていない:\n%s", out)
	}
	if !strings.Contains(out, "****") {
		t.Errorf("伏せ字マークが無い:\n%s", out)
	}
}

// WGFT_DATA_DIR / --data-dir が正しくマップされる(server と agent の共通項目)。
func TestConfigDataDir(t *testing.T) {
	specs := []spec{{Env: "WGFT_DATA_DIR", Flag: "data-dir", Default: "/var/lib/wgft"}}

	cmd := &cobra.Command{Use: "t", Run: func(*cobra.Command, []string) {}}
	cmd.Flags().String("data-dir", "/var/lib/wgft", "")
	cmd.Flags().String("config", "", "")
	cmd.SetArgs(nil)
	cmd.Execute()
	if c, err := loadConfig(cmd, specs, filepath.Join(t.TempDir(), "none.env")); err != nil || c.str("WGFT_DATA_DIR") != "/var/lib/wgft" {
		t.Fatalf("default: %v %+v", err, c)
	}

	t.Setenv("WGFT_DATA_DIR", "/from/env")
	cmd2 := &cobra.Command{Use: "t", Run: func(*cobra.Command, []string) {}}
	cmd2.Flags().String("data-dir", "/var/lib/wgft", "")
	cmd2.Flags().String("config", "", "")
	cmd2.SetArgs(nil)
	cmd2.Execute()
	if c, err := loadConfig(cmd2, specs, filepath.Join(t.TempDir(), "none.env")); err != nil || c.str("WGFT_DATA_DIR") != "/from/env" || c.vals["WGFT_DATA_DIR"].source != "env" {
		t.Fatalf("env: %v %+v", err, c)
	}

	cmd3 := &cobra.Command{Use: "t", Run: func(*cobra.Command, []string) {}}
	cmd3.Flags().String("data-dir", "/var/lib/wgft", "")
	cmd3.Flags().String("config", "", "")
	cmd3.SetArgs([]string{"--data-dir", "/from/flag"})
	cmd3.Execute()
	if c, err := loadConfig(cmd3, specs, filepath.Join(t.TempDir(), "none.env")); err != nil || c.str("WGFT_DATA_DIR") != "/from/flag" || c.vals["WGFT_DATA_DIR"].source != "flag" {
		t.Fatalf("flag: %v %+v", err, c)
	}
}

// specs に無い WGFT_*(他プロセス向け)は読まれず無視される。
func TestConfigIgnoresForeign(t *testing.T) {
	t.Setenv("WGFT_MODE", "userspace") // このコマンドの specs に無い
	cmd := testCmd()
	cmd.SetArgs(nil)
	cmd.Execute()
	c, err := loadConfig(cmd, testSpecs(), filepath.Join(t.TempDir(), "none.env"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.vals["WGFT_MODE"]; ok {
		t.Error("specs に無い WGFT_MODE を読んでしまった")
	}
}
