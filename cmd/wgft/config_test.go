package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/internal/startup"
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
	// 構文の誤りはどれも config の拒否で、終了コード 3(設計文書 11b 節)
	for _, body := range []string{"not a pair\n", " WGFT_NAME=x\n", "WGFT_NAME='x'\n", "WGFT_NAME=a b\n"} {
		_, err := parseDotenv(mk(body))
		if got := exitCode(err); err == nil || got != exitRefusal {
			t.Errorf("%q: err=%v exitCode=%d, want %d", body, err, got, exitRefusal)
		}
	}
}

// 値の誤り(同時フロー数の上限の範囲外)は終了コード 3。範囲内は通る。
func TestLimitsOutOfRangeExitCode(t *testing.T) {
	for _, v := range []string{"abc", "15", "65536"} {
		t.Setenv("WGFT_MAX_UDP_FLOWS", v)
		c, err := loadConfig(&cobra.Command{}, limitSpecs(), filepath.Join(t.TempDir(), "none.env"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = limitsFromConfig(c)
		if got := exitCode(err); err == nil || got != exitRefusal {
			t.Errorf("WGFT_MAX_UDP_FLOWS=%s: err=%v exitCode=%d, want %d", v, err, got, exitRefusal)
		}
		// 文言も確かめる。拒否は種別と対象を Error() が出すので、呼び出し側は対象を第 1 引数で渡す。
		// 書式の引数をずらすと Reason が壊れるが、終了コードだけを見るテストでは気付けない。
		r := startup.Of(err)
		if r == nil || r.Subject != "WGFT_MAX_UDP_FLOWS" || !strings.Contains(r.Reason, strconv.Quote(v)) {
			t.Errorf("WGFT_MAX_UDP_FLOWS=%s: refusal = %v, want the setting as the subject and the value in the reason", v, r)
		}
	}
	t.Setenv("WGFT_MAX_UDP_FLOWS", "2048")
	c, _ := loadConfig(&cobra.Command{}, limitSpecs(), filepath.Join(t.TempDir(), "none.env"))
	if l, err := limitsFromConfig(c); err != nil || l.UDPTotal != 2048 {
		t.Errorf("in range: %+v %v", l, err)
	}
}

// 宛先の許可一覧(エージェントだけの設定)の構文の誤りは、上限の範囲外と同じく終了コード 3 で止める
// (仕様 11a 節)。値が無ければ制限なし(nil)になる。
func TestAllowTargetsFromConfig(t *testing.T) {
	load := func() *config {
		c, err := loadConfig(&cobra.Command{}, agentSpecs(), filepath.Join(t.TempDir(), "none.env"))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	// 最後の "," は、値はあるのに項目が無い一覧。守りの設定なので黙って制限なしにしない
	for _, v := range []string{"192.168.1.0/33", "192.168.1.20:0", "nas.lan:25565", ","} {
		t.Setenv("WGFT_AGENT_ALLOW_TARGETS", v)
		_, err := allowTargetsFromConfig(load())
		if got := exitCode(err); err == nil || got != exitRefusal {
			t.Errorf("WGFT_AGENT_ALLOW_TARGETS=%s: err=%v exitCode=%d, want %d", v, err, got, exitRefusal)
		}
	}
	t.Setenv("WGFT_AGENT_ALLOW_TARGETS", "192.168.1.0/24:2456-2458")
	l, err := allowTargetsFromConfig(load())
	if err != nil || l == nil {
		t.Fatalf("valid list: %v %v", l, err)
	}
	if !l.Allows(netip.MustParseAddrPort("192.168.1.20:2457")) {
		t.Error("the listed target must be allowed")
	}
	t.Setenv("WGFT_AGENT_ALLOW_TARGETS", "")
	if l, err := allowTargetsFromConfig(load()); err != nil || l != nil {
		t.Errorf("unset list = %v %v, want nil (no restriction)", l, err)
	}
}

// 接続元 IP ごとの上限(server だけの設定)は、0 が正当な値(上限なし)である点が
// プロセス全体の上限と異なる。既定値、0、範囲外、負の値を確かめる。
func TestPerSourceLimitsFromConfig(t *testing.T) {
	load := func() *config {
		c, err := loadConfig(&cobra.Command{}, perSourceLimitSpecs(), filepath.Join(t.TempDir(), "none.env"))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// 既定値(未設定):UDP 256、TCP 128
	c := load()
	l, err := perSourceLimitsFromConfig(c)
	if err != nil || l.UDPPerSource != 256 || l.TCPPerSource != 128 {
		t.Errorf("defaults: udp=%d tcp=%d err=%v, want 256 128 <nil>", l.UDPPerSource, l.TCPPerSource, err)
	}

	// 0 は上限なしで、エラーにならない。ゼロ値は既定値の意味なので policy.PerSourceOff に写す
	t.Setenv("WGFT_MAX_UDP_FLOWS_PER_SOURCE", "0")
	t.Setenv("WGFT_MAX_TCP_FLOWS_PER_SOURCE", "0")
	c = load()
	l, err = perSourceLimitsFromConfig(c)
	if err != nil || l.UDPPerSource != policy.PerSourceOff || l.TCPPerSource != policy.PerSourceOff {
		t.Errorf("zero: udp=%d tcp=%d err=%v, want %d %d <nil>", l.UDPPerSource, l.TCPPerSource, err, policy.PerSourceOff, policy.PerSourceOff)
	}

	// 任意の正の値も通る(既定と異なる値を明示できる)
	t.Setenv("WGFT_MAX_UDP_FLOWS_PER_SOURCE", "200")
	c = load()
	l, err = perSourceLimitsFromConfig(c)
	if err != nil || l.UDPPerSource != 200 {
		t.Errorf("custom: udp=%d err=%v, want 200 <nil>", l.UDPPerSource, err)
	}

	// 負の値、非整数、範囲外は設定エラー(終了コード 3)
	for _, v := range []string{"-1", "abc", "65536"} {
		t.Setenv("WGFT_MAX_UDP_FLOWS_PER_SOURCE", v)
		c = load()
		_, err := perSourceLimitsFromConfig(c)
		if got := exitCode(err); err == nil || got != exitRefusal {
			t.Errorf("WGFT_MAX_UDP_FLOWS_PER_SOURCE=%s: err=%v exitCode=%d, want %d", v, err, got, exitRefusal)
		}
	}
}

// 読めない設定ファイルは終了コード 3。読み取りの層はファイル名で直し方を決めない。無いファイルはエラーにしない。
func TestConfigUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix permissions and a non-root user")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "server.env")
	if err := os.WriteFile(p, []byte("WGFT_MODE=kernel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	_, err := parseDotenv(p)
	if err == nil {
		t.Fatal("読めないファイルがエラーにならない")
	}
	if strings.Contains(err.Error(), "0644") {
		t.Errorf("読み取りの層がファイル名から 0644 を勧めている: %v", err)
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("元のエラーを包んでいない: %v", err)
	}
	if got := exitCode(fmt.Errorf("server: %w", err)); got != exitRefusal {
		t.Errorf("exitCode = %d, want %d", got, exitRefusal)
	}
	if m, err := parseDotenv(filepath.Join(dir, "none.env")); err != nil || len(m) != 0 {
		t.Errorf("無いファイル: %v %v", m, err)
	}
	if got := exitCode(errors.New("boom")); got != 1 {
		t.Errorf("exitCode(other) = %d, want 1", got)
	}
}

// 読めない設定ファイルの拒否は、読めなかった理由を断定せず、見分けるための事実を並べる。
// かつては「the user wgft runs as cannot read it」と述べていたが、読めなかったのが呼び出し元で
// ある実行でも同じ文が出るため、事実と食い違っていた。
func TestUnreadableConfigFileStatesTheFactsInsteadOfBlame(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix permissions and a non-root user")
	}
	p := filepath.Join(t.TempDir(), "agent.env")
	if err := os.WriteFile(p, []byte("WGFT_JOIN=wgft://h:1/tok#sha256:ab\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	_, err := parseDotenv(p)
	if err == nil {
		t.Fatal("読めないファイルがエラーにならない")
	}
	if strings.Contains(err.Error(), "the user wgft runs as") {
		t.Errorf("読めない理由を wgft の利用者だと断定している: %v", err)
	}
	for _, want := range []string{"this process runs as uid", "the file is mode", "owner uid"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("見分けに要る事実 %q が無い: %v", want, err)
		}
	}
	// agent の直し方は、勧める所有者とパーミッションが既に満たされている場合も扱う。
	hint := agentUnreadableHint(p)
	if !strings.Contains(hint, "not the one the agent runs as") {
		t.Errorf("直し方が、既に満たされている配置を扱っていない: %s", hint)
	}
}

// agent は、読めないファイルが server.env という名前でも 0644 を勧めない(WGFT_JOIN を含みうる)。
func TestAgentUnreadableHint(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix permissions and a non-root user")
	}
	p := filepath.Join(t.TempDir(), "server.env")
	if err := os.WriteFile(p, []byte("WGFT_JOIN=wgft://h:1/tok#sha256:ab\n"), 0); err != nil {
		t.Fatal(err)
	}
	root := newRootCmd()
	root.SetArgs([]string{"agent", "run", "--config", p, "--data-dir", t.TempDir()})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	err := root.Execute()
	if got := exitCode(err); err == nil || got != exitRefusal {
		t.Fatalf("err=%v exitCode=%d, want %d", err, got, exitRefusal)
	}
	if strings.Contains(err.Error(), "0644") || !strings.Contains(err.Error(), "chmod 0640 "+p) {
		t.Errorf("agent の直し方が違う: %v", err)
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
