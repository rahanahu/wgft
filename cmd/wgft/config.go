package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/startup"
)

// 設定層(仕様 11a 節)。
// どのプロセスも WGFT_* の環境変数で設定する。ファイルはその dotenv、フラグは別名。
// 優先順位はフラグ > 環境変数 > ファイル > 既定。有効な設定を出所付きで印字する。

// defaultConfigPath は WGFT_CONFIG / --config が無いときに読む dotenv。置き場は OS ごと(paths_*.go)。
var defaultConfigPath = joinPath(defaultConfigDir(), "server.env")

// spec は 1 つの設定項目。Env は WGFT_ 名、Flag は同義のフラグ名、Default は既定の文字列表現。
// Secret が真なら印字で伏せる。Slice はコンマ区切りの複数値。
type spec struct {
	Env     string
	Flag    string
	Default string
	Secret  bool
	Slice   bool
}

// resolved は 1 項目の解決結果(値と出所)。
type resolved struct {
	value  string
	source string // "flag" / "env" / "file" / "default"
}

// config は解決済みの設定。key は WGFT_ 名。
type config struct {
	vals  map[string]resolved
	specs []spec
}

// unreadableConfigFile は、設定ファイルがあるのに権限で読めないことを config の拒否として返す
// (設計文書 11b 節)。ファイル名を Subject に持ち、直し方(Hint)は読み取りの層では決めない。
// 同じファイルを server と agent で共有でき、中身を読めない以上秘密の有無も分からないので、
// どの権限にすべきかは呼び出し側のコマンドが知っている範囲で添える。
//
// 文言は、読めなかった理由を断定せずに事実だけを並べる。この拒否は `agent run` のように
// エージェント自身が読む経路でも、`wgft agent doctor` のように別の利用者が読む経路でも起きる。
// 読み手がどちらかはこの層には分からないので、読んだプロセスの識別と、ファイルの持ち主と
// パーミッションを並べ、どちらの側に原因があるかの判断は運用者に残す。
func unreadableConfigFile(path string, err error) *startup.Refusal {
	facts, _ := configFilePermFacts(path)
	// 元のエラーを包んだままにする。呼び出し側とテストが errors.Is(err, os.ErrPermission) で
	// 読めない理由を確かめられるようにするためである。
	return startup.Config(path, "%s; %s", trimSentenceEnd(err.Error()), facts).Wrapping(err)
}

// trimSentenceEnd は、句を繋ぐ前に末尾の句点を落とす。Windows の OS の誤りの文は句点で終わるので、
// そのまま繋ぐと "Access is denied.; this process runs as ..." のように句読点が 2 つ並ぶ。
func trimSentenceEnd(s string) string { return strings.TrimRight(s, ". ") }

// withUnreadableHint は、err が path を読めなかったことによる拒否なら直し方を添える。
// それ以外はそのまま返す。読めないファイルの拒否は Subject にそのファイルのパスを持つので、
// 呼び出し側が渡した path と突き合わせて見分ける。
func withUnreadableHint(err error, path string, hint func(path string) string) error {
	if r := startup.Of(err); r != nil && r.Subject == path {
		r.Hint = hint(path)
	}
	return err
}

// configErrorf は、設定の値の誤りを config の拒否にする。subject は WGFT_ 名で、文言はその名前を
// 繰り返さずに書く(Error がすでに種別と対象を出す)。
func configErrorf(subject, format string, args ...any) error {
	return startup.Config(subject, format, args...)
}

// 入口で使う値だけの検査(設計文書 11b 節)。どれも環境を見ず、値の形だけを判定する。

// validateHostPort は、値が host:port の形で、ホストが空でなく、ポートが解決できることを確かめる。
// 待ち受けには使わない項目(WGFT_WG_ENDPOINT、WGFT_AGENT_API_HOST)に使う。
func validateHostPort(env, val string) error {
	host, port, err := net.SplitHostPort(val)
	if err != nil {
		return configErrorf(env, "%q is not host:port, for example vps.example.com:51820: %v", val, err)
	}
	if host == "" {
		return configErrorf(env, "%q has no host; agents connect to this name or address", val)
	}
	if port == "" {
		return configErrorf(env, "%q has no port", val)
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return configErrorf(env, "%q has an invalid port: %v", val, err)
	}
	return nil
}

// validateBool は、真偽値の設定に綴りの誤りを通さない。かつては 1/true/yes/on 以外のすべてを偽と
// して黙って受けていたので、WGFT_ADMIN_TAILSCALE=ture のような誤りが、設定したつもりの機能を
// 黙って無効にしていた。守りや待ち受けを左右する設定であり、黙って無効にするより止めるほうが安全である。
func validateBool(env, val string) error {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "", "1", "true", "yes", "on", "0", "false", "no", "off":
		return nil
	}
	return configErrorf(env, "%q is not a boolean; write true or false", val)
}

// validateInterfaceName は、カーネルが受け付けないインタフェース名を入口で弾く。判定はカーネルの
// dev_valid_name と同じで、空でないこと、15 バイト以内、"." と ".." でないこと、'/'、':'、空白を
// 含まないことである。これを通さずに進むと netlink の LinkAdd が EINVAL で返るだけで、環境由来の
// 失敗と区別が付かない。
func validateInterfaceName(env, name string) error {
	switch {
	case name == "":
		return configErrorf(env, "is empty; give the WireGuard interface name, for example wgft0")
	case len(name) > 15:
		return configErrorf(env, "%q is longer than the 15 bytes the kernel allows for an interface name", name)
	case name == "." || name == "..":
		return configErrorf(env, "%q is not a usable interface name", name)
	case strings.ContainsAny(name, "/: \t\n\v\f\r"):
		return configErrorf(env, "%q contains a character the kernel rejects in an interface name: /, : or whitespace", name)
	}
	return nil
}

// parseDotenv は最小構文の dotenv を読む(3.1 節)。
// 「KEY=value 1 行、行頭の # だけコメント、引用符なし、値に空白なし」。
// 引用符で始まる値と、値に空白を含むものはエラー(Docker との食い違いを黙って通さない)。
func parseDotenv(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		if os.IsPermission(err) {
			return nil, unreadableConfigFile(path, err)
		}
		return nil, err
	}
	out := map[string]string{}
	// 構文の誤りの Subject は "ファイル:行" にする。読めないファイルの拒否(Subject はファイル名)と
	// 区別が付き、withUnreadableHint が権限の直し方を構文の誤りに添えてしまうことがない。
	at := func(i int) string { return fmt.Sprintf("%s:%d", path, i+1) }
	for i, line := range strings.Split(string(b), "\n") {
		s := strings.TrimRight(line, "\r")
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			return nil, configErrorf(at(i), "not in KEY=value form: %q", line)
		}
		key := s[:eq]
		val := s[eq+1:]
		if key != strings.TrimSpace(key) || strings.ContainsAny(key, " \t") {
			return nil, configErrorf(at(i), "key name may not contain whitespace: %q", key)
		}
		if strings.HasPrefix(val, "\"") || strings.HasPrefix(val, "'") {
			return nil, configErrorf(at(i), "do not quote values; Docker keeps quotes as part of the value: %q", val)
		}
		if strings.ContainsAny(val, " \t") {
			return nil, configErrorf(at(i), "value may not contain whitespace: %q", val)
		}
		out[key] = val
	}
	return out, nil
}

// loadConfig は specs を優先順位に従って解決する。configPath は dotenv のパス。
// 知らない WGFT_*、および specs に無い(他プロセス向けの)WGFT_* は読まないので黙って無視される。
func loadConfig(cmd *cobra.Command, specs []spec, configPath string) (*config, error) {
	file, err := parseDotenv(configPath)
	if err != nil {
		return nil, err
	}
	return resolveConfig(cmd, specs, configPath, file), nil
}

// resolveConfig は、読み終えた dotenv の中身とフラグと環境変数から設定を解決する。dotenv を
// 読む処理と分けてあるのは、`wgft agent doctor` が、設定ファイルを読めない実行でも診断を続ける
// ためである(設計文書 10.2c 節)。その経路は file に空の map を渡し、フラグ、環境変数、既定
// だけから解決する。
func resolveConfig(cmd *cobra.Command, specs []spec, configPath string, file map[string]string) *config {
	c := &config{vals: map[string]resolved{}, specs: specs}
	for _, sp := range specs {
		r := resolved{value: sp.Default, source: "default"}
		if v, ok := file[sp.Env]; ok {
			r = resolved{value: v, source: "file"}
		}
		if v, ok := os.LookupEnv(sp.Env); ok {
			r = resolved{value: v, source: "env"}
		}
		if f := cmd.Flags().Lookup(sp.Flag); f != nil && f.Changed {
			r = resolved{value: f.Value.String(), source: "flag"}
		}
		c.vals[sp.Env] = r
	}
	warnInsecureConfigFile(os.Stderr, configPath, c)
	return c
}

func (c *config) str(env string) string { return c.vals[env].value }

func (c *config) boolVal(env string) bool {
	switch strings.ToLower(c.vals[env].value) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func (c *config) slice(env string) []string {
	v := strings.TrimSpace(c.vals[env].value)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// print は有効な設定を出所付きで書く(トークン類は伏せ字)。specs の順で出す。
func (c *config) print(w interface{ Write([]byte) (int, error) }) {
	keys := make([]spec, len(c.specs))
	copy(keys, c.specs)
	sort.SliceStable(keys, func(i, j int) bool { return keys[i].Env < keys[j].Env })
	for _, sp := range keys {
		r := c.vals[sp.Env]
		val := r.value
		if sp.Secret && val != "" {
			val = "****"
		}
		fmt.Fprintf(w, "  %-22s = %-28s from %s\n", sp.Env, val, r.source)
	}
}

// resolveConfigPath は dotenv のパスを決める(--config > WGFT_CONFIG > 既定)。
func resolveConfigPath(cmd *cobra.Command, dflt string) string {
	if f := cmd.Flags().Lookup("config"); f != nil && f.Changed {
		return f.Value.String()
	}
	if v, ok := os.LookupEnv("WGFT_CONFIG"); ok {
		return v
	}
	return dflt
}
