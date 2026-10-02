package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/rahanahu/wgft/internal/startup"
)

// 設定層(仕様 11a 節)。
// どのプロセスも WGFT_* の環境変数で設定する。ファイルはその dotenv、フラグは別名。
// 優先順位はフラグ > 環境変数 > ファイル > 既定。有効な設定を出所付きで印字する。

// defaultConfigPath は WGFT_CONFIG / --config が無いときに読む dotenv。置き場は OS ごと(paths_*.go)。
var defaultConfigPath = joinPath(defaultConfigDir(), "server.env")

// spec は 1 つの設定項目。Env は WGFT_ 名、Flag は同義のフラグ名、Default は既定の文字列表現。
// Secret が真なら印字で伏せる。Slice はコンマ区切りの複数値。
//
// spec は設定の解決(resolveConfig)とフラグ別名の登録(registerSpecFlags)の両方の元である。
// フラグの名前と既定値を spec から取って登録するので、2 つの名前と既定値は食い違わない。Kind は
// フラグの型、Usage は --help に出すフラグの説明である。同じ設定項目でもコマンドによって説明が
// 違うので、説明は withUsage で差し替える。
type spec struct {
	Env     string
	Flag    string
	Default string
	Secret  bool
	Slice   bool
	Kind    flagKind
	Usage   string
}

// flagKind は、設定項目のフラグ別名の型である。登録のとき、spec の Default をこの型の既定値に
// する。
type flagKind int

const (
	flagString      flagKind = iota // fl.String
	flagInt                         // fl.Int。Default は 10 進の整数
	flagUint16                      // fl.Uint16。Default は 10 進の整数
	flagBool                        // fl.Bool。Default は strconv.ParseBool が読む値
	flagStringSlice                 // fl.StringSlice。Default は空で、nil を既定値にする
)

// specEnvAnnotation は、spec から登録したフラグに付ける注記の鍵である。値は spec の Env で、
// テストが、どのフラグ別名も spec から登録されたことを確かめるために読む。--help には出ない。
const specEnvAnnotation = "wgft_env"

// withUsage は、Usage だけを差し替えた写しを返す。
func (sp spec) withUsage(usage string) spec {
	sp.Usage = usage
	return sp
}

// registerSpecFlags は、specs のフラグ別名を fl に登録する。名前、既定値、型は spec から取る。
// Default を Kind の型として読めない spec は作りの誤りなので、コマンドを組み立てる時点で panic する。
func registerSpecFlags(fl *pflag.FlagSet, specs ...spec) {
	for _, sp := range specs {
		switch sp.Kind {
		case flagString:
			fl.String(sp.Flag, sp.Default, sp.Usage)
		case flagInt:
			n, err := strconv.Atoi(sp.Default)
			if err != nil {
				panic(fmt.Sprintf("setting %s: default %q is not an integer", sp.Env, sp.Default))
			}
			fl.Int(sp.Flag, n, sp.Usage)
		case flagUint16:
			n, err := strconv.ParseUint(sp.Default, 10, 16)
			if err != nil {
				panic(fmt.Sprintf("setting %s: default %q is not a 16-bit unsigned integer", sp.Env, sp.Default))
			}
			fl.Uint16(sp.Flag, uint16(n), sp.Usage)
		case flagBool:
			b, err := strconv.ParseBool(sp.Default)
			if err != nil {
				panic(fmt.Sprintf("setting %s: default %q is not a boolean", sp.Env, sp.Default))
			}
			fl.Bool(sp.Flag, b, sp.Usage)
		case flagStringSlice:
			if sp.Default != "" {
				panic(fmt.Sprintf("setting %s: a list flag takes no default, not %q", sp.Env, sp.Default))
			}
			fl.StringSlice(sp.Flag, nil, sp.Usage)
		default:
			panic(fmt.Sprintf("setting %s: unknown flag kind %d", sp.Env, sp.Kind))
		}
		if err := fl.SetAnnotation(sp.Flag, specEnvAnnotation, []string{sp.Env}); err != nil {
			panic(err)
		}
	}
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

// validateHostPort は、値が host:port の形で、ホストが空でなく、ポートが 1 から 65535 を 10 進の
// 数字で書いた値であることを確かめる。接続文字列にそのまま入る WGFT_AGENT_API_HOST に使う。
// サービス名や "+443" は net.LookupPort なら通るが、エージェントの ParseJoin は 10 進の数字しか
// 受け付けないので、入口で拒む(設計文書 11b 節)。WGFT_WG_ENDPOINT は normalizeEndpoint が扱う。
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
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return configErrorf(env, "%q has a port that is not a number from 1 to 65535; agents read this value and accept only decimal digits, not a service name", val)
	}
	return nil
}

// normalizeEndpoint は WGFT_WG_ENDPOINT の値を、エージェントに配る形に直す。値は host:port の形で
// ホストが空でないことを求め、ポートの部分だけを net.LookupPort("udp", ...) で番号に直して 10 進の
// 数字で書き直す。"+51820" や "051820" は 51820 に、"domain" のようなサービス名はこのホストの
// サービスの一覧が示す番号になる。ホストは書かれたまま残し、IP アドレスに引かない。名前の引き直しは
// エージェントが行うためである。ユーザー空間モードのエージェントは 10 進の数字しか受け付けず、
// カーネルモードのエージェントはエージェントのホストのサービスの一覧で引くので、番号を決める場所を
// server の入口の 1 か所にする。UDP として引けない名前は TCP で引き直さず、0 と範囲外の値と同じく
// 拒む(設計文書 11b 節)。直すのはこの起動の Options だけで、設定ファイルは書き換えず、
// 「値と出所」の表示も入力の値のままである。
func normalizeEndpoint(env, val string) (string, error) {
	host, port, err := net.SplitHostPort(val)
	if err != nil {
		return "", configErrorf(env, "%q is not host:port, for example vps.example.com:51820: %v", val, err)
	}
	if host == "" {
		return "", configErrorf(env, "%q has no host; agents connect to this name or address", val)
	}
	if port == "" {
		return "", configErrorf(env, "%q has no port", val)
	}
	p, err := net.LookupPort("udp", port)
	if err != nil || p < 1 || p > 65535 {
		return "", configErrorf(env, "%q does not give a UDP port from 1 to 65535; write the port as a number, for example vps.example.com:51820", val)
	}
	return net.JoinHostPort(host, strconv.Itoa(p)), nil
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
//
// dev_valid_name はインタフェース名を Unicode の文字列としてではなく、生のバイト列として 1 バイト
// ずつ調べる。空白の判定も同じで、カーネルの isspace(lib/ctype.c の _ctype テーブル)が空白とする
// 7 バイトは、通常の ASCII の空白(0x09-0x0D、0x20)に加えて 0xA0 を含む。0xA0 は Latin-1 の
// non-breaking space だが、UTF-8 では "à" (U+00E0) のような文字の 2 バイト目にも現れる。このため
// isKernelSpace はバイト単位で調べる。Unicode のルーンとして比べる strings.ContainsAny では、
// "à" は 1 つのルーンとして扱われ、その内側の 0xA0 というバイトを見逃す。
//
// 合わせて次の 2 バイトも拒む。どちらも dev_valid_name 自身には拒まれないが、通すと宣言した名前と
// 実際に付く名前が食い違う。NUL バイトは、name を C の文字列として netlink へ渡す際にそこで
// 切られるので、検査した文字列と実際に設定される名前が食い違う。'%' は、`register_netdevice` が
// "wg%d" のような名前をテンプレートとして扱い、指定と違う番号付きの名前を作ってしまう。
func validateInterfaceName(env, name string) error {
	switch {
	case name == "":
		return configErrorf(env, "is empty; give the WireGuard interface name, for example wgft0")
	case len(name) > 15:
		return configErrorf(env, "%q is longer than the 15 bytes the kernel allows for an interface name", name)
	case name == "." || name == "..":
		return configErrorf(env, "%q is not a usable interface name", name)
	}
	for i := 0; i < len(name); i++ {
		if b := name[i]; b == '/' || b == ':' || b == '%' || b == 0 || isKernelSpace(b) {
			return configErrorf(env, "%q contains byte 0x%02x, which is not usable in an interface name; /, :, %%, a NUL byte and whitespace including 0xa0 are not allowed", name, b)
		}
	}
	return nil
}

// isKernelSpace は、カーネルの isspace が空白とみなすバイトかどうかを返す(validateInterfaceName
// のコメントを参照)。
func isKernelSpace(b byte) bool {
	switch b {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xA0:
		return true
	}
	return false
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
		// 誤りの文言には行の中身も値も出さない。ファイル:行 と、名前の形をしたキーだけを出す。
		// WGFT_JOIN の接続文字列のような秘密の値が、起動の失敗の文言としてジャーナルに残らない
		// ようにするためである(設計文書 11a 節)。
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			return nil, configErrorf(at(i), "not in KEY=value form; the line is not shown, since it may hold a secret")
		}
		key := s[:eq]
		val := s[eq+1:]
		if key != strings.TrimSpace(key) || strings.ContainsAny(key, " \t") {
			return nil, configErrorf(at(i), "key name may not contain whitespace; the line is not shown, since it may hold a secret")
		}
		if strings.HasPrefix(val, "\"") || strings.HasPrefix(val, "'") {
			return nil, configErrorf(at(i), "do not quote the value of %s; Docker keeps quotes as part of the value", dotenvKeyLabel(key))
		}
		if strings.ContainsAny(val, " \t") {
			return nil, configErrorf(at(i), "the value of %s may not contain whitespace", dotenvKeyLabel(key))
		}
		out[key] = val
	}
	return out, nil
}

// dotenvKeyLabel は、構文の誤りの文言に出すキーの名前である。英数字と _ だけの名前はそのまま出し、
// それ以外は出さない。行が壊れていると、= より前に値の一部が入りうるためである。
func dotenvKeyLabel(key string) string {
	if key == "" {
		return "this key"
	}
	for _, r := range key {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return "this key"
		}
	}
	return key
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

// source は、その項目の値をどこから取ったかである。"flag"、"env"、"file"、"default" のいずれかで、
// print が出す出所と同じものである。
func (c *config) source(env string) string { return c.vals[env].source }

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
