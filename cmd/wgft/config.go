package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
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

// configUnreadableError は、設定ファイルがあるのに権限で読めないこと。設定起因の失敗なので
// 再起動しても直らない。main が終了コード 3 にして、unit の再起動の繰り返しを止める(仕様 11a 節)。
// 直し方(hint)は読み取りの層では決めない。同じファイルを server と agent で共有でき、中身を読めない以上
// 秘密の有無も分からないので、どの権限にすべきかは呼び出し側のコマンドが知っている範囲で添える。
type configUnreadableError struct {
	path string
	err  error
	hint string
}

func (e *configUnreadableError) Error() string {
	s := fmt.Sprintf("%v; the user wgft runs as cannot read it", e.err)
	if e.hint != "" {
		s += ". " + e.hint
	}
	return s
}

func (e *configUnreadableError) Unwrap() error { return e.err }

// withUnreadableHint は、err が読めない設定ファイルによるものなら直し方を添える。それ以外はそのまま返す。
func withUnreadableHint(err error, hint func(path string) string) error {
	var e *configUnreadableError
	if errors.As(err, &e) {
		e.hint = hint(e.path)
	}
	return err
}

// configError は設定ファイルの構文や設定値の誤り。読めないファイルと同じく再起動しても直らないので、
// main が終了コード 3 にする(仕様 11a 節)。
type configError struct{ err error }

func (e *configError) Error() string { return e.err.Error() }
func (e *configError) Unwrap() error { return e.err }

// configErrorf は fmt.Errorf と同じ書式で configError を作る。
func configErrorf(format string, args ...any) error {
	return &configError{err: fmt.Errorf(format, args...)}
}

// isConfigError は、err が設定起因(読めない設定ファイル、構文や値の誤り)かを返す。
func isConfigError(err error) bool {
	var u *configUnreadableError
	var c *configError
	return errors.As(err, &u) || errors.As(err, &c)
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
			return nil, &configUnreadableError{path: path, err: err}
		}
		return nil, err
	}
	out := map[string]string{}
	for i, line := range strings.Split(string(b), "\n") {
		s := strings.TrimRight(line, "\r")
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			return nil, configErrorf("%s:%d: not in KEY=value form: %q", path, i+1, line)
		}
		key := s[:eq]
		val := s[eq+1:]
		if key != strings.TrimSpace(key) || strings.ContainsAny(key, " \t") {
			return nil, configErrorf("%s:%d: key name may not contain whitespace: %q", path, i+1, key)
		}
		if strings.HasPrefix(val, "\"") || strings.HasPrefix(val, "'") {
			return nil, configErrorf("%s:%d: do not quote values; Docker keeps quotes as part of the value: %q", path, i+1, val)
		}
		if strings.ContainsAny(val, " \t") {
			return nil, configErrorf("%s:%d: value may not contain whitespace: %q", path, i+1, val)
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
	return c, nil
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
		fmt.Fprintf(w, "  %-22s = %-28s (%s)\n", sp.Env, val, r.source)
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
