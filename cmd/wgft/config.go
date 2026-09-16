package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// 設定層(仕様 11a 節)。
// どのプロセスも WGFT_* の環境変数で設定する。ファイルはその dotenv、フラグは別名。
// 優先順位はフラグ > 環境変数 > ファイル > 既定。有効な設定を出所付きで印字する。

// defaultConfigPath は WGFT_CONFIG / --config が無いときに読む dotenv。
const defaultConfigPath = "/etc/wgft/server.env"

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

// parseDotenv は最小構文の dotenv を読む(3.1 節)。
// 「KEY=value 1 行、行頭の # だけコメント、引用符なし、値に空白なし」。
// 引用符で始まる値と、値に空白を含むものはエラー(Docker との食い違いを黙って通さない)。
func parseDotenv(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
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
			return nil, fmt.Errorf("%s:%d: not in KEY=value form: %q", path, i+1, line)
		}
		key := s[:eq]
		val := s[eq+1:]
		if key != strings.TrimSpace(key) || strings.ContainsAny(key, " \t") {
			return nil, fmt.Errorf("%s:%d: key name may not contain whitespace: %q", path, i+1, key)
		}
		if strings.HasPrefix(val, "\"") || strings.HasPrefix(val, "'") {
			return nil, fmt.Errorf("%s:%d: do not quote values; Docker keeps quotes as part of the value: %q", path, i+1, val)
		}
		if strings.ContainsAny(val, " \t") {
			return nil, fmt.Errorf("%s:%d: value may not contain whitespace: %q", path, i+1, val)
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
