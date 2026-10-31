package enroll

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"unicode/utf8"
)

// このファイルは、ParseJoin の結果の一覧 testdata/spec/join/join-corpus.json を作り、ParseJoin の振る舞いが
// 一覧から離れていないことを確かめる。Rust の実装 (crates/wgft-proto) は同じ一覧を読み、Go と同じ入力を
// 同じ結果に読むことを確かめる。一覧は種の入力と、種から決まった手順で作る変異の入力から成る。
// ParseJoin の振る舞いを意図して変えたときだけ、次で作り直す。
//
//	go test ./internal/agent/enroll -run TestJoinCorpus -update

var updateJoinCorpus = flag.Bool("update", false, "rewrite testdata/spec/join/join-corpus.json")

const joinCorpusPath = "../../../testdata/spec/join/join-corpus.json"

// joinCorpusCase は一覧の 1 件である。Go が受けた入力は endpoint、token、pin を持ち、拒んだ入力は err を
// 持つ。utf8 が false の件は、Go が受けたが endpoint かトークンが UTF-8 でない入力で、値を載せない。
type joinCorpusCase struct {
	Input    string `json:"input"`
	Endpoint string `json:"endpoint,omitempty"`
	Token    string `json:"token,omitempty"`
	Pin      string `json:"pin,omitempty"`
	Err      string `json:"err,omitempty"`
	UTF8     *bool  `json:"utf8,omitempty"`
}

const corpusPin = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

var joinCorpusSeeds = []string{
	"wgft://203.0.113.1:8443/tok_ABC-def#sha256:" + corpusPin,
	"  WGFT://vps.example:8443/t#sha256:00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF\n",
	"wgft://[2001:db8::1]:8443/t#sha256:" + corpusPin,
	"wgft://[fe80::1%25eth0]:8443/t#sha256:" + corpusPin,
	"wgft://[::ffff:192.0.2.1]:8443/t#sha256:" + corpusPin,
	"wgft://[192.0.2.1]:8443/t#sha256:" + corpusPin,
	"wgft://user:pw@h:8443/t#sha256:" + corpusPin,
	"wgft://u%41@h:8443/t#sha256:" + corpusPin,
	"wgft://h:8443/t?x=1#sha256:" + corpusPin,
	"wgft://h:8443/t?#sha256:" + corpusPin,
	"wgft://h:8443/t%41#sha256:" + corpusPin,
	"wgft://h:8443/t%2Fx#sha256:" + corpusPin,
	"wgft://h:8443/t%C3%A9#sha256:" + corpusPin,
	"wgft://h%C3%A9:8443/t#sha256:" + corpusPin,
	"wgft://h:8443//t#sha256:" + corpusPin,
	"wgft://h:8443/t#sha256%3A" + corpusPin,
	"wgft://h:08443/t#sha256:" + corpusPin,
	"wgft://h:1/t#SHA256:" + corpusPin,
	"wgft:h:1/t#sha256:" + corpusPin,
	"wgft:/h:1/t#sha256:" + corpusPin,
	"wgft:///t#sha256:" + corpusPin,
	"http://h:1/t#sha256:" + corpusPin,
	"wgft://h/t#sha256:" + corpusPin,
	"wgft://:8443/t#sha256:" + corpusPin,
	"wgft://h:0/t#sha256:" + corpusPin,
	"wgft://h:65536/t#sha256:" + corpusPin,
	"wgft://h:1/#sha256:" + corpusPin,
	"wgft://h:1/a/b#sha256:" + corpusPin,
	"wgft://h:1/t",
	"wgft://h:1/t#md5:" + corpusPin,
	"wgft://h:1/t#sha256:abcd",
	"wgft://h:1/t%zz#sha256:" + corpusPin,
	"wgft://h h:1/t#sha256:" + corpusPin,
	"wgft://<token>",
	"wgft://h:1:2/t#sha256:" + corpusPin,
	"wgft://[::1:1/t#sha256:" + corpusPin,
	"wgft://h:1/t#sha256:" + corpusPin + "\x01",
	"",
	"1wgft://h:1/t#sha256:" + corpusPin,
	"*",
}

// joinCorpusAlphabet は変異で差し込む断片である。URL の区切り、escape、角括弧、制御文字、空白、
// 非 ASCII の文字を含む。
var joinCorpusAlphabet = []string{
	"[", "]", ":", "@", "%", "%25", "%2", "%41", "%C3%A9", "%FF", "%20", "/", "//", "#", "?", ".", "-", "_",
	"~", "!", "$", "&", "'", "(", ")", "*", "+", ",", ";", "=", "<", ">", "\"", "{", "|", "\\", "^", "`",
	" ", "\t", "\x01", "\x7f", "é", " ", " ", "0", "9", "a", "Z", "::", "::1", "ffff", "1.2.3.4",
}

const joinCorpusMutations = 3000

func buildJoinCorpus() []joinCorpusCase {
	r := rand.New(rand.NewSource(1))
	seen := map[string]bool{}
	var inputs []string
	add := func(s string) {
		if utf8.ValidString(s) && !seen[s] {
			seen[s] = true
			inputs = append(inputs, s)
		}
	}
	for _, s := range joinCorpusSeeds {
		add(s)
	}
	for len(inputs) < len(joinCorpusSeeds)+joinCorpusMutations {
		s := []byte(joinCorpusSeeds[r.Intn(len(joinCorpusSeeds))])
		for n := 1 + r.Intn(3); n > 0; n-- {
			pos := 0
			if len(s) > 0 {
				pos = r.Intn(len(s) + 1)
			}
			frag := joinCorpusAlphabet[r.Intn(len(joinCorpusAlphabet))]
			switch r.Intn(3) {
			case 0: // 差し込む
				s = append(s[:pos:pos], append([]byte(frag), s[pos:]...)...)
			case 1: // 1 byte を消す
				if pos < len(s) {
					s = append(s[:pos:pos], s[pos+1:]...)
				}
			default: // 置き換える
				end := min(pos+len(frag), len(s))
				s = append(s[:pos:pos], append([]byte(frag), s[end:]...)...)
			}
		}
		add(string(s))
	}
	sort.Strings(inputs)
	out := make([]joinCorpusCase, 0, len(inputs))
	for _, in := range inputs {
		c := joinCorpusCase{Input: in}
		j, err := ParseJoin(in)
		switch {
		case err != nil:
			c.Err = err.Error()
		case !utf8.ValidString(j.Endpoint) || !utf8.ValidString(j.Token):
			f := false
			c.UTF8 = &f
		default:
			c.Endpoint, c.Token, c.Pin = j.Endpoint, j.Token, hex.EncodeToString(j.Pin[:])
		}
		out = append(out, c)
	}
	return out
}

func encodeJoinCorpus(cases []joinCorpusCase) []byte {
	var b bytes.Buffer
	b.WriteString("[\n")
	for i, c := range cases {
		line, err := json.Marshal(c)
		if err != nil {
			panic(err)
		}
		b.WriteString("  ")
		b.Write(line)
		if i < len(cases)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("]\n")
	return b.Bytes()
}

// TestJoinCorpus は、ParseJoin の今の結果が一覧と一致することを確かめる。-update で一覧を書き直す。
func TestJoinCorpus(t *testing.T) {
	got := encodeJoinCorpus(buildJoinCorpus())
	if *updateJoinCorpus {
		if err := os.WriteFile(filepath.FromSlash(joinCorpusPath), got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(filepath.FromSlash(joinCorpusPath))
	if err != nil {
		t.Fatal(err)
	}
	// Windows の checkout は改行を CRLF にすることがある
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from ParseJoin's results; if ParseJoin changed on purpose, run go test ./internal/agent/enroll -run TestJoinCorpus -update", joinCorpusPath)
	}
}
