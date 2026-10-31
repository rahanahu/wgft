package proto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// このファイルは、言語に依らない仕様(docs/design/spec)の fixture(リポジトリの直下の testdata/spec)と
// Go の v1 の実装を照らす。fixture は Rust の実装も読む。fixture を書き換えるのは、Go の v1 の振る舞いを
// 意図して変えたときだけで、そのときは同じコミットで仕様も直す。

// specDir は fixture の置き場所である。
var specDir = filepath.Join("..", "testdata", "spec")

// specMessage は fixture のファイル 1 つを読み、末尾の改行を 1 つだけ除く。メッセージの fixture は、
// 送る byte 列の後に改行を 1 つ付けて保存する。
func specMessage(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(specDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(b, []byte("\n"))
}

// specQuirk は wire/quirks.json の 1 件である。input か input_base64 の片方を持つ。want は Go の v1 が
// 読んだ値を json.Marshal で書き直したもので、error が真なら読みが誤りになる。
type specQuirk struct {
	Name        string `json:"name"`
	Input       string `json:"input,omitempty"`
	InputBase64 string `json:"input_base64,omitempty"`
	Want        string `json:"want,omitempty"`
	Error       bool   `json:"error,omitempty"`
}

func (q specQuirk) raw(t *testing.T) []byte {
	t.Helper()
	if q.InputBase64 != "" {
		b, err := base64.StdEncoding.DecodeString(q.InputBase64)
		if err != nil {
			t.Fatalf("%s: input_base64: %v", q.Name, err)
		}
		return b
	}
	return []byte(q.Input)
}

// TestSpecWireQuirks は、encoding.md の「読む側の規則」の例を、Go の v1 の encoding/json で読んだ
// 結果と照らす。
func TestSpecWireQuirks(t *testing.T) {
	var cases []specQuirk
	if err := json.Unmarshal(specMessage(t, "wire/quirks.json"), &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for _, q := range cases {
		var m Message
		err := json.Unmarshal(q.raw(t), &m)
		if q.Error {
			if err == nil {
				t.Errorf("%s: read without an error, want an error", q.Name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", q.Name, err)
			continue
		}
		got, err := json.Marshal(m)
		if err != nil {
			t.Errorf("%s: marshal: %v", q.Name, err)
			continue
		}
		if string(got) != q.Want {
			t.Errorf("%s:\n got %s\nwant %s", q.Name, got, q.Want)
		}
	}
}

// TestSpecWireMessagesRoundTrip は、メッセージの fixture が Go の v1 の型で読めて、json.Marshal で
// 同じ byte 列に戻ることを確かめる。fixture のどのキーも型が知っていて、キーの順と省略が型のとおり
// であることの確かめになる。
func TestSpecWireMessagesRoundTrip(t *testing.T) {
	for _, name := range []string{
		"wire/pubkey.json", "wire/pubkey-legacy.json",
		"wire/state.json", "wire/state-legacy.json", "wire/state-disabled.json",
		"wire/heartbeat.json", "wire/heartbeat-no-tunnel.json",
	} {
		want := specMessage(t, name)
		dec := json.NewDecoder(bytes.NewReader(want))
		dec.DisallowUnknownFields()
		var m Message
		if err := dec.Decode(&m); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got, err := json.Marshal(m)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s:\n got %s\nwant %s", name, got, want)
		}
	}
}

// TestSpecWireVersionConstants は、stream.md の版と機能と再接続の値を固定する。
func TestSpecWireVersionConstants(t *testing.T) {
	if SupportedProtocol != (ProtocolRange{Min: 1, Max: 1}) {
		t.Errorf("SupportedProtocol = %+v, want [1,1]", SupportedProtocol)
	}
	if SupportedCapabilities == nil || len(SupportedCapabilities) != 0 {
		t.Errorf("SupportedCapabilities = %#v, want an empty non-nil slice", SupportedCapabilities)
	}
	codes := map[string]int{"superseded": CloseSuperseded, "revoked": CloseRevoked, "heartbeat timeout": CloseHeartbeatTimeout,
		"protocol mismatch": CloseProtocolMismatch, "protocol malformed": CloseProtocolMalformed}
	want := map[string]int{"superseded": 4000, "revoked": 4001, "heartbeat timeout": 4002, "protocol mismatch": 4003, "protocol malformed": 4004}
	for k, v := range want {
		if codes[k] != v {
			t.Errorf("close code %s = %d, want %d", k, codes[k], v)
		}
	}
	if ReasonMaxBytes != 512 || MaxRuleIDLen != 128 || MaxTargetLen != 259 || MaxRulesPerAgent != 512 {
		t.Errorf("limits = reason %d, id %d, target %d, rules %d", ReasonMaxBytes, MaxRuleIDLen, MaxTargetLen, MaxRulesPerAgent)
	}
	if ReconnectBackoffMax.String() != "5m0s" || KeyChangeEvery.String() != "10m0s" {
		t.Errorf("ReconnectBackoffMax = %v, KeyChangeEvery = %v", ReconnectBackoffMax, KeyChangeEvery)
	}
}
