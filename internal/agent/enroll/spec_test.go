package enroll

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/startup"
)

// このファイルは、言語に依らない仕様(docs/design/spec/join.md)の fixture と、agent の接続文字列の
// 解釈と登録の API の呼び出しを照らす。fixture はリポジトリの直下の testdata/spec にあり、Rust の
// 実装も読む。

var specDir = filepath.Join("..", "..", "..", "testdata", "spec")

func specFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(specDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSpecJoinStrings は、接続文字列の正と誤りの例を ParseJoin と照らす。
func TestSpecJoinStrings(t *testing.T) {
	var cases []struct {
		Name     string `json:"name"`
		Input    string `json:"input"`
		Endpoint string `json:"endpoint"`
		Token    string `json:"token"`
		Pin      string `json:"pin"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(specFixture(t, "join/join-strings.json"), &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range cases {
		j, err := ParseJoin(c.Input)
		if c.Error != "" {
			if err == nil || err.Error() != c.Error {
				t.Errorf("%s: err = %v, want %q", c.Name, err, c.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		if j.Endpoint != c.Endpoint || j.Token != c.Token || hex.EncodeToString(j.Pin[:]) != c.Pin {
			t.Errorf("%s: got %s %s %x, want %s %s %s", c.Name, j.Endpoint, j.Token, j.Pin, c.Endpoint, c.Token, c.Pin)
		}
	}
}

// specRegisterServer は、要求の本文を記録して、決めた状態と本文を返す TLS の登録 API である。
func specRegisterServer(t *testing.T, status int, body []byte, contentType string) (*Join, <-chan []byte) {
	t.Helper()
	got := make(chan []byte, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agents/register" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("request %s %s %q", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		b, _ := io.ReadAll(r.Body)
		got <- b
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	j := &Join{Endpoint: strings.TrimPrefix(srv.URL, "https://"), Token: "x7Jq3fK9mPz2LwR8tV5nYb"}
	j.Pin = sha256.Sum256(srv.Certificate().Raw)
	return j, got
}

// TestSpecRegisterExchange は、agent が送る登録の要求の本文と、fixture の応答の読み方を確かめる。
func TestSpecRegisterExchange(t *testing.T) {
	for _, tc := range []struct{ name, request string }{
		{"home", "join/register-request.json"},
		{"", "join/register-request-noname.json"},
	} {
		j, got := specRegisterServer(t, http.StatusOK, specFixture(t, "join/register-response.json"), "application/json")
		tok, addr, name, err := Register(context.Background(), j, tc.name)
		if err != nil {
			t.Fatal(err)
		}
		if body, want := <-got, bytes.TrimSuffix(specFixture(t, tc.request), []byte("\n")); !bytes.Equal(body, want) {
			t.Errorf("request body:\n got %s\nwant %s", body, want)
		}
		if tok != "Zq4m9K2xV7pL1nR8sT3wYb" || addr != "10.200.0.2" || name != "home" {
			t.Errorf("Register = %q %q %q", tok, addr, name)
		}
	}
}

// TestSpecRegisterErrors は、登録の API の誤りの状態を、agent がどう扱うかを fixture と照らす。
func TestSpecRegisterErrors(t *testing.T) {
	var cases []struct {
		Status  int    `json:"status"`
		Body    string `json:"body"`
		Refusal string `json:"refusal"`
		Subject string `json:"subject"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(specFixture(t, "join/register-errors.json"), &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		j, _ := specRegisterServer(t, c.Status, []byte(c.Body), "text/plain; charset=utf-8")
		_, _, _, err := Register(context.Background(), j, "home")
		if err == nil {
			t.Errorf("HTTP %d: no error", c.Status)
			continue
		}
		r := startup.Of(err)
		switch {
		case c.Refusal != "":
			if r == nil || string(r.Category) != c.Refusal || r.Subject != c.Subject {
				t.Errorf("HTTP %d: err = %v, want a %s refusal of %s", c.Status, err, c.Refusal, c.Subject)
			}
		default:
			if r != nil || err.Error() != c.Error {
				t.Errorf("HTTP %d: err = %v, want %q and no refusal", c.Status, err, c.Error)
			}
		}
	}
}

// TestSpecRegisterInvalidResponse は、200 でも恒久トークンか名前が無い応答を誤りにすることを確かめる。
func TestSpecRegisterInvalidResponse(t *testing.T) {
	for _, body := range []string{`{"address":"10.200.0.2","name":"home"}`, `{"permanent_token":"t","address":"10.200.0.2"}`, `not json`} {
		j, _ := specRegisterServer(t, http.StatusOK, []byte(body), "application/json")
		if _, _, _, err := Register(context.Background(), j, ""); err == nil || err.Error() != "registration API returned an invalid response" {
			t.Errorf("%s: err = %v", body, err)
		}
	}
}
