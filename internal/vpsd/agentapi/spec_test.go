package agentapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// このファイルは、言語に依らない仕様(docs/design/spec/join.md)の fixture と、server の登録の API を
// 照らす。fixture はリポジトリの直下の testdata/spec にあり、Rust の実装も読む。

var specDir = filepath.Join("..", "..", "..", "testdata", "spec")

func specFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(specDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// specBackend は fixture の応答を返す登録の Backend である。
type specBackend struct{ err error }

func (b *specBackend) Register(joinToken, name, from string) (string, string, netip.Addr, error) {
	if b.err != nil {
		return "", "", netip.Addr{}, b.err
	}
	if joinToken != "x7Jq3fK9mPz2LwR8tV5nYb" || (name != "" && name != "home") {
		return "", "", netip.Addr{}, store.ErrInvalidToken
	}
	return "Zq4m9K2xV7pL1nR8sT3wYb", "home", netip.MustParseAddr("10.200.0.2"), nil
}

func specPost(t *testing.T, base string, body []byte) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Post(base+"/api/v1/agents/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

// TestSpecRegisterResponse は、fixture の要求に server が返す本文が fixture と byte 単位で一致する
// ことを確かめる。
func TestSpecRegisterResponse(t *testing.T) {
	srv := newTestServer(t, &specBackend{})
	for _, req := range []string{"join/register-request.json", "join/register-request-noname.json"} {
		resp, body := specPost(t, srv.URL, specFixture(t, req))
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s: %d %q", req, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		if want := specFixture(t, "join/register-response.json"); !bytes.Equal(body, want) {
			t.Errorf("%s:\n got %q\nwant %q", req, body, want)
		}
	}
}

// TestSpecRegisterErrorBodies は、server が返す誤りの状態と本文が fixture と一致することを確かめる。
func TestSpecRegisterErrorBodies(t *testing.T) {
	var cases []struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	if err := json.Unmarshal(specFixture(t, "join/register-errors.json"), &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		backend := &specBackend{}
		req := specFixture(t, "join/register-request.json")
		switch c.Status {
		case http.StatusBadRequest:
			req = []byte(`{"token":"x7Jq3fK9mPz2LwR8tV5nYb","name":"Not_A_Name"}`)
		case http.StatusUnauthorized:
			req = []byte(`{"token":"used","name":"home"}`)
		case http.StatusConflict:
			backend.err = store.ErrAgentAlreadyRegistered
		case http.StatusInternalServerError:
			backend.err = errors.New("database is locked")
		}
		srv := newTestServer(t, backend)
		var resp *http.Response
		var body []byte
		// 送信元の頻度の上限は毎秒 1 回、溜めて 5 回までなので、6 回目で 429 になる
		for i := 0; i < 6; i++ {
			resp, body = specPost(t, srv.URL, req)
			if c.Status != http.StatusTooManyRequests {
				break
			}
		}
		if resp.StatusCode != c.Status || string(body) != c.Body || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain; charset=utf-8") {
			t.Errorf("want %d %q, got %d %q %q", c.Status, c.Body, resp.StatusCode, body, resp.Header.Get("Content-Type"))
		}
	}
}
