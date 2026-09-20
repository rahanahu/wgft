package admin

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Client の既定の HTTP クライアントには打ち切りのタイムアウトがある。無いと、応答しない
// サーバに対して wgft rule ls のようなコマンドが永久に待ち続け、診断も出ない(仕様 11 節)。
func TestClientDefaultHasTimeout(t *testing.T) {
	c := &Client{Base: "http://127.0.0.1:1"}
	if got := c.httpClient().Timeout; got <= 0 {
		t.Fatalf("default admin API client has no timeout (got %s); a stalled server would hang forever", got)
	}

	socketClient := &Client{Base: "unix:///tmp/does-not-matter.sock"}
	if got := socketClient.httpClient().Timeout; got <= 0 {
		t.Fatalf("default admin API client (unix socket) has no timeout (got %s)", got)
	}
}

// HTTP を明示的に注入した呼び出し元は、その設定(タイムアウトの有無を含む)をそのまま使う。
func TestClientInjectedHTTPIsNotOverridden(t *testing.T) {
	injected := &http.Client{}
	c := &Client{Base: "http://127.0.0.1:1", HTTP: injected}
	if got := c.httpClient(); got != injected {
		t.Fatal("Client must use the injected HTTP client as-is")
	}
}

// サーバが応答せずに黙っていると、Client はタイムアウトで打ち切り、はっきりした英語のエラーを返す。
func TestClientTimeoutProducesClearError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// 応答を返さずに接続を握ったままにする(テストの終わりまで、または ln.Close() まで)
			go func() {
				<-done
				conn.Close()
			}()
		}
	}()

	c := &Client{Base: "http://" + ln.Addr().String(), HTTP: &http.Client{Timeout: 100 * time.Millisecond}}
	_, err = c.Rules()
	if err == nil {
		t.Fatal("expected an error from a server that never responds")
	}
	if !strings.Contains(err.Error(), "did not respond") {
		t.Fatalf("error %q does not look like a clear timeout message", err)
	}
}
