package admin

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// roundTripFunc adapts a function to http.RoundTripper, so tests can inject a transport-level
// error without a real socket.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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

// 実際の権限拒否(os.ErrPermission を実装に沿って包んだ形)は、sudo を案内する分かりやすい
// エラーになる。design.md 10.5 節: 型で判定するので、文面が典型的でなくても正しく分類する。
func TestClientPermissionErrorSuggestsSudo(t *testing.T) {
	c := &Client{Base: "unix:///run/wgft/admin.sock", HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("dial unix /run/wgft/admin.sock: connect: %w", os.ErrPermission)
	})}}
	_, err := c.Rules()
	if err == nil || !strings.Contains(err.Error(), "run with sudo") {
		t.Fatalf("got %v, want an error suggesting sudo", err)
	}
}

// 以前は err.Error() に "permission denied" が含まれるかどうかで判定していた。この判定だと、
// 権限とは無関係な理由でたまたま同じ文言を含むエラーまで誤って「ソケットの権限」と読み違える。
// 型で判定する今は、そのようなエラーを正しく素通しする(design.md 10.5 節)。
func TestClientDoesNotMisreadPermissionSubstring(t *testing.T) {
	c := &Client{Base: "unix:///run/wgft/admin.sock", HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial unix /run/wgft/admin.sock: some unrelated wrapper mentions permission denied in passing")
	})}}
	_, err := c.Rules()
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "run with sudo") {
		t.Fatalf("a dial error that merely mentions \"permission denied\" in its text must not be misread as the socket's own permission bit; got %v", err)
	}
}
