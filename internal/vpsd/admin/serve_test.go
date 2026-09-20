package admin

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// TCP で開いた管理用 API には ReadHeaderTimeout・ReadTimeout・WriteTimeout・IdleTimeout が付き、
// Unix ソケットには付かない(相手はすでに root か、その root に入れる人に限られる境界の内側なので、
// 期限を付ける必要が無い)。
func TestAdminServerForTimeouts(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	tcpSrv := adminServerFor(tcpLn, http.NotFoundHandler())
	if tcpSrv.ReadHeaderTimeout <= 0 || tcpSrv.ReadTimeout <= 0 || tcpSrv.WriteTimeout <= 0 || tcpSrv.IdleTimeout <= 0 {
		t.Errorf("TCP admin server has no timeouts: %+v", tcpSrv)
	}

	unixLn, err := net.Listen("unix", filepath.Join(t.TempDir(), "admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer unixLn.Close()
	unixSrv := adminServerFor(unixLn, http.NotFoundHandler())
	if unixSrv.ReadHeaderTimeout != 0 || unixSrv.ReadTimeout != 0 || unixSrv.WriteTimeout != 0 || unixSrv.IdleTimeout != 0 {
		t.Errorf("Unix socket admin server should have no timeouts, got: %+v", unixSrv)
	}
}

// ヘッダを送り終えない TCP 接続は ReadHeaderTimeout で切れる(agentapi の同種のテストと同じ形)。
func TestAdminServerTCPHeaderStall(t *testing.T) {
	timeouts := adminTimeouts{ReadHeaderTimeout: 100 * time.Millisecond, ReadTimeout: 200 * time.Millisecond, WriteTimeout: 200 * time.Millisecond, IdleTimeout: 150 * time.Millisecond}
	called := false
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusOK) })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newAdminHTTPServer(h, timeouts)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example\r\n")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(timeouts.ReadHeaderTimeout * 10))
	buf := make([]byte, 4096)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("connection with an unfinished header should have been closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("connection still open after %s", timeouts.ReadHeaderTimeout*10)
	}
	if called {
		t.Error("handler must not run for a request whose headers never complete")
	}
}

// 何もしない keep-alive の TCP 接続は IdleTimeout で切れる。
func TestAdminServerTCPIdleTimeout(t *testing.T) {
	timeouts := adminTimeouts{ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 150 * time.Millisecond}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newAdminHTTPServer(h, timeouts)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: example\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("reading the first response: %v", err)
	}

	start := time.Now()
	conn.SetReadDeadline(start.Add(timeouts.IdleTimeout * 10))
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected the idle connection to be closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("connection still open after %s", timeouts.IdleTimeout*10)
	}
}

// Web UI と JSON の両方の応答に防御的なヘッダが付く。/static/ の応答は埋め込みの静的資産なので
// Cache-Control: no-store を付けない(それ以外には付ける)。
func TestSecurityHeaders(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer(New(st, &fakeBackend{st: st}))
	defer srv.Close()

	for _, path := range []string{"/", "/api/v1/rules"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		h := resp.Header
		if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", path, got)
		}
		if got := h.Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("%s: X-Frame-Options = %q, want DENY", path, got)
		}
		if got := h.Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("%s: Referrer-Policy = %q, want no-referrer", path, got)
		}
		if got := h.Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
			t.Errorf("%s: Content-Security-Policy = %q, want it to restrict default-src to 'self'", path, got)
		}
		if got := h.Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", path, got)
		}
	}

	resp, err := http.Get(srv.URL + "/static/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got == "no-store" {
		t.Error("/static/ responses should not be forced to no-store")
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("/static/: X-Content-Type-Options = %q, want nosniff", got)
	}
}
