package agentapi

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// fakeBackend は Backend の単純な実装(仕様 5.1 節の register ハンドラの動作だけを確かめる)。
// name が空ならトークンに紐付いた名前(boundName)で、name があれば一致するときだけ登録が通る。
type fakeBackend struct {
	boundName string
	addr      netip.Addr
}

func (b *fakeBackend) Register(joinToken, name, from string) (string, string, netip.Addr, error) {
	if joinToken != "tok" {
		return "", "", netip.Addr{}, store.ErrInvalidToken
	}
	if name != "" && name != b.boundName {
		return "", "", netip.Addr{}, store.ErrInvalidToken
	}
	return "permanent-token", b.boundName, b.addr, nil
}

func newTestServer(t *testing.T, backend Backend) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "wgft.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s, err := New(st, backend)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(s)
}

func doRegister(t *testing.T, srv *httptest.Server, token, name string) (status int, body []byte) {
	t.Helper()
	req := map[string]string{"token": token}
	if name != "" {
		req["name"] = name
	}
	b, _ := json.Marshal(req)
	resp, err := http.Post(srv.URL+"/api/v1/agents/register", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// 名前を送らない登録は成功し、応答にトークンに紐付いた名前が入る。
func TestRegisterNameOptional(t *testing.T) {
	backend := &fakeBackend{boundName: "home", addr: netip.MustParseAddr("10.200.0.2")}
	srv := newTestServer(t, backend)
	defer srv.Close()

	status, body := doRegister(t, srv, "tok", "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, body)
	}
	var res RegisterResponse
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	if res.Name != "home" || res.PermanentToken == "" || res.Address != "10.200.0.2" {
		t.Errorf("response = %+v", res)
	}
}

// 名前が違えば拒否され、応答は未知のトークンと見分けがつかない(理由を漏らさない)。
func TestRegisterNameMismatchSameAsUnknownToken(t *testing.T) {
	backend := &fakeBackend{boundName: "home", addr: netip.MustParseAddr("10.200.0.2")}
	srv := newTestServer(t, backend)
	defer srv.Close()

	mismatchStatus, mismatchBody := doRegister(t, srv, "tok", "office")
	unknownStatus, unknownBody := doRegister(t, srv, "nope", "home")

	if mismatchStatus != http.StatusUnauthorized {
		t.Fatalf("mismatch status = %d, body = %s", mismatchStatus, mismatchBody)
	}
	if unknownStatus != http.StatusUnauthorized {
		t.Fatalf("unknown token status = %d, body = %s", unknownStatus, unknownBody)
	}
	if !bytes.Equal(mismatchBody, unknownBody) {
		t.Errorf("bodies differ: mismatch=%q unknown=%q", mismatchBody, unknownBody)
	}
}

// 一致する名前を送ってもよい(確認の用途)。
func TestRegisterNameMatches(t *testing.T) {
	backend := &fakeBackend{boundName: "home", addr: netip.MustParseAddr("10.200.0.2")}
	srv := newTestServer(t, backend)
	defer srv.Close()

	status, body := doRegister(t, srv, "tok", "home")
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, body)
	}
}

// testTimeouts は本番より大幅に短い期限(テストを速くするため)。
func testTimeouts() serverTimeouts {
	return serverTimeouts{
		ReadHeaderTimeout: 100 * time.Millisecond,
		ReadTimeout:       200 * time.Millisecond,
		IdleTimeout:       150 * time.Millisecond,
		MaxHeaderBytes:    1 << 20,
	}
}

// startTestServer は TLS なしの生の TCP で待ち受ける(期限の検査に TLS ハンドシェイクは要らない)。
func startTestServer(t *testing.T, h http.Handler, timeouts serverTimeouts) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newHTTPServer("", h, nil, timeouts)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// expectClosedWithin は、budget 以内に接続がサーバ側から閉じられる(読みがエラーになる)ことを確かめる。
// 届いた応答バイトは読み捨てる。
func expectClosedWithin(t *testing.T, conn net.Conn, budget time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	conn.SetReadDeadline(start.Add(budget))
	buf := make([]byte, 4096)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatalf("connection still open after %s", budget)
			}
			return time.Since(start)
		}
	}
}

// (a) ヘッダだけ送って止まる接続は ReadHeaderTimeout で切れる。
func TestServerTimeouts_HeaderStall(t *testing.T) {
	timeouts := testTimeouts()
	called := false
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusOK) })
	addr := startTestServer(t, h, timeouts)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// ヘッダの途中まで送って止まる(終端の空行を送らない)
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example\r\n")); err != nil {
		t.Fatal(err)
	}
	expectClosedWithin(t, conn, timeouts.ReadHeaderTimeout*10)
	if called {
		t.Error("handler must not run for a request whose headers never complete")
	}
}

// (b) 本文を途中で止める接続は ReadTimeout で切れる。
func TestServerTimeouts_BodyStall(t *testing.T) {
	timeouts := testTimeouts()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	addr := startTestServer(t, h, timeouts)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := "POST / HTTP/1.1\r\nHost: example\r\nContent-Length: 100\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	// 本文の一部だけ送って止まる
	if _, err := conn.Write([]byte("only ten b")); err != nil {
		t.Fatal(err)
	}
	expectClosedWithin(t, conn, timeouts.ReadTimeout*10)
}

// (c) 何もしない keep-alive 接続は IdleTimeout で切れる。
func TestServerTimeouts_IdleKeepAlive(t *testing.T) {
	timeouts := testTimeouts()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })

	// startTestServer は使わず、ここだけ ConnState を差し込めるように組み立てる。net/http は
	// (HTTP/1.x で) 1 リクエストへの応答を終えると ConnState を StateIdle で呼んでから
	// SetReadDeadline で idle タイマを仕掛ける。つまり StateIdle の通知時刻は、サーバ側の
	// idle タイマの起点と同時かそれより前になる。ここを起点に経過を測れば、その値は接続が
	// 実際に idle のまま待たされた時間そのものになり、応答の生成にかかった時間を含めて
	// 下限を水増ししない。リクエストを送る前に起点を取る旧方式は、その水増し分だけ
	// IdleTimeout を早く切っても見逃してしまう。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newHTTPServer("", h, nil, timeouts)
	idleAt := make(chan time.Time, 1)
	srv.ConnState = func(_ net.Conn, state http.ConnState) {
		if state != http.StateIdle {
			return
		}
		select {
		case idleAt <- time.Now():
		default: // この接続で 2 回目以降の StateIdle、または既に受信済み: 最初の 1 回だけを使う
		}
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	addr := ln.Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: example\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	var start time.Time
	select {
	case start = <-idleAt:
	case <-time.After(timeouts.IdleTimeout * 10):
		t.Fatal("connection never reached http.StateIdle")
	}

	// リクエストを完了させたあと、何も送らずに待つ
	conn.SetReadDeadline(start.Add(timeouts.IdleTimeout * 10))
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected the idle connection to be closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("connection still open after %s", timeouts.IdleTimeout*10)
	}
	if elapsed := time.Since(start); elapsed < timeouts.IdleTimeout {
		t.Errorf("closed after %s, want at least IdleTimeout %s", elapsed, timeouts.IdleTimeout)
	}
}

// (d) 同時接続数が上限に達すると、新しい接続は accept を待つだけで、既存の接続(stream 役)は
// 切れない。上限に空きができれば、待っていた接続がそのまま処理される。
// started はチャネルではなく atomic なカウンタで数える。バッファ付きチャネルだと、上限が
// 効いていない場合でも n+1 番目の send がチャネルの容量で偶然ブロックし、限定が効いているのと
// 見分けが付かなくなる(実際に一度そのバグを作り込んで確かめた)ため
func TestServerConnLimit(t *testing.T) {
	const n = 2
	var started atomic.Int32
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started.Add(1)
		<-release // stream のような長命の接続に見立てて、応答せずに居座る
		fmt.Fprint(w, "ok")
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	longTimeouts := serverTimeouts{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 1 << 20}
	srv := newHTTPServer("", h, nil, longTimeouts)
	go srv.Serve(limitListener(ln, n))
	t.Cleanup(func() { srv.Close() })
	addr := ln.Addr().String()

	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
		if _, err := fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
	}
	waitForCount(t, &started, n, 2*time.Second)

	// 上限ちょうどで動いている状態で、もう 1 本繋ぐと accept されず応答が来ない
	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	if _, err := fmt.Fprint(extra, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	extra.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 16)
	if _, err := extra.Read(buf); err == nil {
		t.Fatal("connection beyond the limit got a response before any slot freed up")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("unexpected error waiting on the extra connection: %v", err)
	}
	if got := started.Load(); got != n {
		t.Fatalf("handler ran %d times while waiting for a slot, want exactly the limit (%d); the extra connection was accepted early", got, n)
	}

	// release を閉じて、これから accept される extra の handler も進めるようにしておく。
	// held[1] の handler もこれで進むが、その接続はまだ開いたままなので枠は空かない
	close(release)
	// held[0] をクライアント側から閉じて枠を 1 つ空ける
	held[0].Close()

	extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := extra.Read(buf); err != nil {
		t.Fatalf("expected the extra connection to be served once a slot freed up: %v", err)
	}
	waitForCount(t, &started, n+1, 2*time.Second)
}

// waitForCount は c が want に達するまで待つ(上限。ポーリング)。
func waitForCount(t *testing.T, c *atomic.Int32, want int32, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if c.Load() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("handler count = %d after %s, want at least %d", c.Load(), budget, want)
}

// --- 登録の名前検証と失敗応答の一様性 ---

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// countingBackend は backend.Register が呼ばれた回数を数える(名前検証がハンドラ側で
// 止めていることの確認用)。
type countingBackend struct{ calls int }

func (b *countingBackend) Register(joinToken, name, from string) (string, string, netip.Addr, error) {
	b.calls++
	return "", "", netip.Addr{}, store.ErrInvalidToken
}

func doRegisterRaw(t *testing.T, base, token, name string) (*http.Response, []byte) {
	t.Helper()
	body, err := json.Marshal(RegisterRequest{Token: token, Name: name})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(base+"/api/v1/agents/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

// (d) 改行・空白・大文字・33 文字以上(仕様 5.1 節の正規表現の上限は 32 文字)の名前は、
// backend に届く前に拒否される。空の名前は任意なので通る。
func TestRegisterRejectsInvalidNames(t *testing.T) {
	backend := &countingBackend{}
	s, err := New(newTestStore(t), backend)
	if err != nil {
		t.Fatal(err)
	}
	s.limiter = newIPLimiter(1000, 1000) // レート制限をテストの邪魔にしない
	srv := httptestServer(t, s)

	bad := []string{
		"Home",                  // 大文字
		"has space",             // 空白
		"new\nline",             // 改行
		strings.Repeat("a", 33), // 32 文字を超える
	}
	for _, name := range bad {
		resp, body := doRegisterRaw(t, srv, "some-token", name)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("name %q: status = %d, want %d (body %q)", name, resp.StatusCode, http.StatusBadRequest, body)
		}
	}
	if backend.calls != 0 {
		t.Errorf("backend.Register must not be called for invalid names, got %d calls", backend.calls)
	}
}

// (e) 登録失敗の応答は、理由(トークン不明・期限切れ・使用済み・名前不一致)によらず同一。
func TestRegisterUniformFailureResponse(t *testing.T) {
	st := newTestStore(t)
	network := netip.MustParsePrefix("10.200.0.0/24")
	backend := &storeRegisterAdapter{st: st, network: network}
	s, err := New(st, backend)
	if err != nil {
		t.Fatal(err)
	}
	s.limiter = newIPLimiter(1000, 1000)
	srv := httptestServer(t, s)

	validTok, err := st.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	expiredTok, err := st.IssueJoinToken("gone", -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	usedTok, err := st.IssueJoinToken("used", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Register(usedTok, "used", "203.0.113.1", network); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		reason   string
		token    string
		sendName string
	}{
		{"unknown token", "does-not-exist-at-all", "home"},
		{"expired", expiredTok, "gone"},
		{"already used", usedTok, "used"},
		{"name mismatch", validTok, "office"},
	}
	var wantStatus int
	var wantBody []byte
	for i, c := range cases {
		resp, body := doRegisterRaw(t, srv, c.token, c.sendName)
		if i == 0 {
			wantStatus, wantBody = resp.StatusCode, body
			if wantStatus != http.StatusUnauthorized {
				t.Fatalf("%s: status = %d, want %d", c.reason, wantStatus, http.StatusUnauthorized)
			}
			continue
		}
		if resp.StatusCode != wantStatus || !bytes.Equal(body, wantBody) {
			t.Errorf("%s: response = (%d, %q), want (%d, %q) [same as %q]", c.reason, resp.StatusCode, body, wantStatus, wantBody, cases[0].reason)
		}
	}
}

// alreadyRegisteredBackend は Backend の単純な実装。トークンは有効だが、紐付いた名前の
// エージェントがすでにいる場合を模す(store.ErrAgentAlreadyRegistered)。
type alreadyRegisteredBackend struct{}

func (alreadyRegisteredBackend) Register(joinToken, name, from string) (string, string, netip.Addr, error) {
	return "", "", netip.Addr{}, store.ErrAgentAlreadyRegistered
}

// (f) トークンは有効だが、紐付いた名前のエージェントがすでにいる場合は 409 を返し、500 にしない。
// store.Register 自体がこの誤りを返すこと(PRIMARY KEY 違反にならないこと)は
// store パッケージの TestRegisterAgentAlreadyRegistered で確かめている。ここでは
// ハンドラがその誤りを一様な 401 応答に丸めず、専用の 409 に変換することを確かめる。
func TestRegisterAlreadyRegisteredNameReturnsConflict(t *testing.T) {
	s, err := New(newTestStore(t), alreadyRegisteredBackend{})
	if err != nil {
		t.Fatal(err)
	}
	s.limiter = newIPLimiter(1000, 1000)
	srv := httptestServer(t, s)

	resp, body := doRegisterRaw(t, srv, "some-token", "home")
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, body = %s, want %d", resp.StatusCode, body, http.StatusConflict)
	}
}

// storeRegisterAdapter は *store.Store を agentapi.Backend の形に合わせる(テスト用)。
type storeRegisterAdapter struct {
	st      *store.Store
	network netip.Prefix
}

func (a *storeRegisterAdapter) Register(joinToken, name, from string) (string, string, netip.Addr, error) {
	tok, agent, err := a.st.Register(joinToken, name, from, a.network)
	if err != nil {
		return "", "", netip.Addr{}, err
	}
	return tok, agent.Name, agent.Address, nil
}

// httptestServer は s を http.Handler として生の HTTP で待ち受ける(TLS なし)。
func httptestServer(t *testing.T, s *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: s}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "http://" + ln.Addr().String()
}

// h2 を申し出るクライアントに対しても、サーバは ALPN で h2 を選ばない。
func TestHTTPServerDoesNotNegotiateHTTP2(t *testing.T) {
	certSrc := httptest.NewTLSServer(nil)
	cert := certSrc.TLS.Certificates[0]
	certSrc.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newHTTPServer("", http.NotFoundHandler(), &tls.Config{Certificates: []tls.Certificate{cert}}, defaultTimeouts)
	go srv.ServeTLS(ln, "", "")
	defer srv.Close()
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got == "h2" {
		t.Fatalf("negotiated %q, want http/1.1", got)
	}
}
