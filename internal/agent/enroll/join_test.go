package enroll

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseJoin(t *testing.T) {
	good := "wgft://vps.example.com:8443/abcDEF-123#sha256:" + strings.Repeat("ab", 32)
	j, err := ParseJoin(good)
	if err != nil || j.Endpoint != "vps.example.com:8443" || j.Token != "abcDEF-123" || j.Pin[0] != 0xab {
		t.Fatalf("%+v %v", j, err)
	}
	if h := j.TokenHash(); len(h) != 64 {
		t.Errorf("hash %q", h)
	}
	for _, bad := range []string{
		"https://vps.example.com:8443/tok#sha256:" + strings.Repeat("ab", 32),
		"wgft://vps.example.com/tok#sha256:" + strings.Repeat("ab", 32),
		"wgft://vps.example.com:8443/#sha256:" + strings.Repeat("ab", 32),
		"wgft://vps.example.com:8443/tok",
		"wgft://vps.example.com:8443/tok#sha256:zz",
		"wgft://vps.example.com:8443/tok#md5:" + strings.Repeat("ab", 32),
		"wgft://vps.example.com:/tok#sha256:" + strings.Repeat("ab", 32),
		"wgft://vps.example.com:0/tok#sha256:" + strings.Repeat("ab", 32),
		"wgft://vps.example.com:70000/tok#sha256:" + strings.Repeat("ab", 32),
		"",
	} {
		if _, err := ParseJoin(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

// TestParseJoinNeverEchoesTheToken guards against the join token reaching a log through
// ParseJoin's own error text. When a join string has no port and no path, url.Parse puts the
// whole string into u.Host, so an error that quotes u.Host quotes the token
// (scripts/check-log-tokens.sh forbids a token value in tool output). This must hold for every
// rejection path, not only the missing-port one, because a caller logs whichever error comes
// back (cmd/wgft/agent.go's "WGFT_JOIN is malformed" warning), and a malformed or truncated join
// string can put the token where any of the other fields are expected too, for example by
// dropping the "/" before it. Each case below puts the token where u.Host ends up, then drives a
// different rejection path (no-port, port-range, no-token, no-#sha256, bad-hash) past it. Two
// checks per case: the token substring must be absent from the error text, and the error must be
// one of ParseJoin's fixed messages (parseJoinErrors), so a rewrite that reintroduces a %q or %s
// of the input is caught even for a token that happens not to collide with this test's literal.
func TestParseJoinNeverEchoesTheToken(t *testing.T) {
	const token = "sekritjointoken1234567890"
	pin := "sha256:" + strings.Repeat("ab", 32)
	for _, bad := range []string{
		"wgft://" + token,                       // no port, no path: the no-port path
		"wgft://" + token + "#" + pin,           // same, with a fragment attached
		"wgft://" + token + ":8443",             // token as host, no path: the no-token path
		"wgft://" + token + ":0#" + pin,         // token as host, port 0: the port-range path
		"wgft://" + token + ":8443/x",           // token as host, no fragment: the no-#sha256 path
		"wgft://" + token + ":8443/x#sha256:zz", // token as host, bad hex: the bad-hash path
	} {
		_, err := ParseJoin(bad)
		if err == nil {
			t.Fatalf("%q should be rejected", bad)
		}
		if strings.Contains(err.Error(), token) {
			t.Errorf("ParseJoin(%q) error %q echoes the token", bad, err.Error())
		}
		known := false
		for _, want := range parseJoinErrors {
			if errors.Is(err, want) {
				known = true
				break
			}
		}
		if !known {
			t.Errorf("ParseJoin(%q) error %q is not one of ParseJoin's fixed messages", bad, err.Error())
		}
	}
}

// TestParseJoinRejectsBadPorts covers the port values a malformed or truncated join string
// could carry: no digits at all, zero, and a value past the 16-bit port range. Of these, only the
// empty port ("", from "host:") and the two in-range-shaped-but-invalid values (0, 70000) used to
// be accepted, because net.SplitHostPort only requires a port field to be present, not that it be
// a usable TCP port. "-1" and "not-a-port" were always rejected already, one level up, by
// url.Parse's own port syntax check (it requires the text after the last ":" to be all decimal
// digits), so ParseJoin never saw them; they stay in this list as a regression guard on that
// syntax check's shape, not as cases this change newly rejects.
func TestParseJoinRejectsBadPorts(t *testing.T) {
	pin := "#sha256:" + strings.Repeat("ab", 32)
	for _, port := range []string{"", "0", "70000", "-1", "not-a-port"} {
		bad := "wgft://vps.example.com:" + port + "/tok" + pin
		if _, err := ParseJoin(bad); err == nil {
			t.Errorf("port %q should be rejected", port)
		}
	}
	good := "wgft://vps.example.com:1/tok" + pin
	if _, err := ParseJoin(good); err != nil {
		t.Errorf("port 1 should be accepted: %v", err)
	}
	good = "wgft://vps.example.com:65535/tok" + pin
	if _, err := ParseJoin(good); err != nil {
		t.Errorf("port 65535 should be accepted: %v", err)
	}
}

// 登録が 409 で拒まれた場合の文面は、revoke を案内する前に、その名前で動いているエージェントを
// 指すよう述べる。別のデータディレクトリで動いているエージェントを見落として revoke すると、
// 動いているエージェントを切るためである(設計文書 10.2c 節)。
func TestRegisterConflictPointsAtTheRunningAgentFirst(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "agent already registered", http.StatusConflict)
	}))
	defer srv.Close()
	j := &Join{Endpoint: strings.TrimPrefix(srv.URL, "https://"), Token: "t", Pin: sha256.Sum256(srv.Certificate().Raw)}
	_, _, _, err := Register(context.Background(), j, "home")
	if err == nil {
		t.Fatal("a 409 registered")
	}
	msg := err.Error()
	point, revoke := strings.Index(msg, "point WGFT_DATA_DIR at its directory"), strings.Index(msg, "wgft agent revoke")
	if point < 0 || revoke < 0 || point > revoke {
		t.Errorf("the refusal does not point at the running agent before the revoke: %s", msg)
	}
}
