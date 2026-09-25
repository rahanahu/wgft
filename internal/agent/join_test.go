package agent

import (
	"context"
	"crypto/sha256"
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
		"",
	} {
		if _, err := ParseJoin(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
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
