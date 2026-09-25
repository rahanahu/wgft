package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"strings"
	"testing"
)

// FuzzParseJoin feeds arbitrary strings as the WGFT_JOIN connect string (join.go), the
// wgft://host:port/token#sha256:HASH value an operator copies from the VPS's `wgft agent
// join-string` output into the agent's environment. It is operator-supplied rather than
// attacker-controlled, but it is parsed with url.Parse, net.SplitHostPort and hex.DecodeString in
// sequence, on every agent startup that has not yet registered, so a panic here is a startup
// denial of service, and this is the kind of layered string-splitting logic (host:port inside a
// URL, a hex-encoded pin inside a fragment) that is easy to get subtly wrong at the edges.
//
// The property: ParseJoin never panics, and on success its result is internally consistent --
// Endpoint really is host:port shaped, Token is non-empty and holds no slash (the code path that
// rejects a Path containing an extra "/" must actually have rejected it), Pin is the exact 32
// bytes the connect string's own #sha256:HASH fragment decodes to (recomputed independently of
// ParseJoin), and TokenHash is the actual sha256 of Token, not merely a string of the right shape.
func FuzzParseJoin(f *testing.F) {
	f.Add("wgft://vps.example.com:8443/abcDEF-123#sha256:" + strings.Repeat("ab", 32))
	f.Add("https://vps.example.com:8443/tok#sha256:" + strings.Repeat("ab", 32))
	f.Add("wgft://vps.example.com/tok#sha256:" + strings.Repeat("ab", 32))
	f.Add("wgft://vps.example.com:8443/#sha256:" + strings.Repeat("ab", 32))
	f.Add("wgft://vps.example.com:8443/tok")
	f.Add("wgft://vps.example.com:8443/tok#sha256:zz")
	f.Add("wgft://vps.example.com:8443/tok#md5:" + strings.Repeat("ab", 32))
	f.Add("wgft://vps.example.com:8443/a/b#sha256:" + strings.Repeat("ab", 32))
	f.Add("wgft:///tok#sha256:" + strings.Repeat("ab", 32))
	f.Add("wgft://[::1]:8443/tok#sha256:" + strings.Repeat("ab", 32))
	f.Add("wgft://vps:8443/tok#sha256:" + strings.Repeat("ab", 40)) // pin too long
	f.Add("wgft://vps:8443/tok#sha256:" + strings.Repeat("ab", 16)) // pin too short
	f.Add("")
	f.Add("wgft://")
	f.Add("not a url at all \x00\x01")

	f.Fuzz(func(t *testing.T, s string) {
		j, err := ParseJoin(s)
		if err != nil {
			return
		}
		if _, _, err := net.SplitHostPort(j.Endpoint); err != nil {
			t.Fatalf("ParseJoin(%q).Endpoint = %q, not host:port: %v", s, j.Endpoint, err)
		}
		if j.Token == "" || strings.Contains(j.Token, "/") {
			t.Fatalf("ParseJoin(%q).Token = %q, want non-empty and slash-free", s, j.Token)
		}
		// Pin must be exactly what the connect string's own fragment decodes to, recomputed here
		// independently of ParseJoin, not merely 32 bytes of some value.
		u, uerr := url.Parse(strings.TrimSpace(s))
		if uerr != nil {
			t.Fatalf("ParseJoin(%q) succeeded but url.Parse fails on the same string: %v", s, uerr)
		}
		_, hexPin, _ := strings.Cut(u.Fragment, ":")
		wantPin, herr := hex.DecodeString(hexPin)
		if herr != nil || len(wantPin) != 32 {
			t.Fatalf("ParseJoin(%q) succeeded but its own fragment %q is not a 32-byte hex pin", s, u.Fragment)
		}
		if !bytes.Equal(j.Pin[:], wantPin) {
			t.Fatalf("ParseJoin(%q).Pin = %x, want %x (decoded from fragment %q)", s, j.Pin, wantPin, u.Fragment)
		}
		// TokenHash must be the actual sha256 of Token, not merely a 64-character hex string.
		wantHash := sha256.Sum256([]byte(j.Token))
		if got, want := j.TokenHash(), hex.EncodeToString(wantHash[:]); got != want {
			t.Fatalf("ParseJoin(%q).TokenHash() = %q, want %q (sha256 of Token %q)", s, got, want, j.Token)
		}
	})
}
