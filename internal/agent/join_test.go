package agent

import (
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
