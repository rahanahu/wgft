//go:build linux

package vpsd

import (
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/enroll"
)

// TestJoinHost pins how the join string's host:port is chosen (design.md 11b 節): the
// WGFT_AGENT_API_HOST value as given, or else the WGFT_WG_ENDPOINT host with the port the agent
// API listener binds, written as decimal digits even when the listen address names the port, so
// that the agent's ParseJoin accepts the join string.
func TestJoinHost(t *testing.T) {
	const pin = "#sha256:abababababababababababababababababababababababababababababababab"
	for _, tc := range []struct {
		apiHost, endpoint, apiAddr string
		want                       string
	}{
		{"join.example.com:9443", "vps.example.com:51820", "0.0.0.0:8443", "join.example.com:9443"},
		{"", "vps.example.com:51820", "0.0.0.0:8443", "vps.example.com:8443"},
		{"", "vps.example.com:51820", ":https", "vps.example.com:443"},
		{"", "vps.example.com:51820", "0.0.0.0:+8443", "vps.example.com:8443"},
		{"", "vps.example.com:51820", "localhost:08443", "vps.example.com:8443"},
		{"", "[2001:db8::1]:51820", "[::]:8443", "[2001:db8::1]:8443"},
	} {
		got, err := joinHost(tc.apiHost, tc.endpoint, tc.apiAddr)
		if err != nil || got != tc.want {
			t.Errorf("joinHost(%q, %q, %q) = %q, %v; want %q", tc.apiHost, tc.endpoint, tc.apiAddr, got, err, tc.want)
			continue
		}
		if _, err := enroll.ParseJoin("wgft://" + got + "/tok" + pin); err != nil {
			t.Errorf("the agent refuses a join string for %q: %v", got, err)
		}
	}
	for _, tc := range []struct {
		endpoint, apiAddr, inErr string
	}{
		{"", "0.0.0.0:8443", "--wg-endpoint"},
		{":51820", "0.0.0.0:8443", "--wg-endpoint"},
		{"vps.example.com:51820", "0.0.0.0:no-such-service-wgft", "--agent-api-host"},
		{"vps.example.com:51820", "0.0.0.0:0", "kernel pick"},
	} {
		got, err := joinHost("", tc.endpoint, tc.apiAddr)
		if err == nil || !strings.Contains(err.Error(), tc.inErr) {
			t.Errorf("joinHost(\"\", %q, %q) = %q, %v; want an error mentioning %q", tc.endpoint, tc.apiAddr, got, err, tc.inErr)
		}
	}
}
