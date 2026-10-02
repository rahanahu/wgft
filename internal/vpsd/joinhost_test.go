//go:build linux

package vpsd

import (
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/enroll"
	"github.com/rahanahu/wgft/internal/vpsd/store"
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
	// The listener looks the port up as TCP, so the join string must too: a name known only for
	// TCP (Go's built-in table has "submissions") gives the TCP number. Left out on a host whose
	// services database also lists it for UDP.
	if p, err := net.LookupPort("tcp", "submissions"); err == nil {
		if _, err := net.LookupPort("udp", "submissions"); err != nil {
			want := net.JoinHostPort("vps.example.com", strconv.Itoa(p))
			if got, err := joinHost("", "vps.example.com:51820", "0.0.0.0:submissions"); err != nil || got != want {
				t.Errorf("joinHost with a TCP-only service name = %q, %v; want %q", got, err, want)
			}
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

// TestDeliveredEndpointIsTheServerInfoEndpoint checks that the endpoint delivered to agents in
// the state and the admin API's wg_endpoint are the same value, Options.WGEndpoint, which
// cmd/wgft's buildServerOptions has already normalized (design.md 11b 節). Neither path reads the
// setting again or rewrites the host.
func TestDeliveredEndpointIsTheServerInfoEndpoint(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const endpoint = "vps.example.com:51820"
	d := &Daemon{opts: Options{WGEndpoint: endpoint}, st: st, network: netip.MustParsePrefix("10.200.0.0/24")}
	info, err := d.ServerInfo()
	if err != nil {
		t.Fatal(err)
	}
	snap := d.deliveryCandidate(nil, []store.Agent{{Name: "home", Address: netip.MustParseAddr("10.200.0.2")}}, 1)
	got := snap.entries["home"].state.WG.Endpoint
	if got != endpoint || info.WGEndpoint != endpoint {
		t.Errorf("delivered endpoint %q, admin API wg_endpoint %q; want both %q", got, info.WGEndpoint, endpoint)
	}
}
