package admin

import (
	"reflect"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// TestReservedFromServerInfo pins ReservedFromServerInfo's rule with explicit inputs and exact
// outputs, comparing the full returned map with reflect.DeepEqual rather than only checking for
// the presence of the ports a test cares about. That distinction matters here: a mutation that
// reserves some fixed placeholder port (for example port 0, the zero value a parsed-but-empty
// netip.AddrPort's Port() would return) when AdminAddr fails to parse as host:port can never be
// caught by exercising this behavior through the Web UI's confirm page or the CLI's --dry-run,
// because no valid proto.Rule can ever have a listen_port containing port 0
// (proto.Rule.Validate rejects ListenPort.Lo == 0, and PortRange.Contains(0) is therefore always
// false) -- such a reservation would sit in the map inert, never colliding with anything a real
// upload could contain. Only a test that inspects the map itself, as this one does, can catch it.
//
// This function moved here from cmd/wgft/rule.go (which now only delegates to it), so this is
// also where its rule is pinned; cmd/wgft/ruledryrun_test.go keeps a much smaller test that only
// guards the delegation itself.
func TestReservedFromServerInfo(t *testing.T) {
	cases := []struct {
		name string
		info ServerInfo
		want proto.Reserved
	}{
		{
			name: "unix socket admin_addr reserves no port",
			info: ServerInfo{WGPort: 51820, AdminAddr: "unix:///run/wgft/admin.sock", AgentAPIPort: "9443"},
			want: proto.Reserved{51820: "WireGuard", 9443: "agent API"},
		},
		{
			name: "TCP admin_addr reserves its port",
			info: ServerInfo{WGPort: 51820, AdminAddr: "10.0.0.5:8443", AgentAPIPort: "9443"},
			want: proto.Reserved{51820: "WireGuard", 8443: "admin API", 9443: "agent API"},
		},
		{
			// admin_addr that fails to parse as host:port for a reason other than being a Unix
			// socket (e.g. garbage, or a host with no port) must also reserve nothing for it, not
			// some fixed fallback port such as 0.
			name: "admin_addr that otherwise fails to parse as host:port reserves no port",
			info: ServerInfo{WGPort: 51820, AdminAddr: "not-a-host-port-value", AgentAPIPort: "9443"},
			want: proto.Reserved{51820: "WireGuard", 9443: "agent API"},
		},
		{
			// admin_addr missing a host parses the same way netip.ParseAddrPort does everywhere
			// else in this codebase: it fails, so nothing is reserved. This is not a defect, and
			// is pinned here so a change to this rule is caught by this test.
			name: `admin_addr missing a host (":8443") reserves no port`,
			info: ServerInfo{WGPort: 51820, AdminAddr: ":8443", AgentAPIPort: "9443"},
			want: proto.Reserved{51820: "WireGuard", 9443: "agent API"},
		},
		{
			name: "empty admin_addr reserves no port",
			info: ServerInfo{WGPort: 51820, AdminAddr: "", AgentAPIPort: "9443"},
			want: proto.Reserved{51820: "WireGuard", 9443: "agent API"},
		},
		{
			name: "empty agent_api_port reserves no port",
			info: ServerInfo{WGPort: 51820, AdminAddr: "10.0.0.5:8443", AgentAPIPort: ""},
			want: proto.Reserved{51820: "WireGuard", 8443: "admin API"},
		},
		{
			name: "zero value reserves only WireGuard port 0",
			info: ServerInfo{},
			want: proto.Reserved{0: "WireGuard"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ReservedFromServerInfo(tc.info)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ReservedFromServerInfo(%+v) = %v, want %v", tc.info, got, tc.want)
			}
		})
	}
}
