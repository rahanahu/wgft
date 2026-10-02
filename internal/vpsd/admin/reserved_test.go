package admin

import (
	"reflect"
	"strings"
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
			// A Unix socket path with a colon still listens on the socket, not on a port.
			name: "unix socket admin_addr with a colon in the path reserves no port",
			info: ServerInfo{WGPort: 51820, AdminAddr: "unix:///x:80", AgentAPIPort: "9443"},
			want: proto.Reserved{51820: "WireGuard", 9443: "agent API"},
		},
		{
			name: "TCP admin_addr reserves its port",
			info: ServerInfo{WGPort: 51820, AdminAddr: "10.0.0.5:8443", AgentAPIPort: "9443"},
			want: proto.Reserved{51820: "WireGuard", 8443: "admin API", 9443: "agent API"},
		},
		{
			// admin_addr that fails to split as host:port for a reason other than being a Unix
			// socket (e.g. garbage, or a host with no port) must also reserve nothing for it, not
			// some fixed fallback port such as 0. The server's startup check refuses such a value.
			name: "admin_addr that otherwise fails to split as host:port reserves no port",
			info: ServerInfo{WGPort: 51820, AdminAddr: "not-a-host-port-value", AgentAPIPort: "9443"},
			want: proto.Reserved{51820: "WireGuard", 9443: "agent API"},
		},
		{
			// The listener binds the port whatever the host part is, so the host part does not
			// decide whether the port is reserved.
			name: `admin_addr missing a host (":8443") reserves its port`,
			info: ServerInfo{WGPort: 51820, AdminAddr: ":8443", AgentAPIPort: "9443"},
			want: proto.Reserved{51820: "WireGuard", 8443: "admin API", 9443: "agent API"},
		},
		{
			name: "admin_addr with a host name reserves its port",
			info: ServerInfo{WGPort: 51820, AdminAddr: "localhost:8686", AgentAPIPort: "9443"},
			want: proto.Reserved{51820: "WireGuard", 8686: "admin API", 9443: "agent API"},
		},
		{
			name: "admin_addr with a service name reserves the port it resolves to",
			info: ServerInfo{WGPort: 51820, AdminAddr: "0.0.0.0:https", AgentAPIPort: "9443"},
			want: proto.Reserved{51820: "WireGuard", 443: "admin API", 9443: "agent API"},
		},
		{
			name: "admin_addr with a signed or zero-padded port reserves the number net.Listen binds",
			info: ServerInfo{WGPort: 51820, AdminAddr: "[::1]:+8686", AgentAPIPort: "09443"},
			want: proto.Reserved{51820: "WireGuard", 8686: "admin API", 9443: "agent API"},
		},
		{
			// Port 0 lets the kernel pick a port; no rule can listen on port 0, so nothing is
			// reserved for it rather than an inert entry.
			name: "port 0 reserves nothing",
			info: ServerInfo{WGPort: 51820, AdminAddr: "127.0.0.1:0", AgentAPIPort: "0"},
			want: proto.Reserved{51820: "WireGuard"},
		},
		{
			name: "agent_api_port given as a service name reserves the port it resolves to",
			info: ServerInfo{WGPort: 51820, AdminAddr: "unix:///run/wgft/admin.sock", AgentAPIPort: "https"},
			want: proto.Reserved{51820: "WireGuard", 443: "agent API"},
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
			got, err := ReservedFromServerInfo(tc.info)
			if err != nil {
				t.Fatalf("ReservedFromServerInfo(%+v): %v", tc.info, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ReservedFromServerInfo(%+v) = %v, want %v", tc.info, got, tc.want)
			}
		})
	}
}

// TestReservedFromServerInfoUnresolvedPort pins what happens when a port given by name does not
// resolve: an error that names the listener, never a set that silently leaves that port out. A
// caller that went on with such a set would report a rule on that port as acceptable.
func TestReservedFromServerInfoUnresolvedPort(t *testing.T) {
	const name = "no-such-service-wgft"
	for _, tc := range []struct {
		info     ServerInfo
		listener string
	}{
		{ServerInfo{WGPort: 51820, AdminAddr: "127.0.0.1:" + name, AgentAPIPort: "9443"}, "admin API"},
		{ServerInfo{WGPort: 51820, AdminAddr: "unix:///run/wgft/admin.sock", AgentAPIPort: name}, "agent API"},
		{ServerInfo{WGPort: 51820, AdminAddr: "127.0.0.1:65536", AgentAPIPort: "9443"}, "admin API"},
	} {
		got, err := ReservedFromServerInfo(tc.info)
		if err == nil {
			t.Errorf("ReservedFromServerInfo(%+v) = %v, want an error", tc.info, got)
			continue
		}
		if got != nil {
			t.Errorf("ReservedFromServerInfo(%+v) returned %v with its error, want nil", tc.info, got)
		}
		if !strings.Contains(err.Error(), tc.listener) {
			t.Errorf("ReservedFromServerInfo(%+v) error %q does not name the %s", tc.info, err, tc.listener)
		}
	}
}
