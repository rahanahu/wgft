//go:build linux

package vpsd

import (
	"reflect"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// TestReservedPorts pins reservedPorts's rule with explicit inputs and outputs: this is the
// authoritative construction of Daemon.reserved (Options -> proto.Reserved), which
// internal/vpsd/admin.ReservedFromServerInfo mirrors from admin.ServerInfo for the CLI's
// `rule add`/`rule set --dry-run` and the Web UI's read-import confirmation. Before this test
// existed, nothing in the repository exercised this construction: a mutation dropping the admin
// API's reservation, for example, left `go test ./...` green everywhere. Guarding the real
// construction (as opposed to only a copy of it, the way admin's own tests necessarily do) is
// what lets the CLI's and Web UI's promise to match the real Daemon.Batch mean something: if this
// rule drifts, this test -- not a downstream copy -- is what has to notice.
func TestReservedPorts(t *testing.T) {
	cases := []struct {
		name string
		opts Options
		want proto.Reserved
	}{
		{
			name: "WireGuard port is always reserved",
			opts: Options{WGPort: 51820},
			want: proto.Reserved{51820: "WireGuard"},
		},
		{
			name: "admin API is reserved when AdminAddr parses as host:port",
			opts: Options{WGPort: 51821, AdminAddr: "127.0.0.1:8686"},
			want: proto.Reserved{51821: "WireGuard", 8686: "admin API"},
		},
		{
			name: "admin API is not reserved when AdminAddr is a Unix socket path",
			opts: Options{WGPort: 51821, AdminAddr: "unix:///run/wgft/admin.sock"},
			want: proto.Reserved{51821: "WireGuard"},
		},
		{
			name: "admin API is not reserved, and no fallback port is reserved, when AdminAddr does not parse as host:port for some other reason",
			opts: Options{WGPort: 51821, AdminAddr: "not-a-host-port-value"},
			want: proto.Reserved{51821: "WireGuard"},
		},
		{
			name: "admin API is not reserved when AdminAddr is empty (unset)",
			opts: Options{WGPort: 51821, AdminAddr: ""},
			want: proto.Reserved{51821: "WireGuard"},
		},
		{
			name: "agent API is reserved from AgentAPIAddr's port",
			opts: Options{WGPort: 51821, AgentAPIAddr: "0.0.0.0:8443"},
			want: proto.Reserved{51821: "WireGuard", 8443: "agent API"},
		},
		{
			name: "agent API is not reserved when AgentAPIAddr is empty (unset)",
			opts: Options{WGPort: 51821, AgentAPIAddr: ""},
			want: proto.Reserved{51821: "WireGuard"},
		},
		{
			name: "agent API is not reserved when AgentAPIAddr has no port",
			opts: Options{WGPort: 51821, AgentAPIAddr: "0.0.0.0"},
			want: proto.Reserved{51821: "WireGuard"},
		},
		{
			name: "all three reserved together, distinct ports",
			opts: Options{WGPort: 51820, AdminAddr: "127.0.0.1:8686", AgentAPIAddr: "0.0.0.0:8443"},
			want: proto.Reserved{51820: "WireGuard", 8686: "admin API", 8443: "agent API"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reservedPorts(tc.opts); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("reservedPorts(%+v) = %v, want %v", tc.opts, got, tc.want)
			}
		})
	}
}
