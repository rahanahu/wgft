//go:build linux

package vpsd

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// TestReservedPorts pins reservedPorts's rule with explicit inputs and outputs: this is the
// construction of Daemon.reserved (Options -> proto.Reserved), which goes through
// internal/vpsd/admin.ReservedFromServerInfo, the function the CLI's `rule add`/`rule set
// --dry-run` and the Web UI's read-import confirmation call on admin.ServerInfo. Before this test
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
			name: "admin API given with a host name is reserved",
			opts: Options{WGPort: 51821, AdminAddr: "localhost:8686"},
			want: proto.Reserved{51821: "WireGuard", 8686: "admin API"},
		},
		{
			name: "admin API given with no host is reserved",
			opts: Options{WGPort: 51821, AdminAddr: ":8686"},
			want: proto.Reserved{51821: "WireGuard", 8686: "admin API"},
		},
		{
			name: "admin API given with a service name reserves the port it resolves to",
			opts: Options{WGPort: 51821, AdminAddr: "0.0.0.0:https"},
			want: proto.Reserved{51821: "WireGuard", 443: "admin API"},
		},
		{
			name: "agent API given with a service name reserves the port it resolves to",
			opts: Options{WGPort: 51821, AgentAPIAddr: "vps.example.com:https"},
			want: proto.Reserved{51821: "WireGuard", 443: "agent API"},
		},
		{
			name: "all three reserved together, distinct ports",
			opts: Options{WGPort: 51820, AdminAddr: "127.0.0.1:8686", AgentAPIAddr: "0.0.0.0:8443"},
			want: proto.Reserved{51820: "WireGuard", 8686: "admin API", 8443: "agent API"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := reservedPorts(tc.opts)
			if err != nil {
				t.Fatalf("reservedPorts(%+v): %v", tc.opts, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("reservedPorts(%+v) = %v, want %v", tc.opts, got, tc.want)
			}
		})
	}
}

// TestReservedPortsUnresolvedPort pins that a port the listener could not resolve is an error,
// which Run returns before it opens anything, instead of a set that leaves that port out.
func TestReservedPortsUnresolvedPort(t *testing.T) {
	for _, opts := range []Options{
		{WGPort: 51821, AdminAddr: "127.0.0.1:no-such-service-wgft", AgentAPIAddr: "0.0.0.0:8443"},
		{WGPort: 51821, AdminAddr: "unix:///run/wgft/admin.sock", AgentAPIAddr: "0.0.0.0:no-such-service-wgft"},
	} {
		if got, err := reservedPorts(opts); err == nil {
			t.Errorf("reservedPorts(%+v) = %v, want an error", opts, got)
		}
	}
}

// TestStoredRuleOnNewlyReservedPort pins the effect on a rule saved before the API ports given by
// host name or service name were reserved (design.md 5.4 節、11a 節): the reserved-port check runs
// on unchanged rows too, so a batch that keeps such a rule is refused, while a batch that moves
// it off the port or deletes it passes.
func TestStoredRuleOnNewlyReservedPort(t *testing.T) {
	reserved, err := reservedPorts(Options{WGPort: 51820, AdminAddr: "unix:///run/wgft/admin.sock", AgentAPIAddr: "0.0.0.0:https"})
	if err != nil {
		t.Fatal(err)
	}
	old := proto.Rule{ID: "r_old", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 443, Hi: 443},
		Target: "192.168.1.20:443", VPSMode: proto.ModeKernel, Enabled: true}
	other := proto.Rule{ID: "r_other", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2456},
		Target: "192.168.1.20:2456", VPSMode: proto.ModeKernel, Enabled: true}
	before := []proto.Rule{old}
	if err := proto.ValidateRules(before, nil); err != nil {
		t.Fatalf("the stored rule must have been valid without the reservation: %v", err)
	}
	err = proto.ValidateUpsert([]proto.Rule{old, other}, before, reserved)
	if err == nil || !strings.Contains(err.Error(), "agent API port 443") {
		t.Errorf("a batch that keeps the stored rule on the reserved port must be refused for it, got %v", err)
	}
	moved := old
	moved.ListenPort = proto.PortRange{Lo: 4443, Hi: 4443}
	if err := proto.ValidateUpsert([]proto.Rule{moved, other}, before, reserved); err != nil {
		t.Errorf("a batch that moves the stored rule off the reserved port must pass: %v", err)
	}
	if err := proto.ValidateUpsert([]proto.Rule{other}, before, reserved); err != nil {
		t.Errorf("a batch that deletes the stored rule must pass: %v", err)
	}
}
