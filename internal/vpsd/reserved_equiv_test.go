//go:build linux

package vpsd

import (
	"net"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// reservedPortsOwnRule is reservedPorts as it was before it went through
// admin.ReservedFromServerInfo, kept verbatim so that the tests below can show the two give the
// same set for every input the server can have.
func reservedPortsOwnRule(opts Options) proto.Reserved {
	reserved := proto.Reserved{opts.WGPort: "WireGuard"}
	if ap, err := netip.ParseAddrPort(opts.AdminAddr); err == nil {
		reserved[ap.Port()] = "admin API"
	}
	if _, port, err := net.SplitHostPort(opts.AgentAPIAddr); err == nil {
		if p, err := netip.ParseAddrPort("0.0.0.0:" + port); err == nil {
			reserved[p.Port()] = "agent API"
		}
	}
	return reserved
}

// reservedAddrs are values for AdminAddr and AgentAPIAddr: the defaults, Unix sockets, every
// shape of host:port the parsers treat differently, ports at and past the ends of the range, and
// ports equal to the WireGuard ports below, so that collisions overwrite in the same order.
var reservedAddrs = []string{
	"", "unix:///run/wgft/admin.sock", "unix://", "unix:///x:80", "not-a-host-port-value",
	"0.0.0.0:8443", "127.0.0.1:8686", "10.0.0.5:8443", ":8443", "0.0.0.0:", "0.0.0.0", "0.0.0.0:0",
	"0.0.0.0:1", "0.0.0.0:65535", "0.0.0.0:65536", "0.0.0.0:-1", "0.0.0.0:+80", "0.0.0.0:080",
	"0.0.0.0: 80", "0.0.0.0:0x50", "0.0.0.0:http", "localhost:8443", "vps.example.com:8443",
	"[::1]:8443", "[::]:8443", "[::1]", "::1:8443", "[fe80::1%eth0]:8443", "1.2.3.4:5:6",
	"[::ffff:1.2.3.4]:8443", "0.0.0.0:51820", "127.0.0.1:51820", "0.0.0.0:00000000000000051820",
	"8443", "51820", "https",
}

// wgPorts are WireGuard ports that collide with the ports in reservedAddrs, and the ends of the
// range.
var wgPorts = []uint16{0, 1, 80, 8443, 8686, 51820, 65535}

// TestReservedPortsMatchesTheOwnRule compares reservedPorts with the rule it had before it went
// through admin.ReservedFromServerInfo: every WireGuard port in the uint16 range with the default
// listeners, and every pair of reservedAddrs with each of wgPorts.
func TestReservedPortsMatchesTheOwnRule(t *testing.T) {
	check := func(opts Options) {
		t.Helper()
		if got, want := reservedPorts(opts), reservedPortsOwnRule(opts); !reflect.DeepEqual(got, want) {
			t.Fatalf("reservedPorts(%+v) = %v, the rule before gives %v", opts, got, want)
		}
	}
	for p := 0; p <= 65535; p++ {
		check(Options{WGPort: uint16(p), AdminAddr: "unix:///run/wgft/admin.sock", AgentAPIAddr: "0.0.0.0:8443"})
		check(Options{WGPort: uint16(p), AdminAddr: "127.0.0.1:8686", AgentAPIAddr: "0.0.0.0:8443"})
	}
	for _, wg := range wgPorts {
		for _, adminAddr := range reservedAddrs {
			for _, agent := range reservedAddrs {
				check(Options{WGPort: wg, AdminAddr: adminAddr, AgentAPIAddr: agent})
			}
		}
	}
}

// TestUnsplittableAgentAPIAddrReservesNothing pins the one step where the two rules take different
// paths. When net.SplitHostPort fails, the rule before reserved nothing for the agent API without
// parsing; ReservedFromServerInfo receives an empty AgentAPIPort and parses "0.0.0.0:", which has
// to fail for the two to agree.
func TestUnsplittableAgentAPIAddrReservesNothing(t *testing.T) {
	if ap, err := netip.ParseAddrPort("0.0.0.0:"); err == nil {
		t.Fatalf(`netip.ParseAddrPort("0.0.0.0:") = %v, want an error`, ap)
	}
	if p := agentAPIPort("0.0.0.0"); p != "" {
		t.Fatalf(`agentAPIPort("0.0.0.0") = %q, want empty`, p)
	}
}

// FuzzReservedPortsMatchesTheOwnRule extends TestReservedPortsMatchesTheOwnRule to inputs the
// fuzzer finds.
func FuzzReservedPortsMatchesTheOwnRule(f *testing.F) {
	for _, wg := range wgPorts {
		for _, a := range reservedAddrs {
			f.Add(wg, a, "0.0.0.0:8443")
			f.Add(wg, "unix:///run/wgft/admin.sock", a)
		}
	}
	f.Fuzz(func(t *testing.T, wg uint16, adminAddr, agent string) {
		opts := Options{WGPort: wg, AdminAddr: adminAddr, AgentAPIAddr: agent}
		if got, want := reservedPorts(opts), reservedPortsOwnRule(opts); !reflect.DeepEqual(got, want) {
			t.Fatalf("reservedPorts(%+v) = %v, the rule before gives %v", opts, got, want)
		}
	})
}

// TestServerInfoReservesWhatTheServerReserves checks that the CLI and the Web UI, which build the
// reserved ports from the admin API's ServerInfo, get the same set as Daemon.reserved, and that
// ServerInfo reports the agent API's port as it did before it shared serverPortsInfo.
func TestServerInfoReservesWhatTheServerReserves(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, adminAddr := range reservedAddrs {
		for _, agent := range reservedAddrs {
			opts := Options{WGPort: 51820, AdminAddr: adminAddr, AgentAPIAddr: agent}
			info, err := (&Daemon{opts: opts, st: st}).ServerInfo()
			if err != nil {
				t.Fatal(err)
			}
			if got, want := admin.ReservedFromServerInfo(info), reservedPorts(opts); !reflect.DeepEqual(got, want) {
				t.Fatalf("%+v: ServerInfo reserves %v, the server %v", opts, got, want)
			}
			apiPort := ""
			if _, p, err := net.SplitHostPort(agent); err == nil {
				apiPort = p
			}
			if info.WGPort != 51820 || info.AdminAddr != adminAddr || info.AgentAPIPort != apiPort {
				t.Fatalf("%+v: ServerInfo reports WGPort %d, AdminAddr %q, AgentAPIPort %q", opts, info.WGPort, info.AdminAddr, info.AgentAPIPort)
			}
		}
	}
}
