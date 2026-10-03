//go:build linux

package vpsd

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// reservedPortsByListener is the set reservedPorts must give, found independently of it: the
// ports the two listeners bind for opts. internal/vpsd/admin.Listen serves a "unix://" value on a
// Unix socket and passes anything else to net.Listen("tcp", addr), as agentapi.Server.Listen does
// for the agent API. net.ResolveTCPAddr finds the port the same way net.Listen does; the host is
// fixed to 127.0.0.1 so that no name is looked up, since the host part does not change the port.
// Port 0 lets the kernel pick one, so it reserves nothing. A value that does not split as
// host:port reserves nothing; the startup check refuses such values before reservedPorts runs.
// ok is false when a port does not resolve, where reservedPorts must return an error.
func reservedPortsByListener(opts Options) (reserved proto.Reserved, ok bool) {
	reserved = proto.Reserved{opts.WGPort: "WireGuard"}
	bound := func(addr string) (uint16, bool) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return 0, true
		}
		a, err := net.ResolveTCPAddr("tcp", net.JoinHostPort("127.0.0.1", port))
		if err != nil {
			return 0, false
		}
		return uint16(a.Port), true
	}
	if !strings.HasPrefix(opts.AdminAddr, "unix://") {
		p, ok := bound(opts.AdminAddr)
		if !ok {
			return nil, false
		}
		if p != 0 {
			reserved[p] = "admin API"
		}
	}
	p, ok := bound(opts.AgentAPIAddr)
	if !ok {
		return nil, false
	}
	if p != 0 {
		reserved[p] = "agent API"
	}
	return reserved, true
}

// checkReservedPorts compares reservedPorts with reservedPortsByListener for opts.
func checkReservedPorts(t *testing.T, opts Options) {
	t.Helper()
	got, err := reservedPorts(opts)
	want, ok := reservedPortsByListener(opts)
	if (err == nil) != ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("reservedPorts(%+v) = %v, %v; the listeners bind %v, resolvable %v", opts, got, err, want, ok)
	}
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
	"0.0.0.0:https", "localhost:http", "0.0.0.0:no-such-service-wgft", "unix:///run/wgft/a:https",
}

// wgPorts are WireGuard ports that collide with the ports in reservedAddrs, and the ends of the
// range.
var wgPorts = []uint16{0, 1, 80, 8443, 8686, 51820, 65535}

// TestReservedPortsMatchTheListeners compares reservedPorts with the ports the listeners bind:
// every WireGuard port in the uint16 range with the default listeners, and every pair of
// reservedAddrs with each of wgPorts.
func TestReservedPortsMatchTheListeners(t *testing.T) {
	for p := 0; p <= 65535; p++ {
		checkReservedPorts(t, Options{WGPort: uint16(p), AdminAddr: "unix:///run/wgft/admin.sock", AgentAPIAddr: "0.0.0.0:8443"})
		checkReservedPorts(t, Options{WGPort: uint16(p), AdminAddr: "127.0.0.1:8686", AgentAPIAddr: "0.0.0.0:8443"})
	}
	for _, wg := range wgPorts {
		for _, adminAddr := range reservedAddrs {
			for _, agent := range reservedAddrs {
				checkReservedPorts(t, Options{WGPort: wg, AdminAddr: adminAddr, AgentAPIAddr: agent})
			}
		}
	}
}

// TestReservedPortsAreWhatTheListenersBind opens the real listeners on forms of one free port
// that the old rule, netip.ParseAddrPort, did not reserve, and checks that reservedPorts
// reserves the port each listener actually bound. Service names are left to
// TestReservedPortsMatchTheListeners: the well-known ones resolve to ports below 1024, which an
// unprivileged test cannot bind.
func TestReservedPortsAreWhatTheListenersBind(t *testing.T) {
	// The free port is picked and closed before the listeners bind it, so another process can take
	// the number in the gap. Only an address-in-use failure of the listen repeats the pass with a new
	// port; every other failure and every wrong reservation still fails the test.
	const attempts = 5
	var last error
	for i := 1; i <= attempts; i++ {
		if last = reservedPortsAreWhatTheListenersBind(t); last == nil {
			return
		}
		t.Logf("attempt %d of %d: a listen failed with address-in-use, retrying with a new port: %v", i, attempts, last)
	}
	t.Fatalf("a listen failed with address-in-use in all %d attempts: %v", attempts, last)
}

// reservedPortsAreWhatTheListenersBind runs one pass. It returns the address-in-use error when a
// listen failed with it, before it checks that pass any further, and nil when the pass ran.
func reservedPortsAreWhatTheListenersBind(t *testing.T) (collision error) {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	free := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	for _, addr := range []string{
		fmt.Sprintf("localhost:%d", free),
		fmt.Sprintf(":%d", free),
		fmt.Sprintf("127.0.0.1:+%d", free),
		fmt.Sprintf("127.0.0.1:0%d", free),
	} {
		for _, opts := range []Options{{WGPort: 51820, AdminAddr: addr}, {WGPort: 51820, AdminAddr: "unix:///run/wgft/admin.sock", AgentAPIAddr: addr}} {
			var ln net.Listener
			if opts.AgentAPIAddr == "" {
				ln, err = admin.Listen(addr, false)
			} else {
				ln, err = net.Listen("tcp", addr)
			}
			if errors.Is(err, syscall.EADDRINUSE) {
				return err
			}
			if err != nil {
				t.Fatalf("listening on %q: %v", addr, err)
			}
			boundPort := uint16(ln.Addr().(*net.TCPAddr).Port)
			ln.Close()
			got, err := reservedPorts(opts)
			if err != nil {
				t.Fatalf("reservedPorts(%+v): %v", opts, err)
			}
			if _, ok := got[boundPort]; !ok || len(got) != 2 {
				t.Errorf("reservedPorts(%+v) = %v; the listener bound port %d", opts, got, boundPort)
			}
		}
	}
	return nil
}

// FuzzReservedPortsMatchTheListeners extends TestReservedPortsMatchTheListeners to inputs the
// fuzzer finds.
func FuzzReservedPortsMatchTheListeners(f *testing.F) {
	for _, wg := range wgPorts {
		for _, a := range reservedAddrs {
			f.Add(wg, a, "0.0.0.0:8443")
			f.Add(wg, "unix:///run/wgft/admin.sock", a)
		}
	}
	f.Fuzz(func(t *testing.T, wg uint16, adminAddr, agent string) {
		checkReservedPorts(t, Options{WGPort: wg, AdminAddr: adminAddr, AgentAPIAddr: agent})
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
			got, gotErr := admin.ReservedFromServerInfo(info)
			want, wantErr := reservedPorts(opts)
			if !reflect.DeepEqual(got, want) || (gotErr == nil) != (wantErr == nil) {
				t.Fatalf("%+v: ServerInfo reserves %v, %v; the server %v, %v", opts, got, gotErr, want, wantErr)
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
