package nettun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/rahanahu/wgft/internal/lograte"
)

// These tests pin the UDP accounting at the Device: the budget values, the
// refusal counts and their log, the fail-stop, the length the Device hands to
// gVisor, and that no UDP endpoint exists outside the registry.

// captureLog replaces the accounting's log for one test.
func captureLog(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var lines []string
	saved := logf
	logf = func(format string, args ...any) {
		mu.Lock()
		lines = append(lines, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	t.Cleanup(func() { logf = saved })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

func TestUDPIngressReassembledDatagramsAreAccounted(t *testing.T) {
	d := ingressDevice(t)
	local := netip.AddrPortFrom(accountingLocal, accountingPort)
	pc, err := d.ListenUDP(local)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	complete := registryPacket([]byte("abcdefgh12345678"), 41000, accountingPort)
	first, last := splitIngressIPv4(complete, 16)
	sendIngress(t, d, last)
	sendIngress(t, d, first)
	assertDeviceUsage(t, d, 16+udpDatagramCharge, 1)
	b := make([]byte, 16)
	if n, _, err := pc.ReadFrom(b); err != nil || n != 16 || !bytes.Equal(b, []byte("abcdefgh12345678")) {
		t.Fatalf("reassembled ReadFrom = %d/%q/%v", n, b, err)
	}
	assertDeviceUsage(t, d, 0, 0)
}

// The Device's budget: 4 MiB and 4096 datagrams, 64 bytes charged per
// datagram, and a quarter of each for one endpoint.
func TestUDPIngressBudgetValues(t *testing.T) {
	d := ingressDevice(t)
	acc := d.registry.accounting
	if acc.maxBytes != 4<<20 || acc.maxPackets != 4096 || acc.fixedOverhead != 64 ||
		acc.maxEndpointBytes != 1<<20 || acc.maxEndpointPackets != 1024 {
		t.Fatalf("budget = %d/%d charge %d, endpoint %d/%d", acc.maxBytes, acc.maxPackets, acc.fixedOverhead,
			acc.maxEndpointBytes, acc.maxEndpointPackets)
	}
}

// Refusals are counted by kind and logged on one line at most once a minute,
// and a refused datagram is a drop, not a Write error.
func TestUDPIngressRefusalsCountedAndLoggedOnce(t *testing.T) {
	lines := captureLog(t)
	d := ingressDevice(t)
	acc := d.registry.accounting
	var stalled []*rawUDPAdapter
	for i := 0; i < udpEndpointShare; i++ {
		stalled = append(stalled, listenAdapter(t, d, uint16(40100+i)))
	}
	quiet := listenAdapter(t, d, 40200)
	for i := 0; i < 1030; i++ {
		sendIngress(t, d, registryPacket([]byte("abc"), 50000, 40100))
	}
	if got := acc.refusedEndpoint.Load(); got != 6 {
		t.Fatalf("endpoint refusals = %d, want 6", got)
	}
	if got := len(lines()); got != 1 {
		t.Fatalf("log lines after the first refusals = %d, want 1: %q", got, lines())
	}
	for i := 1; i < udpEndpointShare; i++ {
		for j := 0; j < 1024; j++ {
			sendIngress(t, d, registryPacket([]byte("abc"), 50000, uint16(40100+i)))
		}
	}
	assertDeviceUsage(t, d, 4096*67, 4096)
	sendIngress(t, d, registryPacket([]byte("q"), 50001, 40200))
	if got := acc.refusedDevice.Load(); got != 1 {
		t.Fatalf("device refusals = %d, want 1", got)
	}
	if got := acc.refusedEndpoint.Load(); got != 6 {
		t.Fatalf("endpoint refusals changed to %d by a device refusal", got)
	}
	// The one line so far was written at the first refusal.
	if got := lines(); len(got) != 1 || !strings.Contains(got[0], "1 refused at one socket's cap of 1048576 bytes or 1024 datagrams") ||
		!strings.Contains(got[0], "0 refused at the tunnel's total of 4194304 bytes or 4096 datagrams") || strings.ContainsAny(got[0], "()") {
		t.Fatalf("refusal log = %q", got)
	}
	// Opening the gate again logs both counts on one new line.
	acc.refusalLog = lograte.Gate{}
	sendIngress(t, d, registryPacket([]byte("q"), 50001, 40200))
	if got := lines(); len(got) != 2 || !strings.Contains(got[1], "6 refused at one socket's cap") ||
		!strings.Contains(got[1], "2 refused at the tunnel's total") {
		t.Fatalf("second refusal log = %q", got)
	}
	readOne(t, stalled[0])
	sendIngress(t, d, registryPacket([]byte("q"), 50001, 40200))
	readOne(t, quiet)
	if _, _, fault := d.registry.usage(); fault != nil {
		t.Fatal(fault)
	}
}

// Fail-stop: a ledger inconsistency stops the Device's UDP, is logged once,
// and is readable from the Device. Write does not return it.
func TestUDPIngressFaultStopsUDPAndIsReported(t *testing.T) {
	lines := captureLog(t)
	d := ingressDevice(t)
	x := listenAdapter(t, d, accountingPort)
	sendIngress(t, d, registryPacket([]byte("four"), 41000, accountingPort))
	acc := d.registry.accounting
	acc.mu.Lock()
	acc.generations[x].fifo[0].payload = 3 // model a ledger that no longer matches the queue
	acc.mu.Unlock()
	if d.UDPReceiveFault() != nil {
		t.Fatal("fault before the mismatched Read")
	}
	if _, _, err := x.ReadFrom(make([]byte, 8)); err == nil {
		t.Fatal("Read of a mismatched datagram returned no error")
	}
	fault := d.UDPReceiveFault()
	if fault == nil || !strings.Contains(fault.Error(), "payload mismatch") {
		t.Fatalf("UDPReceiveFault = %v", fault)
	}
	got := lines()
	if len(got) != 1 || !strings.Contains(got[0], "stopped all UDP on this tunnel") ||
		!strings.Contains(got[0], "payload mismatch") || strings.ContainsAny(got[0], "()") {
		t.Fatalf("fault log = %q", got)
	}
	// Later UDP input is dropped without a Write error; nothing reaches x.
	if n, err := d.Write([][]byte{registryPacket([]byte("late"), 41000, accountingPort)}, 0); n != 1 || err != nil {
		t.Fatalf("Write after the fault = %d/%v", n, err)
	}
	if x.ep.Readiness(waiter.ReadableEvents) != 0 {
		t.Fatal("a datagram reached the endpoint after the fault")
	}
	if _, err := d.ListenUDP(netip.AddrPortFrom(accountingLocal, accountingPort+1)); err == nil {
		t.Fatal("ListenUDP after the fault succeeded")
	}
	if _, err := d.DialUDP(netip.AddrPortFrom(accountingRemote, 9)); err == nil {
		t.Fatal("DialUDP after the fault succeeded")
	}
	// TCP is not part of the accounting: a SYN to a closed port still gets
	// gVisor's RST.
	queued := d.ep.NumQueued()
	sendIngress(t, d, lockTestTCPSYN())
	if d.ep.NumQueued() != queued+1 {
		t.Fatal("TCP stopped with the UDP fault")
	}
	// Another path that meets the fault does not log again.
	acc.reportFault()
	if got := lines(); len(got) != 1 {
		t.Fatalf("fault logged %d times", len(got))
	}
}

// wireguard-go cuts each packet to its IPv4 Total Length, but the Device does
// not rely on it. Without the cut, a datagram with bytes past the Total
// Length reaches gVisor, which delivers it by the Total Length, unreserved,
// and the next Read stops the Device's UDP.
func TestUDPIngressCutsBytesPastTotalLength(t *testing.T) {
	d := ingressDevice(t)
	x := listenAdapter(t, d, accountingPort)
	p := append(registryPacket([]byte("four"), 41000, accountingPort), "trailing"...)
	sendIngress(t, d, p)
	assertDeviceUsage(t, d, 4+udpDatagramCharge, 1)
	b := make([]byte, 64)
	if n, _, err := x.ReadFrom(b); err != nil || string(b[:n]) != "four" {
		t.Fatalf("ReadFrom = %q/%v", b[:n], err)
	}
	assertDeviceUsage(t, d, 0, 0)
	// A fragment with trailing bytes is cut the same way and completes.
	first, last := splitIngressIPv4(registryPacket([]byte("abcdefgh12345678"), 41000, accountingPort), 8)
	sendIngress(t, d, append(first, 0, 0, 0))
	sendIngress(t, d, append(last, 1, 2))
	if n, _, err := x.ReadFrom(b); err != nil || string(b[:n]) != "abcdefgh12345678" {
		t.Fatalf("reassembled ReadFrom = %q/%v", b[:n], err)
	}
	assertDeviceUsage(t, d, 0, 0)
	if err := d.UDPReceiveFault(); err != nil {
		t.Fatal(err)
	}
}

// Each reservation matches one delivered datagram: after every Read, the
// usage falls by exactly that datagram's payload and charge, whatever the
// reader's buffer, in the order the datagrams arrived, whole and fragmented.
func TestUDPIngressReservationMatchesEachDatagram(t *testing.T) {
	d := ingressDevice(t)
	x := listenAdapter(t, d, accountingPort)
	sizes := []int{0, 1, 7, 300, 1400, 5000, 65507}
	total, count := 0, 0
	for i, n := range sizes {
		payload := bytes.Repeat([]byte{byte('a' + i)}, n)
		p := registryPacket(payload, 41000, accountingPort)
		if len(p) > 1420 {
			for _, part := range fragmentIngressIPv4(p, 1420) {
				sendIngress(t, d, part)
			}
		} else {
			sendIngress(t, d, p)
		}
		total += n + udpDatagramCharge
		count++
		assertDeviceUsage(t, d, total, count)
	}
	for i, n := range sizes {
		b := make([]byte, 1+i*i) // short buffers still return the whole reservation
		got, _, err := x.ReadFrom(b)
		if err != nil || got != min(n, len(b)) || (got > 0 && b[0] != byte('a'+i)) {
			t.Fatalf("Read %d = %d/%v", i, got, err)
		}
		total -= n + udpDatagramCharge
		count--
		assertDeviceUsage(t, d, total, count)
	}
}

// No sequence of packets from the TUN can make the ledger disagree with the
// queues: fragments, bad lengths, options, lying UDP lengths, bad checksums,
// broadcast and multicast, connected and unconnected receivers, unknown
// ports, and trailing bytes, in batches, with reads in between.
func TestUDPIngressExternalInputKeepsTheLedger(t *testing.T) {
	d := ingressDevice(t)
	listener := listenAdapter(t, d, accountingPort)
	listener.ep.SocketOptions().SetReceiveBufferSize(16384, false)
	remote := netip.AddrPortFrom(accountingRemote, 41001)
	connected := dialAdapter(t, d, remote)
	cport := connected.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	rng := rand.New(rand.NewPCG(7, 11))
	dests := [][4]byte{{10, 99, 0, 1}, {255, 255, 255, 255}, {224, 0, 0, 1}, {10, 99, 0, 255}, {10, 1, 1, 1}}
	build := func() [][]byte {
		payload := make([]byte, []int{0, 1, 8, 100, 1300, 3000}[rng.IntN(6)])
		sport, dport := uint16(41000+rng.IntN(3)), []uint16{accountingPort, cport, accountingPort + 7}[rng.IntN(3)]
		p := registryPacket(payload, sport, dport)
		if rng.IntN(5) == 0 {
			copy(p[16:20], dests[rng.IntN(len(dests))][:])
		}
		if rng.IntN(6) == 0 { // an IPv4 option: NOP padding
			p = append(p[:20:20], append([]byte{1, 1, 1, 0}, p[20:]...)...)
			p[0] = 0x46
			binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		}
		hl := int(p[0]&15) * 4
		switch rng.IntN(8) {
		case 0: // UDP length shorter than the IP payload
			binary.BigEndian.PutUint16(p[hl+4:hl+6], uint16(8+len(payload)/2))
		case 1: // UDP length longer than the IP payload
			binary.BigEndian.PutUint16(p[hl+4:hl+6], uint16(8+len(payload)+9))
		case 2: // a nonzero, wrong UDP checksum
			binary.BigEndian.PutUint16(p[hl+6:hl+8], 1)
		case 3: // Total Length shorter than the UDP header
			binary.BigEndian.PutUint16(p[2:4], uint16(hl+4))
		case 4: // Total Length past the packet
			binary.BigEndian.PutUint16(p[2:4], uint16(len(p)+5))
		}
		ipv4SetChecksum(p[:hl])
		if rng.IntN(4) == 0 {
			p = append(p, make([]byte, 1+rng.IntN(9))...) // bytes past the Total Length
		}
		if rng.IntN(4) == 0 && hl == 20 && len(p) > 60 && int(binary.BigEndian.Uint16(p[2:4])) == len(p) {
			binary.BigEndian.PutUint16(p[4:6], uint16(rng.IntN(4)))
			ipv4SetChecksum(p[:20])
			parts := fragmentIngressIPv4(p, 20+8*(1+rng.IntN(8)))
			rng.Shuffle(len(parts), func(i, j int) { parts[i], parts[j] = parts[j], parts[i] })
			if rng.IntN(3) == 0 {
				parts = parts[1:] // a lost fragment
			}
			return parts
		}
		return [][]byte{p}
	}
	drain := func() {
		for _, c := range []*rawUDPAdapter{listener, connected} {
			for {
				_ = c.SetReadDeadline(time.Now().Add(time.Millisecond))
				if _, _, err := c.ReadFrom(make([]byte, 4096)); err != nil {
					var ne net.Error
					if !errors.As(err, &ne) || !ne.Timeout() {
						t.Fatalf("drain Read: %v", err)
					}
					break
				}
			}
		}
	}
	for round := 0; round < 300; round++ {
		var batch [][]byte
		for i := 0; i < 1+rng.IntN(12); i++ {
			batch = append(batch, build()...)
		}
		if _, err := d.Write(batch, 0); err != nil {
			t.Fatalf("round %d: Write = %v", round, err)
		}
		if round%7 == 0 {
			drain()
		}
		for d.ep.NumQueued() > 0 {
			d.ep.Read().DecRef()
		}
		if err := d.UDPReceiveFault(); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}
	drain()
	assertDeviceUsage(t, d, 0, 0)
}

// No UDP endpoint exists outside the registry. The Device exports nothing
// that reaches the stack or an endpoint, the package creates UDP endpoints
// only in newRawUDPAdapter, which only open calls, and after the public
// constructors run, every UDP endpoint the stack holds is registered.
func TestUDPEndpointsAreCreatedOnlyThroughTheRegistry(t *testing.T) {
	dt := reflect.TypeOf(&Device{})
	stackT := reflect.TypeOf(&stack.Stack{})
	endpointT := reflect.TypeOf((*tcpip.Endpoint)(nil)).Elem()
	for i := 0; i < dt.NumMethod(); i++ {
		m := dt.Method(i)
		for j := 0; j < m.Type.NumOut(); j++ {
			out := m.Type.Out(j)
			if out == stackT || (out.Kind() != reflect.Interface && out.Implements(endpointT)) || out == endpointT {
				t.Errorf("Device.%s returns %v, which reaches gVisor directly", m.Name, out)
			}
		}
	}
	for i := 0; i < dt.Elem().NumField(); i++ {
		if f := dt.Elem().Field(i); f.IsExported() {
			t.Errorf("Device has the exported field %s", f.Name)
		}
	}

	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	type site struct{ file, fn, what string }
	var sites []site
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					what := fun.Sel.Name
					if x, ok := fun.X.(*ast.Ident); ok && x.Name == "gonet" {
						what = "gonet." + what
					}
					if what == "NewEndpoint" && len(call.Args) > 0 {
						if a, ok := call.Args[0].(*ast.SelectorExpr); ok {
							if x, ok := a.X.(*ast.Ident); ok {
								what = "NewEndpoint(" + x.Name + "." + a.Sel.Name + ")"
							}
						}
					}
					sites = append(sites, site{name, fn.Name.Name, what})
				case *ast.Ident:
					sites = append(sites, site{name, fn.Name.Name, fun.Name})
				}
				return true
			})
		}
	}
	seenCreate, seenOpen := false, false
	for _, s := range sites {
		switch {
		case strings.HasPrefix(s.what, "NewEndpoint(") && s.what != "NewEndpoint(tcp.ProtocolNumber)" && s.what != "NewEndpoint(icmp.ProtocolNumber4)":
			if s.what != "NewEndpoint(udp.ProtocolNumber)" || s.fn != "newRawUDPAdapter" {
				t.Errorf("%s: %s creates %s outside newRawUDPAdapter", s.file, s.fn, s.what)
			}
			seenCreate = true
		case s.what == "NewEndpoint":
			t.Errorf("%s: %s calls NewEndpoint with a protocol this test cannot read", s.file, s.fn)
		case s.what == "gonet.DialUDP" || (s.what == "gonet.NewUDPConn" && s.fn != "DialPing"):
			t.Errorf("%s: %s calls %s", s.file, s.fn, s.what)
		case s.what == "newRawUDPAdapter":
			if s.fn != "open" {
				t.Errorf("%s: %s calls newRawUDPAdapter; only the registry's open may", s.file, s.fn)
			}
			seenOpen = true
		}
	}
	if !seenCreate || !seenOpen {
		t.Fatalf("the scan found no UDP endpoint creation (%v) or no call from open (%v); did the code move?", seenCreate, seenOpen)
	}

	d := ingressDevice(t)
	listenAdapter(t, d, accountingPort)
	dialAdapter(t, d, netip.AddrPortFrom(accountingRemote, 9))
	dialAdapter(t, d, netip.AddrPortFrom(accountingLocal, accountingPort))
	ping, err := d.DialPing(accountingLocal, accountingRemote)
	if err != nil {
		t.Fatal(err)
	}
	defer ping.Close()
	registered := map[any]bool{}
	acc := d.registry.accounting
	acc.mu.Lock()
	for c := range acc.generations {
		registered[any(c.ep)] = true
	}
	acc.mu.Unlock()
	udps := 0
	for _, ep := range d.stack.RegisteredEndpoints() {
		if fmt.Sprintf("%T", ep) != "*udp.endpoint" {
			continue
		}
		udps++
		if !registered[any(ep)] {
			t.Errorf("the stack holds a UDP endpoint the registry does not know: %p", ep)
		}
	}
	if udps != 3 {
		t.Fatalf("the stack holds %d UDP endpoints, want 3", udps)
	}
}

func TestUDPIngressClosedDeviceRefusesConstructors(t *testing.T) {
	d, err := Create(accountingLocal, 1420)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := d.ListenUDP(netip.AddrPortFrom(accountingLocal, accountingPort))
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	if _, _, err := pc.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrom on an endpoint of a closed Device = %v", err)
	}
	if _, err := d.ListenUDP(netip.AddrPortFrom(accountingLocal, accountingPort+1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ListenUDP after Close = %v", err)
	}
	if _, err := d.DialUDP(netip.AddrPortFrom(accountingRemote, 9)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("DialUDP after Close = %v", err)
	}
	if _, err := d.Write([][]byte{registryPacket([]byte("x"), 41000, accountingPort)}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write after Close = %v", err)
	}
}

// A UDP datagram for another address is not the registry's: it reaches
// gVisor as before, which refuses the destination.
func TestUDPIngressNonlocalUDPReachesGVisor(t *testing.T) {
	d := ingressDevice(t)
	listenAdapter(t, d, accountingPort)
	invalid := d.stack.Stats().IP.InvalidDestinationAddressesReceived
	before := invalid.Value()
	sendIngress(t, d, lockTestNonlocalUDP())
	if invalid.Value() != before+1 {
		t.Fatalf("a nonlocal UDP datagram did not reach gVisor's destination check: %d -> %d", before, invalid.Value())
	}
	assertDeviceUsage(t, d, 0, 0)
}

// After a fault, a second violation does not replace the first: the one log
// line and UDPReceiveFault name the same violation. UDP stops for every
// endpoint, including one opened before the fault, and TCP continues.
func TestUDPIngressFaultKeepsTheFirstViolation(t *testing.T) {
	lines := captureLog(t)
	d := ingressDevice(t)
	x := listenAdapter(t, d, accountingPort)
	y := listenAdapter(t, d, accountingPort+1)
	sendIngress(t, d, registryPacket([]byte("four"), 41000, accountingPort))
	sendIngress(t, d, registryPacket([]byte("five!"), 41000, accountingPort+1))
	acc := d.registry.accounting
	acc.mu.Lock()
	acc.generations[x].fifo[0].payload = 3
	acc.generations[y].fifo[0].payload = 2
	acc.mu.Unlock()
	if _, _, err := x.ReadFrom(make([]byte, 8)); err == nil {
		t.Fatal("first mismatched Read returned no error")
	}
	first := d.UDPReceiveFault()
	if first == nil || !strings.Contains(first.Error(), "read 4, reserved 3") {
		t.Fatalf("first fault = %v", first)
	}
	if _, _, err := y.ReadFrom(make([]byte, 8)); err == nil {
		t.Fatal("second mismatched Read returned no error")
	}
	if got := d.UDPReceiveFault(); got == nil || got.Error() != first.Error() {
		t.Fatalf("fault after a second violation = %v, want the first %v", got, first)
	}
	if got := lines(); len(got) != 1 || !strings.Contains(got[0], "read 4, reserved 3") {
		t.Fatalf("fault log = %q", got)
	}
	sendIngress(t, d, registryPacket([]byte("late"), 41000, accountingPort+1))
	if y.ep.Readiness(waiter.ReadableEvents) != 0 {
		t.Fatal("UDP reached an endpoint opened before the fault")
	}
	queued := d.ep.NumQueued()
	sendIngress(t, d, lockTestTCPSYN())
	if d.ep.NumQueued() != queued+1 {
		t.Fatal("TCP stopped with the UDP fault")
	}
}
