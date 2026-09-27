package nettun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const ingressPort = 32000

var (
	ingressLocal  = netip.MustParseAddr("10.99.0.1")
	ingressRemote = netip.MustParseAddr("10.99.0.2")
)

// These tests enter through the actual Device.Write and the public UDP constructors.
func ingressDevice(t *testing.T) *Device {
	t.Helper()
	d, err := Create(ingressLocal, 1420)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// ingressUDP builds a complete IPv4 UDP datagram from ingressRemote to ingressLocal.
func ingressUDP(payload []byte, sourcePort, destPort uint16) []byte {
	p := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(p[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(p)),
		ID:          4242,
		TTL:         64,
		Protocol:    uint8(udp.ProtocolNumber),
		SrcAddr:     tcpip.AddrFromSlice(ingressRemote.AsSlice()),
		DstAddr:     tcpip.AddrFromSlice(ingressLocal.AsSlice()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	u := header.UDP(p[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{SrcPort: sourcePort, DstPort: destPort, Length: uint16(header.UDPMinimumSize + len(payload))})
	copy(p[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
	return p
}

func sendIngress(t *testing.T, d *Device, packet []byte) {
	t.Helper()
	if n, err := d.Write([][]byte{packet}, 0); err != nil || n != 1 {
		t.Fatalf("Device.Write = %d/%v", n, err)
	}
}

func splitIngressIPv4(packet []byte, firstPayload int) ([]byte, []byte) {
	makePart := func(start, end int, more bool) []byte {
		part := append([]byte(nil), packet[:20]...)
		part = append(part, packet[20+start:20+end]...)
		binary.BigEndian.PutUint16(part[2:4], uint16(len(part)))
		flags := uint16(start / 8)
		if more {
			flags |= 0x2000
		}
		binary.BigEndian.PutUint16(part[6:8], flags)
		ipv4SetChecksum(part[:20])
		return part
	}
	return makePart(0, firstPayload, true), makePart(firstPayload, len(packet)-20, false)
}

// fragmentIngressIPv4 cuts a complete 20-byte-header datagram into fragments
// of at most mtu bytes, as a peer's stack does for the tunnel MTU.
func fragmentIngressIPv4(packet []byte, mtu int) [][]byte {
	per := (mtu - 20) &^ 7
	var parts [][]byte
	payload := packet[20:]
	for start := 0; start < len(payload); start += per {
		end := min(start+per, len(payload))
		part := append([]byte(nil), packet[:20]...)
		part = append(part, payload[start:end]...)
		binary.BigEndian.PutUint16(part[2:4], uint16(len(part)))
		flags := uint16(start / 8)
		if end < len(payload) {
			flags |= 0x2000
		}
		binary.BigEndian.PutUint16(part[6:8], flags)
		ipv4SetChecksum(part[:20])
		parts = append(parts, part)
	}
	return parts
}

func TestIngressReassembledUDPReachesListener(t *testing.T) {
	d := ingressDevice(t)
	pc, err := d.ListenUDP(netip.AddrPortFrom(ingressLocal, ingressPort))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	first, last := splitIngressIPv4(ingressUDP([]byte("abcdefgh12345678"), 41000, ingressPort), 16)
	sendIngress(t, d, last)
	sendIngress(t, d, first)
	if err := pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 16)
	if n, _, err := pc.ReadFrom(b); err != nil || n != 16 || !bytes.Equal(b, []byte("abcdefgh12345678")) {
		t.Fatalf("reassembled ReadFrom = %d/%q/%v", n, b, err)
	}
	if _, entries, pieces := d.reassembly.Usage(); entries != 0 || pieces != 0 {
		t.Fatalf("after completion: %d entries, %d pieces", entries, pieces)
	}
}

// gVisor's own reassembler leaves one uncancelled 30-second timer per
// fragmented datagram. No fragment may reach it: gVisor's IPv4 layer counts
// every packet it receives, so a fragmented datagram must count once, as the
// completed copy, and a fragment the table holds or refuses must not count.
func TestIngressFragmentsNeverReachGVisorReassembly(t *testing.T) {
	d := ingressDevice(t)
	pc, err := d.ListenUDP(netip.AddrPortFrom(ingressLocal, ingressPort))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ipStats := d.stack.Stats().IP
	received := func() uint64 { return ipStats.PacketsReceived.Value() }

	payload := make([]byte, 65507)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	parts := fragmentIngressIPv4(ingressUDP(payload, 41000, ingressPort), 1420)
	if len(parts) != 47 {
		t.Fatalf("65507-byte datagram at MTU 1420 = %d fragments, want 47", len(parts))
	}
	rand.New(rand.NewPCG(1, 2)).Shuffle(len(parts), func(i, j int) { parts[i], parts[j] = parts[j], parts[i] })
	before := received()
	for i, part := range parts {
		sendIngress(t, d, part)
		if i < len(parts)-1 && received() != before {
			t.Fatalf("fragment %d reached gVisor: PacketsReceived %d -> %d", i, before, received())
		}
	}
	if got := received() - before; got != 1 {
		t.Fatalf("completed datagram reached gVisor %d times, want 1", got)
	}
	if err := pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 65535)
	if n, _, err := pc.ReadFrom(b); err != nil || !bytes.Equal(b[:n], payload) {
		t.Fatalf("65507-byte datagram = %d/%v", n, err)
	}

	// Held, duplicate, malformed and overlapping fragments.
	before = received()
	first, last := splitIngressIPv4(ingressUDP([]byte("abcdefgh12345678"), 41000, ingressPort), 16)
	binary.BigEndian.PutUint16(first[4:6], 99)
	ipv4SetChecksum(first[:20])
	sendIngress(t, d, first) // held
	sendIngress(t, d, first) // duplicate
	bad := append([]byte(nil), last...)
	bad[10] ^= 1 // header checksum
	sendIngress(t, d, bad)
	overlap := reasmIPv4Fragment(17, 99, 8, false, 0, nil, []byte("xxxxxxxxxx"))
	copy(overlap[12:20], first[12:20])
	ipv4SetChecksum(overlap[:20])
	sendIngress(t, d, overlap)
	if got := received() - before; got != 0 {
		t.Fatalf("refused or held fragments reached gVisor %d times", got)
	}
	if st := ipStats.MalformedFragmentsReceived.Value(); st != 0 {
		t.Fatalf("gVisor saw %d malformed fragments", st)
	}
}

func TestIngressUnknownPortICMPAndCloseJoin(t *testing.T) {
	d := ingressDevice(t)
	input := ingressUDP([]byte("unknown"), 41000, ingressPort)
	sendIngress(t, d, input)
	output := readIngressOutput(t, d, time.Second)
	if len(output) < 20+8+28 || output[9] != 1 || output[20] != 3 || output[21] != 3 ||
		!bytes.Equal(output[20+8+12:20+8+20], input[12:20]) ||
		!bytes.Equal(output[20+8+20:20+8+24], input[20:24]) {
		t.Fatalf("unknown-port ICMP/quote = %x", output)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-d.sweepDone:
	default:
		t.Fatal("sweeper did not join")
	}
	before := d.stack.Stats().IP.PacketsReceived.Value()
	first, _ := splitIngressIPv4(input, 8)
	for _, p := range [][]byte{input, first} {
		if n, err := d.Write([][]byte{p}, 0); n != 0 || !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Write after Close = %d/%v", n, err)
		}
	}
	if got := d.stack.Stats().IP.PacketsReceived.Value(); got != before {
		t.Fatalf("Write after Close reached gVisor: %d -> %d", before, got)
	}
	if _, entries, _ := d.reassembly.Usage(); entries != 0 {
		t.Fatalf("Write after Close held %d entries", entries)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}

// Close runs while Writes are delivering fragments and completed datagrams.
// Every Write returns, Close joins the sweeper, and later Writes are refused.
func TestIngressCloseDuringWrites(t *testing.T) {
	for round := 0; round < 20; round++ {
		d, err := Create(ingressLocal, 1420)
		if err != nil {
			t.Fatal(err)
		}
		pc, err := d.ListenUDP(netip.AddrPortFrom(ingressLocal, ingressPort))
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				for i := 0; i < 200; i++ {
					p := ingressUDP(bytes.Repeat([]byte{byte(g)}, 3000), uint16(41000+g), ingressPort)
					binary.BigEndian.PutUint16(p[4:6], uint16(g*1000+i))
					ipv4SetChecksum(p[:20])
					for _, part := range fragmentIngressIPv4(p, 1420) {
						if _, err := d.Write([][]byte{part}, 0); err != nil {
							if !errors.Is(err, os.ErrClosed) {
								t.Errorf("Write = %v", err)
							}
							return
						}
					}
				}
			}(g)
		}
		time.Sleep(time.Duration(round%5) * time.Millisecond)
		done := make(chan struct{})
		go func() { d.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Close did not return during Writes")
		}
		wg.Wait()
		pc.Close()
		select {
		case <-d.sweepDone:
		default:
			t.Fatal("sweeper did not join")
		}
		if _, err := d.Write([][]byte{ingressUDP([]byte("x"), 41000, ingressPort)}, 0); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Write after Close = %v", err)
		}
	}
}

// Close joins the sweeper before it marks the Device closed and before it
// closes the stack, so a timeout notice never reaches a closing stack. The
// test holds the table's mutex until the sweeper blocks in Sweep; Close must
// then wait with the stack still open.
func TestIngressCloseJoinsSweeperBeforeStack(t *testing.T) {
	d, err := Create(ingressLocal, 1420)
	if err != nil {
		t.Fatal(err)
	}
	d.reassembly.mu.Lock()
	time.Sleep(2*reassemblySweep + 500*time.Millisecond) // the sweeper is now blocked in Sweep
	done := make(chan struct{})
	go func() { d.Close(); close(done) }()
	time.Sleep(100 * time.Millisecond)
	closedEarly, nicGone := d.closed.Load(), !d.stack.HasNIC(1)
	d.reassembly.mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}
	if closedEarly || nicGone {
		t.Fatalf("Close went on before joining the sweeper: closed=%v nicRemoved=%v", closedEarly, nicGone)
	}
	select {
	case <-d.sweepDone:
	default:
		t.Fatal("sweeper did not join")
	}
}

// The sweeper expires a held fragment with no further traffic, and Close
// stops it.
func TestIngressSweeperRunsWithoutTraffic(t *testing.T) {
	d := ingressDevice(t)
	d.reassembly.mu.Lock()
	d.reassembly.limits.Lifetime = 20 * time.Millisecond
	d.reassembly.mu.Unlock()
	first, _ := splitIngressIPv4(ingressUDP([]byte("abcdefgh12345678"), 41000, ingressPort), 16)
	copy(first[16:20], []byte{10, 1, 1, 99}) // nonlocal: no ICMP output
	ipv4SetChecksum(first[:20])
	sendIngress(t, d, first)
	waitIngressEmpty(t, d)
	d.Close()
	select {
	case <-d.sweepDone:
	case <-time.After(time.Second):
		t.Fatal("sweeper did not stop")
	}
}

func waitIngressEmpty(t *testing.T, d *Device) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, entries, _ := d.reassembly.Usage()
		if entries == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("held fragment did not expire")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func readIngressOutput(t *testing.T, d *Device, wait time.Duration) []byte {
	t.Helper()
	type output struct {
		packet []byte
		err    error
	}
	done := make(chan output, 1)
	go func() {
		b := make([]byte, 1500)
		sizes := []int{0}
		n, err := d.Read([][]byte{b}, sizes, 0)
		if err == nil && n == 1 {
			done <- output{packet: append([]byte(nil), b[:sizes[0]]...)}
		} else {
			done <- output{err: err}
		}
	}()
	select {
	case got := <-done:
		if got.err != nil || len(got.packet) == 0 {
			t.Fatalf("Device.Read output = %v/%x", got.err, got.packet)
		}
		return got.packet
	case <-time.After(wait):
		d.Close() // unblock the helper before failing
		t.Fatal("timed out waiting for output")
		return nil
	}
}

func TestIngressFragmentTimeoutICMP(t *testing.T) {
	d := ingressDevice(t)
	d.reassembly.mu.Lock()
	d.reassembly.limits.Lifetime = 20 * time.Millisecond
	d.reassembly.mu.Unlock()
	first, _ := splitIngressIPv4(ingressUDP([]byte("abcdefgh12345678"), 41000, ingressPort), 16)
	sendIngress(t, d, first)
	out := readIngressOutput(t, d, 3*time.Second)
	if len(out) < 56 || out[9] != 1 || out[20] != 11 || out[21] != 1 ||
		!bytes.Equal(out[12:16], first[16:20]) || !bytes.Equal(out[16:20], first[12:16]) ||
		!bytes.Equal(out[28:56], first[:28]) {
		t.Fatalf("timeout ICMP/quote = %x", out)
	}
}

// A fragment whose key expired but was not yet swept reports the timeout and
// then starts a new entry.
func TestIngressExpiredKeyRetriesFragment(t *testing.T) {
	d := ingressDevice(t)
	pc, err := d.ListenUDP(netip.AddrPortFrom(ingressLocal, ingressPort))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	close(d.sweepStop) // stop the sweeper so only Write sees the expiry
	<-d.sweepDone
	d.sweepStop = nil
	d.reassembly.mu.Lock()
	d.reassembly.limits.Lifetime = 20 * time.Millisecond
	d.reassembly.mu.Unlock()
	first, last := splitIngressIPv4(ingressUDP([]byte("abcdefgh12345678"), 41000, ingressPort), 16)
	sendIngress(t, d, first)
	time.Sleep(50 * time.Millisecond)
	sendIngress(t, d, first) // expired entry: Time Exceeded, then held again
	out := readIngressOutput(t, d, time.Second)
	if len(out) < 56 || out[20] != 11 || out[21] != 1 {
		t.Fatalf("expiry on Write: %x", out)
	}
	sendIngress(t, d, last)
	if err := pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 32)
	if n, _, err := pc.ReadFrom(b); err != nil || string(b[:n]) != "abcdefgh12345678" {
		t.Fatalf("datagram after retried fragment = %q/%v", b[:n], err)
	}
}

func TestIngressMalformedOptionParameterProblem(t *testing.T) {
	d := ingressDevice(t)
	base := ingressUDP([]byte("abcdefgh"), 41000, ingressPort)
	first := append([]byte(nil), base[:20]...)
	first[0] = 0x46                      // IHL 24
	first = append(first, 0x82, 1, 0, 0) // invalid copied-option length at byte 20
	first = append(first, base[20:]...)
	binary.BigEndian.PutUint16(first[2:4], uint16(len(first)))
	binary.BigEndian.PutUint16(first[6:8], 0x2000)
	ipv4SetChecksum(first[:24])
	sendIngress(t, d, first)
	out := readIngressOutput(t, d, time.Second)
	if len(out) < 60 || out[9] != 1 || out[20] != 12 || out[21] != 0 || out[24] != 20 ||
		!bytes.Equal(out[28:60], first[:32]) {
		t.Fatalf("Parameter Problem/quote = %x", out)
	}
}

func TestIngressLaterOptionConflictDoesNotQuoteFirst(t *testing.T) {
	d := ingressDevice(t)
	first := reasmIPv4Fragment(17, 77, 0, true, 0, []byte{0x82, 4, 7, 8}, []byte("abcdefgh"))
	later := reasmIPv4Fragment(17, 77, 8, false, 0, []byte{0x83, 4, 7, 8}, []byte("x"))
	// Use the Device's local destination, not the reassembly fixture's default.
	copy(first[16:20], ingressLocal.AsSlice())
	copy(later[16:20], ingressLocal.AsSlice())
	ipv4SetChecksum(first[:24])
	ipv4SetChecksum(later[:24])
	sendIngress(t, d, first)
	sendIngress(t, d, later)
	if got := d.ep.NumQueued(); got != 0 {
		t.Fatalf("later fragment caused ICMP output: %d", got)
	}
}

func TestIngressNonlocalTimeoutHasNoFalseLocalICMP(t *testing.T) {
	d := ingressDevice(t)
	d.reassembly.mu.Lock()
	d.reassembly.limits.Lifetime = 20 * time.Millisecond
	d.reassembly.mu.Unlock()
	first, _ := splitIngressIPv4(ingressUDP([]byte("abcdefgh12345678"), 41000, ingressPort), 16)
	copy(first[16:20], []byte{10, 1, 1, 99})
	ipv4SetChecksum(first[:20])
	sendIngress(t, d, first)
	waitIngressEmpty(t, d)
	if got := d.ep.NumQueued(); got != 0 {
		t.Fatalf("nonlocal timeout caused ICMP output: %d", got)
	}
}

func TestIngressTimeoutSuppressesNoninitialAndICMPError(t *testing.T) {
	for _, tc := range []struct {
		name   string
		packet []byte
	}{
		{name: "noninitial", packet: reasmIPv4Fragment(17, 81, 8, true, 0, nil, []byte("abcdefgh"))},
		{name: "ICMP error", packet: reasmIPv4Fragment(1, 82, 0, true, 0, nil, []byte{3, 3, 0, 0, 0, 0, 0, 0})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := ingressDevice(t)
			d.reassembly.mu.Lock()
			d.reassembly.limits.Lifetime = 20 * time.Millisecond
			d.reassembly.mu.Unlock()
			copy(tc.packet[16:20], ingressLocal.AsSlice())
			ipv4SetChecksum(tc.packet[:20])
			sendIngress(t, d, tc.packet)
			waitIngressEmpty(t, d)
			if got := d.ep.NumQueued(); got != 0 {
				t.Fatalf("suppressed timeout emitted %d packets", got)
			}
		})
	}
}

// A refused fragment is a network-layer drop. It is not a Write error, so it
// neither hides later packets in the batch nor makes wireguard-go log a line.
func TestIngressBatchContinuesAfterRefusedFragment(t *testing.T) {
	for _, name := range []string{"malformed", "capacity", "overlap", "option"} {
		t.Run(name, func(t *testing.T) {
			d := ingressDevice(t)
			pc, err := d.ListenUDP(netip.AddrPortFrom(ingressLocal, ingressPort))
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			bad, _ := splitIngressIPv4(ingressUDP([]byte("abcdefgh12345678"), 41000, ingressPort), 16)
			batch := [][]byte{bad}
			switch name {
			case "malformed":
				bad[10] ^= 1 // checksum failure; no ICMP output obscures the result.
			case "capacity":
				// Leave space for metadata but none for a fragment payload.
				d.reassembly.mu.Lock()
				d.reassembly.limits.Bytes = d.reassembly.baseCost
				d.reassembly.mu.Unlock()
			case "overlap":
				over := reasmIPv4Fragment(17, 4242, 8, false, 0, nil, []byte("xxxxxxxxxxxx"))
				copy(over[12:20], bad[12:20])
				ipv4SetChecksum(over[:20])
				batch = append(batch, over)
			case "option":
				// A later fragment with a non-copied option to a nonlocal
				// address: refused, and no ICMP for a nonlocal destination.
				opt := reasmIPv4Fragment(17, 5, 8, false, 0, []byte{0x44, 4, 5, 0}, []byte("x"))
				batch = [][]byte{opt}
			}
			good := ingressUDP([]byte("after-bad"), 41000, ingressPort)
			batch = append(batch, good)
			n, err := d.Write(batch, 0)
			if n != len(batch) || err != nil {
				t.Fatalf("batch accepted/error = %d/%v, want %d/nil", n, err, len(batch))
			}
			if err := pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 32)
			if n, _, err := pc.ReadFrom(b); err != nil || string(b[:n]) != "after-bad" {
				t.Fatalf("later good packet = %q/%v", b[:n], err)
			}
			if got := d.ep.NumQueued(); got != 0 {
				t.Fatalf("refused fragment emitted %d packets", got)
			}
		})
	}
}

// A non-IPv4 packet stays a Write error, as before, but no longer hides the
// rest of the batch.
func TestIngressNonIPv4KeepsBatch(t *testing.T) {
	d := ingressDevice(t)
	pc, err := d.ListenUDP(netip.AddrPortFrom(ingressLocal, ingressPort))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	v6 := make([]byte, 40)
	v6[0] = 0x60
	n, err := d.Write([][]byte{v6, ingressUDP([]byte("v4"), 41000, ingressPort)}, 0)
	if n != 1 || err == nil {
		t.Fatalf("batch with IPv6 = %d/%v, want 1/EAFNOSUPPORT", n, err)
	}
	if err := pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 8)
	if n, _, err := pc.ReadFrom(b); err != nil || string(b[:n]) != "v4" {
		t.Fatalf("IPv4 after IPv6 = %q/%v", b[:n], err)
	}
}

// A table full of incomplete datagrams must not stop a legitimate fragmented
// datagram whose fragments arrive back to back: the oldest entries are
// evicted silently (no ICMP) and the datagram reaches the listener.
func TestIngressFullReassemblyTableEvictsForLegitDatagram(t *testing.T) {
	for _, tc := range []struct {
		name          string
		keys, perKey  int
		wantEvictions uint64
	}{
		{name: "keys", keys: reassemblyEntries, perKey: 1, wantEvictions: 1},
		// Fewer keys than the key limit hold every slot.
		{name: "slots", keys: reassemblyFragments / 32, perKey: 32, wantEvictions: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := ingressDevice(t)
			pc, err := d.ListenUDP(netip.AddrPortFrom(ingressLocal, ingressPort))
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			for k := 0; k < tc.keys; k++ {
				for f := 0; f < tc.perKey; f++ {
					// Offsets skip every other 8-byte block, so no key completes.
					sendIngress(t, d, reasmIPv4Fragment(99, uint16(2000+k), 16*f, true, 0, nil, []byte("pppppppp")))
				}
			}
			_, entries, pieces := d.reassembly.Usage()
			if entries != tc.keys || pieces != tc.keys*tc.perKey || d.reassembly.Evicted() != 0 {
				t.Fatalf("filled table: entries %d pieces %d evicted %d", entries, pieces, d.reassembly.Evicted())
			}
			first, last := splitIngressIPv4(ingressUDP([]byte("abcdefgh12345678"), 41000, ingressPort), 16)
			sendIngress(t, d, first)
			sendIngress(t, d, last)
			if err := pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 32)
			if n, _, err := pc.ReadFrom(b); err != nil || !bytes.Equal(b[:n], []byte("abcdefgh12345678")) {
				t.Fatalf("legit datagram in a full table = %q/%v", b[:n], err)
			}
			if got := d.reassembly.Evicted(); got != tc.wantEvictions {
				t.Fatalf("evicted = %d, want %d", got, tc.wantEvictions)
			}
			if got := d.ep.NumQueued(); got != 0 {
				t.Fatalf("eviction emitted %d packets", got)
			}
		})
	}
}
