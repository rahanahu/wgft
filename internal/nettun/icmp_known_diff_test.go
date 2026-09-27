package nettun

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

// knownDiffFragments returns a first fragment carrying firstOpts and a final
// later fragment carrying laterOpts, both UDP from 10.99.0.2 to the Device
// address 10.99.0.1 port ingressPort. The datagram carries 16 payload bytes.
func knownDiffFragments(firstOpts, laterOpts []byte) (first, later []byte) {
	fh := 20 + len(firstOpts)
	first = make([]byte, fh+16)
	first[0], first[8], first[9] = 0x40|byte(fh/4), 64, 17
	binary.BigEndian.PutUint16(first[2:], uint16(len(first)))
	binary.BigEndian.PutUint16(first[4:], 901)
	binary.BigEndian.PutUint16(first[6:], 0x2000)
	copy(first[12:16], []byte{10, 99, 0, 2})
	copy(first[16:20], []byte{10, 99, 0, 1})
	copy(first[20:], firstOpts)
	binary.BigEndian.PutUint16(first[fh:], 41000)
	binary.BigEndian.PutUint16(first[fh+2:], ingressPort)
	binary.BigEndian.PutUint16(first[fh+4:], 8+8+8)
	copy(first[fh+8:], "abcdefgh")
	shortSetChecksum(first[:fh])

	lh := 20 + len(laterOpts)
	later = make([]byte, lh+8)
	later[0], later[8], later[9] = 0x40|byte(lh/4), 64, 17
	binary.BigEndian.PutUint16(later[2:], uint16(len(later)))
	binary.BigEndian.PutUint16(later[4:], 901)
	binary.BigEndian.PutUint16(later[6:], 2) // offset 16, final
	copy(later[12:16], []byte{10, 99, 0, 2})
	copy(later[16:20], []byte{10, 99, 0, 1})
	copy(later[20:], laterOpts)
	copy(later[lh:], "ijklmnop")
	shortSetChecksum(later[:lh])
	return first, later
}

// The finite reassembly checks options itself and differs from the pinned
// gVisor in three known cases (design section 7). The pinned values below
// were recorded by giving the same inputs to the path in which gVisor
// handled every fragment. This test pins the present behavior instead.
//
//   - A later fragment with a non-copied option: the pinned path answered
//     timestamp_bad_flags with pointer 23, the flags byte, and completed the
//     datagram for the two well-formed options without ICMP. Here the later
//     fragment is refused with Parameter Problem pointer 20, the option type
//     byte, quoting that fragment, and the datagram does not complete.
//   - A first fragment with a well-sized non-copied option whose content is
//     invalid: the pinned path refused the first fragment at once with
//     Parameter Problem pointer 23 quoting it, 40 bytes. Here the first
//     fragment is held; once the datagram completes gVisor refuses it with
//     pointer 23 quoting the completed datagram, 48 bytes. The datagram is
//     not delivered in either path.
func TestICMPKnownDifferencesFromPinnedStack(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		firstOpts, laterOpts []byte
		wantPointer          int
		quoteCompleted       bool // the quote is the completed datagram, not the later fragment
	}{
		// Timestamp with invalid flags 2: the pinned stack points at the flags byte, 23.
		{"timestamp_bad_flags", nil, []byte{0x44, 4, 1, 2}, 20, false},
		// A well-formed non-copied Timestamp and Record Route on a later fragment.
		{"timestamp_valid", nil, []byte{0x44, 4, 5, 0}, 20, false},
		{"record_route_valid", nil, []byte{0x07, 7, 4, 0, 0, 0, 0, 0}, 20, false},
		// The invalid Timestamp on the first fragment instead.
		{"first_timestamp_bad_flags", []byte{0x44, 4, 1, 2}, nil, 23, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Create(netip.MustParseAddr("10.99.0.1"), 1420)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			pc, err := d.ListenUDP(netip.AddrPortFrom(netip.MustParseAddr("10.99.0.1"), ingressPort))
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			out := make(chan []byte, 4)
			readDone := make(chan struct{})
			go func() {
				defer close(readDone)
				for {
					b := make([]byte, 1500)
					sizes := []int{0}
					n, e := d.Read([][]byte{b}, sizes, 0)
					if e != nil {
						return
					}
					if n == 1 {
						out <- append([]byte(nil), b[:sizes[0]]...)
					}
				}
			}()
			first, later := knownDiffFragments(tc.firstOpts, tc.laterOpts)
			var writeErrs []string
			for _, p := range [][]byte{first, later} {
				if n, e := d.Write([][]byte{p}, 0); n != 1 || e != nil {
					writeErrs = append(writeErrs, e.Error())
				}
			}
			if err := pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 64)
			n, _, rerr := pc.ReadFrom(b)
			delivered := rerr == nil && string(b[:n]) == "abcdefghijklmnop"
			result := map[string]any{"case": tc.name, "write_errors": len(writeErrs), "delivered": delivered, "outputs": 0, "type": -1, "code": -1, "pointer": -1, "quote_length": 0, "quote_matches": false, "checksum_ok": false}
			var response []byte
			select {
			case response = <-out:
			case <-time.After(50 * time.Millisecond):
			}
			wantQuote := later
			if tc.quoteCompleted {
				fh := 20 + len(tc.firstOpts)
				wantQuote = append(append([]byte(nil), first[:fh+16]...), later[len(later)-8:]...)
			}
			if len(response) >= 28 {
				result["outputs"] = 1
				result["type"] = int(response[20])
				result["code"] = int(response[21])
				result["pointer"] = int(response[24])
				result["quote_length"] = len(response) - 28
				q := response[28:]
				if tc.quoteCompleted {
					// A completed header differs from the first fragment in
					// total length, flags and checksum; compare everything else.
					result["quote_matches"] = len(q) == len(wantQuote) &&
						string(q[:2]) == string(wantQuote[:2]) && string(q[4:6]) == string(wantQuote[4:6]) &&
						string(q[8:10]) == string(wantQuote[8:10]) && string(q[12:]) == string(wantQuote[12:])
				} else {
					result["quote_matches"] = string(q) == string(wantQuote)
				}
				result["checksum_ok"] = checksum.Checksum(response[20:], 0) == 0xffff
			}
			line, _ := json.Marshal(result)
			t.Logf("KNOWNDIFF %s", line)
			if len(writeErrs) != 0 || delivered || result["outputs"] != 1 || result["type"] != 12 ||
				result["code"] != 0 || result["pointer"] != tc.wantPointer || result["quote_matches"] != true ||
				result["checksum_ok"] != true {
				t.Errorf("known difference changed: %s", line)
			}
			d.Close()
			<-readDone
		})
	}
}

// With only the first fragment of the third known difference, the pinned
// path answered Parameter Problem at once. Here the fragment is held without
// ICMP, and at expiry it yields Time Exceeded like any held first fragment.
// The lifetime is shortened for the test.
func TestICMPKnownDifferenceFirstFragmentAlone(t *testing.T) {
	d := ingressDevice(t)
	d.reassembly.mu.Lock()
	d.reassembly.limits.Lifetime = 300 * time.Millisecond
	d.reassembly.mu.Unlock()
	first, _ := knownDiffFragments([]byte{0x44, 4, 1, 2}, nil)
	sendIngress(t, d, first)
	if got := d.ep.NumQueued(); got != 0 {
		t.Fatalf("held first fragment emitted %d packets at once", got)
	}
	out := readIngressOutput(t, d, 3*time.Second)
	if len(out) < 20+8+32 || out[9] != 1 || out[20] != 11 || out[21] != 1 ||
		string(out[28:28+32]) != string(first[:32]) {
		t.Fatalf("expiry of the held first fragment = %x", out)
	}
}
