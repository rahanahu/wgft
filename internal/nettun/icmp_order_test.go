package nettun

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// The expected values are those of the pinned gVisor path, which handled
// every fragment before the finite reassembly (recorded with the same inputs).
func TestICMPCompoundValidationOrder(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		payload                 int
		badChecksum, noninitial bool
	}{
		{name: "aligned_option", payload: 704},
		{name: "compound_option_alignment", payload: 700},
		{name: "compound_bad_checksum", payload: 700, badChecksum: true},
		{name: "noninitial_compound", payload: 700, noninitial: true},
		{name: "noninitial_alignment_only", payload: 700, noninitial: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Create(netip.MustParseAddr("10.99.0.1"), 1420)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			p := parityMalformedFirst(tc.payload, 17, [4]byte{10, 99, 0, 2}, [4]byte{10, 99, 0, 1})
			if tc.name == "noninitial_alignment_only" {
				copy(p[20:24], []byte{0, 0, 0, 0})
			}
			if tc.noninitial {
				binary.BigEndian.PutUint16(p[6:8], 0x2001)
				h := header.IPv4(p)
				h.SetChecksum(0)
				h.SetChecksum(^h.CalculateChecksum())
			}
			if tc.badChecksum {
				p[8] ^= 1
			}
			recv := make(chan []byte, 1)
			readDone := make(chan struct{})
			go func() {
				defer close(readDone)
				b := make([]byte, 1500)
				sizes := []int{0}
				n, e := d.Read([][]byte{b}, sizes, 0)
				if n == 1 && e == nil {
					recv <- append([]byte(nil), b[:sizes[0]]...)
				}
			}()
			type writeResult struct {
				N   int
				Err string
			}
			done := make(chan writeResult, 1)
			go func() {
				n, e := d.Write([][]byte{p}, 0)
				r := writeResult{N: n}
				if e != nil {
					r.Err = e.Error()
				}
				done <- r
			}()
			var wr writeResult
			select {
			case wr = <-done:
			case <-time.After(3 * time.Second):
				d.Close()
				t.Fatal("Write did not finish")
			}
			var response []byte
			select {
			case response = <-recv:
			case <-time.After(100 * time.Millisecond):
			}
			result := map[string]any{"case": tc.name, "accepted": wr.N, "write_error": wr.Err, "outputs": 0, "quote_length": 0, "quote_matches": false, "checksum_ok": false}
			if len(response) != 0 {
				result["outputs"] = 1
				result["output_length"] = len(response)
				if len(response) >= 28 {
					qlen := len(response) - 28
					result["quote_length"] = qlen
					result["quote_matches"] = qlen <= len(p) && string(response[28:]) == string(p[:qlen])
					result["checksum_ok"] = checksum.Checksum(response[20:], 0) == 0xffff
					result["type"] = int(response[20])
					result["code"] = int(response[21])
					result["pointer"] = int(response[24])
				}
			}
			result["param_sent"] = d.stack.Stats().ICMP.V4.PacketsSent.ParamProblem.Value()
			result["dropped"] = d.stack.Stats().ICMP.V4.PacketsSent.Dropped.Value()
			// The pinned stack checks options before reassembly even for a
			// noninitial fragment, but alignment alone produces no response.
			wantOutput := !tc.badChecksum && tc.name != "noninitial_alignment_only"
			if (len(response) != 0) != wantOutput {
				t.Errorf("ICMP output=%v, want=%v", len(response) != 0, wantOutput)
			}
			if len(response) != 0 && (result["type"] != 12 || result["code"] != 0 || result["pointer"] != 20 || result["quote_matches"] != true || result["checksum_ok"] != true) {
				t.Errorf("bad Parameter Problem output: %v", result)
			}
			line, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("ORDER %s", line)
			d.Close()
			select {
			case <-readDone:
			case <-time.After(time.Second):
				t.Fatal("Read did not close")
			}
		})
	}
}
