package nettun

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

func shortOptionFragment(local bool, payloadSize int) []byte {
	p := make([]byte, 24+payloadSize)
	p[0], p[8], p[9] = 0x46, 64, 99
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:], 700)
	binary.BigEndian.PutUint16(p[6:], 1) // noninitial, final fragment
	copy(p[12:16], []byte{10, 99, 0, 2})
	if local {
		copy(p[16:20], []byte{10, 99, 0, 1})
	} else {
		copy(p[16:20], []byte{10, 1, 1, 2})
	}
	copy(p[20:24], []byte{0x82, 1, 0, 0}) // malformed option length, as in the parity fixture
	for i := 24; i < len(p); i++ {
		p[i] = byte(i)
	}
	shortSetChecksum(p[:24])
	return p
}

func shortSetChecksum(h []byte) {
	var sum uint32
	for i := 0; i < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(h[10:], ^uint16(sum))
}

// A noninitial final fragment with a malformed copied option and a short
// payload. The expected values are those of the pinned gVisor path, which
// handled every fragment before the finite reassembly.
func TestICMPShortOptionComparison(t *testing.T) {
	for _, tc := range []struct {
		name       string
		local      bool
		size       int
		wantOutput int // ICMP packet length; 0 means no ICMP
	}{
		{"nonlocal_short", false, 1, 0},
		{"local_short", true, 1, 53},
		{"nonlocal_eight", false, 8, 0},
		{"local_eight", true, 8, 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Create(netip.MustParseAddr("10.99.0.1"), 1420)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			out := make(chan []byte, 1)
			readDone := make(chan struct{})
			go func() {
				defer close(readDone)
				b := make([]byte, 1500)
				sizes := []int{0}
				n, e := d.Read([][]byte{b}, sizes, 0)
				if n == 1 && e == nil {
					out <- append([]byte(nil), b[:sizes[0]]...)
				}
			}()
			p := shortOptionFragment(tc.local, tc.size)
			type writeResult struct {
				N   int
				Err string
			}
			written := make(chan writeResult, 1)
			go func() {
				n, e := d.Write([][]byte{p}, 0)
				r := writeResult{N: n}
				if e != nil {
					r.Err = e.Error()
				}
				written <- r
			}()
			var wr writeResult
			select {
			case wr = <-written:
			case <-time.After(time.Second):
				t.Fatal("Write blocked")
			}
			var response []byte
			select {
			case response = <-out:
			case <-time.After(20 * time.Millisecond):
			}
			result := map[string]any{"case": tc.name, "accepted": wr.N, "write_error": wr.Err, "output_length": len(response), "param_sent": d.stack.Stats().ICMP.V4.PacketsSent.ParamProblem.Value(), "type": -1, "code": -1, "pointer": -1, "quote_length": 0, "quote_matches": false, "checksum_ok": false}
			if len(response) >= 28 {
				result["type"] = int(response[20])
				result["code"] = int(response[21])
				result["pointer"] = int(response[24])
				result["quote_length"] = len(response) - 28
				result["quote_matches"] = len(response)-28 == len(p) && string(response[28:]) == string(p)
				result["checksum_ok"] = checksum.Checksum(response[20:], 0) == 0xffff
			}
			line, _ := json.Marshal(result)
			t.Logf("SHORTCOMPARE %s", line)
			wantSent := uint64(0)
			if tc.wantOutput != 0 {
				wantSent = 1
			}
			if wr.N != 1 || wr.Err != "" || len(response) != tc.wantOutput || result["param_sent"] != wantSent ||
				(tc.wantOutput != 0 && (result["type"] != 12 || result["code"] != 0 || result["pointer"] != 20 ||
					result["quote_matches"] != true || result["checksum_ok"] != true)) {
				t.Errorf("short option response differs from the pinned stack: %s", line)
			}
			d.Close()
			select {
			case <-readDone:
			case <-time.After(time.Second):
				t.Fatal("Read did not close")
			}
		})
	}
}
