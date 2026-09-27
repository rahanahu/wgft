package nettun

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

// The expected values are those of the pinned gVisor path, which handled
// every fragment before the finite reassembly (recorded with the same inputs).
func TestICMPParityEdgeQuote(t *testing.T) {
	for _, tc := range []struct {
		name             string
		payload, linkMTU int
		wantOutput       int // ICMP packet length; the quote is 28 bytes shorter
	}{
		{"quote_cap_aligned", 704, 1420, 576},
		{"nonaligned_option", 700, 1420, 576},
		{"mtu_80", 64, 80, 80},
		{"mtu_68", 64, 68, 68},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Create(netip.MustParseAddr("10.99.0.1"), 1420)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			d.ep.SetMTU(uint32(tc.linkMTU))
			p := parityMalformedFirst(tc.payload, 17, [4]byte{10, 99, 0, 2}, [4]byte{10, 99, 0, 1})
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
				t.Fatal("Write did not finish with a concurrent Read")
			}
			var response []byte
			select {
			case response = <-recv:
			case <-time.After(time.Second):
			}
			result := map[string]any{"case": tc.name, "link_mtu": tc.linkMTU, "input_length": len(p), "accepted": wr.N, "write_error": wr.Err, "outputs": 0, "quote_length": 0, "quote_matches": false, "checksum_ok": false}
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
			line, _ := json.Marshal(result)
			t.Logf("EDGE_QUOTE %s", line)
			if wr.N != 1 || wr.Err != "" || len(response) != tc.wantOutput ||
				result["type"] != 12 || result["code"] != 0 || result["pointer"] != 20 ||
				result["quote_matches"] != true || result["checksum_ok"] != true ||
				result["param_sent"] != uint64(1) || result["dropped"] != uint64(0) {
				t.Errorf("edge quote differs from the pinned stack: %s", line)
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
