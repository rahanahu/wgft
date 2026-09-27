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

type parityResult struct {
	Case         string `json:"case"`
	Accepted     int    `json:"accepted"`
	WriteError   string `json:"write_error"`
	Outputs      int    `json:"outputs"`
	Type         int    `json:"type"`
	Code         int    `json:"code"`
	Pointer      int    `json:"pointer"`
	QuoteLength  int    `json:"quote_length"`
	QuoteMatches bool   `json:"quote_matches"`
	ChecksumOK   bool   `json:"checksum_ok"`
	ParamSent    uint64 `json:"param_sent"`
	RateLimited  uint64 `json:"rate_limited"`
}

func parityMalformedFirst(payloadLen int, proto byte, src, dst [4]byte) []byte {
	p := make([]byte, 24+payloadLen)
	p[0] = 0x46
	p[8] = 64
	p[9] = proto
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], 123)
	binary.BigEndian.PutUint16(p[6:8], 0x2000)
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	copy(p[20:24], []byte{0x82, 1, 0, 0})
	for i := 24; i < len(p); i++ {
		p[i] = byte(i)
	}
	if proto == 1 {
		p[24] = 3
		p[25] = 3
	} // ICMP Destination Unreachable
	h := header.IPv4(p)
	h.SetChecksum(^h.CalculateChecksum())
	return p
}

func TestICMPParityProbe(t *testing.T) {
	local := [4]byte{10, 99, 0, 1}
	remote := [4]byte{10, 99, 0, 2}
	for _, tc := range []struct {
		name     string
		payload  int
		proto    byte
		src, dst [4]byte
		noRoute  bool
		burst    int
		repeat   int
	}{
		{name: "normal8", payload: 8, proto: 17, src: remote, dst: local, burst: -1, repeat: 1},
		{name: "long64", payload: 64, proto: 17, src: remote, dst: local, burst: -1, repeat: 1},
		{name: "source0", payload: 8, proto: 17, src: [4]byte{}, dst: local, burst: -1, repeat: 1},
		{name: "icmp_error", payload: 8, proto: 1, src: remote, dst: local, burst: -1, repeat: 1},
		{name: "multicast", payload: 8, proto: 17, src: remote, dst: [4]byte{224, 0, 0, 1}, burst: -1, repeat: 1},
		{name: "route_missing", payload: 8, proto: 17, src: remote, dst: local, noRoute: true, burst: -1, repeat: 1},
		{name: "rate0", payload: 8, proto: 17, src: remote, dst: local, burst: 0, repeat: 1},
		{name: "rate1_two", payload: 8, proto: 17, src: remote, dst: local, burst: 1, repeat: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Create(netip.MustParseAddr("10.99.0.1"), 1420)
			if err != nil {
				t.Fatal(err)
			}
			if tc.noRoute {
				d.stack.SetRouteTable(nil)
			}
			if tc.burst >= 0 {
				d.stack.SetICMPBurst(tc.burst)
			}
			output := make(chan []byte, 4)
			readerDone := make(chan struct{})
			go func() {
				defer close(readerDone)
				for {
					b := make([]byte, 1500)
					sizes := []int{0}
					n, e := d.Read([][]byte{b}, sizes, 0)
					if e != nil {
						return
					}
					if n == 1 {
						output <- append([]byte(nil), b[:sizes[0]]...)
					}
				}
			}()
			p := parityMalformedFirst(tc.payload, tc.proto, tc.src, tc.dst)
			result := parityResult{Case: tc.name, Type: -1, Code: -1, Pointer: -1}
			writeDone := make(chan struct{})
			go func() {
				defer close(writeDone)
				for i := 0; i < tc.repeat; i++ {
					n, e := d.Write([][]byte{p}, 0)
					result.Accepted += n
					if e != nil {
						result.WriteError = e.Error()
					}
				}
			}()
			select {
			case <-writeDone:
			case <-time.After(time.Second):
				d.Close()
				t.Fatal("Write blocked")
			}
			time.Sleep(20 * time.Millisecond)
			drained := false
			for !drained {
				select {
				case b := <-output:
					result.Outputs++
					if result.Outputs == 1 && len(b) >= 28 {
						result.Type = int(b[20])
						result.Code = int(b[21])
						result.Pointer = int(b[24])
						result.QuoteLength = len(b) - 28
						result.QuoteMatches = result.QuoteLength <= len(p) && string(b[28:]) == string(p[:result.QuoteLength])
						result.ChecksumOK = checksum.Checksum(b[20:], 0) == 0xffff
					}
				default:
					drained = true
				}
			}
			stats := d.stack.Stats().ICMP.V4.PacketsSent
			result.ParamSent = stats.ParamProblem.Value()
			result.RateLimited = stats.RateLimited.Value()
			wantOutputs, wantQuote, wantSent, wantRate := 0, 0, uint64(0), uint64(0)
			switch tc.name {
			case "normal8", "rate1_two":
				wantOutputs, wantQuote, wantSent = 1, 32, 1
			case "long64":
				wantOutputs, wantQuote, wantSent = 1, 88, 1
			}
			if tc.name == "rate0" || tc.name == "rate1_two" {
				wantRate = 1
			}
			if result.Accepted != tc.repeat || result.WriteError != "" ||
				result.Outputs != wantOutputs || result.QuoteLength != wantQuote ||
				result.ParamSent != wantSent || result.RateLimited != wantRate {
				t.Fatalf("fixed-baseline parity: %+v", result)
			}
			if wantOutputs != 0 && (result.Type != 12 || result.Code != 0 || result.Pointer != 20 || !result.QuoteMatches || !result.ChecksumOK) {
				t.Fatalf("bad Parameter Problem output: %+v", result)
			}
			d.Close()
			select {
			case <-readerDone:
			case <-time.After(time.Second):
				t.Fatal("Read did not close")
			}
			line, _ := json.Marshal(result)
			t.Logf("PARITY %s", line)
		})
	}
}
