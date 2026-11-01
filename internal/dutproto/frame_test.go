package dutproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/frames from the examples")

// examples has one message of every kind, with fields that are not zero where the kind has any,
// so a field's place or width shows in the bytes.
func examples() []Msg {
	seed := make(Bytes, SeedLen)
	for i := range seed {
		seed[i] = byte(i*7 + 1)
	}
	peer := netip.MustParseAddrPort("10.200.0.1:40001")
	syn := Bytes{0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, 10, 200, 0, 1, 10, 200, 0, 2,
		0x9c, 0x41, 0, 80, 0, 0, 0, 100, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0}
	return []Msg{
		&Hello{Version: Version, Clock: ClockFake, Addr: netip.MustParseAddr("10.200.0.2"), MTU: 1420, Seed: seed,
			Limits: []Limit{}, Boost: BoostAtAccept, Congestion: CongestionNewReno},
		&Hello{Version: Version, Clock: ClockReal, Addr: netip.MustParseAddr("10.200.0.2"), MTU: 1280, Seed: seed,
			Limits: []Limit{{Name: "maxFlows", Value: 8}, {Name: "acceptQ", Value: 4}}},
		&Inject{Packets: []Bytes{syn, {1, 2, 3}}},
		&Poll{Max: 1},
		&Advance{D: 1500 * time.Microsecond},
		&Now{},
		&TCPListen{Port: 8011},
		&UDPListen{Port: 5353},
		&Accept{handleBody{H: 1}},
		&Read{H: 2, Max: 65536},
		&Write{H: 2, Data: Bytes("after")},
		&Close{handleBody{H: 2}},
		&CloseWrite{handleBody{H: 2}},
		&Abort{handleBody{H: 2}},
		&CloseForDelivery{handleBody{H: 2}},
		&Delivered{handleBody{H: 2}},
		&BoostPolicy{H: 2, Floor: true},
		&Events{},
		&UDPRecv{H: 3, Max: 65507},
		&UDPSend{H: 3, To: peer, Data: Bytes("reply")},
		&PingOpen{To: netip.MustParseAddr("10.200.0.1")},
		&PingSend{H: 4, Data: Bytes{8, 0, 0, 0, 0, 1, 0, 1}},
		&PingRecv{H: 4, Max: 1500},
		&PingClose{handleBody{H: 4}},
		&Stats{},
		&Bound{},
		&Held{},
		&RTOAt{H: 2, At: 3 * time.Second},
		&ConnSocket{H: 2, Path: "/tmp/qbench/conn-2.sock"},
		&HelloOK{Engine: "wgstack", Version: Version},
		&OK{},
		&Error{Err: ErrReset, Msg: "read tcp 10.200.0.2:8011->10.200.0.1:40001: connection reset by peer"},
		&WouldBlock{},
		&Packets{Packets: []Bytes{syn}},
		&Packets{Packets: []Bytes{}},
		&Time{Now: 35 * time.Second},
		&HandleResp{handleBody{H: 7}},
		&Accepted{H: 2, Remote: peer},
		&Data{Data: Bytes("bye")},
		&Wrote{N: 1000},
		&Bool{V: true},
		&EventList{Events: []BoostEvent{{H: 2, Boosted: true}, {H: 5, Boosted: false}}},
		&Datagram{From: peer, Data: Bytes("hello")},
		&Text{S: "Conns=1 SynRows=0"},
		&RTO{Known: true, RTO: 200 * time.Millisecond},
	}
}

// exampleName is the file name of the i-th example: its kind, and a number when the kind has
// more than one example.
func exampleNames(ms []Msg) []string {
	seen := map[Kind]int{}
	names := make([]string, len(ms))
	for i, m := range ms {
		seen[m.Kind()]++
		names[i] = strings.ToLower(m.Kind().String())
		if n := seen[m.Kind()]; n > 1 {
			names[i] += "-" + string(rune('0'+n))
		}
	}
	return names
}

// fixture is the JSON beside each frame example: the kind and the message's fields, so another
// language's codec can build the message and compare its bytes with the .bin file.
type fixture struct {
	Kind     string          `json:"kind"`
	KindByte uint8           `json:"kind_byte"`
	Msg      json.RawMessage `json:"msg"`
	Display  string          `json:"display"`
}

// TestFrameExamples checks every example against testdata/frames: the frame's bytes, the JSON of
// its fields and its display. With -update it writes them. A Rust codec reads the same files.
func TestFrameExamples(t *testing.T) {
	dir := filepath.Join("testdata", "frames")
	ms := examples()
	names := exampleNames(ms)
	if *update {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for i, m := range ms {
		frame := AppendFrame(nil, m)
		js, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		fx, err := json.MarshalIndent(fixture{Kind: m.Kind().String(), KindByte: uint8(m.Kind()), Msg: js, Display: Format(m)}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		fx = append(fx, '\n')
		bin, js1 := filepath.Join(dir, names[i]+".bin"), filepath.Join(dir, names[i]+".json")
		if *update {
			if err := os.WriteFile(bin, frame, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(js1, fx, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(bin)
		if err != nil {
			t.Fatalf("%v; run go test ./internal/dutproto -run TestFrameExamples -update", err)
		}
		if !bytes.Equal(frame, want) {
			t.Errorf("%s: frame\n got %x\nwant %x", names[i], frame, want)
		}
		wantJS, err := os.ReadFile(js1)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(fx, wantJS) {
			t.Errorf("%s: fixture\n got %s\nwant %s", names[i], fx, wantJS)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2*len(ms) {
		t.Errorf("%s has %d files, want a .bin and a .json for each of the %d examples; run with -update", dir, len(entries), len(ms))
	}
}

// TestExamplesCoverEveryKind keeps the examples in step with the kinds.
func TestExamplesCoverEveryKind(t *testing.T) {
	have := map[Kind]bool{}
	for _, m := range examples() {
		have[m.Kind()] = true
	}
	for k := range makers {
		if !have[k] {
			t.Errorf("no example of %s", k)
		}
	}
	for k := range kindNames {
		if _, ok := makers[k]; !ok {
			t.Errorf("%s has a name and no decoder", k)
		}
	}
}

// TestRoundTrip decodes each example's frame back to the same message, from the frame and from
// its JSON.
func TestRoundTrip(t *testing.T) {
	for _, m := range examples() {
		got, err := ReadMsg(bytes.NewReader(AppendFrame(nil, m)))
		if err != nil {
			t.Fatalf("%s: %v", Format(m), err)
		}
		if !reflect.DeepEqual(got, m) {
			t.Errorf("%s: decoded %s", Format(m), Format(got))
		}
		js, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		back := makers[m.Kind()]()
		if err := json.Unmarshal(js, back); err != nil {
			t.Fatalf("%s: %v", js, err)
		}
		if !reflect.DeepEqual(back, m) {
			t.Errorf("%s: from JSON %s", Format(m), Format(back))
		}
	}
}

// TestDecodeRejects checks that a malformed body is a protocol error and that no length in it
// makes the decoder allocate what the body cannot hold.
func TestDecodeRejects(t *testing.T) {
	cases := []struct {
		name string
		k    Kind
		body []byte
	}{
		{"unknown kind", 0x7f, nil},
		{"short", KindRead, []byte{1, 0, 0}},
		{"trailing", KindNow, []byte{0}},
		{"bool byte", KindBool, []byte{2}},
		{"huge byte string", KindData, []byte{0xff, 0xff, 0xff, 0x7f}},
		{"huge list", KindPackets, []byte{0xff, 0xff, 0xff, 0x7f}},
		{"short seed", KindHello, append([]byte{1, 0, 0, 10, 200, 0, 2, 0x8c, 5, 0, 0}, make([]byte, 10)...)},
	}
	for _, c := range cases {
		if _, err := Decode(c.k, c.body); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: Decode returned %v, want a protocol error", c.name, err)
		}
	}
}

// TestReadFrameEnds checks the ends of a stream: EOF only on a frame boundary.
func TestReadFrameEnds(t *testing.T) {
	frame := AppendFrame(nil, &Poll{Max: 1})
	if _, _, err := ReadFrame(bytes.NewReader(nil)); err != io.EOF {
		t.Errorf("empty stream: %v, want EOF", err)
	}
	for cut := 1; cut < len(frame); cut++ {
		if _, _, err := ReadFrame(bytes.NewReader(frame[:cut])); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("frame cut at %d: %v, want unexpected EOF", cut, err)
		}
	}
	if _, _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 0})); !errors.Is(err, ErrProtocol) {
		t.Errorf("zero length: %v, want a protocol error", err)
	}
	if _, _, err := ReadFrame(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff})); !errors.Is(err, ErrProtocol) {
		t.Errorf("huge length: %v, want a protocol error", err)
	}
}

// TestPacketString checks the display of a TCP segment, the form a replay's mismatch report uses.
func TestPacketString(t *testing.T) {
	m := examples()[2].(*Inject)
	got := PacketString(m.Packets[0])
	want := "ipv4 id=1 DF tcp 10.200.0.1:40001>10.200.0.2:80 S seq=100 ack=0 win=65535 len=0"
	if got != want {
		t.Errorf("PacketString = %q, want %q", got, want)
	}
	if got := PacketString(m.Packets[1]); !strings.HasPrefix(got, "raw 3:") {
		t.Errorf("PacketString of 3 bytes = %q", got)
	}
	if !slices.Contains(strings.Fields(Format(&Poll{Max: 1})), "max=1") {
		t.Errorf("Format(Poll) = %q", Format(&Poll{Max: 1}))
	}
}
