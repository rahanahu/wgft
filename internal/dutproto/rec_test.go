package dutproto

import (
	"bytes"
	"compress/gzip"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func sampleFrames() []byte {
	var b []byte
	b = AppendFrame(b, &Hello{Version: Version, Addr: netip.MustParseAddr("10.200.0.2"), MTU: 1420,
		Seed: make(Bytes, SeedLen), Limits: []Limit{}, Boost: BoostNever, Congestion: CongestionNewReno})
	b = AppendFrame(b, &HelloOK{Engine: "wgstack", Version: Version})
	b = AppendFrame(b, &Advance{D: time.Millisecond})
	b = AppendFrame(b, &Time{Now: time.Millisecond})
	return b
}

// TestRecordSameBytes checks that a recording's bytes depend only on its meta and frames: gzip's
// header carries no time and no name.
func TestRecordSameBytes(t *testing.T) {
	meta := RecMeta{Source: "fuzzcore", Name: "x", Test: "FuzzCore", Tags: []string{"newreno"}}
	var a, b bytes.Buffer
	if err := WriteRecord(&a, meta, sampleFrames()); err != nil {
		t.Fatal(err)
	}
	if err := WriteRecord(&b, meta, sampleFrames()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("two writes of the same recording differ")
	}
	zr, err := gzip.NewReader(bytes.NewReader(a.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !zr.ModTime.IsZero() || zr.Name != "" || zr.Comment != "" {
		t.Errorf("gzip header has time %v, name %q, comment %q", zr.ModTime, zr.Name, zr.Comment)
	}
	got, frames, err := ReadRecord(bytes.NewReader(a.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "x" || !slices.Equal(got.Tags, meta.Tags) || !bytes.Equal(frames, sampleFrames()) {
		t.Errorf("read back %+v and %d bytes of frames", got, len(frames))
	}
}

// TestSplitFrames checks the alternation of requests and responses.
func TestSplitFrames(t *testing.T) {
	fr, err := SplitFrames(sampleFrames())
	if err != nil || len(fr) != 4 {
		t.Fatalf("%d frames, %v", len(fr), err)
	}
	bad := [][]byte{
		AppendFrame(nil, &Now{}),                         // a request without response
		AppendFrame(nil, &OK{}),                          // a response first
		append(sampleFrames(), 1, 0),                     // trailing bytes
		AppendFrame(AppendFrame(nil, &Now{}), &Events{}), // two requests
	}
	for i, b := range bad {
		if _, err := SplitFrames(b); !errors.Is(err, ErrProtocol) {
			t.Errorf("case %d: %v, want a protocol error", i, err)
		}
	}
}

// TestTags checks the tag rules on SYN options, other segments' options, protocols, fragments,
// requests and HELLO's choices.
func TestTags(t *testing.T) {
	syn := func(flags byte, opts ...byte) Bytes {
		p := make([]byte, 40+len(opts))
		p[0], p[9] = 0x45, 6
		p[32] = byte((20+len(opts))/4) << 4
		p[33] = flags
		copy(p[40:], opts)
		return p
	}
	sackPerm := []byte{4, 2, 1, 1}
	ts := []byte{8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1}
	ws := []byte{3, 3, 7, 1}
	udp := Bytes{0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	frag := slices.Clone(udp)
	frag[6] = 0x20
	var b []byte
	b = AppendFrame(b, &Hello{Version: Version, Addr: netip.MustParseAddr("10.200.0.2"), Seed: make(Bytes, SeedLen), Limits: []Limit{}, Boost: BoostOnDemand})
	b = AppendFrame(b, &HelloOK{})
	b = AppendFrame(b, &Inject{Packets: []Bytes{syn(0x02, append(append([]byte{}, sackPerm...), ws...)...), syn(0x10, ts...)}})
	b = AppendFrame(b, &OK{})
	fr, err := SplitFrames(b)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := Tags(fr), []string{"boost-on-demand", "cubic", "sack", "ws"}; !slices.Equal(got, want) {
		t.Errorf("Tags = %v, want %v; timestamps outside a SYN are no tag", got, want)
	}
	b = AppendFrame(b, &Inject{Packets: []Bytes{frag, udp, syn(0x12, ts...)}})
	b = AppendFrame(b, &OK{})
	b = AppendFrame(b, &PingOpen{To: netip.MustParseAddr("10.200.0.1")})
	b = AppendFrame(b, &HandleResp{})
	fr, _ = SplitFrames(b)
	if got, want := Tags(fr), []string{"boost-on-demand", "cubic", "frag", "ping", "sack", "ts", "udp", "ws"}; !slices.Equal(got, want) {
		t.Errorf("Tags = %v, want %v", got, want)
	}
	if !Within([]string{"newreno", "ws"}, Stage4bTags) || Within([]string{"newreno", "sack"}, Stage4bTags) {
		t.Errorf("Within does not follow Stage4bTags")
	}
}
