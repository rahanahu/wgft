package dutproto

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"slices"
)

// RecMagic starts a recording, after gzip.
const RecMagic = "WGFTREC1"

// RecMeta describes a recording: where it came from and what the engine needs to replay it. It
// holds no time of making, so the same inputs make the same file.
type RecMeta struct {
	// Source is the kind of test the recording comes from: scenarios, fuzzcore, stream-rx,
	// stream-tx or adversarial. Name is the recording's name within it.
	Source string `json:"source"`
	Name   string `json:"name"`
	// Test is the Go test that made it. Scenario, RunSeed and ScenarioSeed are set for a
	// conformance scenario; Seed for a test of internal/wgstack that takes one.
	Test         string `json:"test"`
	Scenario     string `json:"scenario,omitempty"`
	RunSeed      uint64 `json:"run_seed,omitempty"`
	ScenarioSeed uint64 `json:"scenario_seed,omitempty"`
	Seed         uint64 `json:"seed,omitempty"`
	// Variant names a test configuration the source does not use by itself, such as the 4b
	// variant: NewReno, no boost, and a peer without SACK or timestamps.
	Variant string `json:"variant,omitempty"`
	// GoCommit is the last commit that changed the Go wgstack's product code; GoVersion, GOARCH
	// and GOAMD64 are the toolchain and target that built it.
	GoCommit  string `json:"go_commit"`
	GoVersion string `json:"go_version"`
	GOARCH    string `json:"goarch"`
	GOAMD64   string `json:"goamd64"`
	// Tags are the features the recording uses (Tags); a replay takes a recording only when the
	// engine has all of them.
	Tags []string `json:"tags"`
	// Truncated, when set, says why the recording ends before the test did: the test went on with
	// an operation the frames do not have, such as an internal boost flip.
	Truncated string `json:"truncated,omitempty"`
	// Checks are a scenario's checks and their outcomes in order, run without an
	// expected-difference list, so a known difference of the Go wgstack shows as fail. The Rust
	// replay does not use them; they say what the recording shows.
	Checks []RecCheck `json:"checks,omitempty"`
	// Concurrent marks a scenario that reads or writes from a goroutine of its own: its frames
	// replay as recorded, but a second making may order them differently.
	Concurrent bool `json:"concurrent,omitempty"`
}

// Stage4bTags are the tags of a recording the Rust wgstack's PR 4b replays to the end
// (wgstack-rs.md, the stages of the bit-exact match): window scale, NewReno and no boost. A
// recording of the 4b variant has no other tag.
var Stage4bTags = []string{"boost-never", "newreno", "ws"}

// Within reports whether every tag of tags is in stage.
func Within(tags, stage []string) bool {
	for _, t := range tags {
		if !slices.Contains(stage, t) {
			return false
		}
	}
	return true
}

// RecCheck is one check of a scenario recording: its "scenario/check" key and its outcome.
type RecCheck struct {
	Key     string `json:"key"`
	Outcome string `json:"outcome"`
}

// RawFrame is one frame of a recording as it was on the wire.
type RawFrame struct {
	Kind  Kind
	Body  []byte
	Bytes []byte // the whole frame: length, kind and body
}

// WriteRecord writes a recording: gzip, at the best compression and with a header that has no
// time or name, of the magic, the meta's length as a u32, the meta as JSON and the frames.
func WriteRecord(w io.Writer, meta RecMeta, frames []byte) error {
	if meta.Tags == nil {
		meta.Tags = []string{}
	}
	js, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	zw, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return err
	}
	var hdr []byte
	hdr = append(hdr, RecMagic...)
	hdr = binary.LittleEndian.AppendUint32(hdr, uint32(len(js)))
	hdr = append(hdr, js...)
	if _, err := zw.Write(hdr); err != nil {
		return err
	}
	if _, err := zw.Write(frames); err != nil {
		return err
	}
	return zw.Close()
}

// ReadRecord reads a recording and returns its meta and its frames' bytes.
func ReadRecord(r io.Reader) (RecMeta, []byte, error) {
	var meta RecMeta
	zr, err := gzip.NewReader(r)
	if err != nil {
		return meta, nil, err
	}
	all, err := io.ReadAll(zr)
	if err != nil {
		return meta, nil, err
	}
	if len(all) < len(RecMagic)+4 || string(all[:len(RecMagic)]) != RecMagic {
		return meta, nil, protoErr("not a recording: no %s magic", RecMagic)
	}
	all = all[len(RecMagic):]
	n := binary.LittleEndian.Uint32(all)
	all = all[4:]
	if uint64(n) > uint64(len(all)) {
		return meta, nil, protoErr("meta of %d bytes in %d", n, len(all))
	}
	dec := json.NewDecoder(bytes.NewReader(all[:n]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&meta); err != nil {
		return meta, nil, fmt.Errorf("recording meta: %w", err)
	}
	return meta, all[n:], nil
}

// SplitFrames cuts a recording's frames apart. They alternate: a request and its response.
func SplitFrames(frames []byte) ([]RawFrame, error) {
	var out []RawFrame
	for len(frames) > 0 {
		if len(frames) < 5 {
			return nil, protoErr("%d bytes after the last frame", len(frames))
		}
		n := binary.LittleEndian.Uint32(frames)
		if n == 0 || uint64(n)+4 > uint64(len(frames)) {
			return nil, protoErr("frame length %d with %d bytes left", n, len(frames))
		}
		f := RawFrame{Kind: Kind(frames[4]), Body: frames[5 : 4+n], Bytes: frames[:4+n]}
		if want := len(out)%2 == 0; f.Kind.IsRequest() != want {
			return nil, protoErr("frame %d is %s; requests and responses alternate", len(out), f.Kind)
		}
		out = append(out, f)
		frames = frames[4+n:]
	}
	if len(out)%2 != 0 {
		return nil, protoErr("the last request has no response")
	}
	return out, nil
}

// Tags returns the features a recording's requests use, sorted:
//
//   - from HELLO: the congestion control (cubic, newreno) and the boost policy (boost-on-demand,
//     boost-at-accept, boost-never)
//   - from the injected packets: sack (SACK-permitted or SACK blocks), ts (timestamps) and ws
//     (window scale) offered in a TCP SYN, frag (an IPv4 fragment), udp, icmp, and proto-N for
//     any other IPv4 protocol N. An option in a segment without SYN is no tag: an engine at any
//     stage has to pass over options that were not negotiated
//   - from the requests: udp (a UDP socket), ping (an echo endpoint), boost-hook (BOOST_POLICY
//     or EVENTS)
func Tags(frames []RawFrame) []string {
	set := map[string]bool{}
	for i := 0; i < len(frames); i += 2 {
		f := frames[i]
		switch f.Kind {
		case KindHello:
			m, err := Decode(f.Kind, f.Body)
			if err != nil {
				continue
			}
			h := m.(*Hello)
			set[map[Congestion]string{CongestionCubic: "cubic", CongestionNewReno: "newreno"}[h.Congestion]] = true
			set[map[Boost]string{BoostOnDemand: "boost-on-demand", BoostAtAccept: "boost-at-accept", BoostNever: "boost-never"}[h.Boost]] = true
		case KindInject:
			m, err := Decode(f.Kind, f.Body)
			if err != nil {
				continue
			}
			for _, p := range m.(*Inject).Packets {
				packetTags(p, set)
			}
		case KindUDPListen, KindUDPRecv, KindUDPSend:
			set["udp"] = true
		case KindPingOpen, KindPingSend, KindPingRecv, KindPingClose:
			set["ping"] = true
		case KindBoostPolicy, KindEvents:
			set["boost-hook"] = true
		}
	}
	delete(set, "")
	tags := make([]string, 0, len(set))
	for t := range set {
		tags = append(tags, t)
	}
	slices.Sort(tags)
	return tags
}

// packetTags adds the tags of one injected IPv4 packet. Bytes that are not IPv4 add none.
func packetTags(p []byte, set map[string]bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return
	}
	ihl := int(p[0]&0xf) * 4
	if ihl < 20 || len(p) < ihl {
		return
	}
	if frag := binary.BigEndian.Uint16(p[6:8]); frag&0x3fff != 0 {
		set["frag"] = true
		return
	}
	l4 := p[ihl:]
	switch p[9] {
	case 6:
		if len(l4) < 20 {
			return
		}
		doff := int(l4[12]>>4) * 4
		if doff < 20 || doff > len(l4) || l4[13]&0x02 == 0 {
			// sack、ts、ws は相手が SYN で示す option で決める。交渉の無い option を持つ segment は、
			// どの段の engine も読み飛ばす入力なので印にしない
			return
		}
		opts := l4[20:doff]
		for i := 0; i < len(opts); {
			k := opts[i]
			if k == 0 {
				break
			}
			if k == 1 {
				i++
				continue
			}
			if i+1 >= len(opts) || opts[i+1] < 2 {
				break
			}
			switch k {
			case 3:
				set["ws"] = true
			case 4, 5:
				set["sack"] = true
			case 8:
				set["ts"] = true
			}
			i += int(opts[i+1])
		}
	case 17:
		set["udp"] = true
	case 1:
		set["icmp"] = true
	default:
		set[fmt.Sprintf("proto-%d", p[9])] = true
	}
}
